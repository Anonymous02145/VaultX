# dns.py — VaultX Ultra AI DNS Threat Analyzer (Controlled by dns.c)

import os
import time
import requests
import subprocess
import threading
import socket
import json
from local_llm import LocalLLM
from firewall.packet_filter import block_domain

PHISHING_FEEDS = [
    "https://openphish.com/feed.txt",
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://phishunt.io/feed.txt"
]

BLOCKED_DOMAINS = set()
LLM = LocalLLM()
SCAN_INTERVAL = 3600  # 1 hour


def fetch_phishing_domains():
    domains = set()
    for url in PHISHING_FEEDS:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if "." in line:
                        domains.add(line)
        except Exception as e:
            continue
    return domains


def ai_analyze_domain(domain):
    prompt = f"""
    You are a network security AI. Analyze the domain: {domain}

    Check for:
    - Phishing characteristics
    - Malware distribution
    - DNS poisoning
    - MITM suitability
    - Tor relay or Onion link
    - Obfuscation

    Respond with: RISK (High/Medium/Low) and Reason.
    """
    output = LLM.analyze(prompt)
    return output


def block_if_malicious(domain, reason):
    if domain not in BLOCKED_DOMAINS:
        block_domain(domain)
        BLOCKED_DOMAINS.add(domain)
        log_threat(domain, reason)
        print(f"[⚠️ BLOCKED] {domain} — Reason: {reason}")


def log_threat(domain, reason):
    log_path = "/data/vaultx/logs/dns_ai_threats.json"
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    log_entry = {
        "domain": domain,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "reason": reason
    }
    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            data = json.load(f)
    else:
        data = []

    data.append(log_entry)

    with open(log_path, "w") as f:
        json.dump(data, f, indent=4)


def monitor_dns_traffic():
    """
    Assumes that iptables or nftables has been configured to forward DNS logs
    into a log file or netlink buffer. Here, we simulate that with a dummy log reader.
    """
    LOG_PATH = "/var/log/dns_queries.log"  # Could be from iptables ULOG or audit
    if not os.path.exists(LOG_PATH):
        open(LOG_PATH, "w").close()

    seen_lines = set()
    while True:
        with open(LOG_PATH, "r") as f:
            lines = f.readlines()

        for line in lines:
            if line not in seen_lines:
                seen_lines.add(line)
                if "query:" in line:
                    domain = extract_domain_from_log(line)
                    if domain:
                        reason = ai_analyze_domain(domain)
                        if "High" in reason:
                            block_if_malicious(domain, reason)
        time.sleep(10)


def extract_domain_from_log(line):
    # Simulated log parser
    if "query:" in line:
        parts = line.strip().split("query: ")
        if len(parts) == 2:
            return parts[1].strip()
    return None


def periodic_feed_scan():
    while True:
        print("[DNS AI] Fetching phishing feeds...")
        domains = fetch_phishing_domains()
        for domain in domains:
            reason = ai_analyze_domain(domain)
            if "High" in reason:
                block_if_malicious(domain, reason)
        time.sleep(SCAN_INTERVAL)


def start_threads():
    t1 = threading.Thread(target=periodic_feed_scan, daemon=True)
    t2 = threading.Thread(target=monitor_dns_traffic, daemon=True)

    t1.start()
    t2.start()

    t1.join()
    t2.join()


# No __main__ block because dns.c manages execution
start_threads()
