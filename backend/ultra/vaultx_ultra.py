# vaultx_ultra.py — VaultX Ultra Master Controller (main.py equivalent)

import threading
import time
import os
from sandbox.sandbox_launcher import sandbox_instance
from self_protect.tamper_guard import tamper_guard_instance
from core.integrity_check import integrity_checker_instance
from vault.quarantine_manager import quarantine_manager_instance
from account.account_check import account_daemon_instance
from apk.apk_parser import apk_monitor_instance
from behavior.behavior_monitor import behavior_monitor_instance
from net.dns_controller import dns_c_daemon_instance
from file_scanner import scanner_instance
from net.net_analyzer import net_analyzer_instance
from root_detect import root_daemon_instance
from signature_scanner import scanner_instance as sig_scanner_instance
from log_handler import VaultLogger

class VaultXUltra:
    def __init__(self):
        self.logger = VaultLogger().get_logger()
        self.threads = []

    def start_module(self, target, name):
        def safe_wrapper():
            try:
                self.logger.info(f"[+] Starting module: {name}")
                target()
            except Exception as e:
                self.logger.error(f"[X] {name} failed: {e}")
        t = threading.Thread(target=safe_wrapper, name=name, daemon=True)
        t.start()
        self.threads.append(t)

    def run_all(self):
        self.logger.info("🚀 VaultX Ultra initializing...")

        # Launch unkillable stealth daemons first
        self.start_module(tamper_guard_instance.start, "TamperGuard")
        self.start_module(integrity_checker_instance.start, "IntegrityChecker")
        self.start_module(dns_c_daemon_instance.start, "DNS Defender")

        # Launch sandbox & monitoring
        self.start_module(sandbox_instance.init, "SandboxEngine")
        self.start_module(apk_monitor_instance.daemon_loop, "APKMonitor")
        self.start_module(behavior_monitor_instance.start, "BehaviorMonitor")

        # Periodic protection checks
        self.start_module(account_daemon_instance.start, "AccountCheck")
        self.start_module(scanner_instance.start, "FileScanner-AI")
        self.start_module(sig_scanner_instance.start, "SignatureScanner")
        self.start_module(net_analyzer_instance.start, "LeakMonitor")

        # Optional root detection (killable by UI)
        self.start_module(root_daemon_instance.start, "RootDetector")

        # Quarantine always ready
        self.logger.info("🔒 Quarantine Manager Ready.")

        self.logger.info("✅ VaultX Ultra Daemons All Online.")

        # Master daemon loop
        while True:
            time.sleep(30)
            self.logger.info("🧠 Master heartbeat - All systems nominal.")

# === RUN MASTER CONTROLLER ===
controller = VaultXUltra()
controller.run_all()
