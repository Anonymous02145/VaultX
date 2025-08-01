# signature_scanner.py — Military-Grade Static Malware Signature Detection

import os
import time
import hashlib
import logging
import threading
import json
from pathlib import Path
from local_llm import analyze_file_logic
from log_handler import VaultLogger

SIGNATURE_DB = Path("/data/vaultx/db/signatures.json")
SCAN_PATH = Path("/sdcard/")  # You can adjust this root
EXCLUDE_EXTENSIONS = {".gguf", ".mp4", ".jpg", ".png", ".zip", ".apk"}

class SignatureScanner:
    def __init__(self):
        self.logger = VaultLogger().get_logger()
        self.signatures = self.load_signatures()
        self.scan_interval = 86400  # 24h
        self.running = False

    def load_signatures(self):
        if SIGNATURE_DB.exists():
            try:
                with open(SIGNATURE_DB, "r") as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Failed to load signature DB: {e}")
        return {}

    def calculate_hash(self, path):
        try:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return None

    def is_threat(self, file_hash):
        return file_hash in self.signatures

    def analyze_ai(self, filepath):
        try:
            result = analyze_file_logic(filepath)
            return result.get("threat_level", 0), result.get("reasoning", "")
        except Exception as e:
            return 0, f"LLM analysis error: {e}"

    def scan_file(self, filepath):
        if not os.path.isfile(filepath):
            return

        if any(filepath.endswith(ext) for ext in EXCLUDE_EXTENSIONS):
            return

        file_hash = self.calculate_hash(filepath)
        if not file_hash:
            return

        if self.is_threat(file_hash):
            self.logger.warning(f"[SIGNATURE HIT] Threat: {filepath}")
        else:
            ai_score, reason = self.analyze_ai(filepath)
            if ai_score >= 7:
                self.logger.warning(f"[AI FLAG] File: {filepath} | Score: {ai_score}/10 | Reason: {reason}")
            else:
                self.logger.info(f"[CLEAN] File: {filepath}")

    def recursive_scan(self, directory):
        for root, dirs, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                self.scan_file(full_path)

    def scan_loop(self):
        while self.running:
            self.logger.info("🛡️ Starting full signature + AI scan")
            self.recursive_scan(str(SCAN_PATH))
            self.logger.info("✅ Scan complete, sleeping 24h")
            time.sleep(self.scan_interval)

    def start(self):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self.scan_loop, daemon=True).start()

    def stop(self):
        self.running = False

# DO NOT add if __name__ == "__main__" — Controlled via main.py
scanner_instance = SignatureScanner()
