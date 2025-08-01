# apk_parser.py — AI-integrated APK behavior scanner + sandbox daemon

import os
import time
import logging
import hashlib
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from sandbox.sandbox_launcher import APKSandbox
from self_protect.tamper_guard import disguise_self
from local_llm import LLMScanner
from notify.push_notify import alert_user_decision
from quarantine.quarantine_manager import QuarantineManager

APK_DIR = "/sdcard/Download/"
SCAN_HISTORY = set()

class APKMonitor(FileSystemEventHandler):
    def __init__(self):
        self.logger = self.setup_logger()
        self.sandbox = APKSandbox()
        self.llm = LLMScanner()
        self.quarantine = QuarantineManager()

        disguise_self("apk_parser")
        self.logger.info("📡 APK Monitoring Daemon Activated")

    def setup_logger(self):
        logging.basicConfig(
            level=logging.INFO,
            format='[APK_MONITOR] %(asctime)s %(message)s',
            handlers=[logging.FileHandler("/data/vaultx/logs/apk_monitor.log")]
        )
        return logging.getLogger("APKMonitor")

    def on_created(self, event):
        if event.is_directory or not event.src_path.endswith(".apk"):
            return

        apk_path = event.src_path
        file_hash = self.hash_file(apk_path)

        if file_hash in SCAN_HISTORY:
            return
        SCAN_HISTORY.add(file_hash)

        self.logger.info(f"📦 New APK detected: {apk_path}")
        threading.Thread(target=self.analyze_apk, args=(apk_path,), daemon=True).start()

    def hash_file(self, filepath):
        h = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return "NULL_HASH"

    def analyze_apk(self, path):
        metadata = {
            "file_size": os.path.getsize(path),
            "path": path,
        }

        response = self.llm.analyze_apk_file(path)
        risk_score = response.get("risk_score", 0)
        reason = response.get("explanation", "No reasoning provided")

        self.logger.info(f"[AI] Score: {risk_score}/10 — {reason}")

        if risk_score >= 7:
            # 🚨 Dangerous APK detected
            self.logger.warning(f"⚠️ APK risk high! Asking user: {path}")

            user_decision = alert_user_decision(
                title="Malicious APK?",
                message=f"Risk Score: {risk_score}/10\nReason: {reason}\nAllow execution?",
                apk_path=path
            )

            if user_decision:
                self.logger.info("🔐 User accepted. Sandboxing now...")
                self.sandbox.sandbox_apk(path)
            else:
                self.logger.warning("🚫 APK quarantined by user decision.")
                self.quarantine.quarantine_file(path, reason="AI Risk Detection")
        else:
            self.logger.info("✅ APK passed AI check. Marked safe.")

    def start(self):
        observer = Observer()
        observer.schedule(self, APK_DIR, recursive=False)
        observer.start()
        self.logger.info(f"📁 Watching APK Directory: {APK_DIR}")

        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

# Usage will be handled via main.py integration
apk_monitor = APKMonitor()
apk_monitor.start()
