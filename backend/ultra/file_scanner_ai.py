# file_scanner.py — VaultX Ultra Periodic File AI Scanner

import os
import time
import hashlib
import magic
import joblib
import threading
import logging
import numpy as np
from datetime import datetime
from local_llm import analyze_file_logic  # Must be defined in local_llm.py
from sklearn.neural_network import MLPClassifier

SCAN_INTERVAL_SECONDS = 86400  # 24 hours
SCAN_DIRECTORIES = ["/sdcard/Download/", "/data/vaultx/uploads/", "/data/user/0/"]  # Add more if needed
STATIC_MODEL_PATH = "/data/vaultx/models/static_av_model.pkl"

class FileScannerDaemon:
    def __init__(self):
        self.static_model = self.load_model()
        self.logger = self.setup_logger()
        self.history = set()  # To avoid rescanning same files

    def load_model(self):
        try:
            return joblib.load(STATIC_MODEL_PATH)
        except Exception as e:
            raise RuntimeError(f"Static AV model not found: {e}")

    def setup_logger(self):
        os.makedirs("/data/vaultx/logs/", exist_ok=True)
        logging.basicConfig(filename="/data/vaultx/logs/file_scanner.log",
                            level=logging.INFO,
                            format='[%(asctime)s] %(levelname)s: %(message)s')
        return logging.getLogger("FileScanner")

    def hash_file(self, filepath):
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(4096):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return None

    def calculate_entropy(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            if not data:
                return 0
            from math import log2
            prob = [float(data.count(byte)) / len(data) for byte in set(data)]
            return -sum(p * log2(p) for p in prob)
        except:
            return 0

    def extract_features(self, filepath):
        try:
            size = os.path.getsize(filepath)
            entropy = self.calculate_entropy(filepath)
            return np.array([[size, entropy]])
        except:
            return np.array([[0, 0]])

    def predict_file_threat(self, filepath):
        features = self.extract_features(filepath)
        static_score = int(self.static_model.predict_proba(features)[0][1] * 100)

        llm_result = analyze_file_logic(filepath)
        llm_score = int(llm_result.get("threat_level", 0))
        reason = llm_result.get("reasoning", "Unknown")

        final_score = int(0.6 * static_score + 0.4 * llm_score)
        return {
            "score": final_score,
            "static": static_score,
            "llm": llm_score,
            "reason": reason
        }

    def scan_file(self, filepath):
        if not os.path.isfile(filepath) or os.path.islink(filepath):
            return
        file_hash = self.hash_file(filepath)
        if not file_hash or file_hash in self.history:
            return
        self.history.add(file_hash)

        report = self.predict_file_threat(filepath)
        score = report["score"]
        reason = report["reason"]
        self.logger.info(f"Scanned {filepath} - Score: {score}/100 - Reason: {reason}")

        if score >= 75:
            self.notify_user(filepath, score, reason)

    def notify_user(self, filepath, score, reason):
        print(f"[⚠️ ALERT] Suspicious file detected:\n  → Path: {filepath}\n  → Score: {score}\n  → Reason: {reason}")
        # TODO: Replace with Flutter notification, WebSocket, or native app trigger

    def walk_and_scan(self):
        for root_dir in SCAN_DIRECTORIES:
            for root, dirs, files in os.walk(root_dir):
                for name in files:
                    full_path = os.path.join(root, name)
                    try:
                        self.scan_file(full_path)
                    except Exception as e:
                        self.logger.warning(f"Failed to scan {full_path}: {e}")

    def periodic_scan_loop(self):
        while True:
            self.logger.info("🧠 Starting full scan.")
            self.walk_and_scan()
            self.logger.info("✅ Full scan completed. Sleeping...")
            time.sleep(SCAN_INTERVAL_SECONDS)


# This file will be controlled by `main.py` — do not start main here
scanner_daemon = FileScannerDaemon()

# If integrated via main.py, run:
# threading.Thread(target=scanner_daemon.periodic_scan_loop, daemon=True).start()
