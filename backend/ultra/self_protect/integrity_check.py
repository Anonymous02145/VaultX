# integrity_check.py — Unbypassable File Integrity Monitor for VaultX
import os
import time
import json
import hashlib
import shutil
import stat
import logging
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from local_llm import analyze as ai_analyze  # Optional, if local_llm is present

MONITORED_PATH = "/data/vaultx/backend/ultra"
HASH_DB = "/data/vaultx/.integrity/hashes.json"
BACKUP_DIR = "/data/vaultx/.integrity/backups"
PROTECTED_EXT = [".py", ".cpp", ".h", ".json", ".so"]
AI_SCAN = True

class VaultIntegrityChecker:
    def __init__(self):
        self.hash_map = {}
        self.logger = self.setup_logger()
        self._ensure_dirs()
        self._load_hashes()

    def setup_logger(self):
        logging.basicConfig(level=logging.INFO, format='[INTEGRITY] %(asctime)s %(message)s')
        return logging.getLogger("IntegrityChecker")

    def _ensure_dirs(self):
        os.makedirs(BACKUP_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(HASH_DB), exist_ok=True)

    def _load_hashes(self):
        if os.path.exists(HASH_DB):
            try:
                with open(HASH_DB, "r") as f:
                    self.hash_map = json.load(f)
            except Exception:
                self.hash_map = {}

    def _save_hashes(self):
        with open(HASH_DB, "w") as f:
            json.dump(self.hash_map, f, indent=2)

    def _calculate_hash(self, filepath):
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return None

    def _backup_file(self, path):
        rel_path = os.path.relpath(path, MONITORED_PATH)
        backup_path = os.path.join(BACKUP_DIR, rel_path)
        os.makedirs(os.path.dirname(backup_path), exist_ok=True)
        shutil.copy2(path, backup_path)
        os.chmod(backup_path, stat.S_IREAD | stat.S_IRUSR)

    def _restore_file(self, path):
        rel_path = os.path.relpath(path, MONITORED_PATH)
        backup_path = os.path.join(BACKUP_DIR, rel_path)
        if os.path.exists(backup_path):
            shutil.copy2(backup_path, path)
            self.logger.warning(f"[RESTORE] Recovered: {path}")
        else:
            self.logger.error(f"[FAIL] No backup to recover: {path}")

    def _scan_path(self):
        monitored_files = []
        for root, dirs, files in os.walk(MONITORED_PATH):
            for f in files:
                if any(f.endswith(ext) for ext in PROTECTED_EXT):
                    monitored_files.append(os.path.join(root, f))
        return monitored_files

    def _ai_check(self, filepath):
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
            result = ai_analyze(content, system_role="integrity verifier")
            if "malware" in result.lower() or "injected" in result.lower():
                self.logger.warning(f"[AI] Threat detected in {filepath}: {result}")
                return False
        except Exception:
            pass
        return True

    def build_baseline(self):
        files = self._scan_path()
        for f in files:
            h = self._calculate_hash(f)
            if h:
                self.hash_map[f] = h
                self._backup_file(f)
        self._save_hashes()
        self.logger.info("[✓] Baseline integrity map created.")

    def verify_all(self):
        for path in self._scan_path():
            new_hash = self._calculate_hash(path)
            known_hash = self.hash_map.get(path)

            if known_hash != new_hash:
                self.logger.error(f"[!] Integrity breach: {path}")
                if AI_SCAN and not self._ai_check(path):
                    self._restore_file(path)
                    continue
                self._restore_file(path)
                self.hash_map[path] = self._calculate_hash(path)

        self._save_hashes()

    def daemon_loop(self, interval=15):
        self.logger.info("🔐 Integrity Check Daemon started.")
        while True:
            try:
                self.verify_all()
            except Exception as e:
                self.logger.error(f"[X] Integrity check error: {e}")
            time.sleep(interval)
