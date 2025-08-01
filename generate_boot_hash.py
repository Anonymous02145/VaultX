# generate_boot_hash.py — Generates secure boot-time hash map of critical files
import os
import hashlib
import json
from datetime import datetime
from pathlib import Path
from backend.ultra.log_handler import log_event_secure

class BootHashGenerator:
    def __init__(self, output_path="/data/vaultx/db/boot_integrity.json"):
        self.output_path = output_path
        self.target_paths = [
            "/system/bin/",
            "/vendor/bin/",
            "/system/lib/",
            "/init.rc",
            "/data/data/com.vaultx/",
            "/data/system/",
            "/etc/selinux/"
        ]

    def compute_sha256(self, file_path):
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            log_event_secure(f"[BootHash] Failed to hash {file_path}: {e}")
            return None

    def generate_hashes(self):
        hash_map = {}
        for path in self.target_paths:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        hash_val = self.compute_sha256(full_path)
                        if hash_val:
                            hash_map[full_path] = hash_val
            elif os.path.isfile(path):
                hash_val = self.compute_sha256(path)
                if hash_val:
                    hash_map[path] = hash_val

        self._store_hashes(hash_map)
        log_event_secure(f"[BootHash] Boot hashes generated and stored.")
        return hash_map

    def _store_hashes(self, hash_map):
        try:
            os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
            with open(self.output_path, "w") as f:
                json.dump({
                    "generated_at": datetime.utcnow().isoformat() + "Z",
                    "hashes": hash_map
                }, f, indent=2)
        except Exception as e:
            log_event_secure(f"[BootHash] Failed to store hashes: {e}")

# --- Auto-execution at boot ---
if __name__ == "__main__":
    generator = BootHashGenerator()
    generator.generate_hashes()
