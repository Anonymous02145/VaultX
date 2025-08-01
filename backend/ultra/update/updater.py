# updater.py — Secure auto-update mechanism
import os
import requests
import subprocess
import hashlib
import json
from update.verify_manifest import ManifestVerifier
from log_handler import VaultLogger

class VaultUpdater:
    def __init__(self):
        self.update_url = "https://vaultx-updates.securecdn.com/manifest.json"
        self.download_dir = "/data/vaultx/update_buffer/"
        self.logger = VaultLogger().get_logger()
        self.verifier = ManifestVerifier(public_key_path="/data/vaultx/keys/public_key.pem")

        if not os.path.exists(self.download_dir):
            os.makedirs(self.download_dir, exist_ok=True)

    def fetch_manifest(self):
        self.logger.info("Fetching update manifest...")
        try:
            r = requests.get(self.update_url, timeout=5)
            r.raise_for_status()
            manifest = r.json()
            return manifest
        except Exception as e:
            self.logger.error(f"Manifest fetch failed: {e}")
            return None

    def download_file(self, file_info):
        url = file_info["url"]
        filename = file_info["name"]
        dest = os.path.join(self.download_dir, filename)

        try:
            self.logger.info(f"Downloading {filename}...")
            r = requests.get(url, stream=True, timeout=10)
            r.raise_for_status()

            with open(dest, "wb") as f:
                for chunk in r.iter_content(1024):
                    f.write(chunk)
            return dest
        except Exception as e:
            self.logger.error(f"Failed to download {filename}: {e}")
            return None

    def install_updates(self, manifest):
        for f in manifest["files"]:
            local_path = self.download_file(f)
            if not local_path:
                continue

            if not self.verifier.verify_file(local_path, f["sha256"]):
                self.logger.warning(f"Update file failed integrity check: {f['name']}")
                continue

            target_path = os.path.join("/data/vaultx/backend/ultra/", f["name"])
            os.replace(local_path, target_path)
            os.chmod(target_path, 0o755)
            self.logger.info(f"{f['name']} updated successfully.")

    def run(self):
        manifest = self.fetch_manifest()
        if not manifest:
            return

        if self.verifier.verify_manifest(manifest):
            self.install_updates(manifest)
        else:
            self.logger.error("Manifest signature invalid. Update aborted.")

if __name__ == "__main__":
    updater = VaultUpdater()
    updater.run()
