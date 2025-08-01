# quarantine_manager.py — Military-Grade File Isolation Core for VaultX
import os
import json
import uuid
import logging
import shutil
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

VAULT_PATH = "/data/vaultx/quarantine/"
INDEX_PATH = os.path.join(VAULT_PATH, "q_index.json")
ENCRYPT_META = False  # Set to True to encrypt metadata too

class QuarantineManager:
    def __init__(self):
        self.vault = Path(VAULT_PATH)
        self.index = Path(INDEX_PATH)
        self.logger = self._setup_logger()
        self._ensure_vault()
        self.key, self.nonce = self._generate_key_nonce()

    def _setup_logger(self):
        logging.basicConfig(level=logging.INFO, format='[QUARANTINE] %(asctime)s %(message)s')
        return logging.getLogger("QuarantineManager")

    def _ensure_vault(self):
        self.vault.mkdir(parents=True, exist_ok=True)
        if not self.index.exists():
            with open(self.index, "w") as f:
                json.dump({}, f)

    def _generate_key_nonce(self):
        salt = secrets.token_bytes(16)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        secret = secrets.token_bytes(32)
        key = kdf.derive(secret)
        nonce = secrets.token_bytes(12)
        return key, nonce

    def _encrypt_file(self, src_path):
        try:
            with open(src_path, 'rb') as f:
                raw_data = f.read()
            aes = AESGCM(self.key)
            encrypted = aes.encrypt(self.nonce, raw_data, None)
            return encrypted
        except Exception as e:
            self.logger.error(f"[X] Encryption failed: {e}")
            return None

    def _update_index(self, qid, original_path, reason):
        try:
            with open(self.index, "r+") as f:
                index = json.load(f)

                meta = {
                    "original": original_path,
                    "reason": reason,
                    "timestamp": datetime.now().isoformat(),
                }

                index[qid] = meta
                f.seek(0)
                json.dump(index, f, indent=4)
                f.truncate()

        except Exception as e:
            self.logger.error(f"[X] Index update failed: {e}")

    def quarantine_file(self, path, reason="Unknown"):
        if not os.path.exists(path):
            self.logger.warning(f"[-] File does not exist: {path}")
            return False

        try:
            qid = str(uuid.uuid4())
            qname = f"{qid}.vault"
            encrypted = self._encrypt_file(path)

            if encrypted is None:
                return False

            dest = self.vault / qname
            with open(dest, "wb") as f:
                f.write(encrypted)

            os.remove(path)
            self._update_index(qid, path, reason)
            self.logger.info(f"[+] Quarantined: {path} → {qname}")
            return True

        except Exception as e:
            self.logger.error(f"[X] Quarantine failed: {e}")
            return False

    def auto_quarantine(self, target_list: list):
        """
        List of tuples (file_path, reason)
        """
        for fpath, reason in target_list:
            self.quarantine_file(fpath, reason)

    def list_quarantined(self):
        try:
            with open(self.index, "r") as f:
                data = json.load(f)
                return data
        except Exception as e:
            self.logger.error(f"[X] Failed to load quarantine list: {e}")
            return {}

    def decrypt_file(self, qid, output_path):
        # For internal use only
        enc_path = self.vault / f"{qid}.vault"
        if not enc_path.exists():
            self.logger.error("[X] No such quarantined file")
            return False

        try:
            aes = AESGCM(self.key)
            with open(enc_path, "rb") as f:
                encrypted = f.read()

            decrypted = aes.decrypt(self.nonce, encrypted, None)

            with open(output_path, "wb") as f:
                f.write(decrypted)

            self.logger.info(f"[✓] Decrypted {qid} → {output_path}")
            return True
        except Exception as e:
            self.logger.error(f"[X] Decryption failed: {e}")
            return False
