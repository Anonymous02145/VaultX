# verify_manifest.py — Validates manifest signatures
import hashlib
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

class ManifestVerifier:
    def __init__(self, public_key_path):
        with open(public_key_path, "rb") as f:
            self.public_key = serialization.load_pem_public_key(f.read())

    def verify_manifest(self, manifest):
        try:
            signature = bytes.fromhex(manifest["signature"])
            manifest_data = json.dumps(manifest["files"], sort_keys=True).encode()

            self.public_key.verify(
                signature,
                manifest_data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def verify_file(self, path, expected_hash):
        sha256 = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(4096):
                    sha256.update(chunk)
            return sha256.hexdigest() == expected_hash
        except:
            return False
