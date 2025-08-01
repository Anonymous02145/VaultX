# sandbox_launcher.py — AI-Hardened APK Sandboxing Module

import os
import subprocess
import logging
import hashlib
from quarantine_manager import QuarantineManager
from local_llm import LLMScanner

APK_SANDBOX_LOG = "/data/vaultx/logs/sandbox.log"

class APKSandbox:
    def __init__(self):
        self.logger = self.setup_logger()
        self.quarantine = QuarantineManager()
        self.llm = LLMScanner()

    def setup_logger(self):
        os.makedirs(os.path.dirname(APK_SANDBOX_LOG), exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='[SANDBOX] %(asctime)s %(levelname)s: %(message)s',
            handlers=[logging.FileHandler(APK_SANDBOX_LOG), logging.StreamHandler()]
        )
        return logging.getLogger("APKSandbox")

    def extract_package_name(self, apk_path):
        try:
            result = subprocess.check_output(["aapt", "dump", "badging", apk_path], stderr=subprocess.DEVNULL)
            for line in result.decode().split('\n'):
                if line.startswith("package:"):
                    return line.split("'")[1]
        except Exception:
            self.logger.error(f"[X] Failed to extract package name from {apk_path}")
        return None

    def extract_permissions(self, apk_path):
        try:
            output = subprocess.check_output(["aapt", "dump", "permissions", apk_path], stderr=subprocess.DEVNULL)
            perms = [line.strip() for line in output.decode().splitlines() if "uses-permission" in line]
            return perms
        except Exception:
            return []

    def hash_apk(self, apk_path):
        with open(apk_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    def ai_check_apk(self, apk_path, permissions):
        prompt = f"""
        You are a mobile cybersecurity agent. Analyze the following APK:

        - SHA256: {self.hash_apk(apk_path)}
        - Permissions: {permissions}
        - Target: {apk_path}

        Return:
        - Risk score (0–10)
        - Risk reason
        """

        result = self.llm.analyze_file(apk_path, prompt)
        risk_score = result.get("risk_score", 0)
        reason = result.get("explanation", "Unknown")

        return risk_score, reason

    def sandbox_apk(self, apk_path):
        package_name = self.extract_package_name(apk_path)
        if not package_name:
            self.logger.error(f"[X] Unable to parse APK: {apk_path}")
            return

        permissions = self.extract_permissions(apk_path)
        risk_score, reason = self.ai_check_apk(apk_path, permissions)

        self.logger.info(f"[+] Risk Score: {risk_score}/10 for {package_name} — {reason}")

        if risk_score >= 7:
            self.logger.warning(f"[!] High-risk APK detected: {package_name}. Quarantining.")
            self.quarantine.quarantine_file(apk_path, reason=reason)
            return

        try:
            # Sandbox user profile
            user_id = "999"
            sandbox_path = f"/data/sandbox/{package_name}/"
            os.makedirs(sandbox_path, exist_ok=True)

            subprocess.run(["pm", "install", "--user", user_id, apk_path], check=True)
            subprocess.run(["appops", "set", package_name, "RUN_IN_BACKGROUND", "deny"], check=True)
            subprocess.run(["appops", "set", package_name, "READ_CLIPBOARD", "deny"], check=True)

            self.logger.info(f"[✓] APK sandboxed successfully: {package_name}")

        except Exception as e:
            self.logger.error(f"[X] Sandboxing failed: {e}")
            self.quarantine.quarantine_file(apk_path, reason="Install Failure or Suspicious Behavior")
