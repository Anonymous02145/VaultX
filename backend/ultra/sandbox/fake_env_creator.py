# Creates sandbox-like environments (isolated fake file systems, mount namespaces)

import os
import random
import logging

class FakeEnv:
    def __init__(self):
        self.logger = logging.getLogger('FakeEnv')
        self.root_path = "/data/vaultx_sandbox/"

    def score_risk(self, command):
        """LLM scoring stub — in real build, connects to `local_llm` for scoring"""
        risky_keywords = ["rm -rf", "chmod 777", "curl", "wget", "su", "exec", "nc", "sh"]
        score = sum(1 for kw in risky_keywords if kw in command)
        return score  # Range: 0 to ~10

    def create_namespace_env(self, pid):
        """Mockup: simulate new mount/user/net namespaces using Linux tools"""
        ns_dir = f"{self.root_path}/ns_{pid}_{random.randint(1000, 9999)}"
        os.makedirs(ns_dir, exist_ok=True)
        try:
            # Simulate namespace jailing (real containers would use seccomp + overlayfs)
            os.system(f"unshare --mount --uts --ipc --net --pid --fork -- bash -c 'sleep 0.1'")
            self.logger.info(f"[+] Namespace environment created: {ns_dir}")
        except Exception as e:
            self.logger.error(f"[X] Namespace setup failed: {e}")
        return ns_dir
