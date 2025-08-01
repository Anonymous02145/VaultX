# log_handler.py — Central logging for VaultX Ultra
import os
import logging
from datetime import datetime

class VaultLogger:
    def __init__(self, log_dir="/data/vaultx/logs"):
        self.log_dir = log_dir
        self._ensure_log_dir()

    def _ensure_log_dir(self):
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir, exist_ok=True)

    def get_logger(self, name="VaultX", file_name="vaultx.log"):
        log_path = os.path.join(self.log_dir, file_name)

        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)

        # Avoid duplicate handlers
        if logger.hasHandlers():
            return logger

        formatter = logging.Formatter('[%(levelname)s] %(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        fh = logging.FileHandler(log_path)
        fh.setFormatter(formatter)
        fh.setLevel(logging.INFO)
        logger.addHandler(fh)

        sh = logging.StreamHandler()
        sh.setFormatter(formatter)
        sh.setLevel(logging.INFO)
        logger.addHandler(sh)

        return logger
