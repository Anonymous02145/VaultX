# local_llm.py — VaultX Ultra On-Device Threat Analysis LLM

import os
from pathlib import Path
from llama_cpp import Llama
import logging

MODEL_PATH = Path("/data/vaultx/models/local_model.gguf")

class LocalLLM:
    def __init__(self):
        if not MODEL_PATH.exists():
            raise FileNotFoundError(f"[LLM] Model file not found: {MODEL_PATH}")

        self.model = Llama(
            model_path=str(MODEL_PATH),
            n_ctx=2048,
            n_threads=os.cpu_count(),
            use_mlock=True,        # Prevent swap leakage
            embedding=True,
            low_vram=True          # Optimize for mobile/low-power
        )
        self.logger = self.setup_logger()

    def setup_logger(self):
        os.makedirs("/data/vaultx/logs", exist_ok=True)
        logging.basicConfig(filename="/data/vaultx/logs/llm.log",
                            level=logging.INFO,
                            format='[LLM] %(asctime)s - %(message)s')
        return logging.getLogger("LocalLLM")

    def prompt_model(self, prompt: str, system_role="AI threat analyst"):
        final_prompt = (
            f"<|system|>\nYou are a {system_role}.\n"
            f"<|user|>\n{prompt}\n"
            f"<|assistant|>\n"
        )
        try:
            response = self.model(final_prompt, max_tokens=256, stop=["</s>"])
            return response["choices"][0]["text"].strip()
        except Exception as e:
            self.logger.error(f"LLM failed: {e}")
            return "[LLM ERROR]"

    def analyze_file_logic(self, file_path: str):
        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read(4096)
            sample_text = raw_bytes.hex()[:512]
        except Exception as e:
            return {"threat_level": 0, "reasoning": f"File read failed: {e}"}

        prompt = (
            f"Analyze this file sample (hex):\n\n{sample_text}\n\n"
            "Check for malware indicators such as:\n"
            "- Shellcode or embedded payloads\n"
            "- Obfuscation or encryption\n"
            "- Dangerous imports or opcodes\n"
            "- Packed sections\n"
            "- Any known binary exploits\n\n"
            "Respond with a JSON containing: threat_level (0-100), reasoning (string)."
        )
        try:
            reply = self.prompt_model(prompt)
            self.logger.info(f"Analysis reply: {reply}")

            import json
            parsed = json.loads(reply)
            return {
                "threat_level": int(parsed.get("threat_level", 0)),
                "reasoning": parsed.get("reasoning", "Unclear")
            }
        except Exception as e:
            self.logger.error(f"LLM parsing failed: {e}")
            return {"threat_level": 0, "reasoning": "Failed to parse LLM response"}

# Singleton instance for integration
llm = LocalLLM()

# Used by others like file_scanner or apk_parser
def analyze_file_logic(filepath):
    return llm.analyze_file_logic(filepath)
