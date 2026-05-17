"""
Local Model Client — loads fine-tuned DeepSeek-Coder-6.7B from disk.
4-bit NF4 quantization for inference. VRAM usage: ~3.5GB on RTX 4060.
"""
from __future__ import annotations
import time
import structlog

logger = structlog.get_logger(__name__)

try:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class LocalModelClient:
    """Loads merged fine-tuned model in 4-bit for inference."""

    def __init__(self, model_path: str):
        self.model_path = model_path
        self.model = None
        self.tokenizer = None
        if TORCH_AVAILABLE:
            self._load_model()
        else:
            logger.warning("torch_not_available", msg="Local model disabled — torch not installed")

    def _load_model(self):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

        logger.info("loading_local_model", path=self.model_path)
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
        )
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_path,
            quantization_config=bnb_config,
            device_map="auto",
            torch_dtype=torch.float16,
            trust_remote_code=True,
        )
        self.model.eval()
        vram = torch.cuda.memory_allocated() / 1e9
        logger.info("model_loaded", vram_gb=round(vram, 2))

    def generate(self, messages: list[dict], max_new_tokens: int = 1024) -> str:
        if not self.model or not TORCH_AVAILABLE:
            raise RuntimeError("Local model not loaded")

        import torch
        # Format as chat template
        prompt = self._format_chat(messages)
        start = time.time()
        inputs = self.tokenizer(
            prompt, return_tensors="pt", truncation=True, max_length=512
        ).to("cuda")

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=0.1,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id,
                repetition_penalty=1.1,
            )

        generated = outputs[0][inputs["input_ids"].shape[1]:]
        result = self.tokenizer.decode(generated, skip_special_tokens=True)
        elapsed = time.time() - start
        logger.info("local_inference_done", seconds=round(elapsed, 2))
        return result

    def _format_chat(self, messages: list[dict]) -> str:
        parts = []
        for m in messages:
            role = m["role"]
            content = m["content"]
            if role == "system":
                parts.append(f"<|system|>\n{content}")
            elif role == "user":
                parts.append(f"<|user|>\n{content}")
            elif role == "assistant":
                parts.append(f"<|assistant|>\n{content}")
        parts.append("<|assistant|>")
        return "\n".join(parts)

    @property
    def is_ready(self) -> bool:
        return self.model is not None
