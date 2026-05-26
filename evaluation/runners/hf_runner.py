"""
Local transformers runner — base model or QLoRA fine-tune.

Runs in the training virtualenv (torch + transformers + peft). Deps are imported
lazily so the other runners stay usable in the backend virtualenv, which has no
torch installed.
"""
from __future__ import annotations

from pathlib import Path


from evaluation.parsing import parse_review_output
from evaluation.prompts import build_messages
from evaluation.runners.base import Reviewer
from evaluation.schema import BenchmarkCase, CaseResult


class HFReviewer(Reviewer):
    def __init__(
        self,
        model_path: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct",
        adapter_path: str | None = None,
        prompt_version: str = "v2",
        max_new_tokens: int = 700,
        # fp16, not 4-bit. Quantisation exists to fit a model that otherwise
        # would not: at 1.5B the fp16 weights are ~3GB and fit any card that can
        # run this benchmark, while 4-bit adds a dequantisation step to every
        # token and measurably slows single-sequence generation. Since latency
        # is a reported metric, quantising here would understate the model on a
        # number it does not need to lose. Set True if VRAM is actually tight.
        load_in_4bit: bool = False,
        temperature: float = 0.0,
        name: str | None = None,
    ):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.torch = torch
        self.model_path = model_path
        self.adapter_path = adapter_path
        self.prompt_version = prompt_version
        self.max_new_tokens = max_new_tokens
        self.temperature = temperature
        # The adapter's own directory name goes in the system name. Deriving it
        # from model_path alone made every checkpoint of a run report as the
        # same system, so a sweep over checkpoint-50/150/200 produced three
        # identical labels and the rows could not be told apart.
        if adapter_path:
            tag = Path(adapter_path).name  # 'checkpoint-150', 'final_adapter'
            suffix = "ft" if tag == "final_adapter" else f"ft-{tag}"
        else:
            suffix = "base"
        self.name = name or f"{model_path.split('/')[-1]}-{suffix}-{prompt_version}"

        quant_config = None
        if load_in_4bit and torch.cuda.is_available():
            from transformers import BitsAndBytesConfig

            quant_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True,
            )

        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        self.model = AutoModelForCausalLM.from_pretrained(
            model_path,
            quantization_config=quant_config,
            torch_dtype=torch.float16,
            device_map="auto" if torch.cuda.is_available() else None,
        )

        if adapter_path:
            from peft import PeftModel

            self.model = PeftModel.from_pretrained(self.model, adapter_path)

        self.model.eval()

    def review(self, case: BenchmarkCase, pre_flags: list[dict] | None = None) -> CaseResult:
        messages = build_messages(
            case.code, case.filename, case.language, pre_flags, self.prompt_version
        )

        def run():
            torch = self.torch
            prompt = self.tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=3072)
            inputs = {k: v.to(self.model.device) for k, v in inputs.items()}
            prompt_tokens = int(inputs["input_ids"].shape[1])

            with torch.no_grad():
                output = self.model.generate(
                    **inputs,
                    max_new_tokens=self.max_new_tokens,
                    do_sample=self.temperature > 0,
                    temperature=self.temperature if self.temperature > 0 else None,
                    pad_token_id=self.tokenizer.pad_token_id,
                )

            generated = output[0][prompt_tokens:]
            raw = self.tokenizer.decode(generated, skip_special_tokens=True)
            comments, strict = parse_review_output(raw)
            return comments, strict, {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": int(generated.shape[0]),
                "cost_usd": 0.0,  # local inference: electricity, not API spend
                "raw_output": raw,
            }

        return self._timed(case, run)

    def close(self) -> None:
        del self.model
        if self.torch.cuda.is_available():
            self.torch.cuda.empty_cache()
