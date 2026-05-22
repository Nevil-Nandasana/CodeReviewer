"""
Merge a LoRA adapter into the base weights, producing a standalone model.

    python -m training.merge_adapter --adapter training/checkpoints/<run>/final_adapter

Merging is optional. `evaluation.run_eval --systems local-ft:<adapter>` loads the
base model and applies the adapter at runtime, which is the right choice while
iterating: adapters are ~150MB against ~3GB for merged weights, so keeping ten
experiments on disk costs 1.5GB instead of 30GB.

Merge when you want to serve without PEFT in the loop — a single directory that
`from_pretrained` loads directly, no adapter resolution, slightly lower latency.

Runs on CPU. Qwen2.5-Coder-1.5B needs roughly 4GB of RAM in fp16 and takes about
a minute; the previous version of this file quoted 14GB and 10 minutes because
it was written for a 6.7B model the project no longer uses.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

from training.config import TrainConfig


def main() -> None:
    cfg = TrainConfig()
    parser = argparse.ArgumentParser(description="Merge a LoRA adapter into base weights")
    parser.add_argument("--base-model", default=cfg.base_model)
    parser.add_argument(
        "--adapter",
        default=cfg.adapter_dir(),
        help="directory holding adapter_config.json and adapter_model.safetensors",
    )
    parser.add_argument("--output", default=None, help="default: <adapter>/../merged")
    args = parser.parse_args()

    adapter = Path(args.adapter)
    if not (adapter / "adapter_config.json").exists():
        raise SystemExit(
            f"no adapter at {adapter}\n"
            "Train first, or point --adapter at a checkpoint-N directory."
        )

    output = Path(args.output) if args.output else adapter.parent / "merged"

    print(f"base    : {args.base_model}")
    print(f"adapter : {adapter}")
    print(f"output  : {output}\n")

    from peft import PeftModel

    print("loading base model on CPU...")
    base = AutoModelForCausalLM.from_pretrained(
        args.base_model, torch_dtype=torch.float16, device_map="cpu"
    )

    print("applying adapter...")
    model = PeftModel.from_pretrained(base, str(adapter))

    print("merging...")
    merged = model.merge_and_unload()

    output.mkdir(parents=True, exist_ok=True)
    merged.save_pretrained(str(output))

    # The adapter dir carries the tokenizer saved at the end of training; fall
    # back to the base model's if this adapter came straight from a checkpoint.
    tokenizer_src = adapter if (adapter / "tokenizer_config.json").exists() else args.base_model
    AutoTokenizer.from_pretrained(str(tokenizer_src)).save_pretrained(str(output))

    print(f"\nmerged model -> {output}")
    print(f"benchmark it : python -m evaluation.run_eval --systems local:{output}:v2 --split test")
    print(f"serve it     : set MODEL_BACKEND=local and LOCAL_MODEL_PATH={output} in backend/.env")


if __name__ == "__main__":
    main()
