"""
Training configuration for the CodeReviewer code-review fine-tune.

Base model is Qwen2.5-Coder-1.5B-Instruct, not a 6.7B model. On an 8GB laptop
GPU a 6.7B QLoRA run takes 12-18 hours and leaves no room to iterate; at 1.5B a
run finishes in about an hour, which is what makes eval-driven iteration
possible. An ablation table with five completed runs is worth more than one
unrepeatable run on a bigger model.

bf16 rather than fp16: the RTX 4060 is Ada, which has native bf16, and bf16's
wider exponent range avoids the loss-scaling instabilities fp16 hits with 4-bit
base weights.
"""
from __future__ import annotations

from dataclasses import dataclass

BASE_MODEL = "Qwen/Qwen2.5-Coder-1.5B-Instruct"


@dataclass
class TrainConfig:
    base_model: str = BASE_MODEL
    train_file: str = "training/data/train.jsonl"
    val_file: str = "training/data/val.jsonl"
    output_dir: str = "training/checkpoints"
    run_name: str = "qwen1.5b-sft-v1"

    # Sequence budget. Each example is a line-numbered source file plus a JSON
    # answer. Examples longer than this are dropped, never truncated — a clipped
    # answer would train the model to emit unterminated JSON.
    max_seq_len: int = 1536

    # QLoRA
    load_in_4bit: bool = True
    lora_r: int = 32
    lora_alpha: int = 64
    lora_dropout: float = 0.05
    lora_target_modules: tuple[str, ...] = (
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    )

    # Optimisation.
    #
    # Two epochs is the schedule, not the expectation. With whole template
    # families held out, eval_loss bottoms out around step 50 of 434 and rises
    # afterwards, so early stopping (patience 3) ends the run well short of
    # this. The schedule stays at 2.0 because the cosine decay is defined over
    # it; shortening it would change the learning-rate curve as well as the
    # stopping point.
    epochs: float = 2.0
    per_device_batch_size: int = 1
    gradient_accumulation_steps: int = 8
    learning_rate: float = 2e-4
    lr_scheduler_type: str = "cosine"
    warmup_ratio: float = 0.03
    weight_decay: float = 0.0
    max_grad_norm: float = 0.3
    optim: str = "paged_adamw_8bit"
    gradient_checkpointing: bool = True
    bf16: bool = True

    # Logging / eval.
    #
    # save_steps must equal eval_steps. `load_best_model_at_end` can only
    # restore a checkpoint that was actually written, so with eval every 50 and
    # save every 100 the model is scored at step 50 and then cannot be selected
    # — half the evaluations are unusable as stopping points. On the honest
    # family-held-out split the minimum lands at step 50, exactly the one the
    # old setting threw away.
    logging_steps: int = 10
    eval_steps: int = 50
    save_steps: int = 50
    # Enough to keep the best checkpoint plus recent ones. Transformers exempts
    # the best checkpoint from rotation when load_best_model_at_end is set.
    save_total_limit: int = 3
    seed: int = 42

    def adapter_dir(self) -> str:
        return f"{self.output_dir}/{self.run_name}/final_adapter"
