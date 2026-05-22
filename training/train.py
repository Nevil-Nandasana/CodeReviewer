"""
QLoRA supervised fine-tune for the CodeReviewer code reviewer.

    python -m training.train --run-name qwen1.5b-sft-v1
    tensorboard --logdir training/checkpoints

Uses plain `transformers.Trainer` with a hand-written collator instead of TRL's
SFTTrainer. Two reasons: the TRL API has churned repeatedly across versions and
breaks silently on argument renames, and — more importantly — this gives
explicit control over **completion-only loss masking**.

Loss masking matters here. The prompt is a long numbered source file; the answer
is a short JSON object. Training on the whole sequence spends most of the
gradient signal teaching the model to reproduce source code it was given, which
is both useless and actively harmful (it drifts the model toward echoing input).
Masking prompt tokens to -100 means the loss is computed only over the JSON the
model is supposed to produce.
"""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path

import torch
from torch.utils.data import Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
    set_seed,
)

from training.config import TrainConfig

IGNORE_INDEX = -100


def verify_gpu() -> None:
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA not available — check nvidia-smi and the torch build")
    name = torch.cuda.get_device_name(0)
    vram = torch.cuda.get_device_properties(0).total_memory / 1e9
    print(f"GPU: {name} ({vram:.1f} GB)")
    if vram < 7.0:
        raise RuntimeError(f"need >= 7GB VRAM, found {vram:.1f}GB")


class ReviewDataset(Dataset):
    """
    Chat examples tokenized with the model's own template, with everything up to
    the assistant turn masked out of the loss.
    """

    def __init__(self, path: str, tokenizer, max_seq_len: int):
        self.rows: list[dict] = []
        self.tokenizer = tokenizer
        self.max_seq_len = max_seq_len

        dropped = 0
        lengths: list[int] = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                encoded = self._encode(record["messages"])
                if encoded is None:
                    dropped += 1
                    continue
                lengths.append(len(encoded["input_ids"]))
                self.rows.append(encoded)

        lengths.sort()
        if lengths:
            p50 = lengths[len(lengths) // 2]
            p95 = lengths[int(len(lengths) * 0.95)]
            print(
                f"{Path(path).name}: {len(self.rows)} examples "
                f"(dropped {dropped} over {max_seq_len} tokens) | "
                f"len p50={p50} p95={p95} max={lengths[-1]}"
            )

    def _encode(self, messages: list[dict]) -> dict | None:
        prompt_messages = messages[:-1]
        answer = messages[-1]["content"]

        prompt_text = self.tokenizer.apply_chat_template(
            prompt_messages, tokenize=False, add_generation_prompt=True
        )
        prompt_ids = self.tokenizer(prompt_text, add_special_tokens=False)["input_ids"]
        answer_ids = self.tokenizer(answer, add_special_tokens=False)["input_ids"]
        answer_ids = answer_ids + [self.tokenizer.eos_token_id]

        input_ids = prompt_ids + answer_ids
        if len(input_ids) > self.max_seq_len:
            # Drop rather than truncate: a clipped answer teaches invalid JSON.
            return None

        labels = [IGNORE_INDEX] * len(prompt_ids) + answer_ids[:]
        return {"input_ids": input_ids, "labels": labels}

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, idx: int) -> dict:
        return self.rows[idx]


@dataclass
class PadCollator:
    pad_token_id: int

    def __call__(self, features: list[dict]) -> dict:
        max_len = max(len(f["input_ids"]) for f in features)
        input_ids, labels, attention = [], [], []
        for f in features:
            pad = max_len - len(f["input_ids"])
            input_ids.append(f["input_ids"] + [self.pad_token_id] * pad)
            labels.append(f["labels"] + [IGNORE_INDEX] * pad)
            attention.append([1] * len(f["input_ids"]) + [0] * pad)
        return {
            "input_ids": torch.tensor(input_ids, dtype=torch.long),
            "labels": torch.tensor(labels, dtype=torch.long),
            "attention_mask": torch.tensor(attention, dtype=torch.long),
        }


def build_model(cfg: TrainConfig):
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

    quant_config = None
    if cfg.load_in_4bit:
        from transformers import BitsAndBytesConfig

        quant_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16 if cfg.bf16 else torch.float16,
            bnb_4bit_use_double_quant=True,
        )

    model = AutoModelForCausalLM.from_pretrained(
        cfg.base_model,
        quantization_config=quant_config,
        torch_dtype=torch.bfloat16 if cfg.bf16 else torch.float16,
        device_map={"": 0},
    )
    model.config.use_cache = False

    if cfg.load_in_4bit:
        model = prepare_model_for_kbit_training(
            model, use_gradient_checkpointing=cfg.gradient_checkpointing
        )

    lora = LoraConfig(
        r=cfg.lora_r,
        lora_alpha=cfg.lora_alpha,
        lora_dropout=cfg.lora_dropout,
        target_modules=list(cfg.lora_target_modules),
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()
    return model


class VRAMCallback(__import__("transformers").TrainerCallback):
    def on_log(self, args, state, control, logs=None, **kwargs):
        if torch.cuda.is_available() and logs and "loss" in logs:
            peak = torch.cuda.max_memory_allocated() / 1e9
            print(f"    step {state.global_step}: peak VRAM {peak:.2f}GB")


def main() -> None:
    parser = argparse.ArgumentParser(description="QLoRA fine-tune for code review")
    parser.add_argument("--run-name", default=None)
    parser.add_argument("--epochs", type=float, default=None)
    parser.add_argument("--lr", type=float, default=None)
    parser.add_argument("--lora-r", type=int, default=None)
    parser.add_argument("--max-seq-len", type=int, default=None)
    parser.add_argument("--train-file", default=None)
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument("--grad-accum", type=int, default=None)
    parser.add_argument(
        "--early-stopping-patience",
        type=int,
        default=3,
        help="stop after N evals without improvement; 0 disables",
    )
    args = parser.parse_args()

    cfg = TrainConfig()
    for attr, value in (
        ("run_name", args.run_name),
        ("epochs", args.epochs),
        ("learning_rate", args.lr),
        ("lora_r", args.lora_r),
        ("max_seq_len", args.max_seq_len),
        ("train_file", args.train_file),
        ("per_device_batch_size", args.batch_size),
        ("gradient_accumulation_steps", args.grad_accum),
    ):
        if value is not None:
            setattr(cfg, attr, value)

    verify_gpu()
    set_seed(cfg.seed)

    tokenizer = AutoTokenizer.from_pretrained(cfg.base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    train_ds = ReviewDataset(cfg.train_file, tokenizer, cfg.max_seq_len)
    val_ds = ReviewDataset(cfg.val_file, tokenizer, cfg.max_seq_len)
    if not len(train_ds):
        raise SystemExit(f"no usable training examples in {cfg.train_file}")

    model = build_model(cfg)

    run_dir = Path(cfg.output_dir) / cfg.run_name
    run_dir.mkdir(parents=True, exist_ok=True)

    # TensorBoard's writer goes through TensorFlow's C++ gfile layer, which
    # cannot create directories under a non-ASCII absolute path on Windows —
    # it reports "<dir> is not a directory" and takes the whole run down at
    # step 0. This repository currently lives under a path containing an em
    # dash, so probe instead of assuming, and drop to no reporting rather than
    # lose an hour of training to a logging backend.
    report_to = ["tensorboard"]
    logging_dir = run_dir / "runs"
    try:
        str(run_dir.resolve()).encode("ascii")
        logging_dir.mkdir(parents=True, exist_ok=True)
    except (UnicodeEncodeError, OSError):
        print(
            f"! tensorboard disabled: '{run_dir.resolve()}' is not an ASCII path.\n"
            "  Loss is still printed and saved to trainer_state.json in each checkpoint."
        )
        report_to = []

    training_args = TrainingArguments(
        output_dir=str(run_dir),
        run_name=cfg.run_name,
        num_train_epochs=cfg.epochs,
        per_device_train_batch_size=cfg.per_device_batch_size,
        per_device_eval_batch_size=cfg.per_device_batch_size,
        gradient_accumulation_steps=cfg.gradient_accumulation_steps,
        learning_rate=cfg.learning_rate,
        lr_scheduler_type=cfg.lr_scheduler_type,
        warmup_ratio=cfg.warmup_ratio,
        weight_decay=cfg.weight_decay,
        max_grad_norm=cfg.max_grad_norm,
        optim=cfg.optim,
        gradient_checkpointing=cfg.gradient_checkpointing,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        bf16=cfg.bf16,
        fp16=not cfg.bf16,
        logging_steps=cfg.logging_steps,
        eval_strategy="steps",
        eval_steps=cfg.eval_steps,
        save_strategy="steps",
        save_steps=cfg.save_steps,
        save_total_limit=cfg.save_total_limit,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        report_to=report_to,
        logging_dir=str(logging_dir),
        seed=cfg.seed,
        dataloader_num_workers=0,
    )

    # Early stopping earns its place only now that the validation split is
    # honest. Under the previous random split, eval_loss fell to 1e-4 and
    # flat-lined, so patience never triggered and the curve implied the run
    # should train longer. With whole families held out, eval_loss bottoms out
    # around step 50 of 434 and then climbs — the run overfits for roughly
    # seven eighths of its scheduled length. `load_best_model_at_end` already
    # restores the best checkpoint; this stops burning GPU to reach it.
    callbacks = [VRAMCallback()]
    if args.early_stopping_patience > 0:
        from transformers import EarlyStoppingCallback

        callbacks.append(
            EarlyStoppingCallback(early_stopping_patience=args.early_stopping_patience)
        )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        data_collator=PadCollator(tokenizer.pad_token_id),
        callbacks=callbacks,
    )

    print(f"\ntraining {cfg.run_name}: {len(train_ds)} train / {len(val_ds)} val")
    trainer.train()

    adapter_dir = cfg.adapter_dir()
    os.makedirs(adapter_dir, exist_ok=True)
    trainer.save_model(adapter_dir)
    tokenizer.save_pretrained(adapter_dir)

    metrics = trainer.evaluate()
    (Path(adapter_dir) / "train_summary.json").write_text(
        json.dumps(
            {
                "run_name": cfg.run_name,
                "base_model": cfg.base_model,
                "train_examples": len(train_ds),
                "val_examples": len(val_ds),
                "epochs": cfg.epochs,
                "lora_r": cfg.lora_r,
                "learning_rate": cfg.learning_rate,
                "final_eval_loss": metrics.get("eval_loss"),
                "peak_vram_gb": round(torch.cuda.max_memory_allocated() / 1e9, 2),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"\nadapter -> {adapter_dir}")
    print(f"final eval_loss: {metrics.get('eval_loss'):.4f}")
    print(f"peak VRAM: {torch.cuda.max_memory_allocated()/1e9:.2f}GB")
    print(f"\nnext: python -m evaluation.run_eval --systems local-ft:{adapter_dir} --split test")


if __name__ == "__main__":
    main()
