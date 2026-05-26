"""
Choose a training checkpoint by benchmark F1 rather than by validation loss.

    python -m evaluation.select_checkpoint --run qwen1.5b-sft-v2

Why this exists. `load_best_model_at_end` selects on `eval_loss`, which is
token-level cross-entropy on held-out text. That is a *proxy*. The objective we
actually care about is whether the model finds real vulnerabilities without
crying wolf on safe code, and the two do not have to agree — a model can get
better at predicting the next token of a JSON answer while getting worse at
deciding what belongs in it.

On this project they disagreed sharply. eval_loss bottoms out at step 50, but
step 50 is roughly 400 of 1729 examples: barely a quarter of one epoch. Selecting
on loss handed back a model that had hardly trained.

Selection runs on the **dev** split, never on test. Picking a checkpoint by its
test score is test-set tuning — the number you then report is the maximum over
several draws, not an estimate of held-out performance.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from evaluation.run_eval import run_system, sanitize
from evaluation.schema import load_benchmark
from evaluation.score import score_and_report


def checkpoints(run_dir: Path) -> list[tuple[int, Path]]:
    found = []
    for path in run_dir.glob("checkpoint-*"):
        match = re.search(r"checkpoint-(\d+)$", path.name)
        if match and (path / "adapter_config.json").exists():
            found.append((int(match.group(1)), path))
    return sorted(found)


def main() -> None:
    parser = argparse.ArgumentParser(description="Pick a checkpoint by benchmark F1")
    parser.add_argument("--run", default="qwen1.5b-sft-v2")
    parser.add_argument("--checkpoints-dir", default="training/checkpoints")
    parser.add_argument("--split", default="dev", choices=["dev", "test"])
    parser.add_argument("--out-dir", default="evaluation/results_ckpt")
    parser.add_argument("--prompt-version", default="v2")
    args = parser.parse_args()

    run_dir = Path(args.checkpoints_dir) / args.run
    found = checkpoints(run_dir)
    if not found:
        raise SystemExit(f"no checkpoints with an adapter under {run_dir}")

    if args.split == "test":
        print(
            "! selecting on the test split is test-set tuning; the resulting "
            "score is a maximum over draws, not a held-out estimate.\n"
        )

    cases = load_benchmark("evaluation/data/benchmark.jsonl", args.split)
    out_dir = Path(args.out_dir)
    print(f"{len(found)} checkpoints, {len(cases)} {args.split} cases\n")

    specs = []
    for _step, path in found:
        spec = f"local-ft:{path.as_posix()}:{args.prompt_version}"
        specs.append(spec)
        run_system(spec, cases, out_dir, workers=1)

    metrics = score_and_report(
        "evaluation/data/benchmark.jsonl", out_dir, split=args.split, systems=specs
    )

    print("\nstep   F1     precision  recall")
    ranked = []
    for (step, path), spec in zip(found, specs, strict=False):
        match = next(
            (m for m in metrics if sanitize(spec) in sanitize(m.system) or str(step) in m.system),
            None,
        )
        if not match or not match.f1:
            continue
        ranked.append((match.f1.point, step, path))
        print(
            f"{step:<6} {100*match.f1.point:5.1f}  "
            f"{100*match.precision.point:8.1f}  {100*match.recall.point:6.1f}"
        )

    if ranked:
        best_f1, best_step, best_path = max(ranked)
        print(f"\nbest by {args.split} F1: checkpoint-{best_step} ({100*best_f1:.1f})")
        print(f"score it on test:\n  python -m evaluation.run_eval "
              f"--systems local-ft:{best_path.as_posix()}:{args.prompt_version} --split test")


if __name__ == "__main__":
    main()
