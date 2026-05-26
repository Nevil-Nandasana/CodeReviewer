"""
Run systems under test against the benchmark.

    python -m evaluation.run_eval --systems rules-only --split test
    python -m evaluation.run_eval --systems gpt-4o-mini,hybrid:gpt-4o-mini --split test
    python -m evaluation.run_eval --systems local:Qwen/Qwen2.5-Coder-1.5B-Instruct --split test

Inference and scoring are separate steps: this writes raw per-case results to
evaluation/results/<system>.jsonl, and `python -m evaluation.score` turns those
into metrics. That split means re-scoring after a metric change costs nothing and
never re-runs a model.

Runs are resumable. Cases already present in the output file are skipped unless
--force is passed, so an interrupted 40-minute local-model run picks up where it
stopped.

System specs
  rules-only                     production AST + rule scanner, no LLM
  <openai-model>[:vN]            hosted API, e.g. gpt-4o-mini:v2
  local:<hf-id-or-path>[:vN]     local transformers model
  local-ft:<adapter>[:vN]        local base model + QLoRA adapter
  hybrid:<any-llm-spec>          rule pre-flags injected into the LLM prompt
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from evaluation.schema import BenchmarkCase, CaseResult, load_benchmark, read_jsonl

RESULTS_DIR = Path("evaluation/results")
DEFAULT_BASE_MODEL = "Qwen/Qwen2.5-Coder-1.5B-Instruct"


def sanitize(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)


def build_reviewer(spec: str):
    """Turn a system spec string into a Reviewer instance."""
    if spec.startswith("hybrid:"):
        from evaluation.runners.hybrid_runner import HybridReviewer

        return HybridReviewer(build_reviewer(spec[len("hybrid:") :]))

    if spec == "rules-only":
        from evaluation.runners.rules_runner import RulesReviewer

        return RulesReviewer()

    if spec.startswith("local-ft:"):
        from evaluation.runners.hf_runner import HFReviewer

        rest = spec[len("local-ft:") :]
        adapter, version = _split_version(rest)
        return HFReviewer(
            model_path=DEFAULT_BASE_MODEL, adapter_path=adapter, prompt_version=version
        )

    if spec.startswith("local:"):
        from evaluation.runners.hf_runner import HFReviewer

        model, version = _split_version(spec[len("local:") :])
        return HFReviewer(model_path=model or DEFAULT_BASE_MODEL, prompt_version=version)

    from evaluation.runners.openai_runner import OpenAIReviewer

    model, version = _split_version(spec)
    return OpenAIReviewer(model=model, prompt_version=version)


def _split_version(spec: str) -> tuple[str, str]:
    """'gpt-4o-mini:v2' -> ('gpt-4o-mini', 'v2'); windows paths keep their colon."""
    match = re.search(r":(v\d+)$", spec)
    if match:
        return spec[: match.start()], match.group(1)
    return spec, "v2"


def load_done(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {rec["case_id"] for rec in read_jsonl(path)}


def append_result(path: Path, result: CaseResult) -> None:
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(result.to_json(), ensure_ascii=False) + "\n")
        fh.flush()


def run_system(
    spec: str,
    cases: list[BenchmarkCase],
    out_dir: Path,
    workers: int = 1,
    force: bool = False,
) -> Path:
    out_path = out_dir / f"{sanitize(spec)}.jsonl"
    if force and out_path.exists():
        out_path.unlink()

    done = load_done(out_path)
    todo = [c for c in cases if c.case_id not in done]
    print(f"\n=== {spec} ===")
    print(f"cases: {len(cases)} total, {len(done)} cached, {len(todo)} to run")
    if not todo:
        return out_path

    reviewer = build_reviewer(spec)
    is_local = spec.startswith(("local:", "local-ft:", "hybrid:local"))
    effective_workers = 1 if (is_local or spec == "rules-only") else workers

    started = time.time()
    completed = 0
    try:
        if effective_workers == 1:
            for case in todo:
                append_result(out_path, reviewer.review(case))
                completed += 1
                if completed % 10 == 0 or completed == len(todo):
                    rate = completed / max(time.time() - started, 1e-6)
                    eta = (len(todo) - completed) / max(rate, 1e-9)
                    print(f"  {completed}/{len(todo)}  {rate:.2f} cases/s  eta {eta/60:.1f}m")
        else:
            with ThreadPoolExecutor(max_workers=effective_workers) as pool:
                futures = {pool.submit(reviewer.review, case): case for case in todo}
                for future in as_completed(futures):
                    append_result(out_path, future.result())
                    completed += 1
                    if completed % 20 == 0 or completed == len(todo):
                        rate = completed / max(time.time() - started, 1e-6)
                        print(f"  {completed}/{len(todo)}  {rate:.2f} cases/s")
    finally:
        reviewer.close()

    elapsed = time.time() - started
    print(f"  done in {elapsed/60:.1f}m -> {out_path}")
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run systems against the CodeReviewer benchmark")
    parser.add_argument("--systems", required=True, help="comma-separated system specs")
    parser.add_argument("--benchmark", default="evaluation/data/benchmark.jsonl")
    parser.add_argument("--split", default="test", choices=["test", "dev", "all"])
    parser.add_argument("--limit", type=int, default=0, help="only the first N cases (smoke test)")
    parser.add_argument("--out-dir", default=str(RESULTS_DIR))
    parser.add_argument("--workers", type=int, default=8, help="parallelism for API systems")
    parser.add_argument("--force", action="store_true", help="ignore cached results")
    parser.add_argument("--no-score", action="store_true", help="skip scoring after the run")
    args = parser.parse_args()

    cases = load_benchmark(args.benchmark, None if args.split == "all" else args.split)
    if args.limit:
        cases = cases[: args.limit]
    if not cases:
        sys.exit(f"no cases in {args.benchmark} for split={args.split}")

    out_dir = Path(args.out_dir)
    specs = [s.strip() for s in args.systems.split(",") if s.strip()]
    for spec in specs:
        run_system(spec, cases, out_dir, workers=args.workers, force=args.force)

    if not args.no_score:
        from evaluation.score import score_and_report

        score_and_report(args.benchmark, out_dir, split=args.split, systems=specs)


if __name__ == "__main__":
    main()
