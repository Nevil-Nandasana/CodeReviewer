"""
Score recorded results and render the comparison report.

    python -m evaluation.score --split test

Reads evaluation/results/*.jsonl, scores every system against the benchmark, and
writes results/report.md plus results/metrics.json. Scoring is pure computation
over recorded outputs, so metric changes are free to iterate on.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evaluation.matching import MatchConfig
from evaluation.metrics import SystemMetrics, evaluate_system
from evaluation.schema import load_benchmark, load_results, save_results
from evaluation.taxonomy import BY_CWE

RESULTS_DIR = Path("evaluation/results")

# Above this share of errored cases, a system's detection metrics are noise and
# the report says so instead of printing a misleading 0.0.
HIGH_ERROR_RATE = 0.10


def _pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def _iv(interval) -> str:
    if interval is None:
        return "—"
    return f"{100 * interval.point:.1f} [{100 * interval.low:.0f}–{100 * interval.high:.0f}]"


def render_markdown(all_metrics: list[SystemMetrics], split: str) -> str:
    lines: list[str] = []
    ref = all_metrics[0] if all_metrics else None

    lines.append(f"# CodeReviewer benchmark results — `{split}` split\n")
    if ref:
        lines.append(
            f"{ref.n_cases} cases: {ref.n_vulnerable} vulnerable, "
            f"{ref.n_clean} matched safe twins, {ref.n_distractor} distractors. "
            "Intervals are 95% bootstrap CIs resampled over template families.\n"
        )

    lines.append("## Detection and usability\n")
    lines.append(
        "| System | Precision | Recall | F1 | Clean-code flag rate ↓ | FP/clean case ↓ "
        "| JSON valid | Error rate ↓ | p50 latency | $/100 reviews |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for m in all_metrics:
        lines.append(
            f"| `{m.system}` | {_iv(m.precision)} | {_iv(m.recall)} | {_iv(m.f1)} | "
            f"{_iv(m.clean_flag_rate)} | {m.fp_per_clean_case:.2f} | {_pct(m.json_valid_rate)} | "
            f"{_pct(m.error_rate)} | {m.latency_p50:.2f}s | ${m.cost_per_100_reviews:.3f} |"
        )

    # A run where every call failed scores 0.0 on every detection metric, which
    # is indistinguishable from a system that answered and got everything wrong.
    # Say so explicitly rather than leaving it to be inferred from the table.
    broken = [m for m in all_metrics if m.error_rate >= HIGH_ERROR_RATE]
    if broken:
        lines.append("")
        for m in broken:
            lines.append(
                f"> ⚠️ **`{m.system}` failed to produce output on "
                f"{_pct(m.error_rate)} of cases.** Its detection scores below reflect "
                "API/runtime errors, not review quality, and are not comparable."
            )

    lines.append("\n## Localization and diagnosis\n")
    lines.append(
        "| System | Recall (type must match) | Recall (line only) | Diagnosis gap | Exact line | Mean line error |"
    )
    lines.append("|---|---|---|---|---|---|")
    for m in all_metrics:
        strict_recall = m.recall.point if m.recall else 0.0
        gap = m.recall_location_only - strict_recall
        lines.append(
            f"| `{m.system}` | {_pct(strict_recall)} | {_pct(m.recall_location_only)} | "
            f"{_pct(gap)} | {_pct(m.exact_line_acc)} | {m.mean_line_error:.2f} |"
        )
    lines.append(
        "\n*Diagnosis gap = found the right line but named the wrong bug class.*\n"
    )

    lines.append("\n## Severity calibration\n")
    lines.append("| System | Exact severity | Mean ordinal error | Bias (+ = over-escalates) |")
    lines.append("|---|---|---|---|")
    for m in all_metrics:
        lines.append(
            f"| `{m.system}` | {_pct(m.severity_exact)} | {m.severity_mae:.2f} | {m.severity_bias:+.2f} |"
        )

    # Per-CWE recall matrix
    all_cwes = sorted({cwe for m in all_metrics for cwe in m.per_cwe_recall})
    if all_cwes:
        lines.append("\n## Recall by CWE\n")
        header = "| CWE | Vulnerability | " + " | ".join(f"`{m.system}`" for m in all_metrics) + " |"
        lines.append(header)
        lines.append("|---|---|" + "---|" * len(all_metrics))
        for cwe in all_cwes:
            spec = BY_CWE.get(cwe)
            row = [cwe, spec.name if spec else ""]
            for m in all_metrics:
                hit, total = m.per_cwe_recall.get(cwe, (0, 0))
                row.append(f"{hit}/{total}" if total else "—")
            lines.append("| " + " | ".join(row) + " |")

    lines.append("\n## Held-out families\n")
    lines.append(
        "Four families (SSRF, XXE, weak randomness, file permissions) never appear in the dev "
        "split and are excluded from training-data generation, so their per-CWE rows above "
        "measure generalization to bug classes the system was not tuned on.\n"
    )
    return "\n".join(lines) + "\n"


def reparse(results: list) -> int:
    """
    Re-derive predictions from each result's stored `raw_output`.

    Parsing happens at inference time, so a parser improvement does not reach
    results already on disk. Because every run records the model's raw text, it
    can be re-applied without spending a single GPU-second or API call — which
    is the concrete payoff of keeping inference and scoring separate.

    Used when the parser gains the ability to recover a shape it previously
    discarded. Results with no stored raw output are left untouched.
    """
    from evaluation.parsing import parse_review_output
    from evaluation.schema import PredictedFinding

    changed = 0
    for result in results:
        if not result.raw_output:
            continue
        comments, strict = parse_review_output(result.raw_output)
        before = len(result.predictions)
        result.predictions = [PredictedFinding.from_comment(c) for c in comments]
        result.json_valid = strict
        if len(result.predictions) != before:
            changed += 1
    return changed


def score_and_report(
    benchmark_path: str | Path = "evaluation/data/benchmark.jsonl",
    results_dir: str | Path = RESULTS_DIR,
    split: str = "test",
    systems: list[str] | None = None,
    line_tolerance: int = 3,
    reparse_raw: bool = False,
) -> list[SystemMetrics]:
    results_dir = Path(results_dir)
    cases = load_benchmark(benchmark_path, None if split == "all" else split)
    case_ids = {c.case_id for c in cases}
    cfg = MatchConfig(line_tolerance=line_tolerance)

    files = sorted(results_dir.glob("*.jsonl"))
    if systems:
        from evaluation.run_eval import sanitize

        wanted = {sanitize(s) for s in systems}
        files = [f for f in files if f.stem in wanted]

    all_metrics: list[SystemMetrics] = []
    for path in files:
        results = [r for r in load_results(path) if r.case_id in case_ids]
        if not results:
            continue
        if reparse_raw:
            changed = reparse(results)
            if changed:
                # Persist, so a later plain `score` reports the same numbers.
                # Leaving the correction in memory makes the report depend on
                # whether someone remembered the flag, which is exactly the kind
                # of silent inconsistency this harness exists to prevent.
                save_results(path, results)
                print(f"reparsed {path.stem}: {changed} results changed (written back)")
        system_name = results[0].system or path.stem
        metrics = evaluate_system(system_name, cases, results, cfg)
        # A partially-complete run would silently look better than it is.
        if len(results) < len(cases):
            metrics.system = f"{system_name} (partial {len(results)}/{len(cases)})"
        all_metrics.append(metrics)

    # Systems that mostly errored sort last regardless of F1 — they have no
    # meaningful score to rank on.
    all_metrics.sort(
        key=lambda m: (m.error_rate < HIGH_ERROR_RATE, m.f1.point if m.f1 else 0.0),
        reverse=True,
    )

    report = render_markdown(all_metrics, split)
    (results_dir / "report.md").write_text(report, encoding="utf-8")
    # The report contains arrows and en-dashes; the Windows console defaults to
    # cp1252 and would raise on them.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):  # pragma: no cover - non-reconfigurable stream
        pass
    (results_dir / "metrics.json").write_text(
        json.dumps([m.to_json() for m in all_metrics], indent=2), encoding="utf-8"
    )
    print("\n" + report)
    print(f"wrote {results_dir/'report.md'} and {results_dir/'metrics.json'}")
    return all_metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Score recorded benchmark results")
    parser.add_argument("--benchmark", default="evaluation/data/benchmark.jsonl")
    parser.add_argument("--results-dir", default=str(RESULTS_DIR))
    parser.add_argument("--split", default="test", choices=["test", "dev", "all"])
    parser.add_argument("--line-tolerance", type=int, default=3)
    parser.add_argument(
        "--reparse",
        action="store_true",
        help="re-derive predictions from each result's stored raw_output "
             "(use after a parser change; costs no inference)",
    )
    args = parser.parse_args()
    score_and_report(
        args.benchmark,
        args.results_dir,
        args.split,
        line_tolerance=args.line_tolerance,
        reparse_raw=args.reparse,
    )


if __name__ == "__main__":
    main()
