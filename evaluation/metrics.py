"""
Metrics for code-review systems.

Deliberately NOT BLEU. Text-similarity metrics reward paraphrasing the reference
comment and say nothing about whether the bug was found, so they are the wrong
tool for structured review output. What we measure instead:

  detection      precision / recall / F1, micro-averaged, plus per-CWE recall
  localization   exact-line and +/-k accuracy, mean absolute line error
  usability      false-positive rate on clean code and on look-scary distractors
  calibration    ordinal error between predicted and true severity, with bias sign
  robustness     schema-valid JSON rate, hard error rate
  efficiency     p50/p95 latency, tokens, USD per review

Confidence intervals come from a clustered bootstrap that resamples whole cases,
because findings within a case are not independent.
"""
from __future__ import annotations

import random
import statistics
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from evaluation.matching import MatchConfig, match_all
from evaluation.schema import (
    SEVERITIES,
    BenchmarkCase,
    CaseResult,
    severity_rank,
)


@dataclass
class Interval:
    point: float
    low: float
    high: float

    def __str__(self) -> str:
        return f"{self.point:.3f} [{self.low:.3f}, {self.high:.3f}]"


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return precision, recall, f1


def family_of(case_id: str) -> str:
    """Template family a case came from ('sqli_flask_concat__03__vuln' -> family)."""
    return case_id.split("__", 1)[0]


def bootstrap_ci(
    items: Sequence[Any],
    statistic: Callable[[Sequence[Any]], float],
    n_resamples: int = 1000,
    alpha: float = 0.05,
    seed: int = 1234,
    cluster_by: Callable[[Any], str] | None = None,
) -> Interval:
    """
    Percentile bootstrap.

    Variants inside a template family are near-duplicates (same bug, renamed
    identifiers), so resampling individual cases would treat correlated samples
    as independent and report intervals that are far too tight. When `cluster_by`
    is given we resample whole families instead, which is the honest unit of
    independence for this benchmark.
    """
    point = statistic(items)
    if not items:
        return Interval(point, point, point)

    rng = random.Random(seed)
    samples: list[float] = []

    if cluster_by is None:
        n = len(items)
        for _ in range(n_resamples):
            samples.append(statistic([items[rng.randrange(n)] for _ in range(n)]))
    else:
        clusters: dict[str, list[Any]] = {}
        for item in items:
            clusters.setdefault(cluster_by(item), []).append(item)
        keys = sorted(clusters)
        k = len(keys)
        for _ in range(n_resamples):
            resample: list[Any] = []
            for _ in range(k):
                resample.extend(clusters[keys[rng.randrange(k)]])
            samples.append(statistic(resample))

    samples.sort()
    lo = samples[int((alpha / 2) * n_resamples)]
    hi = samples[min(int((1 - alpha / 2) * n_resamples), n_resamples - 1)]
    return Interval(point, lo, hi)


@dataclass
class SystemMetrics:
    system: str
    n_cases: int = 0
    n_vulnerable: int = 0
    n_clean: int = 0
    n_distractor: int = 0

    # detection (strict type matching)
    precision: Interval | None = None
    recall: Interval | None = None
    f1: Interval | None = None
    tp: int = 0
    fp: int = 0
    fn: int = 0

    # detection with type ignored — the gap vs strict is "found it but misdiagnosed"
    recall_location_only: float = 0.0

    per_cwe_recall: dict[str, tuple[int, int]] = field(default_factory=dict)  # cwe -> (hit, total)

    # localization, over location-mode matches
    exact_line_acc: float = 0.0
    within_1_acc: float = 0.0
    mean_line_error: float = 0.0

    # usability
    clean_flag_rate: Interval | None = None      # fraction of clean cases with >=1 security finding
    distractor_flag_rate: float = 0.0
    fp_per_clean_case: float = 0.0
    fp_per_100_loc_clean: float = 0.0

    # calibration
    severity_mae: float = 0.0
    severity_bias: float = 0.0                    # >0 = over-escalates
    severity_exact: float = 0.0
    severity_confusion: dict[str, dict[str, int]] = field(default_factory=dict)

    # robustness / efficiency
    json_valid_rate: float = 1.0
    error_rate: float = 0.0
    latency_p50: float = 0.0
    latency_p95: float = 0.0
    mean_completion_tokens: float = 0.0
    total_cost_usd: float = 0.0
    cost_per_100_reviews: float = 0.0

    def to_json(self) -> dict[str, Any]:
        def iv(x: Interval | None) -> dict[str, float] | None:
            return {"point": x.point, "low": x.low, "high": x.high} if x else None

        return {
            "system": self.system,
            "n_cases": self.n_cases,
            "n_vulnerable": self.n_vulnerable,
            "n_clean": self.n_clean,
            "n_distractor": self.n_distractor,
            "precision": iv(self.precision),
            "recall": iv(self.recall),
            "f1": iv(self.f1),
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "recall_location_only": self.recall_location_only,
            "per_cwe_recall": {k: list(v) for k, v in self.per_cwe_recall.items()},
            "exact_line_acc": self.exact_line_acc,
            "within_1_acc": self.within_1_acc,
            "mean_line_error": self.mean_line_error,
            "clean_flag_rate": iv(self.clean_flag_rate),
            "distractor_flag_rate": self.distractor_flag_rate,
            "fp_per_clean_case": self.fp_per_clean_case,
            "fp_per_100_loc_clean": self.fp_per_100_loc_clean,
            "severity_mae": self.severity_mae,
            "severity_bias": self.severity_bias,
            "severity_exact": self.severity_exact,
            "severity_confusion": self.severity_confusion,
            "json_valid_rate": self.json_valid_rate,
            "error_rate": self.error_rate,
            "latency_p50": self.latency_p50,
            "latency_p95": self.latency_p95,
            "mean_completion_tokens": self.mean_completion_tokens,
            "total_cost_usd": self.total_cost_usd,
            "cost_per_100_reviews": self.cost_per_100_reviews,
        }


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(int(q * len(ordered)), len(ordered) - 1)
    return ordered[idx]


def evaluate_system(
    system: str,
    cases: list[BenchmarkCase],
    results: list[CaseResult],
    cfg: MatchConfig | None = None,
    n_resamples: int = 1000,
) -> SystemMetrics:
    cfg = cfg or MatchConfig()
    by_case = {r.case_id: r for r in results}
    preds_by_case = {cid: r.predictions for cid, r in by_case.items()}

    strict = match_all(cases, preds_by_case, cfg)
    loose_cfg = MatchConfig(
        line_tolerance=cfg.line_tolerance,
        mode="location",
        security_only_fp=cfg.security_only_fp,
        count_fp_on_vulnerable=cfg.count_fp_on_vulnerable,
    )
    loose = match_all(cases, preds_by_case, loose_cfg)

    m = SystemMetrics(system=system, n_cases=len(cases))
    m.n_vulnerable = sum(1 for c in cases if not c.is_clean)
    m.n_clean = sum(1 for c in cases if c.kind == "clean")
    m.n_distractor = sum(1 for c in cases if c.kind == "distractor")

    m.tp = sum(cm.tp for cm in strict)
    m.fp = sum(cm.fp for cm in strict)
    m.fn = sum(cm.fn for cm in strict)

    cluster = lambda cm: family_of(cm.case_id)
    counts = lambda s: (sum(c.tp for c in s), sum(c.fp for c in s), sum(c.fn for c in s))
    m.precision = bootstrap_ci(strict, lambda s: prf(*counts(s))[0], n_resamples, cluster_by=cluster)
    m.recall = bootstrap_ci(strict, lambda s: prf(*counts(s))[1], n_resamples, cluster_by=cluster)
    m.f1 = bootstrap_ci(strict, lambda s: prf(*counts(s))[2], n_resamples, cluster_by=cluster)

    loose_tp = sum(cm.tp for cm in loose)
    loose_fn = sum(cm.fn for cm in loose)
    m.recall_location_only = _safe_div(loose_tp, loose_tp + loose_fn)

    # Per-CWE recall (strict)
    per_cwe: dict[str, list[int]] = {}
    for cm in strict:
        for match in cm.matches:
            per_cwe.setdefault(match.gt.cwe, [0, 0])[0] += 1
            per_cwe[match.gt.cwe][1] += 1
        for miss in cm.false_negatives:
            per_cwe.setdefault(miss.cwe, [0, 0])[1] += 1
    m.per_cwe_recall = {k: (v[0], v[1]) for k, v in sorted(per_cwe.items())}

    # Localization over location-mode matches (don't penalize a right line twice)
    line_errors = [match.line_error for cm in loose for match in cm.matches]
    if line_errors:
        m.exact_line_acc = _safe_div(sum(1 for e in line_errors if e == 0), len(line_errors))
        m.within_1_acc = _safe_div(sum(1 for e in line_errors if e <= 1), len(line_errors))
        m.mean_line_error = statistics.mean(line_errors)

    # Usability on clean + distractor controls
    clean_cases = [cm for cm in strict if cm.kind == "clean"]
    distractors = [cm for cm in strict if cm.kind == "distractor"]
    controls = clean_cases + distractors
    if controls:
        m.clean_flag_rate = bootstrap_ci(
            controls,
            lambda s: _safe_div(sum(1 for c in s if c.fp > 0), len(s)),
            n_resamples,
            cluster_by=cluster,
        )
        m.fp_per_clean_case = _safe_div(sum(c.fp for c in controls), len(controls))
        total_loc = sum(c.loc for c in controls)
        m.fp_per_100_loc_clean = 100 * _safe_div(sum(c.fp for c in controls), total_loc)
    if distractors:
        m.distractor_flag_rate = _safe_div(sum(1 for c in distractors if c.fp > 0), len(distractors))

    # Severity calibration on strict true positives
    diffs: list[int] = []
    confusion: dict[str, dict[str, int]] = {s: {p: 0 for p in SEVERITIES} for s in SEVERITIES}
    for cm in strict:
        for match in cm.matches:
            gt_rank = severity_rank(match.gt.severity)
            pred_rank = severity_rank(match.pred.severity)
            diffs.append(pred_rank - gt_rank)
            gt_label = match.gt.severity.upper()
            pred_label = match.pred.severity.upper()
            if gt_label in confusion and pred_label in confusion[gt_label]:
                confusion[gt_label][pred_label] += 1
    if diffs:
        m.severity_mae = statistics.mean(abs(d) for d in diffs)
        m.severity_bias = statistics.mean(diffs)
        m.severity_exact = _safe_div(sum(1 for d in diffs if d == 0), len(diffs))
    m.severity_confusion = confusion

    # Robustness + efficiency
    scored = [by_case[c.case_id] for c in cases if c.case_id in by_case]
    if scored:
        m.json_valid_rate = _safe_div(sum(1 for r in scored if r.json_valid), len(scored))
        m.error_rate = _safe_div(sum(1 for r in scored if r.error), len(scored))
        latencies = [r.latency_s for r in scored]
        m.latency_p50 = _percentile(latencies, 0.50)
        m.latency_p95 = _percentile(latencies, 0.95)
        m.mean_completion_tokens = statistics.mean(r.completion_tokens for r in scored)
        m.total_cost_usd = sum(r.cost_usd for r in scored)
        m.cost_per_100_reviews = 100 * _safe_div(m.total_cost_usd, len(scored))

    return m
