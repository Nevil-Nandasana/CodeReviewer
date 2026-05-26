"""
Matching predicted findings to ground truth.

A prediction counts as a true positive when it lands near the right line AND
names the right class of bug. Both halves matter: a system that flags every line
as "SQL injection" would ace a location-only metric, and a system that says
"something's wrong here" on the right line isn't actually useful to a developer.

We report three modes so no single generous assumption can carry a score:
  strict   — type must match (untyped prediction = no match)
  lenient  — type must match, but an untyped prediction is allowed to match
  location — line only, type ignored (upper bound on detection)

Assignment is greedy and one-to-one: one ground-truth finding can be claimed by
at most one prediction, so duplicate findings on the same line become false
positives instead of free true positives.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from evaluation import taxonomy
from evaluation.schema import BenchmarkCase, GroundTruthFinding, PredictedFinding, severity_rank

MatchMode = Literal["strict", "lenient", "location"]


@dataclass
class MatchConfig:
    line_tolerance: int = 3
    mode: MatchMode = "strict"
    # Only security-flavored predictions can be false positives; a style nit on
    # clean code is a reviewer doing its job, not a security false alarm.
    security_only_fp: bool = True
    # On vulnerable cases, do extra unmatched findings count against precision?
    # True for synthetic cases where we control the whole file.
    count_fp_on_vulnerable: bool = True


@dataclass
class Match:
    gt: GroundTruthFinding
    pred: PredictedFinding
    line_error: int
    type_match: bool


@dataclass
class CaseMatch:
    case_id: str
    kind: str
    matches: list[Match] = field(default_factory=list)
    false_positives: list[PredictedFinding] = field(default_factory=list)
    false_negatives: list[GroundTruthFinding] = field(default_factory=list)
    loc: int = 0

    @property
    def tp(self) -> int:
        return len(self.matches)

    @property
    def fp(self) -> int:
        return len(self.false_positives)

    @property
    def fn(self) -> int:
        return len(self.false_negatives)


def is_security_finding(pred: PredictedFinding) -> bool:
    """Security-relevant enough to be scored as a security false positive."""
    return pred.is_security or severity_rank(pred.severity) >= severity_rank("HIGH")


def _line_error(gt: GroundTruthFinding, pred: PredictedFinding) -> int:
    return min(abs(pred.line - anchor) for anchor in gt.anchors())


def match_case(
    case: BenchmarkCase,
    predictions: list[PredictedFinding],
    cfg: MatchConfig | None = None,
) -> CaseMatch:
    """Greedy one-to-one assignment of predictions to ground-truth findings."""
    cfg = cfg or MatchConfig()
    for p in predictions:
        taxonomy.annotate(p)

    result = CaseMatch(case_id=case.case_id, kind=case.kind, loc=case.loc)

    # Build candidate pairs that satisfy both the line and type constraints.
    candidates: list[tuple[int, bool, int, int]] = []  # (line_err, not type_match, gt_i, pred_i)
    for gi, gt in enumerate(case.findings):
        for pi, pred in enumerate(predictions):
            err = _line_error(gt, pred)
            if err > cfg.line_tolerance:
                continue
            type_ok = taxonomy.types_match(gt.cwe, pred.cwe, untyped_counts_as_match=True)
            type_strict = taxonomy.types_match(gt.cwe, pred.cwe, untyped_counts_as_match=False)
            if cfg.mode == "strict" and not type_strict:
                continue
            if cfg.mode == "lenient" and not type_ok:
                continue
            candidates.append((err, not type_strict, gi, pi))

    # Prefer small line error, then exact type matches.
    candidates.sort(key=lambda c: (c[0], c[1]))

    used_gt: set[int] = set()
    used_pred: set[int] = set()
    for err, not_typed, gi, pi in candidates:
        if gi in used_gt or pi in used_pred:
            continue
        used_gt.add(gi)
        used_pred.add(pi)
        result.matches.append(
            Match(gt=case.findings[gi], pred=predictions[pi], line_error=err, type_match=not not_typed)
        )

    result.false_negatives = [gt for gi, gt in enumerate(case.findings) if gi not in used_gt]

    if case.is_clean or cfg.count_fp_on_vulnerable:
        for pi, pred in enumerate(predictions):
            if pi in used_pred:
                continue
            if cfg.security_only_fp and not is_security_finding(pred):
                continue
            result.false_positives.append(pred)

    return result


def match_all(
    cases: list[BenchmarkCase],
    results_by_case: dict[str, list[PredictedFinding]],
    cfg: MatchConfig | None = None,
) -> list[CaseMatch]:
    return [
        match_case(case, results_by_case.get(case.case_id, []), cfg)
        for case in cases
    ]
