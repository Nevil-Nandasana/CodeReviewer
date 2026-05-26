"""
Tests for the evaluation harness.

The harness is the instrument every claim in this project rests on, so its own
correctness cannot be assumed. A scorer that quietly over-counts true positives
makes every number optimistic and nothing else in the repo would reveal it.

    python -m pytest evaluation/tests -q
"""
from __future__ import annotations

import math

import pytest

from evaluation.matching import MatchConfig, match_case
from evaluation.metrics import Interval, bootstrap_ci, evaluate_system, family_of, prf
from evaluation.schema import (
    BenchmarkCase,
    CaseResult,
    GroundTruthFinding,
    PredictedFinding,
    severity_rank,
)
from evaluation.parsing import parse_review_output
from evaluation.taxonomy import infer_cwe, types_match


def gt(line: int, cwe: str = "CWE-89", severity: str = "CRITICAL", **kw):
    return GroundTruthFinding(line=line, cwe=cwe, severity=severity, vuln_type="x", **kw)


def pred(line: int, title: str = "SQL injection", severity: str = "CRITICAL", **kw):
    return PredictedFinding(
        line=line, severity=severity, category="security", title=title, **kw
    )


def case(findings, kind="vulnerable", code="x = 1\n" * 20, case_id="fam__01__vuln"):
    return BenchmarkCase(
        case_id=case_id, language="python", filename="a.py", code=code,
        findings=findings, kind=kind,
    )


# ── Matching ────────────────────────────────────────────────────────────────

def test_exact_hit_is_a_true_positive():
    m = match_case(case([gt(10)]), [pred(10)])
    assert (m.tp, m.fp, m.fn) == (1, 0, 0)


def test_line_tolerance_is_inclusive_and_bounded():
    cfg = MatchConfig(line_tolerance=3)
    assert match_case(case([gt(10)]), [pred(13)], cfg).tp == 1
    assert match_case(case([gt(10)]), [pred(14)], cfg).tp == 0


def test_wrong_bug_class_on_the_right_line_is_not_a_true_positive():
    """Strict mode requires the type to match; this is the 'diagnosis gap'."""
    m = match_case(case([gt(10, "CWE-89")]), [pred(10, title="Hardcoded password")])
    assert m.tp == 0 and m.fn == 1


def test_location_mode_ignores_type():
    cfg = MatchConfig(mode="location")
    m = match_case(case([gt(10, "CWE-89")]), [pred(10, title="Hardcoded password")], cfg)
    assert m.tp == 1


def test_assignment_is_one_to_one():
    """Five findings on one line must not become five true positives."""
    m = match_case(case([gt(10)]), [pred(10) for _ in range(5)])
    assert m.tp == 1 and m.fp == 4


def test_two_ground_truths_need_two_predictions():
    m = match_case(case([gt(10), gt(20)]), [pred(10), pred(20)])
    assert (m.tp, m.fn) == (2, 0)


def test_clean_case_with_a_finding_is_a_false_positive():
    m = match_case(case([], kind="clean"), [pred(5)])
    assert m.fp == 1 and m.tp == 0


def test_clean_case_with_no_findings_is_perfect():
    m = match_case(case([], kind="clean"), [])
    assert (m.tp, m.fp, m.fn) == (0, 0, 0)


def test_style_nit_on_clean_code_is_not_a_security_false_positive():
    """security_only_fp: a low-severity style note is a reviewer doing its job."""
    nit = PredictedFinding(line=5, severity="INFO", category="style", title="naming")
    assert match_case(case([], kind="clean"), [nit]).fp == 0


def test_matching_prefers_the_closer_line():
    m = match_case(case([gt(10)]), [pred(12), pred(10)])
    assert m.tp == 1 and m.matches[0].line_error == 0


def test_acceptable_lines_count_as_anchors():
    """A finding may legitimately be reported at the sink or the tainted assign."""
    finding = gt(20, acceptable_lines=[15])
    assert match_case(case([finding]), [pred(15)]).tp == 1


# ── Taxonomy ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "text,expected",
    [
        ("SQL injection via concatenation", "CWE-89"),
        ("this is CWE-89 exactly", "CWE-89"),
        ("command injection through os.system", "CWE-78"),
        ("insecure deserialization with pickle", "CWE-502"),
        ("arbitrary code execution", "CWE-94"),
    ],
)
def test_cwe_inferred_from_prose(text, expected):
    assert infer_cwe(text) == expected


def test_owasp_category_alone_does_not_pin_a_cwe():
    """A03 covers several CWEs; guessing one would inflate strict-type recall."""
    assert infer_cwe("A03:2021 Injection") is None


def test_equivalence_groups_match_but_distinct_classes_do_not():
    assert types_match("CWE-78", "CWE-77", untyped_counts_as_match=False)
    assert not types_match("CWE-89", "CWE-78", untyped_counts_as_match=False)


def test_untyped_prediction_respects_the_flag():
    assert types_match("CWE-89", None, untyped_counts_as_match=True)
    assert not types_match("CWE-89", None, untyped_counts_as_match=False)


# ── Output parsing ──────────────────────────────────────────────────────────

def test_schema_conforming_object_is_strict_valid():
    comments, strict = parse_review_output(
        '{"comments": [{"line": 4, "severity": "HIGH", "title": "x"}]}'
    )
    assert strict is True and len(comments) == 1


def test_markdown_fence_is_recovered_but_not_strict():
    """Qwen wraps every answer in a fence despite being told not to."""
    comments, strict = parse_review_output(
        '```json\n{"comments": [{"line": 4, "severity": "HIGH", "title": "x"}]}\n```'
    )
    assert strict is False and len(comments) == 1


def test_double_wrapped_envelope_is_unwrapped():
    """
    Prompt v1 elicits `[{"comments": [...]}]` — a list around the object around
    the list. Returning the outer list verbatim produced one finding per case
    whose only key was `comments`, normalising to line 0 so it could never
    match. That understated v1's recall as 1.2% when it is 43.8%, and made a
    prompt ablation measure a parser gap.
    """
    raw = (
        '```json\n[{"comments": ['
        '{"line": 24, "severity": "HIGH", "category": "security", "title": "SQLi"},'
        '{"line": 31, "severity": "LOW", "category": "style", "title": "naming"}'
        ']}]\n```'
    )
    comments, strict = parse_review_output(raw)
    assert strict is False
    assert [c["line"] for c in comments] == [24, 31]


def test_bare_list_of_findings_still_works():
    """Unwrapping the envelope must not break the plain-array shape."""
    comments, _ = parse_review_output('[{"line": 7, "severity": "HIGH", "title": "x"}]')
    assert len(comments) == 1 and comments[0]["line"] == 7


def test_nested_unwrap_does_not_apply_on_the_strict_path():
    """A non-conforming envelope must still be recorded as a schema failure."""
    _, strict = parse_review_output('[{"comments": [{"line": 1, "severity": "LOW"}]}]')
    assert strict is False


def test_unparseable_output_yields_nothing_rather_than_raising():
    comments, strict = parse_review_output("I cannot review this file.")
    assert comments == [] and strict is False


# ── Metrics ─────────────────────────────────────────────────────────────────

def test_prf_arithmetic():
    p, r, f = prf(tp=8, fp=2, fn=2)
    assert p == pytest.approx(0.8) and r == pytest.approx(0.8) and f == pytest.approx(0.8)


def test_prf_is_zero_not_nan_when_nothing_predicted():
    assert prf(0, 0, 5) == (0.0, 0.0, 0.0)


def test_severity_is_ordinal():
    assert severity_rank("CRITICAL") > severity_rank("HIGH") > severity_rank("INFO")
    assert severity_rank(None) == severity_rank("LOW")


def test_family_of_strips_the_variant_suffix():
    assert family_of("sqli_flask_concat__03__vuln") == "sqli_flask_concat"


def test_clustered_bootstrap_is_wider_than_unclustered():
    """
    The whole point of clustering. Ten families of ten identical items each:
    resampling items treats 100 correlated observations as independent and
    reports a far tighter interval than resampling the 10 real units.
    """
    items = [{"fam": f"f{i}", "v": float(i % 2)} for i in range(10) for _ in range(10)]
    stat = lambda s: sum(x["v"] for x in s) / len(s)
    tight = bootstrap_ci(items, stat, n_resamples=300)
    honest = bootstrap_ci(items, stat, n_resamples=300, cluster_by=lambda x: x["fam"])
    assert (honest.high - honest.low) > (tight.high - tight.low)


def test_bootstrap_point_estimate_is_the_plain_statistic():
    items = [{"v": 1.0}, {"v": 0.0}]
    iv = bootstrap_ci(items, lambda s: sum(x["v"] for x in s) / len(s), n_resamples=50)
    assert iv.point == pytest.approx(0.5)


def test_bootstrap_on_empty_input_does_not_divide_by_zero():
    iv = bootstrap_ci([], lambda s: 0.0, n_resamples=10)
    assert isinstance(iv, Interval) and not math.isnan(iv.point)


# ── End-to-end scoring ──────────────────────────────────────────────────────

def test_a_perfect_system_scores_one():
    cases = [case([gt(10)], case_id="fam__01__vuln"), case([], "clean", case_id="fam__01__safe")]
    results = [
        CaseResult(case_id="fam__01__vuln", system="s", predictions=[pred(10)]),
        CaseResult(case_id="fam__01__safe", system="s", predictions=[]),
    ]
    m = evaluate_system("s", cases, results, n_resamples=50)
    assert m.precision.point == 1.0 and m.recall.point == 1.0
    assert m.clean_flag_rate.point == 0.0


def test_a_silent_system_scores_zero_recall_but_no_false_positives():
    """The failure mode the fine-tuned checkpoint actually exhibited."""
    cases = [case([gt(10)], case_id="fam__01__vuln")]
    results = [CaseResult(case_id="fam__01__vuln", system="s", predictions=[])]
    m = evaluate_system("s", cases, results, n_resamples=50)
    assert m.recall.point == 0.0 and m.fp == 0


def test_error_rate_is_reported_separately_from_detection():
    """A run that errored must be distinguishable from one that answered badly."""
    cases = [case([gt(10)], case_id="fam__01__vuln")]
    results = [
        CaseResult(case_id="fam__01__vuln", system="s", predictions=[],
                   json_valid=False, error="RateLimitError: 429")
    ]
    m = evaluate_system("s", cases, results, n_resamples=50)
    assert m.error_rate == 1.0 and m.recall.point == 0.0


def test_missing_results_count_as_misses_not_as_absent_cases():
    """A partial run must not look better than it is by scoring only what it did."""
    cases = [case([gt(10)], case_id="a__01__vuln"), case([gt(10)], case_id="b__01__vuln")]
    results = [CaseResult(case_id="a__01__vuln", system="s", predictions=[pred(10)])]
    m = evaluate_system("s", cases, results, n_resamples=50)
    assert m.recall.point == pytest.approx(0.5)
