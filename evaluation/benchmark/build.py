"""
Build the CodeReviewer benchmark from templates.

    python -m evaluation.benchmark.build --out evaluation/data/benchmark.jsonl

Design notes that matter when reading the results:

* Every vulnerable case ships with a **matched safe twin** differing only in the
  vulnerable idiom, so false-positive rate measures discrimination rather than
  general chattiness.
* Four vulnerability families are **held out entirely from the dev split** and
  never used to generate training data, so the test split can answer "does this
  generalize to a bug class it was not tuned on?"
* Ground-truth line numbers come from inline markers that are stripped before any
  system sees the code — the answer is never in the prompt.
"""
from __future__ import annotations

import argparse
import itertools
import random
import re
from collections import Counter
from string import Template

from evaluation import taxonomy
from evaluation.benchmark.templates import DISTRACTORS, TEMPLATES, VulnTemplate
from evaluation.schema import BenchmarkCase, GroundTruthFinding, save_benchmark

MARKER = re.compile(r"[ \t]*(?:#|//)[ \t]*@(vuln|alt):(CWE-\d+)[ \t]*$")

# Families reserved for the test split only. Never appear in dev, never used to
# generate training data — this is the unseen-bug-class generalization check.
HELD_OUT_FAMILIES = {
    "ssrf_fetch_url",
    "xxe_lxml",
    "perms_world_writable",
    "weak_random_token",
}

DEV_FRACTION = 0.3


def parse_markers(code: str, description: str = "") -> tuple[str, list[GroundTruthFinding]]:
    """
    Strip inline ground-truth markers and return (clean_code, findings).

    `@vuln:` creates a finding; `@alt:` registers an alternative acceptable
    anchor line for the finding with the same CWE.
    """
    out_lines: list[str] = []
    primary: list[tuple[int, str]] = []
    alternates: list[tuple[int, str]] = []

    for idx, raw_line in enumerate(code.splitlines(), start=1):
        match = MARKER.search(raw_line)
        if match:
            kind, cwe = match.group(1), match.group(2)
            (primary if kind == "vuln" else alternates).append((idx, cwe))
            raw_line = raw_line[: match.start()].rstrip()
        out_lines.append(raw_line)

    findings: list[GroundTruthFinding] = []
    for line, cwe in primary:
        spec = taxonomy.BY_CWE.get(cwe)
        findings.append(
            GroundTruthFinding(
                line=line,
                cwe=cwe,
                severity=taxonomy.default_severity(cwe),
                vuln_type=spec.name if spec else cwe,
                description=description,
                acceptable_lines=[ln for ln, alt_cwe in alternates if alt_cwe == cwe],
            )
        )
    return "\n".join(out_lines) + "\n", findings


def expand_params(params: dict[str, list[str]], n: int, seed: str) -> list[dict[str, str]]:
    """Deterministically sample up to n distinct parameter combinations."""
    if not params:
        return [{}]
    keys = sorted(params)
    combos = [dict(zip(keys, values, strict=False)) for values in itertools.product(*(params[k] for k in keys))]
    rng = random.Random(seed)
    rng.shuffle(combos)
    return combos[:n]


def _render(text: str, mapping: dict[str, str]) -> str:
    return Template(text).safe_substitute(mapping)


def build_vuln_family(tpl: VulnTemplate, variants: int, seed: int) -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    combos = expand_params(tpl.params, variants, seed=f"{seed}:{tpl.key}")
    held_out = tpl.key in HELD_OUT_FAMILIES
    n_dev = 0 if held_out else max(1, int(len(combos) * DEV_FRACTION))

    for i, mapping in enumerate(combos):
        split = "dev" if i < n_dev else "test"
        filename = _render(tpl.filename, mapping)
        tags = [*tpl.tags, tpl.key]
        if held_out:
            tags.append("held_out_family")

        vuln_code, findings = parse_markers(_render(tpl.vulnerable, mapping), tpl.description)
        cases.append(
            BenchmarkCase(
                case_id=f"{tpl.key}__{i:02d}__vuln",
                language=tpl.language,
                filename=filename,
                code=vuln_code,
                findings=findings,
                kind="vulnerable",
                source="synthetic",
                split=split,
                tags=tags,
            )
        )

        safe_code, safe_findings = parse_markers(_render(tpl.safe, mapping))
        assert not safe_findings, f"safe twin of {tpl.key} contains a @vuln marker"
        cases.append(
            BenchmarkCase(
                case_id=f"{tpl.key}__{i:02d}__safe",
                language=tpl.language,
                filename=filename,
                code=safe_code,
                findings=[],
                kind="clean",
                source="synthetic",
                split=split,
                tags=[*tags, "safe_twin"],
            )
        )
    return cases


def build_distractors(variants: int, seed: int) -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    for tpl in DISTRACTORS:
        combos = expand_params(tpl.params, variants, seed=f"{seed}:{tpl.key}")
        n_dev = max(1, int(len(combos) * DEV_FRACTION))
        for i, mapping in enumerate(combos):
            code, findings = parse_markers(_render(tpl.code, mapping))
            assert not findings, f"distractor {tpl.key} must have no findings"
            cases.append(
                BenchmarkCase(
                    case_id=f"{tpl.key}__{i:02d}__distractor",
                    language=tpl.language,
                    filename=_render(tpl.filename, mapping),
                    code=code,
                    findings=[],
                    kind="distractor",
                    source="synthetic",
                    split="dev" if i < n_dev else "test",
                    tags=[tpl.key, "distractor"],
                )
            )
    return cases


def build(variants: int = 3, seed: int = 7) -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    for tpl in TEMPLATES:
        cases.extend(build_vuln_family(tpl, variants, seed))
    cases.extend(build_distractors(variants, seed))
    return cases


def summarize(cases: list[BenchmarkCase]) -> str:
    kinds = Counter(c.kind for c in cases)
    splits = Counter(c.split for c in cases)
    cwes = Counter(f.cwe for c in cases for f in c.findings)
    langs = Counter(c.language for c in cases)
    loc = [c.loc for c in cases]

    lines = [
        f"cases           : {len(cases)}",
        f"  vulnerable    : {kinds['vulnerable']}",
        f"  clean twins   : {kinds['clean']}",
        f"  distractors   : {kinds['distractor']}",
        f"findings        : {sum(len(c.findings) for c in cases)}",
        f"splits          : dev={splits['dev']} test={splits['test']}",
        f"languages       : {dict(langs)}",
        f"lines of code   : min={min(loc)} median={sorted(loc)[len(loc)//2]} max={max(loc)}",
        f"held-out families: {sorted(HELD_OUT_FAMILIES)}",
        "",
        "findings per CWE:",
    ]
    for cwe, count in sorted(cwes.items()):
        spec = taxonomy.BY_CWE.get(cwe)
        lines.append(f"  {cwe:9s} {count:4d}  {spec.name if spec else ''}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the CodeReviewer benchmark")
    parser.add_argument("--out", default="evaluation/data/benchmark.jsonl")
    parser.add_argument("--variants", type=int, default=3, help="variants per template family")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    cases = build(variants=args.variants, seed=args.seed)
    n = save_benchmark(args.out, cases)
    print(summarize(cases))
    print(f"\nwrote {n} cases -> {args.out}")


if __name__ == "__main__":
    main()
