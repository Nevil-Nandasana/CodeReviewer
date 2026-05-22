"""
Build the SFT dataset for the code-review fine-tune.

    python -m training.data.build_dataset --examples 6000

This replaces the previous pipeline, which wrapped every human review comment as
`{"line": 1, "severity": "MEDIUM", "category": "quality"}`. Training on that
teaches the model to emit MEDIUM/quality/line-1 for everything and destroys the
two properties the benchmark measures — severity calibration and line
localization. Labels here are generated alongside the code, so line numbers and
severities are exact by construction.

Composition:
  ~50% positive   one or two real vulnerabilities with exact line labels
  ~50% negative   matched safe twins and distractors, target `{"comments": []}`

The negative half is not padding. A model trained only on vulnerable code learns
that every input contains a bug, which is precisely the failure mode that makes
review bots unusable.

Augmentation:
  * identifier/framework parameterisation (from the template param pools)
  * a random noise prelude of 0-14 lines that shifts every ground-truth line
    number, so the model has to count lines rather than memorise positions
  * trailing helper code that changes file length without moving the finding

Leakage control:
  * the four benchmark held-out families are excluded entirely
  * every generated example is checked against every benchmark case, by exact
    normalised hash and by token-level Jaccard similarity
  * train/val is a *grouped* split on template family, so validation never
    contains a renamed variant of a training example (see `split_by_family`)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
from collections import Counter
from pathlib import Path
from string import Template

from evaluation import taxonomy
from evaluation.benchmark.build import expand_params, parse_markers
from evaluation.benchmark.templates import DistractorTemplate, VulnTemplate
from evaluation.prompts import build_messages
from evaluation.schema import GroundTruthFinding, load_benchmark
from training.data.train_templates import TRAIN_DISTRACTORS, TRAIN_TEMPLATES

REMEDIATION: dict[str, str] = {
    "CWE-89": "Use a parameterized query and pass the value as a bound parameter instead of building the SQL string.",
    "CWE-78": "Pass the command as an argument list with shell=False, and validate the untrusted value against an allow-list.",
    "CWE-94": "Do not evaluate untrusted input. Parse it with ast.literal_eval or dispatch through an explicit allow-list.",
    "CWE-502": "Use a data-only format such as JSON, or yaml.safe_load, instead of a deserializer that can construct arbitrary objects.",
    "CWE-22": "Resolve the path with os.path.realpath and reject anything that does not stay inside the intended base directory.",
    "CWE-79": "Escape the value before rendering it as HTML, or set textContent instead of innerHTML.",
    "CWE-798": "Read the credential from an environment variable or secret manager, and rotate the exposed value.",
    "CWE-306": "Require authentication and authorization on this route with the project's auth decorator.",
    "CWE-352": "Keep CSRF protection enabled and use the framework's CSRF token for this state-changing request.",
    "CWE-327": "Use a modern algorithm: PBKDF2, bcrypt, scrypt or Argon2 for passwords, SHA-256 for digests.",
    "CWE-330": "Generate security tokens with the secrets module, which uses a cryptographically secure source.",
    "CWE-295": "Leave certificate verification enabled and supply the internal CA bundle if a private CA is used.",
    "CWE-319": "Use HTTPS so the credentials and payload are encrypted in transit.",
    "CWE-918": "Validate the URL scheme and resolve the host, rejecting private, loopback and link-local addresses.",
    "CWE-611": "Disable entity resolution and DTD loading on the XML parser.",
    "CWE-209": "Log the exception server-side with an incident id and return a generic error message to the client.",
    "CWE-732": "Restrict the file mode to the owning user (0o600 for files, 0o700 for directories).",
}


def normalize_code(code: str) -> str:
    """Whitespace/comment-insensitive form used for dedup and leakage checks."""
    lines = []
    for line in code.splitlines():
        line = re.sub(r"#.*$", "", line)
        line = re.sub(r"//.*$", "", line)
        line = re.sub(r"\s+", " ", line).strip()
        if line:
            lines.append(line)
    return "\n".join(lines)


def code_hash(code: str) -> str:
    return hashlib.sha256(normalize_code(code).encode()).hexdigest()


def tokens(code: str) -> set[str]:
    return set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", normalize_code(code)))


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


PY_NOISE = [
    "import logging\n\nlog = logging.getLogger(__name__)\n",
    "from dataclasses import dataclass\n\n\n@dataclass\nclass Options:\n    verbose: bool = False\n    retries: int = 3\n",
    "DEFAULT_TIMEOUT = 30\nMAX_RETRIES = 5\n",
    "import time\n\n\ndef _now_ms() -> int:\n    return int(time.time() * 1000)\n",
    "from typing import Any\n\nJSON = dict[str, Any]\n",
    "import functools\n\n\n@functools.lru_cache(maxsize=128)\ndef _settings_for(env: str) -> dict:\n    return {\"env\": env, \"debug\": False}\n",
]

JS_NOISE = [
    "const DEFAULT_TIMEOUT = 30000;\n",
    "function formatDate(value) {\n  return new Date(value).toISOString();\n}\n",
    "const LEVELS = [\"debug\", \"info\", \"warn\", \"error\"];\n",
    "export const noop = () => {};\n",
]

PY_TRAILER = [
    "\n\ndef _healthcheck() -> dict:\n    return {\"status\": \"ok\"}\n",
    "\n\nDEFAULTS = {\"page_size\": 50, \"max_page\": 200}\n",
    "",
]

JS_TRAILER = ["\n\nexport function version() {\n  return \"1.4.2\";\n}\n", ""]


def _render(text: str, mapping: dict[str, str]) -> str:
    return Template(text).safe_substitute(mapping)


def augment(code: str, findings: list[GroundTruthFinding], language: str, rng: random.Random):
    """Prepend a noise block (shifting line numbers) and append a trailer."""
    noise_pool = PY_NOISE if language == "python" else JS_NOISE
    trailer_pool = PY_TRAILER if language == "python" else JS_TRAILER

    prelude = ""
    if rng.random() < 0.75:
        prelude = rng.choice(noise_pool) + "\n" * rng.randint(1, 2)
    offset = len(prelude.splitlines()) if prelude else 0

    body = prelude + code + rng.choice(trailer_pool)
    shifted = [
        GroundTruthFinding(
            line=f.line + offset,
            cwe=f.cwe,
            severity=f.severity,
            vuln_type=f.vuln_type,
            description=f.description,
            acceptable_lines=[ln + offset for ln in f.acceptable_lines],
        )
        for f in findings
    ]
    return body, shifted


def build_answer(code: str, findings: list[GroundTruthFinding]) -> str:
    """The assistant target: schema-conforming JSON grounded in the actual code."""
    lines = code.splitlines()
    comments = []
    for f in sorted(findings, key=lambda x: x.line):
        spec = taxonomy.BY_CWE.get(f.cwe)
        snippet = lines[f.line - 1].strip() if 0 < f.line <= len(lines) else ""
        explanation = (
            f"{f.description} Line {f.line} (`{snippet}`) is the sink: untrusted input reaches it "
            f"without adequate validation, which is {f.cwe} ({spec.name if spec else 'security defect'})."
        ).strip()
        comments.append(
            {
                "line": f.line,
                "severity": f.severity,
                "category": "security",
                "title": f"{spec.name if spec else f.cwe} in this code path",
                "explanation": explanation,
                "suggestion": REMEDIATION.get(f.cwe, "Apply the standard mitigation for this vulnerability class."),
                "owasp": spec.owasp if spec else None,
            }
        )
    return json.dumps({"comments": comments}, ensure_ascii=False)


def make_example(code: str, filename: str, language: str, findings: list[GroundTruthFinding], family: str, kind: str) -> dict:
    messages = build_messages(code, filename, language, pre_flags=None, version="v2")
    messages.append({"role": "assistant", "content": build_answer(code, findings)})
    return {
        "messages": messages,
        "meta": {
            "family": family,
            "kind": kind,
            "language": language,
            "n_findings": len(findings),
            "cwes": sorted({f.cwe for f in findings}),
            "code_hash": code_hash(code),
        },
    }


def generate(target: int, seed: int = 13, variants_per_combo: int = 4) -> list[dict]:
    """
    Generate the SFT set from training-only templates.

    Benchmark families are never used, not even with different parameters.
    Sharing a family between train and test would mean the fine-tune sees the
    same code skeleton with renamed identifiers, and its benchmark score would
    measure memorisation rather than transfer. Here the overlap between train
    and test is at the *concept* level only: SQL injection appears in both, but
    training sees it in SQLAlchemy/aiohttp/Express and the benchmark tests it in
    Flask/Django.
    """
    rng = random.Random(seed)
    vuln_templates: list[VulnTemplate] = list(TRAIN_TEMPLATES)
    distractor_templates: list[DistractorTemplate] = list(TRAIN_DISTRACTORS)

    positives: list[dict] = []
    negatives: list[dict] = []
    seen: set[str] = set()

    def add(bucket: list[dict], ex: dict) -> None:
        if ex["meta"]["code_hash"] not in seen:
            seen.add(ex["meta"]["code_hash"])
            bucket.append(ex)

    per_family = max(4, target // (2 * variants_per_combo * max(len(vuln_templates), 1)))

    # Positive + matched-negative pairs. Each param combo is rendered several
    # times with a different noise prelude, so identical code appears at
    # different line offsets and the model cannot memorise absolute positions.
    for tpl in vuln_templates:
        combos = expand_params(tpl.params, per_family, seed=f"train:{seed}:{tpl.key}")
        for mapping in combos:
            filename = _render(tpl.filename, mapping)
            base_vuln, base_findings = parse_markers(_render(tpl.vulnerable, mapping), tpl.description)
            # A vulnerable template with no marker would be labelled "clean" and
            # teach the model that the bug is acceptable. Fail loudly instead.
            if not base_findings:
                raise ValueError(f"template {tpl.key} has no @vuln marker in its vulnerable body")
            base_safe, _ = parse_markers(_render(tpl.safe, mapping))
            for _ in range(variants_per_combo):
                vuln_code, findings = augment(base_vuln, base_findings, tpl.language, rng)
                add(positives, make_example(vuln_code, filename, tpl.language, findings, tpl.key, "vulnerable"))

                safe_code, _ = augment(base_safe, [], tpl.language, rng)
                add(negatives, make_example(safe_code, filename, tpl.language, [], tpl.key, "clean"))

    # Distractors — clean code that looks alarming
    per_distractor = max(6, target // (4 * variants_per_combo * max(len(distractor_templates), 1)))
    for tpl in distractor_templates:
        for mapping in expand_params(tpl.params, per_distractor, seed=f"train:{seed}:{tpl.key}"):
            base, _ = parse_markers(_render(tpl.code, mapping))
            for _ in range(variants_per_combo):
                code, _ = augment(base, [], tpl.language, rng)
                add(negatives, make_example(code, _render(tpl.filename, mapping), tpl.language, [], tpl.key, "distractor"))

    # Multi-finding examples: two vulnerable bodies in one file
    n_multi = max(1, target // 12)
    python_templates = [t for t in vuln_templates if t.language == "python"]
    for _ in range(n_multi):
        a, b = rng.sample(python_templates, 2)
        map_a = expand_params(a.params, 1, seed=f"multi:{rng.random()}")[0]
        map_b = expand_params(b.params, 1, seed=f"multi:{rng.random()}")[0]
        code_a, find_a = parse_markers(_render(a.vulnerable, map_a), a.description)
        code_b, find_b = parse_markers(_render(b.vulnerable, map_b), b.description)

        offset = len(code_a.splitlines()) + 2
        merged = code_a + "\n\n" + code_b
        merged_findings = find_a + [
            GroundTruthFinding(
                line=f.line + offset,
                cwe=f.cwe,
                severity=f.severity,
                vuln_type=f.vuln_type,
                description=f.description,
                acceptable_lines=[ln + offset for ln in f.acceptable_lines],
            )
            for f in find_b
        ]
        merged, merged_findings = augment(merged, merged_findings, "python", rng)
        add(positives, make_example(merged, _render(a.filename, map_a), "python", merged_findings, f"{a.key}+{b.key}", "multi"))

    # Balance the two halves. Left unbalanced, the model learns a prior over how
    # often code contains a bug, and that prior dominates its behaviour on the
    # clean control set.
    stalled = 0
    while len(negatives) < len(positives) and stalled < 500:
        tpl = rng.choice(vuln_templates + [None])
        if tpl is None:
            dtpl = rng.choice(distractor_templates)
            mapping = expand_params(dtpl.params, 1, seed=f"bal:{rng.random()}")[0]
            base, _ = parse_markers(_render(dtpl.code, mapping))
            code, _ = augment(base, [], dtpl.language, rng)
            candidate = make_example(code, _render(dtpl.filename, mapping), dtpl.language, [], dtpl.key, "distractor")
        else:
            mapping = expand_params(tpl.params, 1, seed=f"bal:{rng.random()}")[0]
            base, _ = parse_markers(_render(tpl.safe, mapping))
            code, _ = augment(base, [], tpl.language, rng)
            candidate = make_example(code, _render(tpl.filename, mapping), tpl.language, [], tpl.key, "clean")
        before = len(negatives)
        add(negatives, candidate)
        stalled = 0 if len(negatives) > before else stalled + 1

    examples = positives + negatives
    rng.shuffle(examples)
    return examples


def extract_code(example: dict) -> str:
    """Recover the raw code from the line-numbered block in the user message."""
    user_msg = example["messages"][1]["content"]
    block = user_msg.split("<code>\n", 1)[-1].split("\n</code>", 1)[0]
    return "\n".join(re.sub(r"^\s*\d+\s\|\s?", "", ln) for ln in block.splitlines())


def filter_leakage(
    examples: list[dict], benchmark_path: str, threshold: float = 0.92
) -> tuple[list[dict], dict]:
    """
    Drop any training example that duplicates a benchmark case.

    Training only uses training-only families, so this should find nothing — it
    runs anyway because a silent leak would invalidate every number downstream,
    and "it can't happen by construction" is exactly the assumption worth
    testing on every build.
    """
    cases = load_benchmark(benchmark_path)
    bench_hashes = {code_hash(c.code) for c in cases}
    bench_tokens = [(c.case_id, tokens(c.code)) for c in cases]

    kept: list[dict] = []
    exact: list[str] = []
    near: list[tuple[str, str]] = []

    for ex in examples:
        code = extract_code(ex)
        if code_hash(code) in bench_hashes:
            exact.append(ex["meta"]["family"])
            continue
        toks = tokens(code)
        hit = next(
            (case_id for case_id, btoks in bench_tokens if jaccard(toks, btoks) >= threshold),
            None,
        )
        if hit:
            near.append((ex["meta"]["family"], hit))
            continue
        kept.append(ex)

    return kept, {"exact": exact, "near": near, "n_checked": len(examples)}


def split_by_family(
    examples: list[dict], val_fraction: float, seed: int
) -> tuple[list[dict], list[dict]]:
    """
    Hold out whole template families, never individual examples.

    Every example in a family is the same template with renamed identifiers and
    a shifted line offset, so a random per-example split puts near-duplicates of
    almost every training example into validation. The previous version of this
    function did exactly that, and the resulting run reported eval_loss 1e-4 by
    step 200 — a memorisation readout, not a generalisation one.

    This is the same independence argument `evaluation.metrics.bootstrap_ci`
    already makes when it resamples over families rather than cases. It has to
    hold on both sides of the pipeline or the training signal and the benchmark
    disagree about what an independent sample is.

    Multi-vuln examples carry a composite family key ("fam_a+fam_b"). They are
    assigned by their component families: an example is eligible for validation
    only if *every* component family is held out, so a val example can never
    share a template with a training example.
    """
    def components(example: dict) -> list[str]:
        return example["meta"]["family"].split("+")

    rng = random.Random(seed)
    per_family: Counter[str] = Counter(f for ex in examples for f in components(ex))

    # Primary CWE per family, taken from its single-vulnerability examples.
    # Multi-vuln examples carry both components' CWEs and would blur this.
    primary: dict[str, str] = {}
    for ex in examples:
        parts = components(ex)
        if len(parts) == 1 and ex["meta"]["cwes"]:
            primary.setdefault(parts[0], ex["meta"]["cwes"][0])

    # Bucket families by CWE so the holdout spans bug classes instead of
    # landing on whichever families the shuffle happened to reach first. A
    # validation set covering two CWEs measures two CWEs, not generalisation.
    buckets: dict[str, list[str]] = {}
    for family in sorted(per_family):
        buckets.setdefault(primary.get(family, "_safe"), []).append(family)

    # Smallest family first within a bucket: holding out the smaller of three
    # CWE-89 families leaves the other two in training, so validation tests a
    # new *framework* for a known bug class rather than removing the class.
    for names in buckets.values():
        names.sort(key=lambda f: (per_family[f], f))

    # Spend the holdout budget on as many distinct CWEs as it will buy: visit
    # buckets cheapest-first, so a 15% budget covers four bug classes instead of
    # being consumed by one 275-example family. Deterministic — no shuffle.
    order = sorted(buckets, key=lambda c: (per_family[buckets[c][0]], c))

    # Choose held-out families by target example count, not family count —
    # families differ in size, so taking 10% of families rarely yields 10% of rows.
    target = len(examples) * val_fraction
    held_out: set[str] = set()
    running = 0
    for cwe in order:  # one family per CWE bucket, widest coverage first
        if running >= target:
            break
        family = buckets[cwe][0]
        held_out.add(family)
        running += per_family[family]

    train, val = [], []
    for ex in examples:
        parts = components(ex)
        if all(p in held_out for p in parts):
            val.append(ex)
        elif any(p in held_out for p in parts):
            # Straddles the boundary: one component is held out, one is not.
            # Dropping it is the only choice that keeps the split clean.
            continue
        else:
            train.append(ex)

    rng.shuffle(train)
    rng.shuffle(val)

    dropped = len(examples) - len(train) - len(val)
    train_fams = {f for ex in train for f in components(ex)}
    val_fams = {f for ex in val for f in components(ex)}
    overlap = train_fams & val_fams
    print(
        f"family split: {len(train)} train / {len(val)} val / {dropped} dropped at boundary"
    )
    print(f"  families: {len(train_fams)} train, {len(val_fams)} val, {len(overlap)} shared")
    summary = ", ".join(f"{f} [{primary.get(f, 'safe')}]" for f in sorted(held_out))
    print(f"  held-out: {summary}")
    if overlap:
        raise AssertionError(f"family leaked across split: {sorted(overlap)[:5]}")
    if not val:
        raise AssertionError("empty validation split")

    return train, val


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the SFT dataset")
    parser.add_argument("--examples", type=int, default=6000, help="approximate target size")
    # Higher than a per-example split would need: whole families are held out,
    # and the budget has to stretch across several CWE buckets to be informative.
    parser.add_argument("--val-fraction", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=13)
    parser.add_argument("--variants-per-combo", type=int, default=4,
                        help="augmented renderings per parameter combination")
    parser.add_argument("--out-dir", default="training/data")
    parser.add_argument("--benchmark", default="evaluation/data/benchmark.jsonl")
    args = parser.parse_args()

    examples = generate(args.examples, args.seed, args.variants_per_combo)

    examples, leak = filter_leakage(examples, args.benchmark)
    print(f"leakage check: {leak['n_checked']} generated, {len(examples)} kept")
    print(f"  dropped, exact duplicate of a benchmark case : {len(leak['exact'])}")
    print(f"  dropped, jaccard >= 0.92 to a benchmark case : {len(leak['near'])}")
    if leak["near"]:
        print("  near-duplicate families:", Counter(f for f, _ in leak["near"]).most_common(5))

    train, val = split_by_family(examples, args.val_fraction, args.seed)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, rows in (("train", train), ("val", val)):
        path = out_dir / f"{name}.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"wrote {len(rows):5d} -> {path}")

    kinds = Counter(e["meta"]["kind"] for e in examples)
    cwes = Counter(c for e in examples for c in e["meta"]["cwes"])
    langs = Counter(e["meta"]["language"] for e in examples)
    positives = sum(1 for e in examples if e["meta"]["n_findings"] > 0)
    print("\ncomposition:")
    print(f"  total           : {len(examples)}")
    print(f"  positive        : {positives} ({100*positives/max(len(examples),1):.1f}%)")
    print(f"  negative        : {len(examples)-positives}")
    print(f"  by kind         : {dict(kinds)}")
    print(f"  by language     : {dict(langs)}")
    print(f"  findings by CWE : {dict(sorted(cwes.items()))}")


if __name__ == "__main__":
    main()
