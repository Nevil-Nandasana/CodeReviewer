"""
Core data types for the CodeReviewer evaluation harness.

Everything on disk is JSONL so runs are diffable, resumable, and cheap to inspect.

Three record kinds:
  BenchmarkCase   — one code sample with ground-truth findings (possibly zero)
  PredictedFinding — one issue reported by a system under test
  CaseResult      — what a system produced for one case, plus cost/latency telemetry
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

# Ordinal severity scale — used for calibration error, not just labels.
SEVERITY_ORDER: dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
SEVERITIES = tuple(SEVERITY_ORDER)


def severity_rank(severity: str | None) -> int:
    return SEVERITY_ORDER.get(str(severity or "LOW").upper(), 1)


@dataclass
class GroundTruthFinding:
    """A vulnerability we know is present, at a line we control."""

    line: int
    cwe: str
    severity: str
    vuln_type: str
    description: str = ""
    # Extra lines that are an equally acceptable anchor for this finding
    # (e.g. the sink line and the tainted-assignment line).
    acceptable_lines: list[int] = field(default_factory=list)

    def anchors(self) -> set[int]:
        return {self.line, *self.acceptable_lines}


@dataclass
class BenchmarkCase:
    """
    One evaluation unit: a file (or diff) handed to a reviewer.

    `findings` is empty for clean cases. Clean cases are not filler — they are how
    we measure false-positive rate, which is the metric that decides whether a
    review bot is usable in practice.
    """

    case_id: str
    language: str
    filename: str
    code: str
    findings: list[GroundTruthFinding] = field(default_factory=list)
    #  vulnerable | clean | distractor  (distractor = clean but superficially scary)
    kind: str = "vulnerable"
    source: str = "synthetic"
    split: str = "test"
    tags: list[str] = field(default_factory=list)
    # Populated for cases expressed as a diff; otherwise built from `code`.
    diff: str | None = None

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0

    @property
    def loc(self) -> int:
        return len(self.code.splitlines())

    def as_diff(self) -> str:
        """Render the case as an all-added unified diff (what the pipeline sees)."""
        if self.diff:
            return self.diff
        header = f"--- /dev/null\n+++ b/{self.filename}\n@@ -0,0 +1,{self.loc} @@"
        body = "\n".join(f"+{line}" for line in self.code.splitlines())
        return f"{header}\n{body}"

    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "BenchmarkCase":
        findings = [GroundTruthFinding(**f) for f in d.get("findings", [])]
        return cls(**{**d, "findings": findings})


@dataclass
class PredictedFinding:
    """One issue reported by a system under test, normalized."""

    line: int
    severity: str
    category: str
    title: str
    explanation: str = ""
    suggestion: str = ""
    owasp: str | None = None
    # Filled in by taxonomy.infer_cwe() during scoring.
    cwe: str | None = None

    @property
    def is_security(self) -> bool:
        text = f"{self.category} {self.owasp or ''}".lower()
        return "security" in text or "vuln" in text or bool(self.owasp) or self.cwe is not None

    @classmethod
    def from_comment(cls, c: dict[str, Any]) -> "PredictedFinding":
        """Build from the pipeline's comment dict shape."""
        try:
            line = int(c.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        return cls(
            line=line,
            severity=str(c.get("severity", "LOW")).upper(),
            category=str(c.get("category", "quality")).lower(),
            title=str(c.get("title", ""))[:300],
            explanation=str(c.get("explanation", ""))[:2000],
            suggestion=str(c.get("suggestion", ""))[:2000],
            owasp=c.get("owasp") if isinstance(c.get("owasp"), str) else None,
        )


@dataclass
class CaseResult:
    """What one system produced for one case."""

    case_id: str
    system: str
    predictions: list[PredictedFinding] = field(default_factory=list)
    latency_s: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    # True when the raw output parsed as schema-valid JSON on the first attempt,
    # without the repair path in ResponseParser.
    json_valid: bool = True
    error: str | None = None
    raw_output: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "system": self.system,
            "predictions": [asdict(p) for p in self.predictions],
            "latency_s": round(self.latency_s, 4),
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cost_usd": self.cost_usd,
            "json_valid": self.json_valid,
            "error": self.error,
            "raw_output": self.raw_output[:8000],
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "CaseResult":
        preds = [PredictedFinding(**p) for p in d.get("predictions", [])]
        return cls(**{**d, "predictions": preds})


# ── JSONL helpers ──────────────────────────────────────────────────────────


def write_jsonl(path: str | Path, records: Iterable[dict[str, Any]]) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return n


def read_jsonl(path: str | Path) -> Iterator[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def load_benchmark(path: str | Path, split: str | None = None) -> list[BenchmarkCase]:
    cases = [BenchmarkCase.from_json(d) for d in read_jsonl(path)]
    if split:
        cases = [c for c in cases if c.split == split]
    return cases


def save_benchmark(path: str | Path, cases: list[BenchmarkCase]) -> int:
    return write_jsonl(path, (c.to_json() for c in cases))


def load_results(path: str | Path) -> list[CaseResult]:
    return [CaseResult.from_json(d) for d in read_jsonl(path)]


def save_results(path: str | Path, results: list[CaseResult]) -> int:
    return write_jsonl(path, (r.to_json() for r in results))
