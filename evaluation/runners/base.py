"""Reviewer interface shared by every system under test."""
from __future__ import annotations

import os
import sys
import time
from abc import ABC, abstractmethod
from pathlib import Path

from evaluation.schema import BenchmarkCase, CaseResult, PredictedFinding

REPO_ROOT = Path(__file__).resolve().parents[2]


def add_backend_to_path() -> None:
    """Make `app.*` importable for runners that reuse production components."""
    backend = str(REPO_ROOT / "backend")
    if backend not in sys.path:
        sys.path.insert(0, backend)


def load_env(path: str | Path = REPO_ROOT / "backend" / ".env") -> None:
    """Minimal .env loader — avoids a dependency just to read one API key."""
    path = Path(path)
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


class Reviewer(ABC):
    """A system under test. One instance reviews many cases."""

    name: str = "unnamed"

    @abstractmethod
    def review(self, case: BenchmarkCase) -> CaseResult:
        """Review one case. Must never raise — record the error in the result."""

    def close(self) -> None:  # noqa: B027 - optional hook, deliberately not abstract
        """Release resources. Only the local-model runners need to do anything."""

    def _timed(self, case: BenchmarkCase, fn):
        start = time.perf_counter()
        try:
            payload = fn()
        except Exception as exc:  # noqa: BLE001 - a crash is a measurable outcome
            return CaseResult(
                case_id=case.case_id,
                system=self.name,
                latency_s=time.perf_counter() - start,
                json_valid=False,
                error=f"{type(exc).__name__}: {exc}"[:500],
            )
        elapsed = time.perf_counter() - start
        comments, strict_valid, meta = payload
        return CaseResult(
            case_id=case.case_id,
            system=self.name,
            predictions=[PredictedFinding.from_comment(c) for c in comments],
            latency_s=elapsed,
            json_valid=strict_valid,
            prompt_tokens=meta.get("prompt_tokens", 0),
            completion_tokens=meta.get("completion_tokens", 0),
            cost_usd=meta.get("cost_usd", 0.0),
            raw_output=meta.get("raw_output", ""),
        )
