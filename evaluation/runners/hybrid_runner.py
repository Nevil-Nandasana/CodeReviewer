"""
Hybrid runner: rule scanner pre-flags feed the LLM prompt.

This is the architecture the product actually ships, and the interesting
question it answers is not "does adding rules raise recall" (it usually does)
but "does the model keep the rules' false positives?". The prompt explicitly
invites the model to reject a pre-flag when the code is safe, so the distractor
set measures whether it takes that invitation or just rubber-stamps the scanner.
"""
from __future__ import annotations

from evaluation.runners.base import Reviewer
from evaluation.runners.rules_runner import RulesReviewer
from evaluation.schema import BenchmarkCase, CaseResult


class HybridReviewer(Reviewer):
    def __init__(self, llm: Reviewer, name: str | None = None):
        self.llm = llm
        self.rules = RulesReviewer()
        self.name = name or f"hybrid-{llm.name}"

    def review(self, case: BenchmarkCase) -> CaseResult:
        try:
            pre_flags = self.rules.scan(case)
        except Exception:  # noqa: BLE001 - a scanner crash must not kill the run
            pre_flags = []

        result = self.llm.review(case, pre_flags=pre_flags)
        result.system = self.name
        return result

    def close(self) -> None:
        self.llm.close()
