"""
Rules-only baseline: the production AST engine + OWASP rule scanner, no LLM.

This is the floor every model has to beat. It is also the cheapest and fastest
system in the comparison, so if a 1.5B model cannot beat it on F1 while staying
close on latency, the model is not worth shipping.
"""
from __future__ import annotations

from evaluation.runners.base import Reviewer, add_backend_to_path
from evaluation.schema import BenchmarkCase, CaseResult

add_backend_to_path()

from app.ast_engine.extractor import ASTExtractor  # noqa: E402
from app.ast_engine.security_scanner import SecurityScanner  # noqa: E402


class RulesReviewer(Reviewer):
    def __init__(self, name: str = "rules-only"):
        self.name = name
        self.extractor = ASTExtractor()
        self.scanner = SecurityScanner()

    def scan(self, case: BenchmarkCase) -> list[dict]:
        """Raw scanner findings — also used by the hybrid runner as pre-flags."""
        ctx = self.extractor.extract(case.code, case.language)
        return self.scanner.scan(ctx, case.code)

    def review(self, case: BenchmarkCase) -> CaseResult:
        def run():
            findings = self.scan(case)
            comments = [
                {
                    "line": f.get("line", 0),
                    "severity": f.get("severity", "MEDIUM"),
                    "category": "security",
                    "title": f.get("title", f.get("vuln_type", "issue")),
                    "explanation": f.get("explanation", ""),
                    "suggestion": f.get("suggestion", ""),
                    "owasp": f.get("owasp"),
                }
                for f in findings
            ]
            return comments, True, {"raw_output": ""}

        return self._timed(case, run)
