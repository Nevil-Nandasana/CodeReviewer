"""Code quality analyzer — cyclomatic complexity, function length, comment ratio."""
from __future__ import annotations
from dataclasses import dataclass
from app.ast_engine.extractor import ASTContext


@dataclass
class QualityReport:
    cyclomatic_complexity: float
    cognitive_complexity: float
    lines_of_code: int
    comment_ratio: float
    avg_function_length: float
    max_function_length: int
    function_count: int
    overall_quality_score: float
    issues: list[dict]


class QualityAnalyzer:
    def analyze(self, code: str, ast_context: ASTContext) -> QualityReport:
        lines = code.splitlines()
        loc = len([l for l in lines if l.strip() and not l.strip().startswith("#")])
        comment_lines = len([l for l in lines if l.strip().startswith("#")])
        comment_ratio = comment_lines / max(len(lines), 1)

        func_lengths = [f.length for f in ast_context.functions]
        avg_len = sum(func_lengths) / max(len(func_lengths), 1)
        max_len = max(func_lengths) if func_lengths else 0
        complexities = [f.complexity for f in ast_context.functions]
        avg_complexity = sum(complexities) / max(len(complexities), 1)

        issues = []
        for func in ast_context.functions:
            if func.complexity > 10:
                issues.append({
                    "type": "high_complexity",
                    "severity": "MEDIUM",
                    "line": func.start_line,
                    "title": f"High cyclomatic complexity in '{func.name}': {func.complexity}",
                    "suggestion": "Refactor into smaller functions. Target complexity <= 10.",
                })
            if func.length > 50:
                issues.append({
                    "type": "long_function",
                    "severity": "LOW",
                    "line": func.start_line,
                    "title": f"Long function '{func.name}': {func.length} lines",
                    "suggestion": "Functions longer than 50 lines are harder to test and maintain.",
                })

        # Quality score: 100 minus penalties, floored at 0.
        score = 100.0
        if avg_complexity > 15:
            score -= 30
        elif avg_complexity > 10:
            score -= 15
        elif avg_complexity > 5:
            score -= 5

        if max_len > 100:
            score -= 20
        elif max_len > 50:
            score -= 10

        if comment_ratio < 0.05:
            score -= 10

        score = max(0.0, min(100.0, score))

        return QualityReport(
            cyclomatic_complexity=round(avg_complexity, 2),
            cognitive_complexity=round(avg_complexity * 1.2, 2),
            lines_of_code=loc,
            comment_ratio=round(comment_ratio, 3),
            avg_function_length=round(avg_len, 1),
            max_function_length=max_len,
            function_count=len(ast_context.functions),
            overall_quality_score=round(score, 1),
            issues=issues,
        )
