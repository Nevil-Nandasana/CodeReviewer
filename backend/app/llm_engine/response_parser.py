"""
Response Parser — robust JSON extractor from LLM output.
Handles: valid JSON, markdown-wrapped JSON, truncated JSON, JSON with preamble text.
"""
from __future__ import annotations
import json
import re
import structlog

logger = structlog.get_logger(__name__)


class ResponseParser:
    def parse(self, raw: str) -> list[dict]:
        """
        Parse LLM output into a list of comment dicts.
        Never raises — returns [] on any parse failure.
        """
        if not raw or not raw.strip():
            return []

        # 1. Try direct JSON parse
        result = self._try_parse(raw)
        if result is not None:
            return result

        # 2. Strip markdown code blocks (```json ... ```)
        stripped = self._strip_markdown(raw)
        result = self._try_parse(stripped)
        if result is not None:
            return result

        # 3. Find first { ... } substring
        extracted = self._extract_json_object(raw)
        if extracted:
            result = self._try_parse(extracted)
            if result is not None:
                return result

        # 4. Repair truncated JSON
        repaired = self._repair_truncated(raw)
        result = self._try_parse(repaired)
        if result is not None:
            return result

        logger.warning("response_parser.failed", raw_preview=raw[:200])
        return []

    def _try_parse(self, text: str) -> list[dict] | None:
        try:
            data = json.loads(text.strip())
            if isinstance(data, dict) and "comments" in data:
                comments = data["comments"]
                if isinstance(comments, list):
                    return self._validate_comments(comments)
            if isinstance(data, list):
                return self._validate_comments(data)
        except (json.JSONDecodeError, ValueError):
            pass
        return None

    def _strip_markdown(self, text: str) -> str:
        patterns = [
            r"```json\s*(.*?)\s*```",
            r"```\s*(.*?)\s*```",
        ]
        for pat in patterns:
            match = re.search(pat, text, re.DOTALL)
            if match:
                return match.group(1)
        return text

    def _extract_json_object(self, text: str) -> str | None:
        start = text.find("{")
        if start == -1:
            return None
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i+1]
        return None

    def _repair_truncated(self, text: str) -> str:
        """Try to close unclosed JSON brackets."""
        start = text.find("{")
        if start == -1:
            return text
        fragment = text[start:]
        open_braces = fragment.count("{") - fragment.count("}")
        open_brackets = fragment.count("[") - fragment.count("]")
        return fragment + ("]" * open_brackets) + ("}" * open_braces)

    @staticmethod
    def _coerce_line(value: object) -> int | None:
        """
        Best-effort line number from whatever the model emitted.

        `int(...)` alone raises on `null`, on `"12-14"`, and on `"line 12"` —
        all shapes models produce in practice — which would propagate out of
        `parse()` despite its contract of never raising. A finding whose line
        cannot be recovered is dropped: it can't be filtered against the diff
        or attached to a position, so guessing line 1 would post it against
        unrelated code.
        """
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, int):
            return value if value > 0 else None
        if isinstance(value, float):
            return int(value) if value > 0 else None
        if isinstance(value, str):
            match = re.search(r"\d+", value)
            if match:
                number = int(match.group())
                return number if number > 0 else None
        return None

    def _validate_comments(self, comments: list) -> list[dict]:
        """Filter and normalize comment dicts."""
        valid = []
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for c in comments:
            if not isinstance(c, dict):
                continue
            line = self._coerce_line(c.get("line"))
            if line is None:
                logger.debug("comment_dropped_unusable_line", raw_line=repr(c.get("line")))
                continue
            severity = str(c.get("severity", "LOW")).upper()
            if severity not in valid_severities:
                severity = "LOW"
            valid.append({
                "line": line,
                "severity": severity,
                "category": str(c.get("category", "quality")),
                "title": str(c.get("title", "Code issue"))[:300],
                "explanation": str(c.get("explanation", ""))[:2000],
                "suggestion": str(c.get("suggestion", ""))[:2000],
                "owasp": c.get("owasp"),
            })
        return valid
