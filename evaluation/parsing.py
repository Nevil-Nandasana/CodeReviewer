"""
Stdlib-only parser for model review output.

Intentionally separate from `app.llm_engine.response_parser`:

* The eval harness must *measure* schema compliance, so it needs to distinguish
  "model emitted valid JSON" from "our repair heuristics rescued it". The
  production parser only cares about getting comments out and never reports
  which path it took.
* Runners execute in different virtualenvs (the local-model runner lives in the
  torch env, which has no structlog / tree-sitter), so the harness cannot import
  backend modules.

parse_review_output() returns (comments, strict_valid) where strict_valid is True
only when the raw text parsed as schema-conforming JSON on the first attempt.
"""
from __future__ import annotations

import json
import re
from typing import Any

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _coerce_comments(data: Any, allow_nested: bool = False) -> list[dict] | None:
    """
    Pull the finding list out of whatever envelope the model wrapped it in.

    `allow_nested` is off for the strict attempt and on for the recovery paths,
    so unwrapping a non-conforming shape still counts as a schema failure. That
    separation matters: schema compliance is a reported metric, and silently
    accepting a wrong envelope would make every model look compliant.

    The nested case is real, not hypothetical. Prompt v1 elicits

        [{"comments": [{...}, {...}]}]

    from Qwen2.5-Coder-1.5B — a list wrapping an object wrapping the list.
    Returning the outer list verbatim yielded one "finding" per case whose only
    key was `comments`, which normalised to line 0 and could never match ground
    truth. v1 therefore scored 1.2% recall on 235 emitted findings, and the
    prompt ablation was measuring a parser gap rather than the prompt.
    """
    if isinstance(data, dict) and isinstance(data.get("comments"), list):
        return data["comments"]

    if isinstance(data, list):
        # A list whose elements are themselves {"comments": [...]} envelopes.
        unwrapped: list[dict] = []
        saw_envelope = False
        for item in data:
            if isinstance(item, dict) and isinstance(item.get("comments"), list):
                saw_envelope = True
                unwrapped.extend(item["comments"])
            elif isinstance(item, dict):
                unwrapped.append(item)

        if saw_envelope:
            # Recoverable, but not the requested schema. On the strict path
            # return None so the caller falls through to the recovery branch and
            # records a schema failure — returning the outer list verbatim would
            # both emit line-0 junk *and* count the response as compliant.
            return unwrapped if allow_nested else None

        # A bare array of findings is accepted on either path. It is the one
        # deviation from the envelope that carries the same information.
        return data

    return None


def _normalize(comments: list[Any]) -> list[dict]:
    out: list[dict] = []
    for c in comments:
        if not isinstance(c, dict):
            continue
        try:
            line = int(c.get("line", 0) or 0)
        except (TypeError, ValueError):
            line = 0
        severity = str(c.get("severity", "LOW")).upper().strip()
        if severity not in VALID_SEVERITIES:
            severity = "LOW"
        owasp = c.get("owasp")
        out.append(
            {
                "line": line,
                "severity": severity,
                "category": str(c.get("category", "quality")).lower().strip(),
                "title": str(c.get("title", ""))[:300],
                "explanation": str(c.get("explanation", ""))[:2000],
                "suggestion": str(c.get("suggestion", ""))[:2000],
                "owasp": owasp if isinstance(owasp, str) else None,
            }
        )
    return out


def _strip_markdown(text: str) -> str:
    for pattern in (r"```json\s*(.*?)\s*```", r"```\s*(.*?)\s*```"):
        m = re.search(pattern, text, re.DOTALL)
        if m:
            return m.group(1)
    return text


def _extract_object(text: str) -> str | None:
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
                return text[start : i + 1]
    return None


def _repair_truncated(text: str) -> str:
    start = text.find("{")
    if start == -1:
        return text
    fragment = text[start:]
    # Drop a dangling partial key/value so the closing braces land on valid JSON.
    fragment = re.sub(r",\s*\"[^\"]*$", "", fragment)
    return fragment + ("]" * max(0, fragment.count("[") - fragment.count("]"))) + (
        "}" * max(0, fragment.count("{") - fragment.count("}"))
    )


def parse_review_output(raw: str) -> tuple[list[dict], bool]:
    """
    Returns (comments, strict_valid).

    strict_valid=True means the model produced schema-conforming JSON with no
    repair. Anything rescued by markdown stripping, substring extraction, or
    bracket repair still yields comments but counts as a schema failure.
    """
    if not raw or not raw.strip():
        return [], False

    try:
        comments = _coerce_comments(json.loads(raw.strip()))
        if comments is not None:
            return _normalize(comments), True
    except (json.JSONDecodeError, ValueError):
        pass

    for candidate in (_strip_markdown(raw), _extract_object(raw), _repair_truncated(raw)):
        if not candidate:
            continue
        try:
            comments = _coerce_comments(json.loads(candidate.strip()), allow_nested=True)
        except (json.JSONDecodeError, ValueError):
            continue
        if comments is not None:
            return _normalize(comments), False

    return [], False
