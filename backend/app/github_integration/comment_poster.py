"""
Comment Poster — formats and posts review comments to GitHub PRs.
Deduplicates using existing comment content hashes.
"""
from __future__ import annotations
import hashlib
import re
from typing import TYPE_CHECKING

import structlog

# Type-only. The formatting and fingerprinting helpers below are pure functions
# and are exercised directly by the tests; importing the PyGithub-backed client
# at module scope would make them require the GitHub SDK to be installed.
if TYPE_CHECKING:
    from app.github_integration.github_client import GitHubClient

logger = structlog.get_logger(__name__)

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


# Fenced-code language per source extension, so a JS suggestion isn't
# advertised as Python.
_FENCE_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".go": "go", ".rb": "ruby", ".cs": "csharp", ".php": "php",
}


def fence_language(file_path: str | None) -> str:
    if not file_path or "." not in file_path:
        return ""
    return _FENCE_BY_EXT.get("." + file_path.rsplit(".", 1)[-1].lower(), "")


def comment_fingerprint(file_path: str, comment: dict) -> str:
    """
    Stable identity for a finding, used to avoid re-posting it.

    Keyed on file, line, severity and title rather than the rendered body, so
    a reworded explanation from a non-deterministic model does not read as a
    new finding on the next push.
    """
    raw = "|".join([
        file_path,
        str(comment.get("line")),
        str(comment.get("severity")),
        str(comment.get("title")),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def format_comment_body(comment: dict, file_path: str | None = None) -> str:
    severity = comment.get("severity", "LOW")
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    title = comment.get("title", "Code issue")
    explanation = comment.get("explanation", "")
    suggestion = comment.get("suggestion", "")
    owasp = comment.get("owasp")
    category = comment.get("category", "quality")

    parts = [
        f"{emoji} **[{severity}] {title}**",
        f"**Category:** {category}",
    ]
    if owasp:
        parts.append(f"**OWASP:** {owasp}")
    parts.append(f"\n{explanation}")
    if suggestion:
        parts.append(f"\n**Suggested fix:**\n```{fence_language(file_path)}\n{suggestion}\n```")
    parts.append("\n---\n*Posted by [CodeReviewer AI](https://github.com/Nevil-Nandasana/CodeReviewer)*")
    # Machine-readable marker so a later run can recognise its own comment.
    if file_path:
        parts.append(f"<!-- codereviewer:{comment_fingerprint(file_path, comment)} -->")
    return "\n".join(parts)


def format_summary_body(comments: list[dict], model_name: str, processing_time: float) -> str:
    critical = sum(1 for c in comments if c.get("severity") == "CRITICAL")
    high = sum(1 for c in comments if c.get("severity") == "HIGH")
    medium = sum(1 for c in comments if c.get("severity") == "MEDIUM")
    low = sum(1 for c in comments if c.get("severity") == "LOW")

    return f"""## 🛡️ CodeReviewer AI Review Complete

| Severity | Count |
|----------|-------|
| 🔴 Critical | {critical} |
| 🟠 High | {high} |
| 🟡 Medium | {medium} |
| 🔵 Low | {low} |

**Model:** `{model_name}` | **Processing time:** {processing_time:.1f}s
"""


class CommentPoster:
    def __init__(self, github_client: GitHubClient):
        self.gh = github_client

    def post_review_comments(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        commit_sha: str,
        file_path: str,
        comments: list[dict],
        valid_lines: set[int],
        already_posted: set[str] | None = None,
    ) -> list[int]:
        """
        Post inline comments for valid line numbers. Returns posted comment IDs.

        `already_posted` carries fingerprints seen earlier in this run or on a
        previous run of the same PR. Every push fires a `synchronize` event and
        re-reviews the whole diff, and the Celery task retries on failure, so
        without this the same finding is posted again on every attempt.
        """
        seen = already_posted if already_posted is not None else set()
        posted_ids = []
        for comment in comments:
            line = comment.get("line")
            if line not in valid_lines:
                logger.debug("comment_line_out_of_diff", line=line, file=file_path)
                continue

            fingerprint = comment_fingerprint(file_path, comment)
            if fingerprint in seen:
                logger.debug("comment_duplicate_skipped", file=file_path, line=line)
                continue
            seen.add(fingerprint)

            body = format_comment_body(comment, file_path)
            comment_id = self.gh.post_review_comment(
                installation_id, repo_full_name, pr_number, body, commit_sha, file_path, line
            )
            if comment_id:
                posted_ids.append(comment_id)
        return posted_ids

    def existing_fingerprints(
        self, installation_id: int, repo_full_name: str, pr_number: int
    ) -> set[str]:
        """Fingerprints CodeReviewer already posted on this PR, read back from GitHub."""
        marker = re.compile(r"<!--\s*codereviewer:([0-9a-f]{16})\s*-->")
        try:
            bodies = self.gh.list_review_comment_bodies(
                installation_id, repo_full_name, pr_number
            )
        except Exception as exc:  # noqa: BLE001 - never block a review on this
            logger.warning("existing_comments_unavailable", error=str(exc))
            return set()
        return {m.group(1) for body in bodies for m in marker.finditer(body or "")}

    def post_summary(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        commit_sha: str,
        all_comments: list[dict],
        model_name: str,
        processing_time: float,
    ) -> int | None:
        body = format_summary_body(all_comments, model_name, processing_time)
        return self.gh.post_pr_review_summary(
            installation_id, repo_full_name, pr_number, commit_sha, body
        )
