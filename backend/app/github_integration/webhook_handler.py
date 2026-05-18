"""
GitHub Webhook Handler — HMAC-SHA256 signature verification.
"""
from __future__ import annotations
import hashlib
import hmac
import structlog
from fastapi import HTTPException, Request, status
from app.config import settings

logger = structlog.get_logger(__name__)


async def verify_webhook_signature(request: Request) -> bytes:
    """Verify GitHub HMAC-SHA256 signature. Returns raw body on success."""
    signature_header = request.headers.get("X-Hub-Signature-256", "")
    if not signature_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing signature")

    body = await request.body()
    expected = "sha256=" + hmac.new(
        settings.GITHUB_WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature_header, expected):
        logger.warning("webhook_signature_invalid")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signature")

    logger.info("webhook_signature_verified")
    return body


def parse_webhook_event(headers: dict, payload: dict) -> dict | None:
    """
    Parse GitHub webhook payload. Returns normalized event dict or None if ignored.
    Only processes: pull_request opened/synchronize/reopened events.
    """
    event_type = headers.get("x-github-event", "")
    delivery_id = headers.get("x-github-delivery", "unknown")

    if event_type != "pull_request":
        logger.debug("webhook_event_ignored", event=event_type)
        return None

    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        logger.debug("webhook_pr_action_ignored", action=action)
        return None

    pr = payload.get("pull_request", {})
    repo = payload.get("repository", {})
    installation = payload.get("installation", {})

    return {
        "delivery_id": delivery_id,
        "action": action,
        "pr_number": pr.get("number"),
        "pr_id": pr.get("id"),
        "pr_title": pr.get("title"),
        "pr_author": pr.get("user", {}).get("login"),
        "base_branch": pr.get("base", {}).get("ref"),
        "head_branch": pr.get("head", {}).get("ref"),
        "head_sha": pr.get("head", {}).get("sha"),
        "repo_id": repo.get("id"),
        "repo_owner": repo.get("owner", {}).get("login"),
        "repo_name": repo.get("name"),
        "repo_full_name": repo.get("full_name"),
        "installation_id": installation.get("id"),
    }
