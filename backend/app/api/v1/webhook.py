"""GitHub webhook receiver endpoint."""
import json
import structlog
from fastapi import APIRouter, Request
from app.github_integration.webhook_handler import verify_webhook_signature, parse_webhook_event
from app.tasks.review_task import run_review_task

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.post("/github")
async def github_webhook(request: Request):
    """Receive and process GitHub webhook events."""
    body = await verify_webhook_signature(request)
    payload = json.loads(body)
    headers = dict(request.headers)

    event = parse_webhook_event(headers, payload)
    if event is None:
        return {"status": "ignored"}

    # Enqueue async Celery task
    task = run_review_task.delay(event)
    logger.info("review_task_enqueued", task_id=task.id, pr=event.get("pr_number"))

    return {"status": "accepted", "task_id": task.id, "pr_number": event.get("pr_number")}
