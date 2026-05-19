"""Celery review task — wraps the review pipeline for async execution."""
import structlog
from app.tasks.celery_app import celery_app
from app.db.session import SessionLocal

logger = structlog.get_logger(__name__)


# Failures that will fail identically on every attempt. Retrying a missing
# repository or a malformed payload just burns quota and posts nothing.
PERMANENT_ERRORS = (KeyError, TypeError, ValueError, AttributeError)


@celery_app.task(
    name="tasks.run_review",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    soft_time_limit=300,
    time_limit=360,
)
def run_review_task(self, event: dict) -> dict:
    """
    Async Celery task: runs full review pipeline for a GitHub PR event.

    Retries twice, 30s apart, on *transient* failures only. Retries are safe to
    repeat because the pipeline reads back the fingerprints of comments already
    on the PR before posting, so a second attempt tops up what is missing rather
    than duplicating the whole review.
    """
    logger.info("review_task_start", delivery_id=event.get("delivery_id"))
    db = SessionLocal()
    try:
        import redis as redis_lib
        from app.config import settings
        redis_client = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)

        from app.review_pipeline.pipeline import ReviewPipeline
        pipeline = ReviewPipeline(db=db, redis_client=redis_client)
        result = pipeline.run(event)
        logger.info("review_task_complete", result=result)
        return result
    except PERMANENT_ERRORS as exc:
        logger.exception("review_task_permanent_error", error=str(exc))
        return {"status": "error", "reason": type(exc).__name__, "detail": str(exc)}
    except Exception as exc:
        logger.exception("review_task_error", error=str(exc))
        raise self.retry(exc=exc) from exc
    finally:
        db.close()
