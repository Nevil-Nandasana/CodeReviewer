"""Reviews and Pull Requests API endpoints."""
import uuid
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc

from app.config import settings
from app.dependencies import DbDep, CurrentUser
from app.models import Review, ReviewComment, PullRequest

router = APIRouter()


class ReviewOut(BaseModel):
    id: str
    pull_request_id: str
    status: str
    model_used: str | None
    total_comments: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    overall_quality_score: float | None
    processing_time_seconds: float | None
    created_at: str

    class Config:
        from_attributes = True


class CommentOut(BaseModel):
    id: str
    file_path: str
    line_number: int | None
    severity: str
    category: str | None
    title: str | None
    explanation: str
    suggestion: str | None
    owasp_category: str | None
    is_false_positive: bool

    class Config:
        from_attributes = True


class TriggerReviewRequest(BaseModel):
    repository_id: str
    pr_number: int


class AdHocReviewRequest(BaseModel):
    """A single file submitted directly, not through a PR webhook."""

    diff: str
    filename: str = "snippet.py"
    language: str = "python"


class AdHocReviewResponse(BaseModel):
    comments: list[dict]
    model: str
    inference_seconds: float
    static_findings: int


@router.post("/reviews/trigger", response_model=AdHocReviewResponse)
def review_snippet(payload: AdHocReviewRequest, current_user: CurrentUser):
    """
    Review one file synchronously and return the findings.

    This is what the VS Code extension calls. It is deliberately *not* the
    webhook path: there is no PR, nothing is persisted, and nothing is posted to
    GitHub — the caller wants an answer in-process, so a Celery round-trip would
    only add latency to a request that is already waiting.

    The endpoint existed in the extension and not in the API, so every
    invocation returned 404. See `vscode-extension/src/reviewProvider.ts`.
    """
    from app.ast_engine.extractor import ASTExtractor
    from app.ast_engine.security_scanner import SecurityScanner
    from app.llm_engine.model_client import ModelClient

    if not payload.diff.strip():
        return AdHocReviewResponse(
            comments=[], model="none", inference_seconds=0.0, static_findings=0
        )

    size_kb = len(payload.diff.encode("utf-8")) / 1024
    if size_kb > settings.MAX_DIFF_SIZE_KB:
        raise HTTPException(
            413, f"File is {size_kb:.0f}KB, over the {settings.MAX_DIFF_SIZE_KB}KB limit"
        )

    # The extension sends an all-added diff; the analysers want plain source.
    code = "\n".join(
        line[1:] if line.startswith(("+", "-", " ")) else line
        for line in payload.diff.splitlines()
        if not line.startswith(("+++", "---", "@@"))
    )

    ast_ctx = ASTExtractor().extract(code, payload.language)
    pre_flags = SecurityScanner().scan(ast_ctx, code)

    comments, model_name, elapsed = ModelClient(_redis()).review(
        diff=payload.diff,
        ast_context=ast_ctx,
        pre_flags=pre_flags,
        language=payload.language,
    )

    return AdHocReviewResponse(
        comments=comments,
        model=model_name,
        inference_seconds=round(elapsed, 3),
        static_findings=len(pre_flags),
    )


def _redis():
    """Cache client, or None when Redis is unreachable — a cache is optional."""
    try:
        import redis as redis_lib

        client = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)
        client.ping()
        return client
    except Exception:
        return None


@router.get("/reviews")
def list_reviews(
    db: DbDep, current_user: CurrentUser,
    skip: int = 0, limit: int = 50,
    status: str | None = Query(None),
):
    q = db.query(Review).order_by(desc(Review.created_at))
    if status:
        q = q.filter(Review.status == status)
    reviews = q.offset(skip).limit(limit).all()
    return [
        {
            "id": str(r.id), "status": r.status, "model_used": r.model_used,
            "total_comments": r.total_comments, "critical_count": r.critical_count,
            "high_count": r.high_count, "medium_count": r.medium_count,
            "low_count": r.low_count, "processing_time_seconds": r.processing_time_seconds,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "pull_request_id": str(r.pull_request_id),
        }
        for r in reviews
    ]


@router.get("/reviews/{review_id}")
def get_review(review_id: str, db: DbDep, current_user: CurrentUser):
    r = db.query(Review).filter(Review.id == uuid.UUID(review_id)).first()
    if not r:
        raise HTTPException(404, "Review not found")
    return {
        "id": str(r.id), "status": r.status, "model_used": r.model_used,
        "total_comments": r.total_comments, "critical_count": r.critical_count,
        "high_count": r.high_count, "medium_count": r.medium_count,
        "low_count": r.low_count, "info_count": r.info_count,
        "overall_quality_score": r.overall_quality_score,
        "processing_time_seconds": r.processing_time_seconds,
        "inference_time_seconds": r.inference_time_seconds,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "pull_request_id": str(r.pull_request_id),
    }


@router.get("/reviews/{review_id}/comments")
def get_review_comments(review_id: str, db: DbDep, current_user: CurrentUser):
    comments = db.query(ReviewComment).filter(
        ReviewComment.review_id == uuid.UUID(review_id)
    ).all()
    return [
        {
            "id": str(c.id), "file_path": c.file_path, "line_number": c.line_number,
            "severity": c.severity, "category": c.category, "title": c.title,
            "explanation": c.explanation, "suggestion": c.suggestion,
            "owasp_category": c.owasp_category, "is_false_positive": c.is_false_positive,
        }
        for c in comments
    ]


@router.get("/pull-requests")
def list_pull_requests(
    db: DbDep, current_user: CurrentUser,
    skip: int = 0, limit: int = 50,
):
    prs = db.query(PullRequest).order_by(desc(PullRequest.created_at)).offset(skip).limit(limit).all()
    return [
        {
            "id": str(pr.id), "github_pr_number": pr.github_pr_number,
            "title": pr.title, "author": pr.author, "status": pr.status,
            "base_branch": pr.base_branch, "head_branch": pr.head_branch,
            "repository_id": str(pr.repository_id),
            "created_at": pr.created_at.isoformat() if pr.created_at else None,
        }
        for pr in prs
    ]


@router.get("/pull-requests/{pr_id}")
def get_pull_request(pr_id: str, db: DbDep, current_user: CurrentUser):
    pr = db.query(PullRequest).filter(PullRequest.id == uuid.UUID(pr_id)).first()
    if not pr:
        raise HTTPException(404, "Pull request not found")
    return {
        "id": str(pr.id), "github_pr_number": pr.github_pr_number,
        "title": pr.title, "author": pr.author, "status": pr.status,
        "files_changed": pr.files_changed, "lines_added": pr.lines_added,
        "lines_deleted": pr.lines_deleted, "repository_id": str(pr.repository_id),
    }


@router.get("/pull-requests/{pr_id}/latest-review")
def get_pr_latest_review(pr_id: str, db: DbDep, current_user: CurrentUser):
    review = db.query(Review).filter(
        Review.pull_request_id == uuid.UUID(pr_id)
    ).order_by(desc(Review.created_at)).first()
    if not review:
        raise HTTPException(404, "No review found for this PR")
    return {"id": str(review.id), "status": review.status, "total_comments": review.total_comments}


@router.patch("/review-comments/{comment_id}")
def update_comment(comment_id: str, payload: dict, db: DbDep, current_user: CurrentUser):
    c = db.query(ReviewComment).filter(ReviewComment.id == uuid.UUID(comment_id)).first()
    if not c:
        raise HTTPException(404, "Comment not found")
    if "is_false_positive" in payload:
        c.is_false_positive = bool(payload["is_false_positive"])
    if "was_resolved" in payload:
        c.was_resolved = bool(payload["was_resolved"])
    db.commit()
    return {"id": str(c.id), "is_false_positive": c.is_false_positive, "was_resolved": c.was_resolved}
