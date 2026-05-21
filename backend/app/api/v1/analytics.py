"""Analytics API endpoints — dashboard summary, activity feed."""
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter
from sqlalchemy import desc, func
from app.dependencies import DbDep, CurrentUser
from app.models.review import Review
from app.models.vulnerability import Vulnerability
from app.models.pull_request import PullRequest

router = APIRouter()


@router.get("/dashboard")
def dashboard_summary(db: DbDep, current_user: CurrentUser):
    """Metric cards for dashboard."""
    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)
    total_prs = db.query(PullRequest).count()
    reviews_this_week = db.query(Review).filter(Review.created_at >= week_ago).count()
    open_critical = db.query(Vulnerability).filter(
        Vulnerability.severity == "CRITICAL", Vulnerability.status == "open"
    ).count()
    open_high = db.query(Vulnerability).filter(
        Vulnerability.severity == "HIGH", Vulnerability.status == "open"
    ).count()
    from app.models.quality_metric import QualityMetric
    avg_quality = db.query(func.avg(QualityMetric.overall_quality_score)).scalar()
    return {
        "total_prs_reviewed": total_prs,
        "reviews_this_week": reviews_this_week,
        "critical_open": open_critical,
        "high_open": open_high,
        "avg_quality_score": round(float(avg_quality), 1) if avg_quality else None,
    }


@router.get("/recent-activity")
def recent_activity(db: DbDep, current_user: CurrentUser, limit: int = 10):
    """Last N reviews with severity breakdown."""
    reviews = db.query(Review).order_by(desc(Review.created_at)).limit(limit).all()
    return [
        {
            "id": str(r.id), "status": r.status,
            "critical": r.critical_count, "high": r.high_count,
            "medium": r.medium_count, "low": r.low_count,
            "total": r.total_comments, "model": r.model_used,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "pull_request_id": str(r.pull_request_id),
        }
        for r in reviews
    ]


@router.get("/reviews-per-day")
def reviews_per_day(db: DbDep, current_user: CurrentUser, days: int = 14):
    """Review counts per day for the last N days."""
    now = datetime.now(timezone.utc)
    results = []
    for i in range(days - 1, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        count = db.query(Review).filter(
            Review.created_at >= day_start, Review.created_at < day_end
        ).count()
        results.append({"date": day_start.strftime("%Y-%m-%d"), "count": count})
    return results
