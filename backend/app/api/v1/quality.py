"""Quality metrics API endpoints."""
from fastapi import APIRouter
from sqlalchemy import desc
from app.dependencies import DbDep, CurrentUser
from app.models.quality_metric import QualityMetric

router = APIRouter()


@router.get("/metrics")
def list_quality_metrics(db: DbDep, current_user: CurrentUser, skip: int = 0, limit: int = 100):
    metrics = db.query(QualityMetric).order_by(desc(QualityMetric.created_at)).offset(skip).limit(limit).all()
    return [
        {
            "id": str(m.id), "file_path": m.file_path, "language": m.language,
            "cyclomatic_complexity": m.cyclomatic_complexity,
            "lines_of_code": m.lines_of_code, "comment_ratio": m.comment_ratio,
            "avg_function_length": m.avg_function_length,
            "overall_quality_score": m.overall_quality_score,
            "created_at": m.created_at.isoformat() if m.created_at else None,
        }
        for m in metrics
    ]


@router.get("/trends")
def quality_trends(db: DbDep, current_user: CurrentUser, limit: int = 30):
    """Quality score over last N reviews."""
    metrics = db.query(QualityMetric).filter(
        QualityMetric.overall_quality_score.isnot(None)
    ).order_by(desc(QualityMetric.created_at)).limit(limit).all()
    return [
        {"date": m.created_at.isoformat() if m.created_at else None,
         "score": m.overall_quality_score, "file": m.file_path}
        for m in reversed(metrics)
    ]


@router.get("/files")
def quality_by_file(db: DbDep, current_user: CurrentUser, limit: int = 20):
    """Most complex files ranked by cyclomatic complexity."""
    metrics = db.query(QualityMetric).filter(
        QualityMetric.cyclomatic_complexity.isnot(None)
    ).order_by(desc(QualityMetric.cyclomatic_complexity)).limit(limit).all()
    return [
        {"file_path": m.file_path, "language": m.language,
         "cyclomatic_complexity": m.cyclomatic_complexity,
         "lines_of_code": m.lines_of_code, "overall_quality_score": m.overall_quality_score}
        for m in metrics
    ]


@router.get("/issues")
def common_quality_issues(db: DbDep, current_user: CurrentUser):
    """Aggregated quality issue categories."""
    from app.models.review_comment import ReviewComment
    from collections import Counter
    comments = db.query(ReviewComment).filter(
        ReviewComment.category == "quality"
    ).all()
    titles = Counter(c.title for c in comments if c.title)
    return [{"issue": k, "count": v} for k, v in titles.most_common(15)]
