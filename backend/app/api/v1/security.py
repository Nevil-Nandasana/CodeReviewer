"""Security API endpoints — vulnerabilities, OWASP breakdown, heatmap."""
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import desc
from app.dependencies import DbDep, CurrentUser
from app.models.vulnerability import Vulnerability

router = APIRouter()


@router.get("/vulnerabilities")
def list_vulnerabilities(
    db: DbDep, current_user: CurrentUser,
    status: str | None = Query(None),
    severity: str | None = Query(None),
    skip: int = 0, limit: int = 100,
):
    q = db.query(Vulnerability).order_by(desc(Vulnerability.first_seen_at))
    if status:
        q = q.filter(Vulnerability.status == status)
    if severity:
        q = q.filter(Vulnerability.severity == severity)
    vulns = q.offset(skip).limit(limit).all()
    return [{"id": str(v.id), "file_path": v.file_path, "line_number": v.line_number,
             "vuln_type": v.vuln_type, "severity": v.severity, "owasp_category": v.owasp_category,
             "title": v.title, "status": v.status,
             "first_seen_at": v.first_seen_at.isoformat() if v.first_seen_at else None,
             "repository_id": str(v.repository_id)} for v in vulns]


@router.get("/vulnerabilities/{vuln_id}")
def get_vulnerability(vuln_id: str, db: DbDep, current_user: CurrentUser):
    v = db.query(Vulnerability).filter(Vulnerability.id == uuid.UUID(vuln_id)).first()
    if not v:
        raise HTTPException(404, "Not found")
    return {"id": str(v.id), "file_path": v.file_path, "severity": v.severity,
            "title": v.title, "explanation": v.explanation, "status": v.status}


@router.get("/summary")
def security_summary(db: DbDep, current_user: CurrentUser):
    vulns = db.query(Vulnerability).all()
    open_v = [v for v in vulns if v.status == "open"]
    return {
        "total_open": len(open_v),
        "critical_open": sum(1 for v in open_v if v.severity == "CRITICAL"),
        "high_open": sum(1 for v in open_v if v.severity == "HIGH"),
        "medium_open": sum(1 for v in open_v if v.severity == "MEDIUM"),
        "total_resolved": sum(1 for v in vulns if v.status == "resolved"),
    }


@router.get("/owasp-breakdown")
def owasp_breakdown(db: DbDep, current_user: CurrentUser):
    vulns = db.query(Vulnerability).filter(Vulnerability.status == "open").all()
    counts = Counter(v.owasp_category for v in vulns if v.owasp_category)
    return [{"owasp_category": k, "count": v} for k, v in counts.most_common()]


@router.get("/file-heatmap")
def file_heatmap(db: DbDep, current_user: CurrentUser, limit: int = 20):
    vulns = db.query(Vulnerability).filter(Vulnerability.status == "open").all()
    counts = Counter(v.file_path for v in vulns if v.file_path)
    return [{"file_path": k, "count": v} for k, v in counts.most_common(limit)]


@router.get("/trends")
def security_trends(db: DbDep, current_user: CurrentUser):
    now = datetime.now(timezone.utc)
    results = []
    for i in range(7, -1, -1):
        ws = now - timedelta(weeks=i+1)
        we = now - timedelta(weeks=i)
        count = db.query(Vulnerability).filter(
            Vulnerability.first_seen_at >= ws, Vulnerability.first_seen_at < we
        ).count()
        results.append({"week": ws.strftime("%Y-%m-%d"), "count": count})
    return results


@router.patch("/vulnerabilities/{vuln_id}")
def update_vulnerability(vuln_id: str, payload: dict, db: DbDep, current_user: CurrentUser):
    v = db.query(Vulnerability).filter(Vulnerability.id == uuid.UUID(vuln_id)).first()
    if not v:
        raise HTTPException(404, "Not found")
    if "status" in payload:
        v.status = payload["status"]
        if payload["status"] == "resolved":
            v.resolved_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": str(v.id), "status": v.status}
