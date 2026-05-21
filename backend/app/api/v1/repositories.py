"""Repositories API endpoints."""
import uuid
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.dependencies import DbDep, CurrentUser
from app.models.repository import Repository
from app.models.review import Review
from app.models.vulnerability import Vulnerability

router = APIRouter()


def parse_uuid(value: str) -> uuid.UUID:
    """Path UUIDs come from user input; a bad one is a 422, not a 500."""
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        # `from None` — the caller sent a bad string; the internal ValueError
        # is noise in the traceback and says nothing they can act on.
        raise HTTPException(422, "Invalid repository id") from None


def owned_repository(db, repo_id: str, current_user) -> Repository:
    """
    Fetch a repository the caller is allowed to see.

    Ownership is part of the lookup rather than a separate check afterwards, so
    a new endpoint cannot forget it. Admins bypass. A repository owned by
    someone else returns 404, not 403 — a 403 would confirm the id exists and
    turn the endpoint into an enumeration oracle.
    """
    repo = db.query(Repository).filter(Repository.id == parse_uuid(repo_id)).first()
    if not repo or (not current_user.is_admin and repo.added_by != current_user.id):
        raise HTTPException(404, "Repository not found")
    return repo


class CreateRepoRequest(BaseModel):
    github_repo_id: int
    owner: str
    name: str
    full_name: str
    installation_id: int
    language: str | None = None


class UpdateRepoRequest(BaseModel):
    review_enabled: bool | None = None
    security_scan_enabled: bool | None = None


@router.get("")
def list_repositories(db: DbDep, current_user: CurrentUser):
    query = db.query(Repository).filter(Repository.is_active.is_(True))
    if not current_user.is_admin:
        query = query.filter(Repository.added_by == current_user.id)
    repos = query.all()
    return [
        {
            "id": str(r.id), "owner": r.owner, "name": r.name,
            "full_name": r.full_name, "language": r.language,
            "review_enabled": r.review_enabled,
            "security_scan_enabled": r.security_scan_enabled,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in repos
    ]


@router.post("", status_code=201)
def create_repository(payload: CreateRepoRequest, db: DbDep, current_user: CurrentUser):
    existing = db.query(Repository).filter(
        Repository.github_repo_id == payload.github_repo_id
    ).first()
    if existing:
        raise HTTPException(409, "Repository already registered")
    repo = Repository(
        **payload.model_dump(),
        added_by=current_user.id,
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)
    return {"id": str(repo.id), "full_name": repo.full_name}


@router.get("/{repo_id}")
def get_repository(repo_id: str, db: DbDep, current_user: CurrentUser):
    repo = owned_repository(db, repo_id, current_user)
    return {"id": str(repo.id), "owner": repo.owner, "name": repo.name,
            "full_name": repo.full_name, "language": repo.language,
            "review_enabled": repo.review_enabled, "security_scan_enabled": repo.security_scan_enabled}


@router.patch("/{repo_id}")
def update_repository(repo_id: str, payload: UpdateRepoRequest, db: DbDep, current_user: CurrentUser):
    repo = owned_repository(db, repo_id, current_user)
    if payload.review_enabled is not None:
        repo.review_enabled = payload.review_enabled
    if payload.security_scan_enabled is not None:
        repo.security_scan_enabled = payload.security_scan_enabled
    db.commit()
    return {"id": str(repo.id), "review_enabled": repo.review_enabled}


@router.delete("/{repo_id}", status_code=204)
def delete_repository(repo_id: str, db: DbDep, current_user: CurrentUser):
    repo = owned_repository(db, repo_id, current_user)
    repo.is_active = False
    db.commit()


@router.get("/{repo_id}/stats")
def get_repository_stats(repo_id: str, db: DbDep, current_user: CurrentUser):
    uid = owned_repository(db, repo_id, current_user).id
    total_reviews = db.query(Review).join(Review.pull_request).filter(
        Review.pull_request.has(repository_id=uid)
    ).count()
    open_vulns = db.query(Vulnerability).filter(
        Vulnerability.repository_id == uid, Vulnerability.status == "open"
    ).count()
    critical_vulns = db.query(Vulnerability).filter(
        Vulnerability.repository_id == uid,
        Vulnerability.severity == "CRITICAL",
        Vulnerability.status == "open",
    ).count()
    return {
        "repository_id": repo_id,
        "total_reviews": total_reviews,
        "open_vulnerabilities": open_vulns,
        "critical_vulnerabilities": critical_vulns,
    }
