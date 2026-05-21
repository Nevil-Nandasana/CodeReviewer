"""
Seed demo data — 3 repos and a pre-seeded PR with known vulnerabilities.

    python scripts/seed_demo_repos.py [--email you@example.com]

Repositories are attached to a user. `/api/v1/repositories` filters on
`added_by`, so a repo seeded with a NULL owner is invisible to every non-admin
account and the dashboard looks empty for no apparent reason. If the named user
does not exist it is created, so the script works on a fresh database.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.db.session import SessionLocal
from app.models import PullRequest, Repository, Review, ReviewComment, Vulnerability
from app.models.user import User

parser = argparse.ArgumentParser(description="Seed demo repositories and a review")
parser.add_argument("--email", default="demo@codereviewer.dev", help="owner of the seeded repos")
parser.add_argument("--password", default="demo1234", help="password if the user is created")
args = parser.parse_args()

db = SessionLocal()

# ── Owner ────────────────────────────────────────────────────────────────────
owner_user = db.query(User).filter(User.email == args.email).first()
if not owner_user:
    from passlib.context import CryptContext

    owner_user = User(
        email=args.email,
        username=args.email.split("@")[0],
        hashed_password=CryptContext(schemes=["bcrypt"], deprecated="auto").hash(args.password),
    )
    db.add(owner_user)
    db.commit()
    db.refresh(owner_user)
    print(f"Created user {args.email} (password: {args.password})")
else:
    print(f"Using existing user {args.email}")

# ── Demo repos ───────────────────────────────────────────────────────────────
GITHUB_OWNER = "Nevil-Nandasana"

repos_data = [
    {"github_repo_id": 1001, "owner": GITHUB_OWNER, "name": "api-service", "full_name": f"{GITHUB_OWNER}/api-service", "installation_id": 99001, "language": "Python"},
    {"github_repo_id": 1002, "owner": GITHUB_OWNER, "name": "web-frontend", "full_name": f"{GITHUB_OWNER}/web-frontend", "installation_id": 99001, "language": "TypeScript"},
    {"github_repo_id": 1003, "owner": GITHUB_OWNER, "name": "ml-pipeline", "full_name": f"{GITHUB_OWNER}/ml-pipeline", "installation_id": 99001, "language": "Python"},
]

repos = []
for rd in repos_data:
    existing = db.query(Repository).filter(Repository.github_repo_id == rd["github_repo_id"]).first()
    if not existing:
        repo = Repository(**rd, added_by=owner_user.id)
        db.add(repo)
        db.commit()
        db.refresh(repo)
        repos.append(repo)
        print(f"Created repo: {rd['full_name']}")
    else:
        # Adopt repos seeded before ownership filtering existed, otherwise they
        # stay invisible in the dashboard forever.
        if existing.added_by is None:
            existing.added_by = owner_user.id
            db.commit()
            print(f"Repo exists, assigned owner: {rd['full_name']}")
        else:
            print(f"Repo exists: {rd['full_name']}")
        repos.append(existing)

# ── Demo PRs + Reviews with SQL injection ──────────────────────────────────
if repos:
    repo = repos[0]

    pr = db.query(PullRequest).filter(PullRequest.github_pr_id == 5001).first()
    if not pr:
        pr = PullRequest(
            repository_id=repo.id, github_pr_number=42,
            github_pr_id=5001, title="Add user search endpoint",
            author="Nevil-Nandasana", base_branch="main", head_branch="feat/user-search",
            status="open",
        )
        db.add(pr)
        db.commit()
        db.refresh(pr)

    existing_review = db.query(Review).filter(Review.pull_request_id == pr.id).first()
    if not existing_review:
        review = Review(
            pull_request_id=pr.id, status="complete",
            model_used="deepseek-codereview-6.7b",
            total_comments=3, critical_count=1, high_count=1, medium_count=1,
            overall_quality_score=62.0, processing_time_seconds=18.3,
            inference_time_seconds=2.9,
        )
        db.add(review)
        db.commit()
        db.refresh(review)

        comments = [
            {"file_path": "app/routes/users.py", "line_number": 34, "severity": "CRITICAL", "category": "security",
             "title": "SQL Injection via string concatenation", "owasp_category": "A03:2021 Injection",
             "explanation": "user_id is concatenated directly into the SQL query. An attacker can inject arbitrary SQL by crafting a malicious input.",
             "suggestion": "def get_user(user_id):\n    return db.execute('SELECT * FROM users WHERE id = ?', (user_id,))"},
            {"file_path": "app/routes/users.py", "line_number": 12, "severity": "HIGH", "category": "security",
             "title": "Hardcoded database password", "owasp_category": "A02:2021 Cryptographic Failures",
             "explanation": "DB_PASSWORD is hardcoded in source code. This is exposed in version control.",
             "suggestion": "DB_PASSWORD = os.environ.get('DB_PASSWORD')"},
            {"file_path": "app/utils/helpers.py", "line_number": 7, "severity": "MEDIUM", "category": "quality",
             "title": "High cyclomatic complexity", "owasp_category": None,
             "explanation": "Function has cyclomatic complexity of 12. Target is <= 10.",
             "suggestion": "Refactor into smaller helper functions"},
        ]
        for cd in comments:
            rc = ReviewComment(review_id=review.id, **cd)
            db.add(rc)
            vuln = Vulnerability(
                repository_id=repo.id, file_path=cd["file_path"], line_number=cd["line_number"],
                severity=cd["severity"], owasp_category=cd.get("owasp_category"),
                title=cd["title"], explanation=cd["explanation"],
                vuln_type=cd["owasp_category"] or "quality", status="open",
            )
            db.add(vuln)
        db.commit()
        print(f"Created demo review with {len(comments)} comments")

db.close()
print(f"\nSeed complete. Open http://localhost:3000 and log in as {args.email}.")
