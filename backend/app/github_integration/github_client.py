"""
GitHub Client — wraps PyGithub for PR fetching and diff retrieval.
"""
from __future__ import annotations
import structlog
from github import Auth, Github, GithubIntegration
from app.config import settings

logger = structlog.get_logger(__name__)


class GitHubClient:
    def __init__(self):
        self._integration: GithubIntegration | None = None
        self._setup_integration()

    def _setup_integration(self):
        try:
            with open(settings.GITHUB_APP_PRIVATE_KEY_PATH) as f:
                private_key = f.read()
            auth = Auth.AppAuth(settings.GITHUB_APP_ID, private_key)
            self._integration = GithubIntegration(auth=auth)
            logger.info("github_integration_ready")
        except Exception as e:
            logger.warning("github_integration_failed", error=str(e))

    def _get_installation_github(self, installation_id: int) -> Github:
        if not self._integration:
            raise RuntimeError("GitHub integration not configured")
        auth = self._integration.get_installation(installation_id).get_github_for_installation()
        return Github(auth=auth)

    def get_pr_diff(self, installation_id: int, repo_full_name: str, pr_number: int) -> str:
        """Fetch unified diff for a pull request."""
        gh = self._get_installation_github(installation_id)
        repo = gh.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)
        # Get diff via comparison
        comparison = repo.compare(pr.base.sha, pr.head.sha)
        diff_parts = []
        for f in comparison.files:
            if f.patch:
                diff_parts.append(
                    f"--- a/{f.filename}\n+++ b/{f.filename}\n{f.patch}"
                )
        return "\n".join(diff_parts)

    def get_pr_files(self, installation_id: int, repo_full_name: str, pr_number: int) -> list[dict]:
        """Get list of changed files with metadata."""
        gh = self._get_installation_github(installation_id)
        repo = gh.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)
        return [
            {
                "filename": f.filename,
                "status": f.status,
                "additions": f.additions,
                "deletions": f.deletions,
                "patch": f.patch or "",
            }
            for f in pr.get_files()
        ]

    def get_file_content(
        self, installation_id: int, repo_full_name: str, file_path: str, ref: str
    ) -> str:
        """Fetch full file content at a given ref."""
        gh = self._get_installation_github(installation_id)
        repo = gh.get_repo(repo_full_name)
        try:
            content = repo.get_contents(file_path, ref=ref)
            return content.decoded_content.decode("utf-8")
        except Exception as e:
            logger.warning("file_content_fetch_failed", file=file_path, error=str(e))
            return ""

    def post_review_comment(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        body: str,
        commit_sha: str,
        path: str,
        line: int,
    ) -> int | None:
        """Post an inline review comment on a PR."""
        gh = self._get_installation_github(installation_id)
        repo = gh.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)
        commit = repo.get_commit(commit_sha)
        try:
            comment = pr.create_review_comment(
                body=body, commit=commit, path=path, line=line
            )
            return comment.id
        except Exception as e:
            logger.warning("comment_post_failed", error=str(e))
            return None

    def list_review_comment_bodies(
        self, installation_id: int, repo_full_name: str, pr_number: int
    ) -> list[str]:
        """
        Bodies of every existing inline review comment on a PR.

        Used to recover the fingerprints CodeReviewer posted on earlier runs, so a
        `synchronize` event or a task retry does not duplicate findings that are
        already on the PR.
        """
        gh = self._get_installation_github(installation_id)
        repo = gh.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)
        return [c.body for c in pr.get_review_comments()]

    def post_pr_review_summary(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        commit_sha: str,
        summary_body: str,
    ) -> int | None:
        """Post a PR review summary."""
        gh = self._get_installation_github(installation_id)
        repo = gh.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)
        commit = repo.get_commit(commit_sha)
        try:
            review = pr.create_review(commit=commit, body=summary_body, event="COMMENT")
            return review.id
        except Exception as e:
            logger.warning("review_summary_failed", error=str(e))
            return None
