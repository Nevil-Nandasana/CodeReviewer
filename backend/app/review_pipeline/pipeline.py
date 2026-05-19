"""
Full review pipeline — orchestrates AST + LLM + GitHub comment posting.
Called by Celery task for async execution.
"""
from __future__ import annotations
import hashlib
import time
import structlog
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.ast_engine.extractor import ASTExtractor
from app.ast_engine.security_scanner import SecurityScanner
from app.ast_engine.quality_analyzer import QualityAnalyzer
from app.github_integration.diff_parser import DiffParser
from app.github_integration.github_client import GitHubClient
from app.github_integration.comment_poster import CommentPoster
from app.llm_engine.model_client import ModelClient
from app.models import PullRequest, Repository, Review, ReviewComment, Vulnerability, QualityMetric
from app.config import settings

logger = structlog.get_logger(__name__)


class ReviewPipeline:
    def __init__(self, db: Session, redis_client=None):
        self.db = db
        self.ast_extractor = ASTExtractor()
        self.security_scanner = SecurityScanner()
        self.quality_analyzer = QualityAnalyzer()
        self.diff_parser = DiffParser()
        self.gh_client = GitHubClient()
        self.comment_poster = CommentPoster(self.gh_client)
        self.model_client = ModelClient(redis_client)

    def run(self, event: dict) -> dict:
        """
        Main pipeline entry point.
        event: parsed webhook event dict from webhook_handler.parse_webhook_event()
        """
        start_total = time.time()
        logger.info("pipeline_start", repo=event["repo_full_name"], pr=event["pr_number"])

        # 1. Ensure repository exists in DB
        repo = self._get_or_create_repo(event)
        if not repo.review_enabled:
            logger.info("review_disabled", repo=repo.full_name)
            return {"status": "skipped", "reason": "review_disabled"}

        # 2. Ensure PR exists in DB
        pr = self._get_or_create_pr(repo, event)

        # 3. Create review record (pending)
        review = Review(
            pull_request_id=pr.id,
            status="running",
            trigger_event=event.get("action"),
            model_used=settings.MODEL_BACKEND,
        )
        self.db.add(review)
        self.db.commit()

        try:
            # 4. Fetch diff
            diff_text = self.gh_client.get_pr_diff(
                event["installation_id"], event["repo_full_name"], event["pr_number"]
            )
            review.diff_hash = hashlib.sha256(diff_text.encode()).hexdigest()

            if not diff_text.strip():
                review.status = "complete"
                review.total_comments = 0
                self.db.commit()
                return {"status": "complete", "comments": 0, "reason": "empty_diff"}

            # Cost and latency guard. These settings existed but were never
            # referenced, so a single huge PR could fan out into unbounded model
            # calls. Refuse the review outright rather than truncate — a partial
            # review that looks complete is worse than an honest skip.
            diff_kb = len(diff_text.encode("utf-8")) / 1024
            if diff_kb > settings.MAX_DIFF_SIZE_KB:
                logger.info("diff_too_large", kb=round(diff_kb), limit=settings.MAX_DIFF_SIZE_KB)
                review.status = "skipped"
                review.error_message = (
                    f"Diff is {diff_kb:.0f}KB, over the {settings.MAX_DIFF_SIZE_KB}KB limit."
                )
                self.db.commit()
                return {"status": "skipped", "reason": "diff_too_large", "size_kb": round(diff_kb)}

            # 5. Parse diff into files
            diff_files = self.diff_parser.parse(diff_text)
            supported = settings.supported_languages_list
            diff_files = [
                f for f in diff_files
                if f.language in supported or f.filename.endswith((".py", ".js", ".ts", ".java"))
            ]

            if len(diff_files) > settings.MAX_FILES_PER_PR:
                logger.info(
                    "too_many_files", count=len(diff_files), limit=settings.MAX_FILES_PER_PR
                )
                diff_files = diff_files[: settings.MAX_FILES_PER_PR]
                review.error_message = (
                    f"Reviewed the first {settings.MAX_FILES_PER_PR} files; "
                    "the PR changed more than that."
                )

            all_comments: list[dict] = []
            total_inference_time = 0.0

            # Findings already on the PR from an earlier push or a retried task.
            # Shared across files so one run cannot duplicate within itself either.
            posted = self.comment_poster.existing_fingerprints(
                event["installation_id"], event["repo_full_name"], event["pr_number"]
            )

            for diff_file in diff_files:
                file_comments, inference_time = self._process_file(
                    diff_file, event, pr, review, posted
                )
                all_comments.extend(file_comments)
                total_inference_time += inference_time

            # 6. Update review record
            severity_counts = self._count_severities(all_comments)
            review.status = "complete"
            review.total_comments = len(all_comments)
            review.critical_count = severity_counts.get("CRITICAL", 0)
            review.high_count = severity_counts.get("HIGH", 0)
            review.medium_count = severity_counts.get("MEDIUM", 0)
            review.low_count = severity_counts.get("LOW", 0)
            review.info_count = severity_counts.get("INFO", 0)
            review.processing_time_seconds = time.time() - start_total
            review.inference_time_seconds = total_inference_time
            review.completed_at = datetime.now(timezone.utc)
            review.model_used = settings.OPENAI_MODEL if settings.MODEL_BACKEND == "openai" else "deepseek-codereview-6.7b"
            self.db.commit()

            # 7. Post summary to GitHub
            if all_comments:
                self.comment_poster.post_summary(
                    event["installation_id"],
                    event["repo_full_name"],
                    event["pr_number"],
                    event["head_sha"],
                    all_comments,
                    review.model_used,
                    review.processing_time_seconds,
                )

            logger.info(
                "pipeline_complete",
                comments=len(all_comments),
                seconds=round(review.processing_time_seconds, 2),
            )
            return {"status": "complete", "comments": len(all_comments), "review_id": str(review.id)}

        except Exception as e:
            logger.exception("pipeline_error", error=str(e))
            review.status = "error"
            review.error_message = str(e)
            self.db.commit()
            raise

    def _process_file(
        self, diff_file, event: dict, pr, review, posted: set[str] | None = None
    ) -> tuple[list[dict], float]:
        """Process a single changed file through the full analysis pipeline."""
        code = self.diff_parser.extract_added_code(diff_file)
        if not code.strip():
            return [], 0.0

        valid_lines = self.diff_parser.get_changed_line_numbers(diff_file)

        # AST analysis
        ast_ctx = self.ast_extractor.extract(code, diff_file.language)
        security_flags = self.security_scanner.scan(ast_ctx, code)
        quality_report = self.quality_analyzer.analyze(code, ast_ctx)

        # LLM review.
        # NB: build the header as a plain string. `"\n".join(<one string>)`
        # interleaves newlines between its *characters*, which silently sent a
        # shredded header ("-\n-\n-\n \na\n/...") on every single review.
        parts = [f"--- a/{diff_file.old_filename}", f"+++ b/{diff_file.filename}"]
        prefix = {"added": "+", "deleted": "-"}
        for hunk in diff_file.hunks:
            parts.append(
                f"@@ -{hunk.old_start},{hunk.old_count} +{hunk.new_start},{hunk.new_count} @@"
            )
            for dl in hunk.lines:
                parts.append(f"{prefix.get(dl.kind, ' ')}{dl.content}")
        file_diff = "\n".join(parts)

        comments, model_name, inference_time = self.model_client.review(
            diff=file_diff,
            ast_context=ast_ctx,
            pre_flags=security_flags,
            language=diff_file.language,
        )

        # Filter comments to valid diff lines
        valid_comments = [c for c in comments if c.get("line") in valid_lines]

        # Save to DB
        db_comments = []
        for c in valid_comments:
            rc = ReviewComment(
                review_id=review.id,
                file_path=diff_file.filename,
                line_number=c.get("line"),
                severity=c.get("severity", "LOW"),
                category=c.get("category"),
                title=c.get("title"),
                explanation=c.get("explanation", ""),
                suggestion=c.get("suggestion"),
                owasp_category=c.get("owasp"),
            )
            self.db.add(rc)
            db_comments.append(rc)

            # Save critical/high as vulnerabilities
            if c.get("severity") in ("CRITICAL", "HIGH") and c.get("category") == "security":
                vuln = Vulnerability(
                    repository_id=pr.repository_id,
                    file_path=diff_file.filename,
                    line_number=c.get("line"),
                    vuln_type=c.get("owasp", "unknown"),
                    severity=c.get("severity"),
                    owasp_category=c.get("owasp"),
                    title=c.get("title"),
                    explanation=c.get("explanation"),
                    status="open",
                )
                self.db.add(vuln)

        # Save quality metrics
        qm = QualityMetric(
            review_id=review.id,
            repository_id=pr.repository_id,
            file_path=diff_file.filename,
            language=diff_file.language,
            cyclomatic_complexity=quality_report.cyclomatic_complexity,
            lines_of_code=quality_report.lines_of_code,
            comment_ratio=quality_report.comment_ratio,
            avg_function_length=quality_report.avg_function_length,
            max_function_length=quality_report.max_function_length,
            function_count=quality_report.function_count,
            overall_quality_score=quality_report.overall_quality_score,
        )
        self.db.add(qm)
        self.db.commit()

        # Post inline GitHub comments
        self.comment_poster.post_review_comments(
            event["installation_id"],
            event["repo_full_name"],
            event["pr_number"],
            event["head_sha"],
            diff_file.filename,
            valid_comments,
            valid_lines,
            already_posted=posted,
        )

        return valid_comments, inference_time

    def _get_or_create_repo(self, event: dict) -> Repository:
        repo = self.db.query(Repository).filter(
            Repository.github_repo_id == event["repo_id"]
        ).first()
        if not repo:
            repo = Repository(
                github_repo_id=event["repo_id"],
                owner=event["repo_owner"],
                name=event["repo_name"],
                full_name=event["repo_full_name"],
                installation_id=event["installation_id"],
            )
            self.db.add(repo)
            self.db.commit()
        return repo

    def _get_or_create_pr(self, repo: Repository, event: dict) -> PullRequest:
        pr = self.db.query(PullRequest).filter(
            PullRequest.github_pr_id == event["pr_id"]
        ).first()
        if not pr:
            pr = PullRequest(
                repository_id=repo.id,
                github_pr_number=event["pr_number"],
                github_pr_id=event["pr_id"],
                title=event.get("pr_title"),
                author=event.get("pr_author"),
                base_branch=event.get("base_branch"),
                head_branch=event.get("head_branch"),
            )
            self.db.add(pr)
            self.db.commit()
        return pr

    def _count_severities(self, comments: list[dict]) -> dict:
        counts: dict[str, int] = {}
        for c in comments:
            sev = c.get("severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1
        return counts
