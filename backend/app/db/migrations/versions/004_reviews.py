"""Migration 004 — create reviews and review_comments tables."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "reviews",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("pull_request_id", UUID(as_uuid=True), sa.ForeignKey("pull_requests.id"), nullable=False),
        sa.Column("status", sa.String(50), server_default="pending"),
        sa.Column("model_used", sa.String(100), nullable=True),
        sa.Column("trigger_event", sa.String(100), nullable=True),
        sa.Column("total_comments", sa.Integer(), server_default="0"),
        sa.Column("critical_count", sa.Integer(), server_default="0"),
        sa.Column("high_count", sa.Integer(), server_default="0"),
        sa.Column("medium_count", sa.Integer(), server_default="0"),
        sa.Column("low_count", sa.Integer(), server_default="0"),
        sa.Column("info_count", sa.Integer(), server_default="0"),
        sa.Column("overall_quality_score", sa.Float(), nullable=True),
        sa.Column("total_lines_reviewed", sa.Integer(), nullable=True),
        sa.Column("processing_time_seconds", sa.Float(), nullable=True),
        sa.Column("inference_time_seconds", sa.Float(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("github_review_id", sa.BigInteger(), nullable=True),
        sa.Column("diff_hash", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_reviews_pr", "reviews", ["pull_request_id"])
    op.create_index("ix_reviews_diff_hash", "reviews", ["diff_hash"])

    op.create_table(
        "review_comments",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("review_id", UUID(as_uuid=True), sa.ForeignKey("reviews.id", ondelete="CASCADE"), nullable=False),
        sa.Column("file_path", sa.String(1000), nullable=False),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("end_line_number", sa.Integer(), nullable=True),
        sa.Column("severity", sa.String(50), nullable=False),
        sa.Column("category", sa.String(100), nullable=True),
        sa.Column("title", sa.String(300), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("suggestion", sa.Text(), nullable=True),
        sa.Column("owasp_category", sa.String(100), nullable=True),
        sa.Column("cve_reference", sa.String(100), nullable=True),
        sa.Column("is_false_positive", sa.Boolean(), server_default="false"),
        sa.Column("was_resolved", sa.Boolean(), server_default="false"),
        sa.Column("github_comment_id", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_comments_review", "review_comments", ["review_id"])
    op.create_index("ix_comments_severity", "review_comments", ["severity"])


def downgrade() -> None:
    op.drop_table("review_comments")
    op.drop_table("reviews")
