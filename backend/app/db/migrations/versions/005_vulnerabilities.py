"""Migration 005 — create vulnerabilities and quality_metrics tables."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vulnerabilities",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("repository_id", UUID(as_uuid=True), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("review_comment_id", UUID(as_uuid=True), sa.ForeignKey("review_comments.id"), nullable=True),
        sa.Column("file_path", sa.String(1000), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("vuln_type", sa.String(200), nullable=True),
        sa.Column("severity", sa.String(50), nullable=True),
        sa.Column("owasp_category", sa.String(100), nullable=True),
        sa.Column("title", sa.String(300), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("status", sa.String(50), server_default="open"),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_vulns_repo", "vulnerabilities", ["repository_id"])
    op.create_index("ix_vulns_status", "vulnerabilities", ["status"])

    op.create_table(
        "quality_metrics",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("review_id", UUID(as_uuid=True), sa.ForeignKey("reviews.id"), nullable=False),
        sa.Column("repository_id", UUID(as_uuid=True), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("file_path", sa.String(1000), nullable=True),
        sa.Column("language", sa.String(50), nullable=True),
        sa.Column("cyclomatic_complexity", sa.Float(), nullable=True),
        sa.Column("cognitive_complexity", sa.Float(), nullable=True),
        sa.Column("lines_of_code", sa.Integer(), nullable=True),
        sa.Column("comment_ratio", sa.Float(), nullable=True),
        sa.Column("duplication_score", sa.Float(), nullable=True),
        sa.Column("avg_function_length", sa.Float(), nullable=True),
        sa.Column("max_function_length", sa.Integer(), nullable=True),
        sa.Column("function_count", sa.Integer(), nullable=True),
        sa.Column("overall_quality_score", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("quality_metrics")
    op.drop_table("vulnerabilities")
