"""Migration 003 — create pull_requests table."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "pull_requests",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("repository_id", UUID(as_uuid=True), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("github_pr_number", sa.Integer(), nullable=False),
        sa.Column("github_pr_id", sa.BigInteger(), unique=True, nullable=False),
        sa.Column("title", sa.String(500), nullable=True),
        sa.Column("author", sa.String(200), nullable=True),
        sa.Column("base_branch", sa.String(200), nullable=True),
        sa.Column("head_branch", sa.String(200), nullable=True),
        sa.Column("status", sa.String(50), server_default="open"),
        sa.Column("files_changed", sa.Integer(), nullable=True),
        sa.Column("lines_added", sa.Integer(), nullable=True),
        sa.Column("lines_deleted", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("repository_id", "github_pr_number"),
    )


def downgrade() -> None:
    op.drop_table("pull_requests")
