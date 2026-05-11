"""Migration 002 — create repositories table."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repositories",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("github_repo_id", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("owner", sa.String(200), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("full_name", sa.String(500), nullable=False),
        sa.Column("installation_id", sa.BigInteger(), nullable=False),
        sa.Column("default_branch", sa.String(100), server_default="main"),
        sa.Column("language", sa.String(100), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column("review_enabled", sa.Boolean(), server_default="true"),
        sa.Column("security_scan_enabled", sa.Boolean(), server_default="true"),
        sa.Column("added_by", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("repositories")
