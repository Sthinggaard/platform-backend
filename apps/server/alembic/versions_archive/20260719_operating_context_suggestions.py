"""Append-only organisation operating-context suggestions.

Revision ID: 20260719_operating_context_suggestions
Revises: f1a2b3c4d5e6
Create Date: 2026-07-19 14:30:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260719_operating_context_suggestions"
down_revision = "f1a2b3c4d5e6"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"), {"t": table}
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "organization_operating_context_suggestions"):
        return
    op.create_table(
        "organization_operating_context_suggestions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("suggestion_type", sa.String(40), nullable=False),
        sa.Column("suggestion_key", sa.String(100), nullable=False),
        sa.Column("source_type", sa.String(40), nullable=False),
        sa.Column("source_reference", sa.String(100), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("decided_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        sa.Column("superseded_by_id", sa.String(36), sa.ForeignKey("organization_operating_context_suggestions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_organization_operating_context_org_current",
        "organization_operating_context_suggestions",
        ["organization_id", "superseded_by_id"],
    )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "organization_operating_context_suggestions"):
        op.drop_index("ix_organization_operating_context_org_current", table_name="organization_operating_context_suggestions")
        op.drop_table("organization_operating_context_suggestions")
