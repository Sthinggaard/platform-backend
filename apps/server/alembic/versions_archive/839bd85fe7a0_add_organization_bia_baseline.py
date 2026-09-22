"""Add the auditable organisation-wide Business Impact Assessment baseline.

Guarded so it is idempotent: re-running against a database that already carries
the table (a partially-applied deploy, a re-run upgrade) is a no-op rather than
a ``DuplicateTable`` that aborts the deploy mid-chain.

Revision ID: 839bd85fe7a0
Revises: a71c9e40b552
Create Date: 2026-08-28 11:28:20.449461
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "839bd85fe7a0"
down_revision = "a71c9e40b552"
branch_labels = None
depends_on = None

_TABLE = "organization_bia_baselines"
_INDEX = "ix_organization_bia_baselines_org_status"


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def _index_exists(conn, index_name: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname=:i"),
        {"i": index_name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, _TABLE):
        op.create_table(
            _TABLE,
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("organization_id", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(length=30), nullable=False),
            sa.Column("answers", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("source", sa.String(length=80), nullable=False),
            sa.Column("confidence", sa.String(length=20), nullable=False),
            sa.Column("assumption_state", sa.String(length=30), nullable=False),
            sa.Column("set_by_user_id", sa.Integer(), nullable=True),
            sa.Column("set_at", sa.DateTime(), nullable=False),
            sa.Column("superseded_by_id", sa.String(length=36), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["set_by_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(
                ["superseded_by_id"], [f"{_TABLE}.id"], ondelete="SET NULL"
            ),
            sa.PrimaryKeyConstraint("id"),
        )

    if not _index_exists(conn, _INDEX):
        op.create_index(
            _INDEX,
            _TABLE,
            ["organization_id", "status"],
            unique=False,
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _index_exists(conn, _INDEX):
        op.drop_index(_INDEX, table_name=_TABLE)
    if _table_exists(conn, _TABLE):
        op.drop_table(_TABLE)
