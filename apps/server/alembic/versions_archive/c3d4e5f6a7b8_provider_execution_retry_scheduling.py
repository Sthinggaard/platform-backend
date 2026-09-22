"""Step 4.2 Part 2 (DISC-27/28) — retry scheduling on ProviderExecution

Additive, nullable column: next_retry_at is set only when a job's
status is retry_scheduled (a new ProviderExecutionStatus value, no schema
change needed for the string column itself). See TASKS.md DISC-26's
reconciliation and DISC-27/28.

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-07-23 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "c3d4e5f6a7b8"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, col: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"),
        {"t": table, "c": col},
    ).fetchone() is not None


def _index_exists(conn, index_name: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname=:i"),
        {"i": index_name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _col_exists(conn, "provider_executions", "next_retry_at"):
        op.add_column("provider_executions", sa.Column("next_retry_at", sa.DateTime(), nullable=True))
    if not _index_exists(conn, "ix_provider_executions_status_next_retry_at"):
        op.create_index(
            "ix_provider_executions_status_next_retry_at", "provider_executions", ["status", "next_retry_at"]
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _index_exists(conn, "ix_provider_executions_status_next_retry_at"):
        op.drop_index("ix_provider_executions_status_next_retry_at", table_name="provider_executions")
    if _col_exists(conn, "provider_executions", "next_retry_at"):
        op.drop_column("provider_executions", "next_retry_at")
