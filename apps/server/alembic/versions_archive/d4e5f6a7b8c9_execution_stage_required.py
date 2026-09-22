"""Step 4.2 Part 2 (DISC-30) — required/optional stages

Additive, non-nullable column with a server_default so existing rows
backfill to required=True — every stage generated before this ticket was
implicitly required, so this is a zero-behavior-change migration on its
own; DISC-30's own code changes are what start reading it. See
tasks/active/DISC-26-execution-engine-reconciliation.md.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-07-24 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "d4e5f6a7b8c9"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, col: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"),
        {"t": table, "c": col},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _col_exists(conn, "execution_stages", "required"):
        op.add_column(
            "execution_stages",
            sa.Column("required", sa.Boolean(), nullable=False, server_default=sa.true()),
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "execution_stages", "required"):
        op.drop_column("execution_stages", "required")
