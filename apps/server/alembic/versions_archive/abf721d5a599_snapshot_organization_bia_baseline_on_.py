"""Snapshot the organisation BIA baseline on activation.

Guarded so it is idempotent: re-running against a database that already carries
the column is a no-op rather than a ``DuplicateColumn`` that aborts the deploy
mid-chain.

Revision ID: abf721d5a599
Revises: 839bd85fe7a0
Create Date: 2026-08-29 07:50:18.724523
"""

import sqlalchemy as sa

from alembic import op

revision = "abf721d5a599"
down_revision = "839bd85fe7a0"
branch_labels = None
depends_on = None

_TABLE = "business_process_activations"
_COLUMN = "activated_organization_bia_baseline_id"


def _col_exists(conn) -> bool:
    row = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :table AND column_name = :column"
        ),
        {"table": _TABLE, "column": _COLUMN},
    ).first()
    return row is not None


def upgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn):
        return
    op.add_column(
        _TABLE,
        sa.Column(_COLUMN, sa.String(length=36), nullable=True),
    )


def downgrade() -> None:
    conn = op.get_bind()
    if not _col_exists(conn):
        return
    op.drop_column(_TABLE, _COLUMN)
