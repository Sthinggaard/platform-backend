"""Add alternative category to resolution records

Revision ID: 20250425_resolution_alternative_category
Revises: 20250421_learning_loop_foundation
Create Date: 2026-04-25 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20250425_resolution_alternative_category"
down_revision = "20250421_learning_loop_foundation"
branch_labels = None
depends_on = None


def _column_exists(conn, table_name: str, column_name: str) -> bool:
    return conn.execute(
        sa.text(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_name = :table_name
              AND column_name = :column_name
            """
        ),
        {"table_name": table_name, "column_name": column_name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _column_exists(conn, "resolution_records", "alternative_category"):
        op.add_column("resolution_records", sa.Column("alternative_category", sa.String(40), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if _column_exists(conn, "resolution_records", "alternative_category"):
        op.drop_column("resolution_records", "alternative_category")
