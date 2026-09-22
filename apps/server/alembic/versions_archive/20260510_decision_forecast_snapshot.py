"""Add forecast_snapshot to decision_records

Revision ID: 20260510_decision_forecast_snapshot
Revises: 20260504_business_service_appetite_configs
Create Date: 2026-05-10 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "20260510_decision_forecast_snapshot"
down_revision = "20260504_business_service_appetite_configs"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, col: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": col},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _col_exists(conn, "decision_records", "forecast_snapshot"):
        op.add_column("decision_records", sa.Column("forecast_snapshot", JSONB(), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "decision_records", "forecast_snapshot"):
        op.drop_column("decision_records", "forecast_snapshot")
