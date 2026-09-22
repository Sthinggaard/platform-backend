"""Controlled mapping reason code on slot_instances (Step 4.1C)

Revision ID: 20260719_slot_mapping_reason_code
Revises: 20260719_observation_fields
Create Date: 2026-07-19 02:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260719_slot_mapping_reason_code"
down_revision = "20260719_observation_fields"
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
    if not _col_exists(conn, "slot_instances", "mapping_reason_code"):
        op.add_column("slot_instances", sa.Column("mapping_reason_code", sa.String(60), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "slot_instances", "mapping_reason_code"):
        op.drop_column("slot_instances", "mapping_reason_code")
