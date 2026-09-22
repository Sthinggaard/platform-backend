"""Slot mapping lifecycle fields on slot_instances

Revision ID: 20260705_slot_mapping_lifecycle
Revises: 20260705_business_service_profiles
Create Date: 2026-07-05 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260705_slot_mapping_lifecycle"
down_revision = "20260705_business_service_profiles"
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


COLUMNS: list[sa.Column] = [
    sa.Column("mapping_status", sa.String(20), nullable=False, server_default="approved"),
    sa.Column("mapping_confidence", sa.Float(), nullable=True),
    sa.Column("evidence_source", sa.String(30), nullable=True),
    sa.Column("mapping_reason", sa.Text(), nullable=True),
    sa.Column("provenance", sa.String(30), nullable=True),
    sa.Column("decided_by", sa.String(120), nullable=True),
    sa.Column("decided_at", sa.DateTime(), nullable=True),
]


def upgrade() -> None:
    conn = op.get_bind()
    for column in COLUMNS:
        if not _col_exists(conn, "slot_instances", column.name):
            op.add_column("slot_instances", column.copy())

    # Existing rows were created by the human slot-mapping wizard: mark the
    # resolved ones owner-approved so provenance is not silently blank.
    conn.execute(
        sa.text(
            "UPDATE slot_instances SET provenance = 'owner_approved', mapping_confidence = 1.0 "
            "WHERE status IN ('mapped', 'not_applicable') AND provenance IS NULL"
        )
    )
    conn.execute(
        sa.text(
            "UPDATE slot_instances SET mapping_status = 'needs_review' "
            "WHERE status = 'unknown' AND mapping_status = 'approved'"
        )
    )


def downgrade() -> None:
    conn = op.get_bind()
    for column in COLUMNS:
        if _col_exists(conn, "slot_instances", column.name):
            op.drop_column("slot_instances", column.name)
