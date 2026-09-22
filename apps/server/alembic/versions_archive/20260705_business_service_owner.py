"""Accountable owner on business_services

Revision ID: 20260705_business_service_owner
Revises: 20260705_slot_mapping_lifecycle
Create Date: 2026-07-05 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260705_business_service_owner"
down_revision = "20260705_slot_mapping_lifecycle"
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
    if not _col_exists(conn, "business_services", "owner_user_id"):
        op.add_column(
            "business_services",
            sa.Column("owner_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        )
    if not _col_exists(conn, "business_services", "owner_source"):
        op.add_column("business_services", sa.Column("owner_source", sa.String(20), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "business_services", "owner_source"):
        op.drop_column("business_services", "owner_source")
    if _col_exists(conn, "business_services", "owner_user_id"):
        op.drop_column("business_services", "owner_user_id")
