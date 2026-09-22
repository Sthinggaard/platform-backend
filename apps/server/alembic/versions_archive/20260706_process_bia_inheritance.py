"""Process-level BIA answers on value_streams

Revision ID: 20260706_process_bia_inheritance
Revises: 20260705_business_service_owner
Create Date: 2026-07-06 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "20260706_process_bia_inheritance"
down_revision = "20260705_business_service_owner"
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
    if not _col_exists(conn, "value_streams", "bia_answers"):
        op.add_column("value_streams", sa.Column("bia_answers", JSONB(), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "value_streams", "bia_answers"):
        op.drop_column("value_streams", "bia_answers")
