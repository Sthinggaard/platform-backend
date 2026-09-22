"""value_stream_signals.user_id nullable — engine-initiated signals (BSP-14)

Revision ID: 20260711_signal_system_actor
Revises: 20260711_baseline_risk_hypothesis
Create Date: 2026-07-11 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260711_signal_system_actor"
down_revision = "20260711_baseline_risk_hypothesis"
branch_labels = None
depends_on = None


def _col_nullable(conn, table: str, col: str) -> bool:
    row = conn.execute(
        sa.text(
            "SELECT is_nullable FROM information_schema.columns "
            "WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": col},
    ).fetchone()
    return row is not None and row[0] == "YES"


def upgrade() -> None:
    conn = op.get_bind()
    if not _col_nullable(conn, "value_stream_signals", "user_id"):
        op.alter_column("value_stream_signals", "user_id", existing_type=sa.Integer(), nullable=True)


def downgrade() -> None:
    conn = op.get_bind()
    if _col_nullable(conn, "value_stream_signals", "user_id"):
        op.alter_column("value_stream_signals", "user_id", existing_type=sa.Integer(), nullable=False)
