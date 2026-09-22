"""DISC-46 — discovery_runs.cancellation_reason_code / cancellation_reason_note

Additive, both nullable: a cancellation reason is optional, and existing
cancelled runs simply have neither. Enum validation (DiscoveryCancellationReasonCode)
and the "OTHER requires a note" rule are application-level only, matching
this codebase's existing convention (no DB constraint).

Revision ID: 20260726_discovery_run_cancellation_reason
Revises: 20260726_user_access_expires_at
Create Date: 2026-07-26 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260726_discovery_run_cancellation_reason"
down_revision = "20260726_user_access_expires_at"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, column: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": column},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _col_exists(conn, "discovery_runs", "cancellation_reason_code"):
        op.add_column("discovery_runs", sa.Column("cancellation_reason_code", sa.String(length=40), nullable=True))
    if not _col_exists(conn, "discovery_runs", "cancellation_reason_note"):
        op.add_column("discovery_runs", sa.Column("cancellation_reason_note", sa.Text(), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "discovery_runs", "cancellation_reason_note"):
        op.drop_column("discovery_runs", "cancellation_reason_note")
    if _col_exists(conn, "discovery_runs", "cancellation_reason_code"):
        op.drop_column("discovery_runs", "cancellation_reason_code")
