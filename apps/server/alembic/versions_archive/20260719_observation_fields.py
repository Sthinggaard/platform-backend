"""Structured observation fields on asset_evidence_signals (Step 4.1B)

Revision ID: 20260719_observation_fields
Revises: 20260719_asset_identity_lifecycle
Create Date: 2026-07-19 01:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260719_observation_fields"
down_revision = "20260719_asset_identity_lifecycle"
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
    sa.Column("observation_type", sa.String(60), nullable=True),
    sa.Column("status", sa.String(20), nullable=True),
    # Reuses the existing SeverityLevel values (critical/high/medium/low/info)
    # rather than inventing a parallel severity vocabulary — no DB-level enum
    # to keep this additive, matching AssetEvidenceSignal.kind's own String
    # column precedent.
    sa.Column("severity", sa.String(20), nullable=True),
]


def upgrade() -> None:
    conn = op.get_bind()
    for column in COLUMNS:
        if not _col_exists(conn, "asset_evidence_signals", column.name):
            op.add_column("asset_evidence_signals", column.copy())


def downgrade() -> None:
    conn = op.get_bind()
    for column in COLUMNS:
        if _col_exists(conn, "asset_evidence_signals", column.name):
            op.drop_column("asset_evidence_signals", column.name)
