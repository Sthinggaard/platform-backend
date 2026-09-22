"""Evidence Source — freshness policy columns (spec §13)

Adds warning_after_hours/stale_after_hours to evidence_sources — null
means "use the type-based default" (see DEFAULT_FRESHNESS_*_AFTER_HOURS in
evidence_source_enums.py), never a fabricated value.

Revision ID: e8f1a4b2c3d5
Revises: c4a927fe1b60
Create Date: 2026-07-17 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "e8f1a4b2c3d5"
down_revision = "c4a927fe1b60"
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
    if not _col_exists(conn, "evidence_sources", "warning_after_hours"):
        op.add_column("evidence_sources", sa.Column("warning_after_hours", sa.Integer(), nullable=True))
    if not _col_exists(conn, "evidence_sources", "stale_after_hours"):
        op.add_column("evidence_sources", sa.Column("stale_after_hours", sa.Integer(), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "evidence_sources", "stale_after_hours"):
        op.drop_column("evidence_sources", "stale_after_hours")
    if _col_exists(conn, "evidence_sources", "warning_after_hours"):
        op.drop_column("evidence_sources", "warning_after_hours")
