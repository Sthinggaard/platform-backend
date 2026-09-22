"""DISC-44 — users.access_expires_at (consultant-assisted access)

Additive column: null means "never expires." The invite route enforces
that a role=consultant invite always sets this; no DB constraint (matches
this codebase's existing application-level-only enforcement convention).

Revision ID: 20260726_user_access_expires_at
Revises: 20260725_fix_asset_lifecycle_state_casing
Create Date: 2026-07-26 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260726_user_access_expires_at"
down_revision = "20260725_fix_asset_lifecycle_state_casing"
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
    if not _col_exists(conn, "users", "access_expires_at"):
        op.add_column("users", sa.Column("access_expires_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "users", "access_expires_at"):
        op.drop_column("users", "access_expires_at")
