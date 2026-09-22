"""scanner_credentials.validity_custom_days

Records the caller-supplied day count for validity_policy="custom" so a
later rotate can offer "keep the same duration" (re-applied from the
rotation moment) without re-deriving a day count from timestamps.

Revision ID: a52dba017ea6
Revises: d248704fc69c
Create Date: 2026-08-02 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "a52dba017ea6"
down_revision = "d248704fc69c"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, col: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"),
        {"t": table, "c": col},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _col_exists(conn, "scanner_credentials", "validity_custom_days"):
        op.add_column("scanner_credentials", sa.Column("validity_custom_days", sa.Integer(), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "scanner_credentials", "validity_custom_days"):
        op.drop_column("scanner_credentials", "validity_custom_days")
