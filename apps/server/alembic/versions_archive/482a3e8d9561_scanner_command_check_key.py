"""CA-04.2 — scanner_commands.check_key

Additive, nullable: the registered CheckKey a command represents (nmap
today). NULL for a Step 4.1 whole-run command and for any pre-existing row.

Revision ID: 482a3e8d9561
Revises: 780b64390840
Create Date: 2026-08-04 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "482a3e8d9561"
down_revision = "780b64390840"
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
    if not _col_exists(conn, "scanner_commands", "check_key"):
        op.add_column("scanner_commands", sa.Column("check_key", sa.String(length=30), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "scanner_commands", "check_key"):
        op.drop_column("scanner_commands", "check_key")
