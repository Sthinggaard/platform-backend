"""CA-02 — scanner_instances.os_name / os_version / architecture

Additive, nullable: reported by the agent's own heartbeat call. Null until
the first heartbeat from an agent build that sends it.

Revision ID: f7c2d9e4a681
Revises: e1b4a09c5f37
Create Date: 2026-08-03 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "f7c2d9e4a681"
down_revision = "e1b4a09c5f37"
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
    if not _col_exists(conn, "scanner_instances", "os_name"):
        op.add_column("scanner_instances", sa.Column("os_name", sa.String(length=100), nullable=True))
    if not _col_exists(conn, "scanner_instances", "os_version"):
        op.add_column("scanner_instances", sa.Column("os_version", sa.String(length=100), nullable=True))
    if not _col_exists(conn, "scanner_instances", "architecture"):
        op.add_column("scanner_instances", sa.Column("architecture", sa.String(length=30), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "scanner_instances", "architecture"):
        op.drop_column("scanner_instances", "architecture")
    if _col_exists(conn, "scanner_instances", "os_version"):
        op.drop_column("scanner_instances", "os_version")
    if _col_exists(conn, "scanner_instances", "os_name"):
        op.drop_column("scanner_instances", "os_name")
