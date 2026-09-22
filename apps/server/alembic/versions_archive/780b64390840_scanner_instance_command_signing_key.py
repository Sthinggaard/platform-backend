"""CA-04.1 — scanner_instances.command_signing_key_encrypted

Additive, nullable: the Fernet-encrypted, HKDF-derived per-instance command
signing key (src/core/crypto.py). Null for any instance that has not been
(re)activated since this shipped — signature verification for those falls
back to the legacy shared-secret path until their next activation/rotation.

Revision ID: 780b64390840
Revises: f7c2d9e4a681
Create Date: 2026-08-03 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "780b64390840"
down_revision = "f7c2d9e4a681"
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
    if not _col_exists(conn, "scanner_instances", "command_signing_key_encrypted"):
        op.add_column(
            "scanner_instances", sa.Column("command_signing_key_encrypted", sa.LargeBinary(), nullable=True)
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "scanner_instances", "command_signing_key_encrypted"):
        op.drop_column("scanner_instances", "command_signing_key_encrypted")
