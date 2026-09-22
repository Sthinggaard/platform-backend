"""Step 4.2 Part 2 — link ScannerCommand to a delegated ProviderExecution

Additive, nullable column: NULL means "Step 4.1's original whole-run
command" (unchanged behaviour), set means "this command was issued on
behalf of one delegated ProviderExecution job." Lives on ScannerCommand
(the child) rather than on ProviderExecution, mirroring why DiscoveryRun
itself carries no command_id column — see discovery_run.py's own
docstring. See TASKS.md DISC-20.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-07-22 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "b2c3d4e5f6a7"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, col: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"),
        {"t": table, "c": col},
    ).fetchone() is not None


def _index_exists(conn, index_name: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname=:i"),
        {"i": index_name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _col_exists(conn, "scanner_commands", "provider_execution_id"):
        op.add_column(
            "scanner_commands",
            sa.Column(
                "provider_execution_id",
                sa.String(36),
                sa.ForeignKey("provider_executions.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )
    if not _index_exists(conn, "ix_scanner_commands_provider_execution"):
        op.create_index(
            "ix_scanner_commands_provider_execution", "scanner_commands", ["provider_execution_id"]
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _index_exists(conn, "ix_scanner_commands_provider_execution"):
        op.drop_index("ix_scanner_commands_provider_execution", table_name="scanner_commands")
    if _col_exists(conn, "scanner_commands", "provider_execution_id"):
        op.drop_column("scanner_commands", "provider_execution_id")
