"""CA-04.7 — process-aware execution context: nullable business_process_id/
business_service_id on discovery_runs (plus unused-until-CA-10
process_scan_scope_id/process_scan_scope_revision placeholders) and on
scanner_commands (snapshotted at command-creation time, threaded into the
signed job envelope).

Revision ID: 226fe5c79ac5
Revises: 188df85449d4
Create Date: 2026-08-04 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "226fe5c79ac5"
down_revision = "188df85449d4"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, column: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"),
        {"t": table, "c": column},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _col_exists(conn, "discovery_runs", "business_process_id"):
        op.add_column(
            "discovery_runs",
            sa.Column(
                "business_process_id",
                sa.String(36),
                sa.ForeignKey("value_streams.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )
    if not _col_exists(conn, "discovery_runs", "business_service_id"):
        op.add_column(
            "discovery_runs",
            sa.Column(
                "business_service_id",
                sa.String(36),
                sa.ForeignKey("business_services.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )
    if not _col_exists(conn, "discovery_runs", "process_scan_scope_id"):
        op.add_column("discovery_runs", sa.Column("process_scan_scope_id", sa.String(36), nullable=True))
    if not _col_exists(conn, "discovery_runs", "process_scan_scope_revision"):
        op.add_column("discovery_runs", sa.Column("process_scan_scope_revision", sa.Integer(), nullable=True))

    if not _col_exists(conn, "scanner_commands", "business_process_id"):
        op.add_column(
            "scanner_commands",
            sa.Column(
                "business_process_id",
                sa.String(36),
                sa.ForeignKey("value_streams.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )
    if not _col_exists(conn, "scanner_commands", "business_service_id"):
        op.add_column(
            "scanner_commands",
            sa.Column(
                "business_service_id",
                sa.String(36),
                sa.ForeignKey("business_services.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "scanner_commands", "business_service_id"):
        op.drop_column("scanner_commands", "business_service_id")
    if _col_exists(conn, "scanner_commands", "business_process_id"):
        op.drop_column("scanner_commands", "business_process_id")
    if _col_exists(conn, "discovery_runs", "process_scan_scope_revision"):
        op.drop_column("discovery_runs", "process_scan_scope_revision")
    if _col_exists(conn, "discovery_runs", "process_scan_scope_id"):
        op.drop_column("discovery_runs", "process_scan_scope_id")
    if _col_exists(conn, "discovery_runs", "business_service_id"):
        op.drop_column("discovery_runs", "business_service_id")
    if _col_exists(conn, "discovery_runs", "business_process_id"):
        op.drop_column("discovery_runs", "business_process_id")
