"""CA-04.6 — ProcessScannerLink: one ScannerInstance linkable to many
Business Processes (ValueStreams), each link independently pausable/
revocable. Additive to RISKLENCE-79's existing single-service
EvidenceSource.business_service_id scoping, which is untouched.

Revision ID: 188df85449d4
Revises: 482a3e8d9561
Create Date: 2026-08-04 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "188df85449d4"
down_revision = "482a3e8d9561"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "process_scanner_links"):
        op.create_table(
            "process_scanner_links",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "scanner_instance_id",
                sa.String(36),
                sa.ForeignKey("scanner_instances.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "business_process_id",
                sa.String(36),
                sa.ForeignKey("value_streams.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "business_service_id",
                sa.String(36),
                sa.ForeignKey("business_services.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("status", sa.String(20), nullable=False, server_default="active"),
            sa.Column(
                "linked_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
            ),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("paused_at", sa.DateTime(), nullable=True),
            sa.Column("revoked_at", sa.DateTime(), nullable=True),
            sa.Column(
                "revoked_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
            ),
        )
        op.create_index(
            "ix_process_scanner_links_instance", "process_scanner_links", ["scanner_instance_id", "status"]
        )
        op.create_index(
            "ix_process_scanner_links_process", "process_scanner_links", ["business_process_id", "status"]
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "process_scanner_links"):
        op.drop_index("ix_process_scanner_links_process", table_name="process_scanner_links")
        op.drop_index("ix_process_scanner_links_instance", table_name="process_scanner_links")
        op.drop_table("process_scanner_links")
