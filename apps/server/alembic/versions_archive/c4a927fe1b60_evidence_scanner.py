"""Risklence Scanner setup — Step 3.5 (configure and validate the scanner)

v1 scope: scanner domain/network targets and one scanner instance per
scanner evidence source. Tool execution (Nmap/Subfinder/Nuclei) and scan
result ingestion are deliberately not modelled here — see
src/core/constants/evidence_scanner_enums.py for the scope note.

Revision ID: c4a927fe1b60
Revises: 8f3c1a92e6d4
Create Date: 2026-07-17 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "c4a927fe1b60"
down_revision = "8f3c1a92e6d4"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "scanner_domain_targets"):
        op.create_table(
            "scanner_domain_targets",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "evidence_source_id",
                sa.String(36),
                sa.ForeignKey("evidence_sources.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("domain", sa.String(255), nullable=False),
            sa.Column("source", sa.String(30), nullable=False),
            sa.Column("ownership_status", sa.String(30), nullable=False),
            sa.Column("scan_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("include_subdomains", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
            sa.Column(
                "approved_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
            ),
            sa.Column("approved_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "ix_scanner_domain_targets_source", "scanner_domain_targets", ["evidence_source_id", "status"]
        )

    if not _table_exists(conn, "scanner_network_targets"):
        op.create_table(
            "scanner_network_targets",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "evidence_source_id",
                sa.String(36),
                sa.ForeignKey("evidence_sources.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("cidr", sa.String(50), nullable=False),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column(
                "organisation_unit_id",
                sa.String(36),
                sa.ForeignKey("organization_units.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "location_id",
                sa.String(36),
                sa.ForeignKey("organization_locations.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("environment", sa.String(50), nullable=True),
            sa.Column("network_type", sa.String(20), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
            sa.Column(
                "approved_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
            ),
            sa.Column("approved_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "ix_scanner_network_targets_source", "scanner_network_targets", ["evidence_source_id", "status"]
        )

    if not _table_exists(conn, "scanner_instances"):
        op.create_table(
            "scanner_instances",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "evidence_source_id",
                sa.String(36),
                sa.ForeignKey("evidence_sources.id", ondelete="CASCADE"),
                nullable=False,
                unique=True,
            ),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("public_instance_id", sa.String(36), nullable=False),
            sa.Column("installation_method", sa.String(30), nullable=False),
            sa.Column("scanner_version", sa.String(50), nullable=True),
            sa.Column("configuration_version", sa.String(50), nullable=True),
            sa.Column("status", sa.String(20), nullable=False, server_default="registered"),
            sa.Column("activation_token_hash", sa.String(64), nullable=False),
            sa.Column("activated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("activation_revoked_at", sa.DateTime(), nullable=True),
            sa.Column("scan_profile", sa.String(30), nullable=True),
            sa.Column("tool_status", JSONB(), nullable=True),
            sa.Column("tool_validation_at", sa.DateTime(), nullable=True),
            sa.Column("connection_verified_at", sa.DateTime(), nullable=True),
            sa.Column("test_scan_status", sa.String(30), nullable=True),
            sa.Column("test_scan_completed_at", sa.DateTime(), nullable=True),
            sa.Column(
                "scope_confirmed_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("scope_confirmed_at", sa.DateTime(), nullable=True),
            sa.Column("registered_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("last_heartbeat_at", sa.DateTime(), nullable=True),
            sa.Column("last_successful_connection_at", sa.DateTime(), nullable=True),
            sa.Column("last_scan_at", sa.DateTime(), nullable=True),
        )
        op.create_index("ix_scanner_instances_source", "scanner_instances", ["evidence_source_id"], unique=True)


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "scanner_instances"):
        op.drop_index("ix_scanner_instances_source", table_name="scanner_instances")
        op.drop_table("scanner_instances")
    if _table_exists(conn, "scanner_network_targets"):
        op.drop_index("ix_scanner_network_targets_source", table_name="scanner_network_targets")
        op.drop_table("scanner_network_targets")
    if _table_exists(conn, "scanner_domain_targets"):
        op.drop_index("ix_scanner_domain_targets_source", table_name="scanner_domain_targets")
        op.drop_table("scanner_domain_targets")
