"""Evidence Source — at least one functioning evidence source (post-ORG-STRUCT stage)

v1 scope: file/CMDB upload and manual evidence entry (a degraded,
exception-gated path) only. Collector activation and live CMDB/cloud/
identity/security-platform integrations are deliberately out of scope for
this migration.

Revision ID: 8f3c1a92e6d4
Revises: 76f0ab784980
Create Date: 2026-07-17 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "8f3c1a92e6d4"
down_revision = "76f0ab784980"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "evidence_sources"):
        op.create_table(
            "evidence_sources",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("type", sa.String(20), nullable=False),
            sa.Column("mode", sa.String(20), nullable=False),
            sa.Column("status", sa.String(30), nullable=False, server_default="draft"),
            sa.Column(
                "owner_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
            ),
            sa.Column("connected_at", sa.DateTime(), nullable=True),
            sa.Column("first_evidence_received_at", sa.DateTime(), nullable=True),
            sa.Column("last_successful_sync_at", sa.DateTime(), nullable=True),
            sa.Column("last_attempted_sync_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_evidence_sources_org_status", "evidence_sources", ["organization_id", "status"])

    if not _table_exists(conn, "evidence_source_scopes"):
        op.create_table(
            "evidence_source_scopes",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "evidence_source_id",
                sa.String(36),
                sa.ForeignKey("evidence_sources.id", ondelete="CASCADE"),
                nullable=False,
                unique=True,
            ),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("scope_type", sa.String(30), nullable=False),
            sa.Column("organisation_unit_ids", JSONB(), nullable=True),
            sa.Column("legal_entity_ids", JSONB(), nullable=True),
            sa.Column("country_codes", JSONB(), nullable=True),
            sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
            sa.Column(
                "confirmed_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("confirmed_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )

    if not _table_exists(conn, "evidence_import_batches"):
        op.create_table(
            "evidence_import_batches",
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
            sa.Column("filename", sa.String(255), nullable=False),
            sa.Column("file_type", sa.String(10), nullable=False),
            sa.Column("checksum", sa.String(64), nullable=False),
            sa.Column("status", sa.String(30), nullable=False),
            sa.Column(
                "uploaded_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("uploaded_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("detected_columns", JSONB(), nullable=True),
            sa.Column("column_mapping", JSONB(), nullable=True),
            sa.Column("parsed_rows_json", JSONB(), nullable=True),
            sa.Column("total_rows", sa.Integer(), nullable=True),
            sa.Column("accepted_rows", sa.Integer(), nullable=True),
            sa.Column("rejected_rows", sa.Integer(), nullable=True),
            sa.Column("warning_rows", sa.Integer(), nullable=True),
            sa.Column("validation_summary", JSONB(), nullable=True),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
        )
        op.create_index(
            "ix_evidence_import_batches_source", "evidence_import_batches", ["evidence_source_id", "status"]
        )

    if not _table_exists(conn, "evidence_receipts"):
        op.create_table(
            "evidence_receipts",
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
            sa.Column(
                "evidence_import_batch_id",
                sa.String(36),
                sa.ForeignKey("evidence_import_batches.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("received_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("record_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("validation_summary", JSONB(), nullable=True),
        )
        op.create_index("ix_evidence_receipts_source", "evidence_receipts", ["evidence_source_id"])

    if not _table_exists(conn, "evidence_manual_entries"):
        op.create_table(
            "evidence_manual_entries",
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
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column(
                "entered_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("entered_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_evidence_manual_entries_source", "evidence_manual_entries", ["evidence_source_id"])

    if not _table_exists(conn, "evidence_source_exceptions"):
        op.create_table(
            "evidence_source_exceptions",
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
            sa.Column("reason_code", sa.String(30), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column(
                "approved_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("approved_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("review_at", sa.DateTime(), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        )
        op.create_index(
            "ix_evidence_source_exceptions_source", "evidence_source_exceptions", ["evidence_source_id", "status"]
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "evidence_source_exceptions"):
        op.drop_index("ix_evidence_source_exceptions_source", table_name="evidence_source_exceptions")
        op.drop_table("evidence_source_exceptions")
    if _table_exists(conn, "evidence_manual_entries"):
        op.drop_index("ix_evidence_manual_entries_source", table_name="evidence_manual_entries")
        op.drop_table("evidence_manual_entries")
    if _table_exists(conn, "evidence_receipts"):
        op.drop_index("ix_evidence_receipts_source", table_name="evidence_receipts")
        op.drop_table("evidence_receipts")
    if _table_exists(conn, "evidence_import_batches"):
        op.drop_index("ix_evidence_import_batches_source", table_name="evidence_import_batches")
        op.drop_table("evidence_import_batches")
    if _table_exists(conn, "evidence_source_scopes"):
        op.drop_table("evidence_source_scopes")
    if _table_exists(conn, "evidence_sources"):
        op.drop_index("ix_evidence_sources_org_status", table_name="evidence_sources")
        op.drop_table("evidence_sources")
