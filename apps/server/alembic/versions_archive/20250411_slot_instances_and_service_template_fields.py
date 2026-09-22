"""Add slot_instances table and template_key/template_version to business_services

Revision ID: 20250411_slot_instances_and_service_template_fields
Revises: 20250410_template_library_foundation
Create Date: 2026-04-11 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

revision = "20250411_slot_instances_and_service_template_fields"
down_revision = "20250410_template_library_foundation"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, col: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": col},
    ).fetchone() is not None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name=:t"
        ),
        {"t": table},
    ).fetchone() is not None


def _index_exists(conn, index_name: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :i"),
        {"i": index_name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    # ── template_key / template_version on business_services ─────────────────
    if not _col_exists(conn, "business_services", "template_key"):
        op.add_column(
            "business_services",
            sa.Column("template_key", sa.String(100), nullable=True),
        )

    if not _col_exists(conn, "business_services", "template_version"):
        op.add_column(
            "business_services",
            sa.Column("template_version", sa.Integer(), nullable=True),
        )

    # ── group_key on dependency_bundle_audit_log ──────────────────────────────
    # Added when slot mapping audit log support was introduced.
    if _table_exists(conn, "dependency_bundle_audit_log") and not _col_exists(
        conn, "dependency_bundle_audit_log", "group_key"
    ):
        op.add_column(
            "dependency_bundle_audit_log",
            sa.Column("group_key", sa.String(50), nullable=True),
        )

    # ── org_process_configs table ─────────────────────────────────────────────
    if not _table_exists(conn, "org_process_configs"):
        op.create_table(
            "org_process_configs",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("template_key", sa.String(100), nullable=False),
            sa.Column("excluded_service_keys", ARRAY(sa.String()), nullable=False, server_default="{}"),
            sa.Column("custom_service_slots", JSONB(), nullable=False, server_default="[]"),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column("created_by", sa.String(255), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint(
                "organization_id", "template_key", name="uq_org_process_configs_org_key"
            ),
        )
        op.create_index("ix_org_process_configs_org", "org_process_configs", ["organization_id"])

    # ── org_service_configs table ─────────────────────────────────────────────
    if not _table_exists(conn, "org_service_configs"):
        op.create_table(
            "org_service_configs",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("service_key", sa.String(100), nullable=False),
            sa.Column("excluded_group_keys", ARRAY(sa.String()), nullable=False, server_default="{}"),
            sa.Column("custom_groups", JSONB(), nullable=False, server_default="[]"),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column("created_by", sa.String(255), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint(
                "organization_id", "service_key", name="uq_org_service_configs_org_key"
            ),
        )
        op.create_index("ix_org_service_configs_org", "org_service_configs", ["organization_id"])

    # ── slot_instances table ──────────────────────────────────────────────────
    if not _table_exists(conn, "slot_instances"):
        op.create_table(
            "slot_instances",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "service_id",
                sa.String(36),
                sa.ForeignKey("business_services.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("slot_id", sa.String(100), nullable=False),
            sa.Column("template_version", sa.Integer(), nullable=True),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("asset_id", sa.String(36), nullable=True),
            sa.Column("asset_label", sa.String(255), nullable=True),
            sa.Column("group_key", sa.String(100), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.UniqueConstraint(
                "organization_id",
                "service_id",
                "slot_id",
                name="uq_slot_instances_org_service_slot",
            ),
        )

    if not _index_exists(conn, "ix_slot_instances_org"):
        op.create_index(
            "ix_slot_instances_org", "slot_instances", ["organization_id"]
        )

    if not _index_exists(conn, "ix_slot_instances_service"):
        op.create_index(
            "ix_slot_instances_service", "slot_instances", ["service_id"]
        )

    if not _index_exists(conn, "ix_slot_instances_slot"):
        op.create_index(
            "ix_slot_instances_slot", "slot_instances", ["slot_id"]
        )


def downgrade() -> None:
    conn = op.get_bind()

    if _table_exists(conn, "slot_instances"):
        op.drop_table("slot_instances")

    if _table_exists(conn, "org_service_configs"):
        op.drop_table("org_service_configs")

    if _table_exists(conn, "org_process_configs"):
        op.drop_table("org_process_configs")

    if _col_exists(conn, "business_services", "template_version"):
        op.drop_column("business_services", "template_version")

    if _col_exists(conn, "business_services", "template_key"):
        op.drop_column("business_services", "template_key")
