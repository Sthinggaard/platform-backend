"""add persisted template library foundation

Revision ID: 20250410_template_library_foundation
Revises: 20250408_value_stream_signals
Create Date: 2026-04-10 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

from sqlalchemy.dialects.postgresql import JSONB


revision = "20250410_template_library_foundation"
down_revision = "20250408_value_stream_signals"
branch_labels = None
depends_on = None


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

    if not _table_exists(conn, "process_templates"):
        op.create_table(
            "process_templates",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("template_key", sa.String(length=100), nullable=False),
            sa.Column("name", sa.String(length=200), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("process_family", sa.String(length=50), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="published"),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("service_slots", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("template_key", "version", name="uq_process_templates_key_version"),
        )

    if not _index_exists(conn, "ix_process_templates_key_active"):
        op.create_index(
            "ix_process_templates_key_active",
            "process_templates",
            ["template_key", "is_active"],
            unique=False,
        )
    if not _index_exists(conn, "ix_process_templates_family_active"):
        op.create_index(
            "ix_process_templates_family_active",
            "process_templates",
            ["process_family", "is_active"],
            unique=False,
        )

    if not _table_exists(conn, "service_templates"):
        op.create_table(
            "service_templates",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("service_key", sa.String(length=100), nullable=False),
            sa.Column("service_name", sa.String(length=200), nullable=False),
            sa.Column("archetype", sa.String(length=100), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="published"),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("capability_groups", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("seeded_from", sa.String(length=100), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("service_key", "version", name="uq_service_templates_key_version"),
        )

    if not _index_exists(conn, "ix_service_templates_key_active"):
        op.create_index(
            "ix_service_templates_key_active",
            "service_templates",
            ["service_key", "is_active"],
            unique=False,
        )
    if not _index_exists(conn, "ix_service_templates_archetype_active"):
        op.create_index(
            "ix_service_templates_archetype_active",
            "service_templates",
            ["archetype", "is_active"],
            unique=False,
        )

    if not _table_exists(conn, "slot_templates"):
        op.create_table(
            "slot_templates",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("service_template_id", sa.String(length=36), nullable=False),
            sa.Column("slot_id", sa.String(length=100), nullable=False),
            sa.Column("label", sa.String(length=200), nullable=False),
            sa.Column("purpose", sa.Text(), nullable=False),
            sa.Column("expected_asset_types", sa.ARRAY(sa.String(length=100)), nullable=False, server_default="{}"),
            sa.Column("required", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("capability_group_key", sa.String(length=100), nullable=False),
            sa.Column("display_order", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.ForeignKeyConstraint(["service_template_id"], ["service_templates.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("service_template_id", "slot_id", name="uq_slot_templates_service_slot"),
        )

    if not _index_exists(conn, "ix_slot_templates_service_template"):
        op.create_index(
            "ix_slot_templates_service_template",
            "slot_templates",
            ["service_template_id"],
            unique=False,
        )
    if not _index_exists(conn, "ix_slot_templates_slot_id"):
        op.create_index(
            "ix_slot_templates_slot_id",
            "slot_templates",
            ["slot_id"],
            unique=False,
        )


def downgrade() -> None:
    op.drop_index("ix_slot_templates_slot_id", table_name="slot_templates")
    op.drop_index("ix_slot_templates_service_template", table_name="slot_templates")
    op.drop_table("slot_templates")
    op.drop_index("ix_service_templates_archetype_active", table_name="service_templates")
    op.drop_index("ix_service_templates_key_active", table_name="service_templates")
    op.drop_table("service_templates")
    op.drop_index("ix_process_templates_family_active", table_name="process_templates")
    op.drop_index("ix_process_templates_key_active", table_name="process_templates")
    op.drop_table("process_templates")
