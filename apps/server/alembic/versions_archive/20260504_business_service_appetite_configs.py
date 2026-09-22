"""Add business service appetite configs

Revision ID: 20260504_business_service_appetite_configs
Revises: 20250425_resolution_alternative_category
Create Date: 2026-05-04 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "20260504_business_service_appetite_configs"
down_revision = "20250425_resolution_alternative_category"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    ).fetchone() is not None


def _index_exists(conn, index_name: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :i"),
        {"i": index_name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "business_service_appetite_configs"):
        op.create_table(
            "business_service_appetite_configs",
            sa.Column("id", sa.Integer(), primary_key=True, index=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "business_service_id",
                sa.String(length=36),
                sa.ForeignKey("business_services.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("answers", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("approved_by", sa.String(length=255), nullable=False),
            sa.Column("approved_at", sa.DateTime(), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column("history", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.UniqueConstraint(
                "organization_id",
                "business_service_id",
                name="uq_business_service_appetite_org_service",
            ),
        )

    if not _index_exists(conn, "ix_business_service_appetite_configs_org"):
        op.create_index(
            "ix_business_service_appetite_configs_org",
            "business_service_appetite_configs",
            ["organization_id"],
        )
    if not _index_exists(conn, "ix_business_service_appetite_configs_service"):
        op.create_index(
            "ix_business_service_appetite_configs_service",
            "business_service_appetite_configs",
            ["business_service_id"],
        )


def downgrade() -> None:
    conn = op.get_bind()

    if _index_exists(conn, "ix_business_service_appetite_configs_service"):
        op.drop_index("ix_business_service_appetite_configs_service", table_name="business_service_appetite_configs")
    if _index_exists(conn, "ix_business_service_appetite_configs_org"):
        op.drop_index("ix_business_service_appetite_configs_org", table_name="business_service_appetite_configs")
    if _table_exists(conn, "business_service_appetite_configs"):
        op.drop_table("business_service_appetite_configs")
