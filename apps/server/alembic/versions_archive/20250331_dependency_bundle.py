"""Add dependency_bundles, mapping_decisions tables and archetype column to business_services."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "20250331_dependency_bundle"
down_revision: Union[str, None] = "20250331_add_user_title"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # ── archetype column on business_services ─────────────────────────────────
    bs_columns = {col["name"] for col in inspector.get_columns("business_services")}
    if "archetype" not in bs_columns:
        op.add_column(
            "business_services",
            sa.Column("archetype", sa.String(50), nullable=True),
        )

    # ── dependency_bundles ────────────────────────────────────────────────────
    if "dependency_bundles" not in existing_tables:
        op.create_table(
            "dependency_bundles",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer,
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "service_id",
                sa.String(36),
                sa.ForeignKey("business_services.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
            sa.Column("mode", sa.String(30), nullable=False, server_default="manual_training"),
            sa.Column(
                "lifecycle_state",
                sa.String(40),
                nullable=False,
                server_default="template_loaded",
            ),
            sa.Column("groups", JSONB, nullable=False, server_default="[]"),
            sa.Column(
                "created_at",
                sa.DateTime,
                nullable=False,
                server_default=sa.text("NOW()"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime,
                nullable=False,
                server_default=sa.text("NOW()"),
            ),
        )
        op.create_index("ix_dependency_bundles_service", "dependency_bundles", ["service_id"])
        op.create_index("ix_dependency_bundles_org", "dependency_bundles", ["organization_id"])

    # ── mapping_decisions ─────────────────────────────────────────────────────
    if "mapping_decisions" not in existing_tables:
        op.create_table(
            "mapping_decisions",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer,
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("service_id", sa.String(36), nullable=False),
            sa.Column("bundle_id", sa.String(36), nullable=False),
            sa.Column("node_id", sa.String(36), nullable=True),
            sa.Column("action", sa.String(50), nullable=False),
            sa.Column("group_key", sa.String(50), nullable=True),
            sa.Column("before_state", JSONB, nullable=True),
            sa.Column("after_state", JSONB, nullable=True),
            sa.Column("reason", sa.Text, nullable=True),
            sa.Column("actor_type", sa.String(20), nullable=False, server_default="human"),
            sa.Column(
                "created_at",
                sa.DateTime,
                nullable=False,
                server_default=sa.text("NOW()"),
            ),
        )
        op.create_index("ix_mapping_decisions_bundle", "mapping_decisions", ["bundle_id"])
        op.create_index("ix_mapping_decisions_service", "mapping_decisions", ["service_id"])
        op.create_index("ix_mapping_decisions_org", "mapping_decisions", ["organization_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "mapping_decisions" in existing_tables:
        op.drop_index("ix_mapping_decisions_org", table_name="mapping_decisions")
        op.drop_index("ix_mapping_decisions_service", table_name="mapping_decisions")
        op.drop_index("ix_mapping_decisions_bundle", table_name="mapping_decisions")
        op.drop_table("mapping_decisions")

    if "dependency_bundles" in existing_tables:
        op.drop_index("ix_dependency_bundles_org", table_name="dependency_bundles")
        op.drop_index("ix_dependency_bundles_service", table_name="dependency_bundles")
        op.drop_table("dependency_bundles")

    bs_columns = {col["name"] for col in inspector.get_columns("business_services")}
    if "archetype" in bs_columns:
        op.drop_column("business_services", "archetype")
