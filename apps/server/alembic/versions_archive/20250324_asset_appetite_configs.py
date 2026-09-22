"""Add asset_appetite_configs table for per-asset risk appetite persistence."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "20250324_asset_appetite_configs"
down_revision: Union[str, None] = "20250323_seed_assets_from_threats"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = inspector.get_table_names()

    if "asset_appetite_configs" not in existing:
        op.create_table(
            "asset_appetite_configs",
            sa.Column("id", sa.Integer(), primary_key=True, index=True),
            sa.Column("organization_id", sa.Integer(), nullable=False),
            sa.Column("asset_id", sa.Integer(), nullable=False),
            sa.Column("answers", JSONB(), nullable=False, server_default="{}"),
            sa.Column("approved_by", sa.String(length=255), nullable=False),
            sa.Column("approved_at", sa.DateTime(), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column("history", JSONB(), nullable=False, server_default="[]"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(
                ["organization_id"], ["organizations.id"], ondelete="CASCADE"
            ),
            sa.ForeignKeyConstraint(
                ["asset_id"], ["assets.id"], ondelete="CASCADE"
            ),
            sa.UniqueConstraint(
                "organization_id", "asset_id", name="uq_asset_appetite_org_asset"
            ),
        )
        op.create_index(
            "ix_asset_appetite_configs_org",
            "asset_appetite_configs",
            ["organization_id"],
        )


def downgrade() -> None:
    op.drop_index("ix_asset_appetite_configs_org", table_name="asset_appetite_configs")
    op.drop_table("asset_appetite_configs")
