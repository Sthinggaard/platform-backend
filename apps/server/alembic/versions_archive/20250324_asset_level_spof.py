"""Add level and is_spof columns to assets table.

Revision ID: 20250324_asset_level_spof
Revises: 20250324_recovery_actions
Create Date: 2025-03-24
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20250324_asset_level_spof"
down_revision = "20250324_recovery_actions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    has_level = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name='assets' AND column_name='level'"
        )
    ).fetchone()
    if not has_level:
        op.add_column("assets", sa.Column("level", sa.Integer(), nullable=True))

    has_spof = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name='assets' AND column_name='is_spof'"
        )
    ).fetchone()
    if not has_spof:
        op.add_column(
            "assets",
            sa.Column("is_spof", sa.Boolean(), nullable=False, server_default="false"),
        )


def downgrade() -> None:
    op.drop_column("assets", "is_spof")
    op.drop_column("assets", "level")
