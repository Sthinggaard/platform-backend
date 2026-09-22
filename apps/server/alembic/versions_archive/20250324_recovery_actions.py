"""Add recovery_actions table.

Revision ID: 20250324_recovery_actions
Revises: 20250324_asset_appetite_configs
Create Date: 2025-03-24
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "20250324_recovery_actions"
down_revision = "20250324_asset_appetite_configs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    exists = conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = 'recovery_actions'")
    ).fetchone()
    if exists:
        return

    op.create_table(
        "recovery_actions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("threat_id", sa.String(100), nullable=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("issue", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("affected_services", JSONB(), nullable=False, server_default="[]"),
        sa.Column("exposure_reduction", sa.String(100), nullable=True),
        sa.Column("priority", sa.String(20), nullable=False, server_default="high"),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("assigned_to", sa.String(255), nullable=True),
        sa.Column("due_date", sa.DateTime(), nullable=True),
        sa.Column("ref", sa.String(200), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("steps", JSONB(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["threat_id"], ["threats.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_recovery_actions_org", "recovery_actions", ["organization_id"])
    op.create_index("ix_recovery_actions_threat", "recovery_actions", ["threat_id"])
    op.create_index("ix_recovery_actions_id", "recovery_actions", ["id"])


def downgrade() -> None:
    op.drop_index("ix_recovery_actions_id", table_name="recovery_actions")
    op.drop_index("ix_recovery_actions_threat", table_name="recovery_actions")
    op.drop_index("ix_recovery_actions_org", table_name="recovery_actions")
    op.drop_table("recovery_actions")
