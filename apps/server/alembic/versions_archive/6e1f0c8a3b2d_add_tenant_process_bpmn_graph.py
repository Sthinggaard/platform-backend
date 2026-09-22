"""Add tenant-owned BPMN definitions to Business Processes.

Revision ID: 6e1f0c8a3b2d
Revises: 372cf3c44f7c
Create Date: 2026-07-13 01:15:00.000000
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "6e1f0c8a3b2d"
down_revision = "372cf3c44f7c"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "value_streams",
        sa.Column("bpmn_definition", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("value_streams", "bpmn_definition")
