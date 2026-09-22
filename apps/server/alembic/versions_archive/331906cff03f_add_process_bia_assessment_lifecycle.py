"""Add process BIA assessment lifecycle.

Revision ID: 331906cff03f
Revises: bd3c76b76996
Create Date: 2026-07-12 22:21:20.000000
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "331906cff03f"
down_revision = "bd3c76b76996"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "process_bia_assessments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("process_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("answers", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("source", sa.String(length=80), nullable=False),
        sa.Column("confidence", sa.String(length=20), nullable=False),
        sa.Column("assumption_state", sa.String(length=30), nullable=False),
        sa.Column("prepared_by_user_id", sa.Integer(), nullable=True),
        sa.Column("prepared_at", sa.DateTime(), nullable=False),
        sa.Column("attested_by_user_id", sa.Integer(), nullable=True),
        sa.Column("attested_at", sa.DateTime(), nullable=True),
        sa.Column("review_at", sa.DateTime(), nullable=True),
        sa.Column("superseded_by_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["attested_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["prepared_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["process_id"], ["value_streams.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["superseded_by_id"], ["process_bia_assessments.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_process_bia_assessments_org_process", "process_bia_assessments", ["organization_id", "process_id"], unique=False)
    op.create_index("ix_process_bia_assessments_process_status", "process_bia_assessments", ["process_id", "status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_process_bia_assessments_process_status", table_name="process_bia_assessments")
    op.drop_index("ix_process_bia_assessments_org_process", table_name="process_bia_assessments")
    op.drop_table("process_bia_assessments")
