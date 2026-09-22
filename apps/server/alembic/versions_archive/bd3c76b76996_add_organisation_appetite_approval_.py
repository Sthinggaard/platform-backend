"""Add organisation appetite approval lifecycle.

Revision ID: bd3c76b76996
Revises: 00708260cd08
Create Date: 2026-07-12 22:16:25.335665
"""

import sqlalchemy as sa

from alembic import op

revision = "bd3c76b76996"
down_revision = "00708260cd08"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "risk_appetite_policies",
        sa.Column("prepared_by", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "risk_appetite_policies",
        sa.Column("submitted_by", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "risk_appetite_policies",
        sa.Column("submitted_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "risk_appetite_policies",
        sa.Column("rejected_by", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "risk_appetite_policies",
        sa.Column("rejected_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "risk_appetite_policies",
        sa.Column("rejection_reason", sa.Text(), nullable=True),
    )
    op.add_column(
        "risk_appetite_policies",
        sa.Column("approval_reference", sa.String(length=500), nullable=True),
    )
    op.alter_column(
        "risk_appetite_policies",
        "approved_by",
        existing_type=sa.String(length=255),
        nullable=True,
    )
    op.alter_column(
        "risk_appetite_policies",
        "approved_at",
        existing_type=sa.DateTime(),
        nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "risk_appetite_policies",
        "approved_at",
        existing_type=sa.DateTime(),
        nullable=False,
    )
    op.alter_column(
        "risk_appetite_policies",
        "approved_by",
        existing_type=sa.String(length=255),
        nullable=False,
    )
    op.drop_column("risk_appetite_policies", "approval_reference")
    op.drop_column("risk_appetite_policies", "rejection_reason")
    op.drop_column("risk_appetite_policies", "rejected_at")
    op.drop_column("risk_appetite_policies", "rejected_by")
    op.drop_column("risk_appetite_policies", "submitted_at")
    op.drop_column("risk_appetite_policies", "submitted_by")
    op.drop_column("risk_appetite_policies", "prepared_by")
