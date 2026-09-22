"""Add Business Process confirmation and activation evidence.

Revision ID: dc2ab7162639
Revises: aab224bca22b
Create Date: 2026-07-12 23:25:30.573748
"""

import sqlalchemy as sa

from alembic import op

revision = "dc2ab7162639"
down_revision = "aab224bca22b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "business_process_activations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("process_id", sa.String(length=36), nullable=False),
        sa.Column("confirmed_by_user_id", sa.Integer(), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(), nullable=True),
        sa.Column("activated_by_user_id", sa.Integer(), nullable=True),
        sa.Column("activated_at", sa.DateTime(), nullable=True),
        sa.Column("activated_bia_assessment_id", sa.String(length=36), nullable=True),
        sa.Column("activated_owner_acceptance_id", sa.String(length=36), nullable=True),
        sa.Column("activated_appetite_policy_id", sa.String(length=36), nullable=True),
        sa.Column("activated_confirmation_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["activated_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["confirmed_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["process_id"], ["value_streams.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "process_id",
            name="uq_business_process_activations_org_process",
        ),
    )
    op.create_index(
        "ix_business_process_activations_org_process",
        "business_process_activations",
        ["organization_id", "process_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_business_process_activations_org_process",
        table_name="business_process_activations",
    )
    op.drop_table("business_process_activations")
