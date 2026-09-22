"""Add structured Business Process confirmation decisions.

Revision ID: 372cf3c44f7c
Revises: dc2ab7162639
Create Date: 2026-07-13 00:30:49.807862
"""

import sqlalchemy as sa

from alembic import op

revision = "372cf3c44f7c"
down_revision = "dc2ab7162639"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "business_process_activations",
        sa.Column(
            "confirmation_outcome",
            sa.String(length=30),
            nullable=False,
            server_default="pending",
        ),
    )
    op.add_column(
        "business_process_activations",
        sa.Column("confirmation_reason_code", sa.String(length=80), nullable=True),
    )
    op.add_column(
        "business_process_activations",
        sa.Column("confirmation_reason_detail", sa.String(length=500), nullable=True),
    )
    op.add_column(
        "business_process_activations",
        sa.Column("successor_process_id", sa.String(length=36), nullable=True),
    )
    op.create_foreign_key(
        "fk_business_process_activations_successor_process",
        "business_process_activations",
        "value_streams",
        ["successor_process_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.execute(
        """
        UPDATE business_process_activations
        SET confirmation_outcome = 'confirmed'
        WHERE confirmed_at IS NOT NULL
        """
    )
    op.alter_column("business_process_activations", "confirmation_outcome", server_default=None)


def downgrade() -> None:
    op.drop_constraint(
        "fk_business_process_activations_successor_process",
        "business_process_activations",
        type_="foreignkey",
    )
    op.drop_column("business_process_activations", "successor_process_id")
    op.drop_column("business_process_activations", "confirmation_reason_detail")
    op.drop_column("business_process_activations", "confirmation_reason_code")
    op.drop_column("business_process_activations", "confirmation_outcome")
