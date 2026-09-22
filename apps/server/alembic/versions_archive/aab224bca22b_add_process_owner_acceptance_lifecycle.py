"""Add Business Process Owner invitation and acceptance lifecycle.

Revision ID: aab224bca22b
Revises: 331906cff03f
Create Date: 2026-07-12 22:57:24.661595
"""

import sqlalchemy as sa

from alembic import op

revision = "aab224bca22b"
down_revision = "331906cff03f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "process_owner_acceptances",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("process_id", sa.String(length=36), nullable=False),
        sa.Column("scope_binding_id", sa.String(length=36), nullable=False),
        sa.Column("role_assignment_id", sa.String(length=36), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("invited_by_user_id", sa.Integer(), nullable=True),
        sa.Column("invited_at", sa.DateTime(), nullable=False),
        sa.Column("accepted_at", sa.DateTime(), nullable=True),
        sa.Column("rejected_at", sa.DateTime(), nullable=True),
        sa.Column("rejection_reason", sa.String(length=80), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "status IN ('invitation_sent', 'accepted', 'rejected')",
            name="ck_process_owner_acceptance_status",
        ),
        sa.ForeignKeyConstraint(["invited_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["process_id"], ["value_streams.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["scope_binding_id"], ["org_mandate_scope_bindings.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "scope_binding_id",
            name="uq_process_owner_acceptances_org_scope_binding",
        ),
    )
    op.create_index(
        "ix_process_owner_acceptances_org_process",
        "process_owner_acceptances",
        ["organization_id", "process_id"],
        unique=False,
    )
    op.create_index(
        "ix_process_owner_acceptances_process_status",
        "process_owner_acceptances",
        ["process_id", "status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_process_owner_acceptances_process_status",
        table_name="process_owner_acceptances",
    )
    op.drop_index(
        "ix_process_owner_acceptances_org_process",
        table_name="process_owner_acceptances",
    )
    op.drop_table("process_owner_acceptances")
