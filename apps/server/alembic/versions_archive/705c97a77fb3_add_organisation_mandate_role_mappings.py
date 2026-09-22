"""Add organisation mandate-role mappings and visibility policies.

Revision ID: 705c97a77fb3
Revises: 0f56d67354a0
Create Date: 2026-07-12 08:50:23.952689
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "705c97a77fb3"
down_revision = "0f56d67354a0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "org_mandate_role_assignments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("canonical_role", sa.String(length=80), nullable=False),
        sa.Column("subject_type", sa.String(length=40), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("identity_group_id", sa.String(length=255), nullable=True),
        sa.Column("identity_provider", sa.String(length=50), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "(subject_type = 'user' AND user_id IS NOT NULL AND identity_group_id IS NULL AND identity_provider IS NULL) "
            "OR (subject_type = 'identity_group' AND user_id IS NULL AND identity_group_id IS NOT NULL AND identity_provider IS NOT NULL)",
            name="ck_org_mandate_role_assignment_subject",
        ),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_org_mandate_role_assignments_org_group",
        "org_mandate_role_assignments",
        ["organization_id", "identity_group_id"],
        unique=False,
    )
    op.create_index(
        "ix_org_mandate_role_assignments_org_role",
        "org_mandate_role_assignments",
        ["organization_id", "canonical_role"],
        unique=False,
    )
    op.create_index(
        "ix_org_mandate_role_assignments_org_user",
        "org_mandate_role_assignments",
        ["organization_id", "user_id"],
        unique=False,
    )
    op.create_index(
        "uq_org_mandate_role_assignments_user",
        "org_mandate_role_assignments",
        ["organization_id", "canonical_role", "user_id"],
        unique=True,
        postgresql_where=sa.text("subject_type = 'user'"),
    )
    op.create_index(
        "uq_org_mandate_role_assignments_group",
        "org_mandate_role_assignments",
        ["organization_id", "canonical_role", "identity_provider", "identity_group_id"],
        unique=True,
        postgresql_where=sa.text("subject_type = 'identity_group'"),
    )
    op.create_table(
        "org_visibility_policies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("overview_role_keys", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("full_detail_role_keys", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", name="uq_org_visibility_policies_organization"),
    )


def downgrade() -> None:
    op.drop_table("org_visibility_policies")
    op.drop_index("uq_org_mandate_role_assignments_group", table_name="org_mandate_role_assignments")
    op.drop_index("uq_org_mandate_role_assignments_user", table_name="org_mandate_role_assignments")
    op.drop_index("ix_org_mandate_role_assignments_org_user", table_name="org_mandate_role_assignments")
    op.drop_index("ix_org_mandate_role_assignments_org_role", table_name="org_mandate_role_assignments")
    op.drop_index("ix_org_mandate_role_assignments_org_group", table_name="org_mandate_role_assignments")
    op.drop_table("org_mandate_role_assignments")
