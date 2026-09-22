"""Add scoped mandate bindings.

Revision ID: 00708260cd08
Revises: 382efdf2678c
Create Date: 2026-07-12 15:48:37.777458
"""

import sqlalchemy as sa

from alembic import op

revision = "00708260cd08"
down_revision = "382efdf2678c"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "org_mandate_scope_bindings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("scope_type", sa.String(length=40), nullable=False),
        sa.Column("value_stream_id", sa.String(length=36), nullable=True),
        sa.Column("business_service_id", sa.String(length=36), nullable=True),
        sa.Column("canonical_role", sa.String(length=80), nullable=False),
        sa.Column("role_assignment_id", sa.String(length=36), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "(scope_type = 'business_process' AND value_stream_id IS NOT NULL AND business_service_id IS NULL) "
            "OR (scope_type = 'business_service' AND value_stream_id IS NULL AND business_service_id IS NOT NULL)",
            name="ck_org_mandate_scope_binding_scope",
        ),
        sa.ForeignKeyConstraint(
            ["business_service_id"], ["business_services.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["role_assignment_id"],
            ["org_mandate_role_assignments.id"],
        ),
        sa.ForeignKeyConstraint(["value_stream_id"], ["value_streams.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_org_mandate_scope_bindings_org_role",
        "org_mandate_scope_bindings",
        ["organization_id", "canonical_role"],
        unique=False,
    )
    op.create_index(
        "ix_org_mandate_scope_bindings_role_assignment",
        "org_mandate_scope_bindings",
        ["role_assignment_id"],
        unique=False,
    )
    op.create_index(
        "uq_org_mandate_scope_bindings_process_role",
        "org_mandate_scope_bindings",
        ["organization_id", "value_stream_id", "canonical_role"],
        unique=True,
        postgresql_where=sa.text("scope_type = 'business_process'"),
    )
    op.create_index(
        "uq_org_mandate_scope_bindings_service_role",
        "org_mandate_scope_bindings",
        ["organization_id", "business_service_id", "canonical_role"],
        unique=True,
        postgresql_where=sa.text("scope_type = 'business_service'"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_org_mandate_scope_bindings_service_role",
        table_name="org_mandate_scope_bindings",
    )
    op.drop_index(
        "uq_org_mandate_scope_bindings_process_role",
        table_name="org_mandate_scope_bindings",
    )
    op.drop_index(
        "ix_org_mandate_scope_bindings_role_assignment",
        table_name="org_mandate_scope_bindings",
    )
    op.drop_index(
        "ix_org_mandate_scope_bindings_org_role",
        table_name="org_mandate_scope_bindings",
    )
    op.drop_table("org_mandate_scope_bindings")
