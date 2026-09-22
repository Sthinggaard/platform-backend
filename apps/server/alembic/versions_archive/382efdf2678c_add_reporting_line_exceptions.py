"""Add reporting-line exceptions.

Revision ID: 382efdf2678c
Revises: 705c97a77fb3
Create Date: 2026-07-12 15:09:31.924127
"""

import sqlalchemy as sa

from alembic import op

revision = "382efdf2678c"
down_revision = "705c97a77fb3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "org_reporting_line_exceptions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("employee_user_id", sa.Integer(), nullable=False),
        sa.Column("manager_user_id", sa.Integer(), nullable=False),
        sa.Column("exception_reason", sa.String(length=500), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "employee_user_id <> manager_user_id",
            name="ck_org_reporting_line_exception_distinct_users",
        ),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["employee_user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["manager_user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "employee_user_id",
            name="uq_org_reporting_line_exceptions_employee",
        ),
    )
    op.create_index(
        "ix_org_reporting_line_exceptions_org_manager",
        "org_reporting_line_exceptions",
        ["organization_id", "manager_user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_org_reporting_line_exceptions_org_manager",
        table_name="org_reporting_line_exceptions",
    )
    op.drop_table("org_reporting_line_exceptions")
