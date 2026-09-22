"""Structured Business Service Risk Appetite reassessment (ONB-GOV-11)

A Service Owner requests a reassessment of one appetite category (not the
whole questionnaire); the Process Owner of the process this service belongs
to approves or rejects it. Append-only per (service, category): a new
request supersedes the previous one at that category.

Revision ID: b3f0d1a2c9e5
Revises: a7c92e6f1d34
Create Date: 2026-07-14 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "b3f0d1a2c9e5"
down_revision = "a7c92e6f1d34"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "service_appetite_reassessments"):
        return
    op.create_table(
        "service_appetite_reassessments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "business_service_id",
            sa.String(36),
            sa.ForeignKey("business_services.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "process_id",
            sa.String(36),
            sa.ForeignKey("value_streams.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("category", sa.String(30), nullable=False),
        sa.Column("requested_level", sa.Integer(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("requested_by", sa.String(255), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("effective_from", sa.DateTime(), nullable=True),
        sa.Column("review_at", sa.DateTime(), nullable=True),
        sa.Column(
            "superseded_by_id",
            sa.String(36),
            sa.ForeignKey("service_appetite_reassessments.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_service_appetite_reassessments_service_category",
        "service_appetite_reassessments",
        ["business_service_id", "category", "status"],
    )
    op.create_index(
        "ix_service_appetite_reassessments_process",
        "service_appetite_reassessments",
        ["process_id"],
    )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "service_appetite_reassessments"):
        op.drop_index("ix_service_appetite_reassessments_process", table_name="service_appetite_reassessments")
        op.drop_index(
            "ix_service_appetite_reassessments_service_category",
            table_name="service_appetite_reassessments",
        )
        op.drop_table("service_appetite_reassessments")
