"""add business process recommendation persistence

Revision ID: 20250411_business_process_recommendations
Revises: 20250410_template_library_foundation
Create Date: 2026-04-11 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

from sqlalchemy.dialects.postgresql import JSONB


revision = "20250411_business_process_recommendations"
down_revision = "20250410_template_library_foundation"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def _index_exists(conn, index_name: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :i"),
        {"i": index_name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "business_process_recommendations"):
        op.create_table(
            "business_process_recommendations",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("organization_id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("process_template_id", sa.String(length=100), nullable=False),
            sa.Column("name", sa.String(length=200), nullable=False),
            sa.Column("category", sa.String(length=100), nullable=False),
            sa.Column("confidence", sa.Float(), nullable=False),
            sa.Column("recommendation_reason", sa.Text(), nullable=False),
            sa.Column("source_rule", sa.String(length=120), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'suggested'")),
            sa.Column("model_version", sa.String(length=80), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.PrimaryKeyConstraint("id"),
        )

    if not _index_exists(conn, "ix_business_process_recommendations_org_status"):
        op.create_index(
            "ix_business_process_recommendations_org_status",
            "business_process_recommendations",
            ["organization_id", "status"],
            unique=False,
        )
    if not _index_exists(conn, "ix_business_process_recommendations_org_template"):
        op.create_index(
            "ix_business_process_recommendations_org_template",
            "business_process_recommendations",
            ["organization_id", "process_template_id"],
            unique=False,
        )

    if not _table_exists(conn, "business_process_decision_logs"):
        op.create_table(
            "business_process_decision_logs",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("organization_id", sa.Integer(), nullable=False),
            sa.Column("recommendation_id", sa.String(length=36), nullable=True),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("action", sa.String(length=20), nullable=False),
            sa.Column("reason", JSONB, nullable=True),
            sa.Column("model_version", sa.String(length=80), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.ForeignKeyConstraint(
                ["recommendation_id"],
                ["business_process_recommendations.id"],
                ondelete="SET NULL",
            ),
            sa.PrimaryKeyConstraint("id"),
        )

    if not _index_exists(conn, "ix_business_process_decision_logs_org_created"):
        op.create_index(
            "ix_business_process_decision_logs_org_created",
            "business_process_decision_logs",
            ["organization_id", "created_at"],
            unique=False,
        )
    if not _index_exists(conn, "ix_business_process_decision_logs_recommendation"):
        op.create_index(
            "ix_business_process_decision_logs_recommendation",
            "business_process_decision_logs",
            ["recommendation_id"],
            unique=False,
        )


def downgrade() -> None:
    conn = op.get_bind()

    if _table_exists(conn, "business_process_decision_logs"):
        op.drop_index(
            "ix_business_process_decision_logs_recommendation",
            table_name="business_process_decision_logs",
        )
        op.drop_index(
            "ix_business_process_decision_logs_org_created",
            table_name="business_process_decision_logs",
        )
        op.drop_table("business_process_decision_logs")

    if _table_exists(conn, "business_process_recommendations"):
        op.drop_index(
            "ix_business_process_recommendations_org_template",
            table_name="business_process_recommendations",
        )
        op.drop_index(
            "ix_business_process_recommendations_org_status",
            table_name="business_process_recommendations",
        )
        op.drop_table("business_process_recommendations")

