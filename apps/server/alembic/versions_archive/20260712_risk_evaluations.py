"""Risk evaluations and forecast impacts (dashboard slice 3)

Revision ID: 20260712_risk_evaluations
Revises: 20260712_risk_appetite_policies
Create Date: 2026-07-12 12:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "20260712_risk_evaluations"
down_revision = "20260712_risk_appetite_policies"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "forecast_impacts"):
        op.create_table(
            "forecast_impacts",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "process_id",
                sa.String(36),
                sa.ForeignKey("value_streams.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("estimate", JSONB(), nullable=False, server_default="{}"),
            sa.Column("inputs", JSONB(), nullable=False, server_default="{}"),
            sa.Column("assumptions", JSONB(), nullable=False, server_default="[]"),
            sa.Column("confidence", sa.String(10), nullable=False),
            sa.Column("source", sa.String(60), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "ix_forecast_impacts_org_process", "forecast_impacts", ["organization_id", "process_id"]
        )

    if not _table_exists(conn, "risk_evaluations"):
        op.create_table(
            "risk_evaluations",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "process_id",
                sa.String(36),
                sa.ForeignKey("value_streams.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("status", sa.String(30), nullable=False),
            sa.Column("preparedness", sa.String(30), nullable=False),
            sa.Column("confidence", sa.String(10), nullable=False),
            sa.Column("bia_snapshot", JSONB(), nullable=True),
            sa.Column("appetite_snapshot", JSONB(), nullable=True),
            sa.Column("evidence_snapshot", JSONB(), nullable=False, server_default="{}"),
            sa.Column("dependency_snapshot", JSONB(), nullable=False, server_default="{}"),
            sa.Column("recovery_snapshot", JSONB(), nullable=False, server_default="{}"),
            sa.Column("residual", JSONB(), nullable=False, server_default="{}"),
            sa.Column("explanation", JSONB(), nullable=False, server_default="[]"),
            sa.Column(
                "forecast_id",
                sa.String(36),
                sa.ForeignKey("forecast_impacts.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("evaluated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "ix_risk_evaluations_org_process",
            "risk_evaluations",
            ["organization_id", "process_id", "evaluated_at"],
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "risk_evaluations"):
        op.drop_index("ix_risk_evaluations_org_process", table_name="risk_evaluations")
        op.drop_table("risk_evaluations")
    if _table_exists(conn, "forecast_impacts"):
        op.drop_index("ix_forecast_impacts_org_process", table_name="forecast_impacts")
        op.drop_table("forecast_impacts")
