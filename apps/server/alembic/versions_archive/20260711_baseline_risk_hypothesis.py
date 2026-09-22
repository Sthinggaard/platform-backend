"""Baseline Risk Hypothesis record (BSP-10)

Revision ID: 20260711_baseline_risk_hypothesis
Revises: 20260706_process_bia_inheritance
Create Date: 2026-07-11 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "20260711_baseline_risk_hypothesis"
down_revision = "20260706_process_bia_inheritance"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "baseline_risk_hypotheses"):
        return
    op.create_table(
        "baseline_risk_hypotheses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="generated"),
        sa.Column("company_context", JSONB(), nullable=False, server_default="{}"),
        sa.Column("assumptions", JSONB(), nullable=False, server_default="[]"),
        sa.Column("generated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("validated_by", sa.String(100), nullable=True),
        sa.Column("validated_at", sa.DateTime(), nullable=True),
        sa.Column(
            "superseded_by_id",
            sa.String(36),
            sa.ForeignKey("baseline_risk_hypotheses.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_baseline_risk_hypotheses_org_status",
        "baseline_risk_hypotheses",
        ["organization_id", "status"],
    )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "baseline_risk_hypotheses"):
        op.drop_index("ix_baseline_risk_hypotheses_org_status", table_name="baseline_risk_hypotheses")
        op.drop_table("baseline_risk_hypotheses")
