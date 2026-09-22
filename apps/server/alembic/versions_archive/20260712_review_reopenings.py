"""Review reopenings (dashboard slice 4)

Revision ID: 20260712_review_reopenings
Revises: 20260712_risk_evaluations
Create Date: 2026-07-12 18:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "20260712_review_reopenings"
down_revision = "20260712_risk_evaluations"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "review_reopenings"):
        return
    op.create_table(
        "review_reopenings",
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
        sa.Column("source", sa.String(30), nullable=False),
        sa.Column("decision_reference", sa.String(100), nullable=False),
        sa.Column("review_due_at", sa.String(30), nullable=False),
        sa.Column("review_owner", sa.String(255), nullable=True),
        sa.Column(
            "evaluation_id",
            sa.String(36),
            sa.ForeignKey("risk_evaluations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("scenario_snapshot", JSONB(), nullable=False, server_default="{}"),
        sa.Column("reopened_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "organization_id",
            "process_id",
            "source",
            "decision_reference",
            "review_due_at",
            name="uq_review_reopenings_reference_due",
        ),
    )
    op.create_index(
        "ix_review_reopenings_org_process", "review_reopenings", ["organization_id", "process_id"]
    )


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "review_reopenings"):
        op.drop_index("ix_review_reopenings_org_process", table_name="review_reopenings")
        op.drop_table("review_reopenings")
