"""Risk appetite policies at organisation/process/exception scope (dashboard slice 2)

Revision ID: 20260712_risk_appetite_policies
Revises: 20260711_signal_system_actor
Create Date: 2026-07-12 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "20260712_risk_appetite_policies"
down_revision = "20260711_signal_system_actor"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "risk_appetite_policies"):
        return
    op.create_table(
        "risk_appetite_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("scope", sa.String(30), nullable=False),
        sa.Column(
            "process_id",
            sa.String(36),
            sa.ForeignKey("value_streams.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("decision_reference", sa.String(100), nullable=True),
        sa.Column("answers", JSONB(), nullable=False, server_default="{}"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("approved_by", sa.String(255), nullable=False),
        sa.Column("approved_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("effective_from", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("effective_to", sa.DateTime(), nullable=True),
        sa.Column("review_at", sa.DateTime(), nullable=True),
        sa.Column(
            "superseded_by_id",
            sa.String(36),
            sa.ForeignKey("risk_appetite_policies.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_risk_appetite_policies_org_scope",
        "risk_appetite_policies",
        ["organization_id", "scope", "status"],
    )
    op.create_index("ix_risk_appetite_policies_process", "risk_appetite_policies", ["process_id"])


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "risk_appetite_policies"):
        op.drop_index("ix_risk_appetite_policies_process", table_name="risk_appetite_policies")
        op.drop_index("ix_risk_appetite_policies_org_scope", table_name="risk_appetite_policies")
        op.drop_table("risk_appetite_policies")
