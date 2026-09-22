"""Add threats and business_services tables."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

# revision identifiers, used by Alembic.
revision: str = "20250322_add_threats_and_services"
down_revision: Union[str, None] = "20250320_invite_tokens"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = inspector.get_table_names()

    # ── threats ───────────────────────────────────────────────────────────────
    if "threats" not in existing:
        op.create_table(
            "threats",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("organization_id", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="detected"),
            sa.Column("severity", sa.String(length=20), nullable=False),
            sa.Column("source", sa.String(length=20), nullable=False),
            sa.Column("asset", sa.String(length=200), nullable=False),
            sa.Column("tier", sa.String(length=50), nullable=False),
            sa.Column("signal", sa.Text(), nullable=False),
            sa.Column("what_it_means", sa.Text(), nullable=False),
            sa.Column("recommendation", sa.Text(), nullable=False),
            sa.Column("intelligence", JSONB(), nullable=False, server_default="{}"),
            sa.Column("daily_cost", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("frameworks", ARRAY(sa.String()), nullable=False, server_default="{}"),
            sa.Column("requires_escalation", sa.Boolean(), nullable=False, server_default="false"),
            sa.Column("decision", JSONB(), nullable=True),
            sa.Column("saved_per_hour", sa.Integer(), nullable=True),
            sa.Column("resolved_on", sa.String(length=30), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        )
        op.create_index("ix_threats_org_status", "threats", ["organization_id", "status"])
        op.create_index("ix_threats_org_severity", "threats", ["organization_id", "severity"])

    # ── business_services ─────────────────────────────────────────────────────
    if "business_services" not in existing:
        op.create_table(
            "business_services",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("organization_id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(length=200), nullable=False),
            sa.Column("tier", sa.String(length=50), nullable=False, server_default="Business Critical"),
            sa.Column("trading_impact", sa.Text(), nullable=False, server_default=""),
            sa.Column("l1", ARRAY(sa.String()), nullable=False, server_default="{}"),
            sa.Column("l2", ARRAY(sa.String()), nullable=False, server_default="{}"),
            sa.Column("l3", ARRAY(sa.String()), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        )
        op.create_index("ix_business_services_org", "business_services", ["organization_id"])


def downgrade() -> None:
    op.drop_index("ix_business_services_org", table_name="business_services")
    op.drop_table("business_services")

    op.drop_index("ix_threats_org_severity", table_name="threats")
    op.drop_index("ix_threats_org_status", table_name="threats")
    op.drop_table("threats")
