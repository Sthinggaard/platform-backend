"""Add service_journey_signals table for BIA journey learning data."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "20250402_service_journey_signals"
down_revision: Union[str, None] = "20250402_add_service_tolerance_window"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "service_journey_signals" not in existing_tables:
        op.create_table(
            "service_journey_signals",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer,
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("user_id", sa.Integer, nullable=False),
            sa.Column("event", sa.String(length=50), nullable=False),
            sa.Column("service_id", sa.String(length=36), nullable=True),
            sa.Column("library_item_id", sa.String(length=100), nullable=True),
            sa.Column("service_key", sa.String(length=100), nullable=True),
            sa.Column("service_name", sa.String(length=200), nullable=True),
            sa.Column("search_query", sa.String(length=200), nullable=True),
            sa.Column(
                "recommended_service_keys",
                JSONB,
                nullable=False,
                server_default="[]",
            ),
            sa.Column(
                "matched_service_keys",
                JSONB,
                nullable=False,
                server_default="[]",
            ),
            sa.Column(
                "warning_ids",
                JSONB,
                nullable=False,
                server_default="[]",
            ),
            sa.Column("organization_type", sa.String(length=100), nullable=True),
            sa.Column("industry", sa.String(length=100), nullable=True),
            sa.Column("company_size", sa.String(length=50), nullable=True),
            sa.Column("country", sa.String(length=10), nullable=True),
            sa.Column(
                "payload",
                JSONB,
                nullable=False,
                server_default="{}",
            ),
            sa.Column(
                "created_at",
                sa.DateTime,
                nullable=False,
                server_default=sa.text("NOW()"),
            ),
        )
        op.create_index(
            "ix_service_journey_signals_org_event",
            "service_journey_signals",
            ["organization_id", "event"],
        )
        op.create_index(
            "ix_service_journey_signals_service_key",
            "service_journey_signals",
            ["service_key"],
        )
        op.create_index(
            "ix_service_journey_signals_segment",
            "service_journey_signals",
            ["organization_type", "industry", "company_size", "country"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "service_journey_signals" in existing_tables:
        op.drop_index("ix_service_journey_signals_segment", table_name="service_journey_signals")
        op.drop_index("ix_service_journey_signals_service_key", table_name="service_journey_signals")
        op.drop_index("ix_service_journey_signals_org_event", table_name="service_journey_signals")
        op.drop_table("service_journey_signals")
