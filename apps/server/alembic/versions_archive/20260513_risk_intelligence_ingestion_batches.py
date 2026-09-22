"""Add risk intelligence ingestion batches

Revision ID: 20260513_risk_intelligence_ingestion_batches
Revises: 20260510_decision_forecast_snapshot
Create Date: 2026-05-13 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "20260513_risk_intelligence_ingestion_batches"
down_revision = "20260510_decision_forecast_snapshot"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "risk_intelligence_ingestion_batches",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_name", sa.String(length=150), nullable=False),
        sa.Column("collector_profile", sa.String(length=150), nullable=False),
        sa.Column("file_name", sa.String(length=255), nullable=True),
        sa.Column("content_type", sa.String(length=100), nullable=True),
        sa.Column("payload_checksum", sa.String(length=64), nullable=False),
        sa.Column("raw_payload", JSONB(), nullable=False),
        sa.Column("raw_payload_size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="received"),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_risk_intel_ingestion_batches_org_status",
        "risk_intelligence_ingestion_batches",
        ["organization_id", "status"],
    )
    op.create_index(
        "ix_risk_intel_ingestion_batches_org_created",
        "risk_intelligence_ingestion_batches",
        ["organization_id", "received_at"],
    )
    op.create_index(
        "ix_risk_intelligence_ingestion_batches_source_name",
        "risk_intelligence_ingestion_batches",
        ["source_name"],
    )
    op.create_index(
        "ix_risk_intelligence_ingestion_batches_collector_profile",
        "risk_intelligence_ingestion_batches",
        ["collector_profile"],
    )
    op.create_index(
        "ix_risk_intelligence_ingestion_batches_payload_checksum",
        "risk_intelligence_ingestion_batches",
        ["payload_checksum"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_risk_intelligence_ingestion_batches_payload_checksum",
        table_name="risk_intelligence_ingestion_batches",
    )
    op.drop_index(
        "ix_risk_intelligence_ingestion_batches_collector_profile",
        table_name="risk_intelligence_ingestion_batches",
    )
    op.drop_index(
        "ix_risk_intelligence_ingestion_batches_source_name",
        table_name="risk_intelligence_ingestion_batches",
    )
    op.drop_index(
        "ix_risk_intel_ingestion_batches_org_created",
        table_name="risk_intelligence_ingestion_batches",
    )
    op.drop_index(
        "ix_risk_intel_ingestion_batches_org_status",
        table_name="risk_intelligence_ingestion_batches",
    )
    op.drop_table("risk_intelligence_ingestion_batches")

