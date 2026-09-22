"""Add decision evidence to risk intelligence ingestion batches

Revision ID: 20260514_risk_intelligence_ingestion_batch_decision_evidence
Revises: 20260513_risk_intelligence_ingestion_batches
Create Date: 2026-05-14 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "20260514_risk_intelligence_ingestion_batch_decision_evidence"
down_revision = "20260513_risk_intelligence_ingestion_batches"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "risk_intelligence_ingestion_batches",
        sa.Column("decision_evidence", JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("risk_intelligence_ingestion_batches", "decision_evidence")
