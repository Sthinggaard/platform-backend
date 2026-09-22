"""Business Service Profile fields on service/slot templates

Revision ID: 20260705_business_service_profiles
Revises: 20260514_risk_intelligence_ingestion_batch_decision_evidence
Create Date: 2026-07-05 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "20260705_business_service_profiles"
down_revision = "20260514_risk_intelligence_ingestion_batch_decision_evidence"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, col: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": col},
    ).fetchone() is not None


SERVICE_TEMPLATE_COLUMNS: list[sa.Column] = [
    sa.Column("capability_statement", sa.Text(), nullable=True),
    sa.Column("default_impact_model", JSONB(), nullable=True),
    sa.Column("operational_expectations", JSONB(), nullable=False, server_default="[]"),
    sa.Column("common_risk_patterns", JSONB(), nullable=False, server_default="[]"),
    sa.Column("override_policy", JSONB(), nullable=True),
]

SLOT_TEMPLATE_COLUMNS: list[sa.Column] = [
    sa.Column("matching_hints", JSONB(), nullable=False, server_default="[]"),
    sa.Column("expected_evidence_types", JSONB(), nullable=False, server_default="[]"),
    sa.Column("risk_patterns", JSONB(), nullable=False, server_default="[]"),
]


def upgrade() -> None:
    conn = op.get_bind()

    for column in SERVICE_TEMPLATE_COLUMNS:
        if not _col_exists(conn, "service_templates", column.name):
            op.add_column("service_templates", column.copy())

    for column in SLOT_TEMPLATE_COLUMNS:
        if not _col_exists(conn, "slot_templates", column.name):
            op.add_column("slot_templates", column.copy())


def downgrade() -> None:
    conn = op.get_bind()

    for column in SLOT_TEMPLATE_COLUMNS:
        if _col_exists(conn, "slot_templates", column.name):
            op.drop_column("slot_templates", column.name)

    for column in SERVICE_TEMPLATE_COLUMNS:
        if _col_exists(conn, "service_templates", column.name):
            op.drop_column("service_templates", column.name)
