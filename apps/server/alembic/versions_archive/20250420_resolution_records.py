"""Add resolution_records table

Revision ID: 20250420_resolution_records
Revises: 20250416_recommendations_and_decision_records
Create Date: 2026-04-20 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20250420_resolution_records"
down_revision = "20250416_recommendations_and_decision_records"
branch_labels = None
depends_on = None

RESOLUTION_STATUS_CAPTURED = "captured"
VERIFICATION_STATUS_PENDING = "pending"


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    ).fetchone() is not None


def _index_exists(conn, index_name: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :i"),
        {"i": index_name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "resolution_records"):
        op.create_table(
            "resolution_records",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "recommendation_id",
                sa.String(36),
                sa.ForeignKey("recommendations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "decision_record_id",
                sa.String(36),
                sa.ForeignKey("decision_records.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "threat_id",
                sa.String(36),
                sa.ForeignKey("threats.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "recovery_action_id",
                sa.Integer(),
                sa.ForeignKey("recovery_actions.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("resolution_type", sa.String(40), nullable=False),
            sa.Column("selected_action_option", sa.String(20), nullable=False),
            sa.Column("resolution_summary", sa.Text(), nullable=True),
            sa.Column("resolved_by", sa.String(255), nullable=False),
            sa.Column("resolved_role", sa.String(100), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default=RESOLUTION_STATUS_CAPTURED),
            sa.Column("verification_status", sa.String(30), nullable=False, server_default=VERIFICATION_STATUS_PENDING),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )

    if not _index_exists(conn, "ix_resolution_records_org"):
        op.create_index("ix_resolution_records_org", "resolution_records", ["organization_id"])
    if not _index_exists(conn, "ix_resolution_records_recommendation"):
        op.create_index("ix_resolution_records_recommendation", "resolution_records", ["recommendation_id"])
    if not _index_exists(conn, "ix_resolution_records_decision"):
        op.create_index("ix_resolution_records_decision", "resolution_records", ["decision_record_id"])
    if not _index_exists(conn, "ix_resolution_records_recovery_action"):
        op.create_index("ix_resolution_records_recovery_action", "resolution_records", ["recovery_action_id"])
    if not _index_exists(conn, "ix_resolution_records_org_created"):
        op.create_index("ix_resolution_records_org_created", "resolution_records", ["organization_id", "created_at"])


def downgrade() -> None:
    conn = op.get_bind()
    if _index_exists(conn, "ix_resolution_records_org_created"):
        op.drop_index("ix_resolution_records_org_created", table_name="resolution_records")
    if _index_exists(conn, "ix_resolution_records_recovery_action"):
        op.drop_index("ix_resolution_records_recovery_action", table_name="resolution_records")
    if _index_exists(conn, "ix_resolution_records_decision"):
        op.drop_index("ix_resolution_records_decision", table_name="resolution_records")
    if _index_exists(conn, "ix_resolution_records_recommendation"):
        op.drop_index("ix_resolution_records_recommendation", table_name="resolution_records")
    if _index_exists(conn, "ix_resolution_records_org"):
        op.drop_index("ix_resolution_records_org", table_name="resolution_records")
    if _table_exists(conn, "resolution_records"):
        op.drop_table("resolution_records")
