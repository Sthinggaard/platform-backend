"""Add verification_records table

Revision ID: 20250420_verification_records
Revises: 20250420_resolution_records
Create Date: 2026-04-20 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20250420_verification_records"
down_revision = "20250420_resolution_records"
branch_labels = None
depends_on = None


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

    if not _table_exists(conn, "verification_records"):
        op.create_table(
            "verification_records",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "resolution_record_id",
                sa.String(36),
                sa.ForeignKey("resolution_records.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "recommendation_id",
                sa.String(36),
                sa.ForeignKey("recommendations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "threat_id",
                sa.String(36),
                sa.ForeignKey("threats.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("verification_status", sa.String(30), nullable=False),
            sa.Column("confidence_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column(
                "observed_changes",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("linked_context_type", sa.String(20), nullable=True),
            sa.Column("linked_context_id", sa.String(200), nullable=True),
            sa.Column("compared_observed_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )

    if not _index_exists(conn, "ix_verification_records_org"):
        op.create_index("ix_verification_records_org", "verification_records", ["organization_id"])
    if not _index_exists(conn, "ix_verification_records_resolution"):
        op.create_index("ix_verification_records_resolution", "verification_records", ["resolution_record_id"])
    if not _index_exists(conn, "ix_verification_records_recommendation"):
        op.create_index("ix_verification_records_recommendation", "verification_records", ["recommendation_id"])
    if not _index_exists(conn, "ix_verification_records_org_created"):
        op.create_index("ix_verification_records_org_created", "verification_records", ["organization_id", "created_at"])


def downgrade() -> None:
    conn = op.get_bind()
    if _index_exists(conn, "ix_verification_records_org_created"):
        op.drop_index("ix_verification_records_org_created", table_name="verification_records")
    if _index_exists(conn, "ix_verification_records_recommendation"):
        op.drop_index("ix_verification_records_recommendation", table_name="verification_records")
    if _index_exists(conn, "ix_verification_records_resolution"):
        op.drop_index("ix_verification_records_resolution", table_name="verification_records")
    if _index_exists(conn, "ix_verification_records_org"):
        op.drop_index("ix_verification_records_org", table_name="verification_records")
    if _table_exists(conn, "verification_records"):
        op.drop_table("verification_records")
