"""TENANT-79 — evidence_sources.business_service_id

Additive, nullable: which business process this evidence source was set up
to validate, if any. Null means "org-wide / not yet scoped to a process"
(the pre-existing Configuration/onboarding creation path is unaffected).

Revision ID: c8a1f3e6b2d4
Revises: af8f00af46fe
Create Date: 2026-08-02 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "c8a1f3e6b2d4"
down_revision = "af8f00af46fe"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, column: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": column},
    ).fetchone() is not None


def _index_exists(conn, index_name: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :i"),
        {"i": index_name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _col_exists(conn, "evidence_sources", "business_service_id"):
        op.add_column(
            "evidence_sources",
            sa.Column(
                "business_service_id",
                sa.String(length=36),
                sa.ForeignKey("business_services.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )
    if not _index_exists(conn, "ix_evidence_sources_business_service"):
        op.create_index(
            "ix_evidence_sources_business_service", "evidence_sources", ["business_service_id"]
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _index_exists(conn, "ix_evidence_sources_business_service"):
        op.drop_index("ix_evidence_sources_business_service", table_name="evidence_sources")
    if _col_exists(conn, "evidence_sources", "business_service_id"):
        op.drop_column("evidence_sources", "business_service_id")
