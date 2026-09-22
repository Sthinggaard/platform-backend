"""Store the Collector's own readiness self-checks (CA-02.3).

Until now the platform could not tell a real agent self-check from a user
clicking "Available" in the setup wizard: both wrote
``ScannerInstance.tool_status`` / ``tool_validation_at`` through the same
service, with no source marker. Readiness was therefore assertable by whoever
was doing the onboarding, for a technical state the Collector can verify
directly.

This adds the table the Collector's own reports land in. It is history, not a
single latest-value column, because "when did this stop working and what did it
say at the time?" is the question an operator actually asks, and each report
overwriting the last makes that unanswerable.

Nothing is destroyed. ``tool_status`` and ``tool_validation_at`` stay exactly
where they are for audit continuity — they are simply never read as a readiness
source again, which is what makes legacy manual answers stop enabling
discovery.

Revision ID: b8e1d4a72f95
Revises: a2d5f9c31b70
Create Date: 2026-08-14 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "b8e1d4a72f95"
down_revision = "a2d5f9c31b70"
branch_labels = None
depends_on = None

_TABLE = "collector_readiness_reports"
_INDEX = "ix_collector_readiness_instance_reported"


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, _TABLE):
        return

    # JSONB on Postgres, JSON elsewhere: the test database is SQLite, which has
    # neither, and binding the column type to the dialect keeps one migration
    # chain rather than a divergent one per backend.
    json_type = postgresql.JSONB if conn.dialect.name == "postgresql" else sa.JSON

    op.create_table(
        _TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scanner_instance_id",
            sa.String(36),
            sa.ForeignKey("scanner_instances.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("reported_at", sa.DateTime, nullable=False),
        sa.Column("self_check_started_at", sa.DateTime, nullable=True),
        sa.Column("self_check_completed_at", sa.DateTime, nullable=True),
        sa.Column("overall_status", sa.String(20), nullable=False),
        sa.Column("platform_connectivity_status", sa.String(20), nullable=False),
        sa.Column("evidence_storage_status", sa.String(20), nullable=False),
        sa.Column("collector_version", sa.String(50), nullable=True),
        sa.Column("template_pack_version", sa.String(50), nullable=True),
        sa.Column("components", json_type, nullable=True),
        sa.Column("failure_reason_codes", json_type, nullable=True),
        sa.Column("schema_version", sa.String(20), nullable=False),
        sa.Column("report_sequence", sa.Integer, nullable=True),
    )
    op.create_index(_INDEX, _TABLE, ["scanner_instance_id", "reported_at"])


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, _TABLE):
        return
    op.drop_index(_INDEX, table_name=_TABLE)
    op.drop_table(_TABLE)
