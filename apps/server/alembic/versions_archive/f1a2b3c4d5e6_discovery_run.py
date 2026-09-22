"""Step 4.1 — Discovery Orchestration Foundation

Two tables: discovery_runs (the governed request to scan, with immutable
profile/target snapshots) and scanner_commands (the strongly-typed, signed
envelope delivered to and acknowledged by the scanner). Neither table
stores technical scan results — that's Step 4.3+'s canonical observation
model. See src/core/constants/discovery_run_enums.py for the scope note.

Revision ID: f1a2b3c4d5e6
Revises: e8f1a4b2c3d5
Create Date: 2026-07-18 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "f1a2b3c4d5e6"
down_revision = "e8f1a4b2c3d5"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "discovery_runs"):
        op.create_table(
            "discovery_runs",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
            ),
            sa.Column(
                "evidence_source_id",
                sa.String(36),
                sa.ForeignKey("evidence_sources.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "scanner_instance_id",
                sa.String(36),
                sa.ForeignKey("scanner_instances.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "requested_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
            ),
            sa.Column(
                "approved_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
            ),
            sa.Column("request_source", sa.String(20), nullable=False),
            sa.Column("discovery_purpose", sa.String(40), nullable=False),
            sa.Column("profile_snapshot", JSONB(), nullable=False),
            sa.Column("target_ids", JSONB(), nullable=False),
            sa.Column("target_snapshot", JSONB(), nullable=False),
            sa.Column("status", sa.String(30), nullable=False),
            sa.Column("current_stage", sa.String(30), nullable=False),
            sa.Column("approval_status", sa.String(20), nullable=False),
            sa.Column("requested_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("approved_at", sa.DateTime(), nullable=True),
            sa.Column("queued_at", sa.DateTime(), nullable=True),
            sa.Column("command_available_at", sa.DateTime(), nullable=True),
            sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
            sa.Column("started_at", sa.DateTime(), nullable=True),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
            sa.Column("cancelled_at", sa.DateTime(), nullable=True),
            sa.Column("failed_at", sa.DateTime(), nullable=True),
            sa.Column("cancellation_requested_at", sa.DateTime(), nullable=True),
            sa.Column(
                "cancellation_requested_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "retry_of_discovery_run_id",
                sa.String(36),
                sa.ForeignKey("discovery_runs.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("failure_code", sa.String(60), nullable=True),
            sa.Column("failure_message", sa.Text(), nullable=True),
            sa.Column("next_action", sa.Text(), nullable=True),
            sa.Column("idempotency_key", sa.String(100), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint(
                "organization_id", "requested_by_user_id", "idempotency_key", name="uq_discovery_run_idempotency"
            ),
        )
        op.create_index("ix_discovery_runs_org_status", "discovery_runs", ["organization_id", "status"])
        op.create_index(
            "ix_discovery_runs_scanner_instance_status", "discovery_runs", ["scanner_instance_id", "status"]
        )

    if not _table_exists(conn, "scanner_commands"):
        op.create_table(
            "scanner_commands",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
            ),
            sa.Column(
                "scanner_instance_id",
                sa.String(36),
                sa.ForeignKey("scanner_instances.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "discovery_run_id",
                sa.String(36),
                sa.ForeignKey("discovery_runs.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("command_type", sa.String(30), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("issued_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("not_before", sa.DateTime(), nullable=True),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("delivered_at", sa.DateTime(), nullable=True),
            sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
            sa.Column("accepted", sa.Boolean(), nullable=True),
            sa.Column("rejection_code", sa.String(60), nullable=True),
            sa.Column("rejection_message", sa.Text(), nullable=True),
            sa.Column("scanner_runtime_version", sa.String(50), nullable=True),
            sa.Column("execution_policy", JSONB(), nullable=False),
            sa.Column("signature_version", sa.String(10), nullable=False),
            sa.Column("signature", sa.String(128), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_scanner_commands_instance_status", "scanner_commands", ["scanner_instance_id", "status"])
        op.create_index("ix_scanner_commands_run", "scanner_commands", ["discovery_run_id"])


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "scanner_commands"):
        op.drop_table("scanner_commands")
    if _table_exists(conn, "discovery_runs"):
        op.drop_table("discovery_runs")
