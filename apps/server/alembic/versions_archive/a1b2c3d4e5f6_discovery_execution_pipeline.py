"""Step 4.2 Part 2 — Discovery Execution Pipeline

Six tables: discovery_execution_plans (the executable, immutable-once-started
version of an approved DiscoveryRun), execution_stages + execution_stage_dependencies
(the DAG), provider_executions (one job per provider per stage, retries as
new rows via retry_of_provider_execution_id), worker_leases (stateless-worker
claiming with expiry-based reclaim), and evidence_packages (the sole handoff
artifact to Step 4.1A normalization). None of these tables interpret
evidence or write to Asset/AssetEvidenceSignal/SlotInstance — see
src/core/model_defs/discovery_execution.py and TASKS.md DISC-17/DISC-19.

Revision ID: a1b2c3d4e5f6
Revises: 20260719_slot_mapping_reason_code
Create Date: 2026-07-22 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "a1b2c3d4e5f6"
down_revision = "20260719_slot_mapping_reason_code"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    return conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"),
        {"t": table},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "discovery_execution_plans"):
        op.create_table(
            "discovery_execution_plans",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
            ),
            sa.Column(
                "discovery_run_id",
                sa.String(36),
                sa.ForeignKey("discovery_runs.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("plan_definition", JSONB(), nullable=False),
            sa.Column("status", sa.String(30), nullable=False),
            sa.Column("generated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("started_at", sa.DateTime(), nullable=True),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("discovery_run_id", name="uq_discovery_execution_plan_run"),
        )
        op.create_index(
            "ix_discovery_execution_plans_org_status", "discovery_execution_plans", ["organization_id", "status"]
        )

    if not _table_exists(conn, "execution_stages"):
        op.create_table(
            "execution_stages",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "execution_plan_id",
                sa.String(36),
                sa.ForeignKey("discovery_execution_plans.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("stage_key", sa.String(30), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("started_at", sa.DateTime(), nullable=True),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("execution_plan_id", "stage_key", name="uq_execution_stage_plan_key"),
        )
        op.create_index("ix_execution_stages_plan_status", "execution_stages", ["execution_plan_id", "status"])

    if not _table_exists(conn, "execution_stage_dependencies"):
        op.create_table(
            "execution_stage_dependencies",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "execution_stage_id",
                sa.String(36),
                sa.ForeignKey("execution_stages.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "depends_on_stage_id",
                sa.String(36),
                sa.ForeignKey("execution_stages.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint(
                "execution_stage_id", "depends_on_stage_id", name="uq_execution_stage_dependency"
            ),
        )
        op.create_index(
            "ix_execution_stage_dependencies_stage", "execution_stage_dependencies", ["execution_stage_id"]
        )

    if not _table_exists(conn, "provider_executions"):
        op.create_table(
            "provider_executions",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "execution_stage_id",
                sa.String(36),
                sa.ForeignKey("execution_stages.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("provider_id", sa.String(60), nullable=False),
            sa.Column("provider_version", sa.String(50), nullable=True),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("attempt_number", sa.Integer(), nullable=False, server_default="1"),
            sa.Column(
                "retry_of_provider_execution_id",
                sa.String(36),
                sa.ForeignKey("provider_executions.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("checkpoint", JSONB(), nullable=True),
            sa.Column("failure_code", sa.String(60), nullable=True),
            sa.Column("failure_message", sa.Text(), nullable=True),
            sa.Column("started_at", sa.DateTime(), nullable=True),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "ix_provider_executions_stage_status", "provider_executions", ["execution_stage_id", "status"]
        )

    if not _table_exists(conn, "worker_leases"):
        op.create_table(
            "worker_leases",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "provider_execution_id",
                sa.String(36),
                sa.ForeignKey("provider_executions.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("worker_id", sa.String(120), nullable=False),
            sa.Column("leased_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("lease_expires_at", sa.DateTime(), nullable=False),
            sa.Column("heartbeat_at", sa.DateTime(), nullable=True),
            sa.Column("released_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("provider_execution_id", name="uq_worker_lease_provider_execution"),
        )

    if not _table_exists(conn, "evidence_packages"):
        op.create_table(
            "evidence_packages",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "discovery_run_id",
                sa.String(36),
                sa.ForeignKey("discovery_runs.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "execution_plan_id",
                sa.String(36),
                sa.ForeignKey("discovery_execution_plans.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "execution_stage_id",
                sa.String(36),
                sa.ForeignKey("execution_stages.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "provider_execution_id",
                sa.String(36),
                sa.ForeignKey("provider_executions.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
            ),
            sa.Column("provider_id", sa.String(60), nullable=False),
            sa.Column("provider_version", sa.String(50), nullable=True),
            sa.Column("collector_version", sa.String(50), nullable=True),
            sa.Column("captured_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("schema_version", sa.String(20), nullable=False),
            sa.Column("raw_evidence_reference", sa.Text(), nullable=False),
            sa.Column("evidence_format", sa.String(30), nullable=False),
            sa.Column("integrity_hash", sa.String(128), nullable=True),
            sa.Column("execution_metadata", JSONB(), nullable=False),
            sa.Column("provenance_metadata", JSONB(), nullable=False),
            sa.Column("processing_status", sa.String(20), nullable=False),
            sa.Column("normalization_status", sa.String(20), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index(
            "ix_evidence_packages_org_normalization_status",
            "evidence_packages",
            ["organization_id", "normalization_status"],
        )
        op.create_index("ix_evidence_packages_run", "evidence_packages", ["discovery_run_id"])


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "evidence_packages"):
        op.drop_table("evidence_packages")
    if _table_exists(conn, "worker_leases"):
        op.drop_table("worker_leases")
    if _table_exists(conn, "provider_executions"):
        op.drop_table("provider_executions")
    if _table_exists(conn, "execution_stage_dependencies"):
        op.drop_table("execution_stage_dependencies")
    if _table_exists(conn, "execution_stages"):
        op.drop_table("execution_stages")
    if _table_exists(conn, "discovery_execution_plans"):
        op.drop_table("discovery_execution_plans")
