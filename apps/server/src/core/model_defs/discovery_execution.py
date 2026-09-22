"""Step 4.2 Part 2 — Discovery Execution Pipeline.

Turns an *approved* ``DiscoveryRun`` (Step 4.1) into real, provider-driven
technical discovery. This module owns execution planning/scheduling/
provider-job tracking/worker leasing/evidence packaging only — it never
interprets evidence (that stays Step 4.1A's ``discovery_normalization_service``
job) and never writes to ``Asset``/``AssetEvidenceSignal``/``SlotInstance``.
Design record: TASKS.md DISC-17,
``tasks/active/DISC-17-discovery-execution-pipeline-design.md``.

``DiscoveryExecutionPlan`` is 1:1 with a ``DiscoveryRun`` (a retried run gets
its own new plan — ``DiscoveryRun.retry_of_discovery_run_id`` already owns
that relationship, so no separate retry chain is needed at the plan level).
``ExecutionStage.stage_key`` reuses ``discovery_run_enums.DiscoveryStage``'s
existing values rather than a second stage taxonomy. DAG edges are a real
join table (``ExecutionStageDependency``), not a JSONB edge list, so "what
does this stage still depend on" is directly queryable. ``ProviderExecution``
retries are new rows linked via ``retry_of_provider_execution_id``, exactly
mirroring ``DiscoveryRun.retry_of_discovery_run_id`` — identity stays stable
across retries, never mutated in place.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow


class DiscoveryExecutionPlan(Base):
    __tablename__ = "discovery_execution_plans"
    __table_args__ = (
        UniqueConstraint("discovery_run_id", name="uq_discovery_execution_plan_run"),
        Index("ix_discovery_execution_plans_org_status", "organization_id", "status"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    discovery_run_id: Mapped[str] = Column(
        String(36), ForeignKey("discovery_runs.id", ondelete="CASCADE"), nullable=False
    )

    # Immutable once execution starts (spec): concurrency limits per stage,
    # retry policy, per-stage/job timeout — same fixed-config-object JSONB
    # convention as ScannerCommand.execution_policy.
    plan_definition: Mapped[dict] = Column(JSONB, nullable=False)

    status: Mapped[str] = Column(String(30), nullable=False)

    generated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    started_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class ExecutionStage(Base):
    __tablename__ = "execution_stages"
    __table_args__ = (
        Index("ix_execution_stages_plan_status", "execution_plan_id", "status"),
        UniqueConstraint("execution_plan_id", "stage_key", name="uq_execution_stage_plan_key"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    execution_plan_id: Mapped[str] = Column(
        String(36), ForeignKey("discovery_execution_plans.id", ondelete="CASCADE"), nullable=False
    )
    # Value from discovery_run_enums.DiscoveryStage — reused, not duplicated.
    stage_key: Mapped[str] = Column(String(30), nullable=False)
    status: Mapped[str] = Column(String(20), nullable=False)

    # DISC-30: whether this stage's own total failure fails the whole plan.
    # Every stage generated today is required=True (no code path marks one
    # optional yet — which stage, if any, should be is a real product
    # decision not made here); the field and _advance_plan_completion's
    # handling of it exist so that decision can be wired in later without a
    # schema change.
    required: Mapped[bool] = Column(Boolean, nullable=False, default=True)

    started_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class ExecutionStageDependency(Base):
    """DAG edge: ``execution_stage_id`` depends on ``depends_on_stage_id``
    (both within the same plan). A real join table rather than a JSONB list
    so "what does this stage still depend on" is directly queryable without
    deserializing JSON in application code."""

    __tablename__ = "execution_stage_dependencies"
    __table_args__ = (
        UniqueConstraint("execution_stage_id", "depends_on_stage_id", name="uq_execution_stage_dependency"),
        Index("ix_execution_stage_dependencies_stage", "execution_stage_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    execution_stage_id: Mapped[str] = Column(
        String(36), ForeignKey("execution_stages.id", ondelete="CASCADE"), nullable=False
    )
    depends_on_stage_id: Mapped[str] = Column(
        String(36), ForeignKey("execution_stages.id", ondelete="CASCADE"), nullable=False
    )

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


class ProviderExecution(Base):
    __tablename__ = "provider_executions"
    __table_args__ = (
        Index("ix_provider_executions_stage_status", "execution_stage_id", "status"),
        Index("ix_provider_executions_status_next_retry_at", "status", "next_retry_at"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    execution_stage_id: Mapped[str] = Column(
        String(36), ForeignKey("execution_stages.id", ondelete="CASCADE"), nullable=False
    )
    # Key into the provider registry (nmap, subfinder, nuclei, collector,
    # azure, ...) — never branched on in this table's own code.
    provider_id: Mapped[str] = Column(String(60), nullable=False)
    provider_version: Mapped[str | None] = Column(String(50), nullable=True)

    status: Mapped[str] = Column(String(20), nullable=False)
    attempt_number: Mapped[int] = Column(Integer, nullable=False, default=1)
    # A retried job is a new row, never a mutated one — exactly the
    # DiscoveryRun.retry_of_discovery_run_id pattern.
    retry_of_provider_execution_id: Mapped[str | None] = Column(
        String(36), ForeignKey("provider_executions.id", ondelete="SET NULL"), nullable=True
    )

    # Opaque, provider-defined resume state (checkpoint-based recovery) —
    # the engine never inspects its shape, only the provider that wrote it
    # can interpret it on resume.
    checkpoint: Mapped[dict | None] = Column(JSONB, nullable=True)

    failure_code: Mapped[str | None] = Column(String(60), nullable=True)
    failure_message: Mapped[str | None] = Column(Text, nullable=True)

    # Set only while status == "retry_scheduled" (DISC-27/28) — when the
    # backoff delay elapses, the scheduler spawns the next attempt as a
    # new sibling row rather than mutating this one.
    next_retry_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    started_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class WorkerLease(Base):
    """The stable-identity claiming mechanism that lets stateless workers
    pick up a ProviderExecution without two workers double-executing it,
    and lets a dead worker's job be reclaimed once its lease expires."""

    __tablename__ = "worker_leases"
    __table_args__ = (UniqueConstraint("provider_execution_id", name="uq_worker_lease_provider_execution"),)

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    provider_execution_id: Mapped[str] = Column(
        String(36), ForeignKey("provider_executions.id", ondelete="CASCADE"), nullable=False
    )
    # Identifies the holding worker instance (Celery task id today).
    worker_id: Mapped[str] = Column(String(120), nullable=False)

    leased_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    lease_expires_at: Mapped[datetime] = Column(DateTime, nullable=False)
    heartbeat_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    released_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


class EvidencePackage(Base):
    """The one contract between execution and normalization (Step 4.1A).
    The engine never emits normalized data — only this."""

    __tablename__ = "evidence_packages"
    __table_args__ = (
        Index("ix_evidence_packages_org_normalization_status", "organization_id", "normalization_status"),
        Index("ix_evidence_packages_run", "discovery_run_id"),
        # DISC-34: a given ProviderExecution attempt can only ever
        # legitimately produce one package — a retried attempt is a brand
        # new ProviderExecution row (DISC-27/28's own convention), never a
        # second package on the same row. DB-enforced so a genuine
        # concurrent duplicate result-report race (two in-flight requests
        # for the same attempt, neither committed yet — a plain
        # application-level status check alone cannot close this) fails
        # loudly at the database rather than silently duplicating evidence.
        UniqueConstraint("provider_execution_id", name="uq_evidence_package_provider_execution"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))

    # Full lineage back to the originating run, not just the immediate
    # parent — provenance never needs reconstruction by walking joins.
    discovery_run_id: Mapped[str] = Column(
        String(36), ForeignKey("discovery_runs.id", ondelete="CASCADE"), nullable=False
    )
    execution_plan_id: Mapped[str] = Column(
        String(36), ForeignKey("discovery_execution_plans.id", ondelete="CASCADE"), nullable=False
    )
    execution_stage_id: Mapped[str] = Column(
        String(36), ForeignKey("execution_stages.id", ondelete="CASCADE"), nullable=False
    )
    provider_execution_id: Mapped[str] = Column(
        String(36), ForeignKey("provider_executions.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)

    provider_id: Mapped[str] = Column(String(60), nullable=False)
    provider_version: Mapped[str | None] = Column(String(50), nullable=True)
    collector_version: Mapped[str | None] = Column(String(50), nullable=True)

    captured_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    schema_version: Mapped[str] = Column(String(20), nullable=False)

    # An opaque pointer written by whichever EvidenceStorageBackend is
    # configured — never the payload itself inlined into this row.
    raw_evidence_reference: Mapped[str] = Column(Text, nullable=False)
    evidence_format: Mapped[str] = Column(String(30), nullable=False)
    integrity_hash: Mapped[str | None] = Column(String(128), nullable=True)

    execution_metadata: Mapped[dict] = Column(JSONB, nullable=False)
    # Deliberately restates provider/version/worker/collector-version/
    # timestamp/tenant/org/stage/plan/run redundantly, even though several
    # are already FK columns on this same row — so a package stays fully
    # self-describing if ever extracted independently of this database.
    provenance_metadata: Mapped[dict] = Column(JSONB, nullable=False)

    processing_status: Mapped[str] = Column(String(20), nullable=False)
    normalization_status: Mapped[str] = Column(String(20), nullable=False)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


__all__ = [
    "DiscoveryExecutionPlan",
    "ExecutionStage",
    "ExecutionStageDependency",
    "ProviderExecution",
    "WorkerLease",
    "EvidencePackage",
]
