"""Step 4.1 — Discovery Orchestration Foundation.

``DiscoveryRun`` governs a request to scan an organisation's approved
scope; it never stores the technical results of the scan (that's Step
4.3+'s canonical observation model). ``profile_snapshot``/``target_snapshot``
are immutable copies taken at request time (spec §10) — a run must never
depend on the live, mutable ``ScannerInstance.scan_profile`` or
``ScannerDomainTarget``/``ScannerNetworkTarget`` rows drifting under it.

``ScannerCommand`` is the strongly-typed, signed envelope the scanner
polls for and acknowledges — kept as its own table (SRP: a run may only
ever have one *active* command, but keeping delivery/acknowledgement
lifecycle off the run row itself keeps ``DiscoveryRun`` about governance,
not transport). ``DiscoveryRun`` does not carry a ``command_id`` column on
purpose — ``ScannerCommand.discovery_run_id`` is the one owning
relationship, so there is exactly one place that link is stored (DRY).
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow


class DiscoveryRun(Base):
    __tablename__ = "discovery_runs"
    __table_args__ = (
        Index("ix_discovery_runs_org_status", "organization_id", "status"),
        Index("ix_discovery_runs_scanner_instance_status", "scanner_instance_id", "status"),
        UniqueConstraint(
            "organization_id", "requested_by_user_id", "idempotency_key", name="uq_discovery_run_idempotency"
        ),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    evidence_source_id: Mapped[str] = Column(
        String(36), ForeignKey("evidence_sources.id", ondelete="CASCADE"), nullable=False
    )
    scanner_instance_id: Mapped[str] = Column(
        String(36), ForeignKey("scanner_instances.id", ondelete="CASCADE"), nullable=False
    )

    requested_by_user_id: Mapped[int] = Column(Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    approved_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    request_source: Mapped[str] = Column(String(20), nullable=False)
    discovery_purpose: Mapped[str] = Column(String(40), nullable=False)

    # Immutable execution snapshots (spec §10) — never re-derived from live
    # scope/profile rows once the run exists.
    profile_snapshot: Mapped[dict] = Column(JSONB, nullable=False)
    target_ids: Mapped[list] = Column(JSONB, nullable=False)
    target_snapshot: Mapped[list] = Column(JSONB, nullable=False)

    # CA-04.7 — nullable, additive: which Business Process (and optionally
    # Business Service within it) this run counts toward, snapshotted once
    # at creation from an ACTIVE ProcessScannerLink and never re-read live
    # from it afterwards (same immutable-snapshot philosophy as
    # profile_snapshot/target_snapshot above) — a link later paused/revoked,
    # or a service's own value_stream_ids changing, must never retroactively
    # alter what an already-created run is attributed to. NULL means
    # "org-wide, not process-scoped," matching every run created before
    # this column existed.
    business_process_id: Mapped[str | None] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="SET NULL"), nullable=True
    )
    business_service_id: Mapped[str | None] = Column(
        String(36), ForeignKey("business_services.id", ondelete="SET NULL"), nullable=True
    )
    # CA-04.7/CA-10 — which ProcessScanScope approval (and its revision, for
    # when a scope is re-approved after being edited) this run was
    # authorized under. Populated by create_discovery_run via
    # _resolve_process_context. Still no FK: ProcessScanScope rows are
    # superseded, never deleted, so a run keeps pointing at the exact
    # revision it was authorized under even after a newer one is approved.
    process_scan_scope_id: Mapped[str | None] = Column(String(36), nullable=True)
    process_scan_scope_revision: Mapped[int | None] = Column(Integer, nullable=True)

    status: Mapped[str] = Column(String(30), nullable=False)
    current_stage: Mapped[str] = Column(String(30), nullable=False)
    approval_status: Mapped[str] = Column(String(20), nullable=False)

    requested_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    approved_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    queued_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    command_available_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    acknowledged_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    started_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    cancelled_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    failed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    cancellation_requested_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    cancellation_requested_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # DISC-46 — spec §16's structured cancellation reasonCode. Both null
    # for a run cancelled before this ticket, or one cancelled without a
    # reason supplied (the field is optional, not mandatory).
    cancellation_reason_code: Mapped[str | None] = Column(String(40), nullable=True)
    cancellation_reason_note: Mapped[str | None] = Column(Text, nullable=True)

    retry_of_discovery_run_id: Mapped[str | None] = Column(
        String(36), ForeignKey("discovery_runs.id", ondelete="SET NULL"), nullable=True
    )
    retry_count: Mapped[int] = Column(Integer, nullable=False, default=0)

    failure_code: Mapped[str | None] = Column(String(60), nullable=True)
    failure_message: Mapped[str | None] = Column(Text, nullable=True)
    next_action: Mapped[str | None] = Column(Text, nullable=True)

    # Bound to (organization, requester) via the unique constraint above —
    # a client-supplied key that lets a duplicate POST resolve to the
    # already-created run instead of creating a second one (spec §20).
    idempotency_key: Mapped[str | None] = Column(String(100), nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class ScannerCommand(Base):
    __tablename__ = "scanner_commands"
    __table_args__ = (
        Index("ix_scanner_commands_instance_status", "scanner_instance_id", "status"),
        Index("ix_scanner_commands_run", "discovery_run_id"),
        Index("ix_scanner_commands_provider_execution", "provider_execution_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    scanner_instance_id: Mapped[str] = Column(
        String(36), ForeignKey("scanner_instances.id", ondelete="CASCADE"), nullable=False
    )
    discovery_run_id: Mapped[str] = Column(
        String(36), ForeignKey("discovery_runs.id", ondelete="CASCADE"), nullable=False
    )
    # Step 4.2 — nullable, additive: set only for a command created on
    # behalf of one ProviderExecution (a delegated provider's job), never
    # for Step 4.1's original whole-run command. NULL here means "this is
    # a Step 4.1 whole-run command," exactly as before this column existed.
    # Lives here rather than on ProviderExecution for the same reason
    # DiscoveryRun itself carries no command_id column (see that model's
    # own docstring): the child stores the pointer to what it was created
    # for, so the parent never needs mutating each time a new command is
    # issued/retried.
    provider_execution_id: Mapped[str | None] = Column(
        String(36), ForeignKey("provider_executions.id", ondelete="SET NULL"), nullable=True
    )

    # CA-04.2 — the registered CheckKey this command represents (nmap
    # today). Set from provider_execution.provider_id for a delegated
    # per-job command; NULL for a Step 4.1 whole-run command, which spans
    # whatever the run's profile capabilities allow rather than one single
    # check. Validated against the closed CheckKey vocabulary at creation,
    # never accepted as free text.
    check_key: Mapped[str | None] = Column(String(30), nullable=True)

    # CA-04.7 — snapshotted from DiscoveryRun.business_process_id/
    # business_service_id at the moment this command is created (not a
    # live join through discovery_run_id), so the signed job envelope is
    # self-contained and auditable end-to-end even if the parent run's own
    # ProcessScannerLink is later paused/revoked. Included in the signed
    # payload (discovery_command_service._signable_payload).
    business_process_id: Mapped[str | None] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="SET NULL"), nullable=True
    )
    business_service_id: Mapped[str | None] = Column(
        String(36), ForeignKey("business_services.id", ondelete="SET NULL"), nullable=True
    )

    command_type: Mapped[str] = Column(String(30), nullable=False)
    status: Mapped[str] = Column(String(20), nullable=False)

    issued_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    not_before: Mapped[datetime | None] = Column(DateTime, nullable=True)
    expires_at: Mapped[datetime] = Column(DateTime, nullable=False)
    delivered_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    acknowledged_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    accepted: Mapped[bool | None] = Column(Boolean, nullable=True)
    rejection_code: Mapped[str | None] = Column(String(60), nullable=True)
    rejection_message: Mapped[str | None] = Column(Text, nullable=True)
    scanner_runtime_version: Mapped[str | None] = Column(String(50), nullable=True)

    # {maximumDurationSeconds, maximumConcurrentTargets, stopAtWindowEnd,
    # allowPartialUpload} — spec §14. A fixed small config object, not
    # something separately queried, so JSONB rather than its own columns.
    execution_policy: Mapped[dict] = Column(JSONB, nullable=False)

    signature_version: Mapped[str] = Column(String(10), nullable=False)
    signature: Mapped[str] = Column(String(128), nullable=False)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


__all__ = ["DiscoveryRun", "ScannerCommand"]
