"""Step 4.2 Part 3 (DISC-41) — the first-ever audit-event read API.

AuditEvent has been written prolifically across every discovery-domain
service since DISC-17, but never once queried back by any route
(confirmed by DISC-36's repository inspection) — this module is the first
consumer. Every writer across this domain shares the same
``_write_audit``-style helper *shape* but not the same metadata *key*
convention: ``discovery_run.py``'s own writes use snake_case
(``discovery_run_id``), while every execution-pipeline writer
(``discovery_execution_scheduler_service.py``,
``discovery_execution_retry_service.py``,
``discovery_execution_cancellation_service.py``,
``discovery_execution_command_service.py``,
``discovery_execution_evidence_adapter.py``) uses camelCase
(``executionPlanId``/``executionStageId``/``providerExecutionId``/
``evidencePackageId``) — a real, disclosed inconsistency, not something
this module invents a fix for. It is handled here by branching on the
event_type's own domain prefix rather than assuming one metadata shape.

``AuditEvent`` carries no ``discovery_run_id`` column, so every row for a
run must be found by ``organization_id`` + a known discovery-domain
event_type prefix, then matched in Python against the specific run/plan/
stage/job/package ids this call cares about — there is no join to do this
in SQL given the schema, and Postgres JSONB operator support would not be
portable to this repo's own SQLite test suite anyway (the same
plain-Python-filtering precedent ``discovery_run.py``'s own response
assembly already uses). Capped at the 200 most recent matching rows —
this is a customer-facing timeline, not an unbounded audit export.
"""

from __future__ import annotations

from pydantic import BaseModel
from sqlalchemy import desc, or_
from sqlalchemy.orm import Session

from src.core.model_defs.common import to_utc_iso
from src.core.model_defs.discovery_execution import DiscoveryExecutionPlan, EvidencePackage, ExecutionStage, ProviderExecution
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.tenant_identity import AuditEvent

_DISCOVERY_DOMAIN_PREFIXES = (
    "discovery_run.",
    "discovery_execution_plan.",
    "execution_stage.",
    "provider_execution.",
    "evidence_package.",
)

_MAX_TIMELINE_ENTRIES = 200

_EVENT_LABELS: dict[str, str] = {
    "discovery_run.requested": "Discovery requested",
    "discovery_run.blocked": "Discovery could not be requested",
    "discovery_run.approval_required": "Discovery is awaiting approval",
    "discovery_run.approved": "Discovery approved",
    "discovery_run.queued": "Discovery queued",
    "discovery_run.command_created": "Discovery command created",
    "discovery_run.command_delivered": "Discovery command delivered to the collector",
    "discovery_run.command_acknowledged": "Collector acknowledged the discovery command",
    "discovery_run.command_rejected": "Collector rejected the discovery command",
    "discovery_run.stage_changed": "Discovery stage updated",
    "discovery_run.cancellation_requested": "Cancellation requested",
    "discovery_run.cancelled": "Discovery cancelled",
    "discovery_run.completed": "Discovery completed",
    "discovery_run.failed": "Discovery failed",
    "discovery_run.expired": "Discovery expired",
    "discovery_run.retry_requested": "Discovery retry requested",
    "discovery_execution_plan.generated": "Execution plan generated",
    "discovery_execution_plan.started": "Execution started",
    "discovery_execution_plan.completed": "Execution completed",
    "discovery_execution_plan.partially_completed": "Execution completed with unresolved stages",
    "discovery_execution_plan.completed_with_warnings": "Execution completed with warnings",
    "discovery_execution_plan.failed": "Execution failed",
    "discovery_execution_plan.cancelled": "Execution cancelled",
    "execution_stage.started": "A discovery stage started",
    "execution_stage.completed": "A discovery stage completed",
    "execution_stage.partially_completed": "A discovery stage partially completed",
    "execution_stage.failed": "A discovery stage failed",
    "execution_stage.skipped": "A discovery stage was skipped",
    "execution_stage.cancelled": "A discovery stage was cancelled",
    "provider_execution.leased": "A discovery job was picked up by the collector",
    "provider_execution.started": "A discovery job started",
    "provider_execution.completed": "A discovery job completed",
    "provider_execution.failed": "A discovery job failed",
    "provider_execution.cancelled": "A discovery job was cancelled",
    "provider_execution.retry_queued": "A discovery job was queued for retry",
    "provider_execution.lease_reclaimed": "A discovery job's collector connection was reclaimed after inactivity",
    "evidence_package.received": "Evidence received",
    "evidence_package.storage_failed": "Evidence could not be stored",
    "evidence_package.normalized": "Evidence processed",
    "evidence_package.normalization_failed": "Evidence could not be processed",
}


class DiscoveryTimelineEntry(BaseModel):
    id: int
    event_type: str
    label: str
    #: Always carries an explicit UTC offset — see to_utc_iso.
    occurred_at: str


# DISC-46 — business-language label for the reasonCode this ticket added
# to the cancellation route, so the timeline surfaces *why* alongside
# *that* a cancellation was requested. Deliberately not the raw enum
# value (Ledger's own "never a raw enum, always a business sentence" rule).
_CANCELLATION_REASON_LABELS: dict[str, str] = {
    "customer_requested": "requested by the customer",
    "scope_changed": "the approved scope changed",
    "security_concern": "a security concern was raised",
    "duplicate_run": "a duplicate discovery run",
    "scanner_unavailable": "the scanner became unavailable",
    "other": "another reason",
}


def _label_for(event: AuditEvent) -> str:
    if event.event_type == "provider_execution.retry_queued" and (event.metadata_json or {}).get("trigger") == "customer":
        return "A discovery job was retried"
    if event.event_type == "discovery_run.cancellation_requested":
        reason_code = (event.metadata_json or {}).get("reason_code")
        reason_label = _CANCELLATION_REASON_LABELS.get(reason_code) if reason_code else None
        if reason_label:
            return f"Cancellation requested — {reason_label}"
    return _EVENT_LABELS.get(event.event_type, event.event_type.replace(".", " ").replace("_", " ").capitalize())


def _event_matches_run(
    event: AuditEvent,
    *,
    run_id: str,
    plan_ids: set[str],
    stage_ids: set[str],
    job_ids: set[str],
    package_ids: set[str],
) -> bool:
    metadata = event.metadata_json or {}
    if event.event_type.startswith("discovery_run."):
        return metadata.get("discovery_run_id") == run_id
    if event.event_type.startswith("discovery_execution_plan."):
        # Written by two different files with two different metadata-key
        # conventions for the same event-type prefix: discovery_run.py's
        # own GENERATED/CANCELLED writes use snake_case execution_plan_id,
        # while discovery_execution_scheduler_service.py's COMPLETED/
        # FAILED/etc. writes use camelCase executionPlanId. Check both
        # rather than assuming one shape per prefix.
        return metadata.get("executionPlanId") in plan_ids or metadata.get("execution_plan_id") in plan_ids
    if event.event_type.startswith("execution_stage."):
        return metadata.get("executionStageId") in stage_ids
    if event.event_type.startswith("provider_execution."):
        return metadata.get("providerExecutionId") in job_ids
    if event.event_type.startswith("evidence_package."):
        return metadata.get("evidencePackageId") in package_ids or metadata.get("providerExecutionId") in job_ids
    return False


def resolve_discovery_run_timeline(
    db: Session, organization_id: int, run: DiscoveryRun, plan: DiscoveryExecutionPlan | None
) -> list[DiscoveryTimelineEntry]:
    plan_ids: set[str] = {plan.id} if plan is not None else set()
    stage_ids: set[str] = set()
    job_ids: set[str] = set()
    package_ids: set[str] = set()

    if plan is not None:
        stages = db.query(ExecutionStage).filter(ExecutionStage.execution_plan_id == plan.id).all()
        stage_ids = {stage.id for stage in stages}
        if stage_ids:
            job_ids = {
                job.id for job in db.query(ProviderExecution).filter(ProviderExecution.execution_stage_id.in_(stage_ids)).all()
            }
        package_ids = {
            package.id for package in db.query(EvidencePackage).filter(EvidencePackage.discovery_run_id == run.id).all()
        }

    candidates = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.organization_id == organization_id,
            or_(*(AuditEvent.event_type.startswith(prefix) for prefix in _DISCOVERY_DOMAIN_PREFIXES)),
        )
        .order_by(desc(AuditEvent.created_at), desc(AuditEvent.id))
        .limit(2000)  # bound the Python-side scan; a real per-run filter would need a schema change
        .all()
    )

    matched = [
        event
        for event in candidates
        if _event_matches_run(event, run_id=run.id, plan_ids=plan_ids, stage_ids=stage_ids, job_ids=job_ids, package_ids=package_ids)
    ][:_MAX_TIMELINE_ENTRIES]

    return [
        DiscoveryTimelineEntry(
            id=event.id,
            event_type=event.event_type,
            label=_label_for(event),
            occurred_at=to_utc_iso(event.created_at),
        )
        for event in matched
    ]
