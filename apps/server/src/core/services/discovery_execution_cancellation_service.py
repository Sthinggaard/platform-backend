"""Step 4.2 Part 2 — DISC-31: plan/stage/job-level cancellation.

Propagates a run-level cancellation request into its
``DiscoveryExecutionPlan`` — the disclosed follow-up from ``DISC-24``
(cancelling a RUNNING run only ever set ``DiscoveryRun.status``; nothing
below the run acted on it, so an in-flight plan just kept executing).
Called from the route layer (``src/api/routes/discovery_run.py``), the
same bridging pattern ``DISC-24`` already established with
``_advance_if_approved`` — keeps ``discovery_run_lifecycle_service.py``
(Step 4.1) decoupled from Step 4.2's own execution-pipeline internals.

Real, disclosed limitation carried over from ``DISC-17``'s own scope
statement: there is no live push channel to a scanner agent
(``apps/scanner`` only polls), so "signal active leases" here means
releasing the DB-level lease and marking the job ``CANCELLED``, not
remotely interrupting whatever the scanner is currently doing with it. A
late-arriving report for an already-cancelled job is therefore a real,
expected race — handled as a no-op by the two report-back entry points in
``discovery_execution_command_service.py`` (both now check for a terminal
status before acting), never silently overwritten back to
completed/failed after the cancellation already landed.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.discovery_execution_enums import (
    EXECUTION_STAGE_AUDIT_CANCELLED,
    PROVIDER_EXECUTION_AUDIT_CANCELLED,
    TERMINAL_EXECUTION_PLAN_STATUSES,
    TERMINAL_EXECUTION_STAGE_STATUSES,
    TERMINAL_PROVIDER_EXECUTION_STATUSES,
    ExecutionPlanStatus,
    ExecutionStageStatus,
    ProviderExecutionStatus,
)
from src.core.constants.lifecycle_enums import LifecycleFamily, LifecycleTransitionSource
from src.core.model_defs.discovery_execution import (
    DiscoveryExecutionPlan,
    ExecutionStage,
    ProviderExecution,
)
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.services.discovery_command_service import utcnow
from src.core.services.discovery_execution_plan_lifecycle_service import (
    transition_discovery_execution_plan,
)
from src.core.services.discovery_execution_retry_service import release_lease
from src.core.services.lifecycle_audit_service import (
    LifecycleAuditDetails,
    with_lifecycle_audit_metadata,
)
from src.core.services.provider_execution_lifecycle_service import transition_provider_execution


def _write_audit(db: Session, *, organization_id: int, event_type: str, metadata: dict) -> None:
    # System-triggered (a cancellation request, never itself the acting
    # human — the route already writes its own EXECUTION_PLAN_AUDIT_CANCELLED
    # with real ctx attribution; these per-stage/per-job events are this
    # cascade's own internal detail).
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=None,
            event_type=event_type,
            metadata_json=metadata,
        )
    )


def _with_process_context(metadata: dict, run: DiscoveryRun) -> dict:
    """CA-04.8 — camelCase, matching this file's own existing metadata keys."""
    return {
        **metadata,
        "businessProcessId": run.business_process_id,
        "businessServiceId": run.business_service_id,
        "slotInstanceId": None,
    }


def cancel_execution_plan(db: Session, run: DiscoveryRun) -> DiscoveryExecutionPlan | None:
    """No-op (returns None) if this run never generated a plan (cancelled
    before APPROVED, or plan generation itself failed) — also a no-op
    (returns the plan unchanged) if the plan already reached a terminal
    status, since there is nothing left to stop. Already-terminal
    stages/jobs keep their real recorded outcome; only genuinely
    outstanding work (PENDING/READY/RUNNING/LEASED/RETRY_SCHEDULED) is
    marked CANCELLED. Already-accepted EvidencePackage rows are never
    touched — evidence already captured is preserved, per the spec's own
    requirement, regardless of what happens to the rest of the plan."""
    plan = (
        db.query(DiscoveryExecutionPlan)
        .filter(DiscoveryExecutionPlan.discovery_run_id == run.id)
        .first()
    )
    if plan is None or plan.status in TERMINAL_EXECUTION_PLAN_STATUSES:
        return plan

    stages = db.query(ExecutionStage).filter(ExecutionStage.execution_plan_id == plan.id).all()
    for stage in stages:
        if stage.status in TERMINAL_EXECUTION_STAGE_STATUSES:
            continue  # already finished — its real outcome is left alone

        jobs = (
            db.query(ProviderExecution)
            .filter(ProviderExecution.execution_stage_id == stage.id)
            .all()
        )
        for job in jobs:
            if job.status in TERMINAL_PROVIDER_EXECUTION_STATUSES:
                continue  # already completed/failed — real outcome preserved, not overwritten
            previous_state = job.status
            release_lease(db, job.id)
            transition_provider_execution(job, ProviderExecutionStatus.CANCELLED.value)
            job.completed_at = utcnow()
            db.add(job)
            _write_audit(
                db,
                organization_id=plan.organization_id,
                event_type=PROVIDER_EXECUTION_AUDIT_CANCELLED,
                metadata=with_lifecycle_audit_metadata(
                    _with_process_context({"providerExecutionId": job.id, "executionStageId": stage.id}, run),
                    LifecycleAuditDetails(
                        object_type="provider_execution",
                        object_id=job.id,
                        family=LifecycleFamily.EXECUTION,
                        source=LifecycleTransitionSource.SYSTEM_EXECUTED,
                        previous_state=previous_state,
                        current_state=job.status,
                    ),
                ),
            )

        stage.status = ExecutionStageStatus.CANCELLED.value
        stage.completed_at = utcnow()
        db.add(stage)
        _write_audit(
            db,
            organization_id=plan.organization_id,
            event_type=EXECUTION_STAGE_AUDIT_CANCELLED,
            metadata=_with_process_context({"executionStageId": stage.id, "stageKey": stage.stage_key}, run),
        )

    transition_discovery_execution_plan(plan, ExecutionPlanStatus.CANCELLED.value)
    plan.completed_at = utcnow()
    db.add(plan)
    return plan


__all__ = ["cancel_execution_plan"]
