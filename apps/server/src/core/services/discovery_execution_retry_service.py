"""Step 4.2 Part 2 — DISC-27/28: lease-expiry reconciliation + retry engine.

Two real gaps closed here (see TASKS.md DISC-26's reconciliation):

* Gap A — ``WorkerLease.lease_expires_at`` was set at lease creation but
  never read anywhere. ``reconcile_expired_leases`` is the periodic sweep
  that finds a dead/offline scanner's stale lease and unblocks the job it
  was holding, instead of letting a single silent worker permanently stall
  a plan.
* Gap B — ``RETRYABLE_PROVIDER_FAILURE_CODES``/``NON_RETRYABLE_PROVIDER_
  FAILURE_CODES`` were defined but never consulted. ``handle_job_failure``
  is now the one place any ProviderExecution failure (rejected command,
  reported failure, evidence-storage failure, lease expiry, dispatch-time
  provider error) gets classified and routed to either a scheduled retry or
  a terminal failure.

A retried job is a brand-new sibling row (``retry_of_provider_execution_id``),
never a mutated one — the same identity-stays-stable convention as
``DiscoveryRun.retry_of_discovery_run_id``. ``handle_job_failure`` never
calls ``discovery_execution_scheduler_service.advance_stage_completion``
itself: every call site already calls it immediately afterwards (the
existing per-call-site convention from DISC-20/22), so this module never
needs a module-level import of ``discovery_execution_scheduler_service`` —
`reconcile_expired_leases` uses a local (function-scoped) import instead,
matching this repo's own established pattern for breaking this exact class
of cycle (``nmap_provider.py``, ``discovery_command_service.py``), since
``discovery_execution_scheduler_service`` in turn needs to import
``handle_job_failure`` from this module for its own dispatch-time failure
branches.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from src.core.constants.discovery_execution_enums import (
    NON_RETRYABLE_PROVIDER_FAILURE_CODES,
    PROVIDER_EXECUTION_AUDIT_FAILED,
    PROVIDER_EXECUTION_AUDIT_LEASE_RECLAIMED,
    PROVIDER_EXECUTION_AUDIT_RETRY_QUEUED,
    RETRYABLE_PROVIDER_FAILURE_CODES,
    TERMINAL_EXECUTION_PLAN_STATUSES,
    TERMINAL_EXECUTION_STAGE_STATUSES,
    ExecutionStageStatus,
    ProviderExecutionStatus,
)
from src.core.constants.lifecycle_enums import LifecycleFamily, LifecycleTransitionSource
from src.core.model_defs.discovery_execution import (
    DiscoveryExecutionPlan,
    ExecutionStage,
    ProviderExecution,
    WorkerLease,
)
from src.core.constants.discovery_run_enums import DiscoveryRunStatus
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.services.discovery_command_service import utcnow
from src.core.services.discovery_providers import ProviderNotRegisteredError, get_provider
from src.core.services.lifecycle_audit_service import (
    LifecycleAuditDetails,
    with_lifecycle_audit_metadata,
)
from src.core.services.provider_execution_lifecycle_service import transition_provider_execution

_DEFAULT_MAX_ATTEMPTS = 3
_DEFAULT_BACKOFF_SECONDS = 30


def _organization_id_for_job(db: Session, job: ProviderExecution) -> int | None:
    stage = db.get(ExecutionStage, job.execution_stage_id)
    if stage is None:
        return None
    plan = db.get(DiscoveryExecutionPlan, stage.execution_plan_id)
    return plan.organization_id if plan is not None else None


# A run in one of these states has stopped wanting results: it is cancelling,
# or its outcome is already recorded. Derived from the transition table's own
# terminal set plus the cancelling state, so it cannot drift from what the run
# lifecycle considers finished.
_RUN_STATUSES_NOT_ACCEPTING_WORK: frozenset[str] = frozenset(
    {
        DiscoveryRunStatus.CANCELLATION_REQUESTED.value,
        DiscoveryRunStatus.CANCELLED.value,
        DiscoveryRunStatus.COMPLETED.value,
        DiscoveryRunStatus.PARTIALLY_COMPLETED.value,
        DiscoveryRunStatus.FAILED.value,
        DiscoveryRunStatus.EXPIRED.value,
    }
)


def _run_for_job(db: Session, job: ProviderExecution) -> DiscoveryRun | None:
    """CA-04.8 — same stage->plan chain as _organization_id_for_job, one
    hop further to the run itself, purely so this module's own audit
    events can carry business_process_id/business_service_id."""
    stage = db.get(ExecutionStage, job.execution_stage_id)
    if stage is None:
        return None
    plan = db.get(DiscoveryExecutionPlan, stage.execution_plan_id)
    if plan is None:
        return None
    return db.get(DiscoveryRun, plan.discovery_run_id)


def _with_process_context(metadata: dict, run: DiscoveryRun | None) -> dict:
    """CA-04.8 — camelCase, matching this file's own existing metadata
    keys. run is Optional (a data-inconsistency case must still produce a
    real audit event, same stance _organization_id_for_job's own None
    return already takes)."""
    return {
        **metadata,
        "businessProcessId": run.business_process_id if run is not None else None,
        "businessServiceId": run.business_service_id if run is not None else None,
        "slotInstanceId": None,
    }


def _write_audit(
    db: Session,
    *,
    organization_id: int | None,
    event_type: str,
    metadata: dict,
    actor_user_id: int | None = None,
) -> None:
    if organization_id is None:
        return  # a data-inconsistency case (orphaned job/stage) — never fabricate an org to attribute this to
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            event_type=event_type,
            metadata_json=metadata,
        )
    )


def release_lease(db: Session, provider_execution_id: str) -> None:
    """The one definition of "release this job's active lease" — used by
    every failure path here and by the plain success path in
    discovery_execution_command_service.record_provider_execution_result."""
    lease = (
        db.query(WorkerLease)
        .filter(
            WorkerLease.provider_execution_id == provider_execution_id,
            WorkerLease.released_at.is_(None),
        )
        .first()
    )
    if lease is not None:
        lease.released_at = utcnow()
        db.add(lease)


def _retry_policy_for(provider_id: str) -> tuple[int, int]:
    try:
        recommendation = get_provider(provider_id).capabilities().retry_recommendation
    except ProviderNotRegisteredError:
        return _DEFAULT_MAX_ATTEMPTS, _DEFAULT_BACKOFF_SECONDS
    return (
        recommendation.get("maxAttempts", _DEFAULT_MAX_ATTEMPTS),
        recommendation.get("backoffSeconds", _DEFAULT_BACKOFF_SECONDS),
    )


def _terminal_fail(
    db: Session, job: ProviderExecution, *, failure_code: str, failure_message: str | None
) -> None:
    previous_state = job.status
    transition_provider_execution(job, ProviderExecutionStatus.FAILED.value)
    job.failure_code = failure_code
    job.failure_message = failure_message
    job.completed_at = utcnow()
    db.add(job)
    _write_audit(
        db,
        organization_id=_organization_id_for_job(db, job),
        event_type=PROVIDER_EXECUTION_AUDIT_FAILED,
        metadata=with_lifecycle_audit_metadata(
            _with_process_context({"providerExecutionId": job.id, "failureCode": failure_code}, _run_for_job(db, job)),
            LifecycleAuditDetails(
                object_type="provider_execution",
                object_id=job.id,
                family=LifecycleFamily.EXECUTION,
                source=LifecycleTransitionSource.SYSTEM_EXECUTED,
                previous_state=previous_state,
                current_state=job.status,
                reason_code=failure_code,
            ),
        ),
    )


def handle_job_failure(
    db: Session, job: ProviderExecution, *, failure_code: str, failure_message: str | None
) -> None:
    """The one place a ProviderExecution failure gets classified. Always
    releases the job's lease first. Non-retryable codes and codes that have
    exhausted the provider's own declared maxAttempts terminal-fail
    immediately; everything else in RETRYABLE_PROVIDER_FAILURE_CODES gets a
    new RETRY_SCHEDULED status with an exponential-backoff next_retry_at.
    Caller must call advance_stage_completion(db, job.execution_stage_id)
    immediately afterwards regardless of outcome — this function never does
    so itself (see module docstring)."""
    release_lease(db, job.id)

    if failure_code in NON_RETRYABLE_PROVIDER_FAILURE_CODES:
        _terminal_fail(db, job, failure_code=failure_code, failure_message=failure_message)
        return

    max_attempts, backoff_seconds = _retry_policy_for(job.provider_id)
    if failure_code in RETRYABLE_PROVIDER_FAILURE_CODES and job.attempt_number < max_attempts:
        previous_state = job.status
        transition_provider_execution(job, ProviderExecutionStatus.RETRY_SCHEDULED.value)
        job.failure_code = failure_code
        job.failure_message = failure_message
        job.completed_at = utcnow()
        job.next_retry_at = utcnow() + timedelta(
            seconds=backoff_seconds * (2 ** (job.attempt_number - 1))
        )
        db.add(job)
        _write_audit(
            db,
            organization_id=_organization_id_for_job(db, job),
            event_type=PROVIDER_EXECUTION_AUDIT_RETRY_QUEUED,
            metadata=with_lifecycle_audit_metadata(
                _with_process_context(
                    {
                        "providerExecutionId": job.id,
                        "failureCode": failure_code,
                        "nextRetryAt": job.next_retry_at.isoformat(),
                    },
                    _run_for_job(db, job),
                ),
                LifecycleAuditDetails(
                    object_type="provider_execution",
                    object_id=job.id,
                    family=LifecycleFamily.EXECUTION,
                    source=LifecycleTransitionSource.SYSTEM_EXECUTED,
                    previous_state=previous_state,
                    current_state=job.status,
                    reason_code=failure_code,
                ),
            ),
        )
        return

    _terminal_fail(db, job, failure_code=failure_code, failure_message=failure_message)


def reconcile_expired_leases(db: Session) -> list[ProviderExecution]:
    """Periodic sweep (extends dispatch_ready_jobs's own sweep, called
    right before it from the same Celery tick): every WorkerLease still
    unreleased whose lease_expires_at has passed gets released, and its job
    — unless something else already resolved it first — is routed through
    handle_job_failure with failure_code="worker_lease_expired" (already a
    RETRYABLE code), so a dead/offline scanner gets one automatic retry
    instead of permanently stalling the stage/plan."""
    from src.core.services.discovery_execution_scheduler_service import advance_stage_completion

    now = utcnow()
    expired_leases = (
        db.query(WorkerLease)
        .filter(WorkerLease.released_at.is_(None), WorkerLease.lease_expires_at <= now)
        .all()
    )
    reconciled: list[ProviderExecution] = []
    for lease in expired_leases:
        lease.released_at = now
        db.add(lease)

        job = db.get(ProviderExecution, lease.provider_execution_id)
        if job is None or job.status == ProviderExecutionStatus.RETRY_SCHEDULED.value:
            continue  # already resolved (or resolving) via some other path — skip double-processing

        from src.core.constants.discovery_execution_enums import (
            TERMINAL_PROVIDER_EXECUTION_STATUSES,
        )

        if job.status in TERMINAL_PROVIDER_EXECUTION_STATUSES:
            continue

        _write_audit(
            db,
            organization_id=_organization_id_for_job(db, job),
            event_type=PROVIDER_EXECUTION_AUDIT_LEASE_RECLAIMED,
            metadata=_with_process_context(
                {"providerExecutionId": job.id, "workerId": lease.worker_id}, _run_for_job(db, job)
            ),
        )
        handle_job_failure(
            db,
            job,
            failure_code="worker_lease_expired",
            failure_message="Worker lease expired before the job reported a result.",
        )
        advance_stage_completion(db, job.execution_stage_id)
        reconciled.append(job)
    return reconciled


def _run_still_accepts_work(db: Session, job: ProviderExecution) -> bool:
    """Whether the run behind this job is still in a state that wants results.

    Reads the run through the job's own stage -> plan chain, the same route
    ``_organization_id_for_job`` already uses, rather than adding a denormalised
    run id to ProviderExecution.
    """
    run = _run_for_job(db, job)
    if run is None:
        return True  # no run to consult — behave exactly as before
    return run.status not in _RUN_STATUSES_NOT_ACCEPTING_WORK


def process_due_retries(db: Session) -> list[ProviderExecution]:
    """Every RETRY_SCHEDULED job whose next_retry_at has elapsed spawns its
    next attempt as a brand-new sibling PENDING row — the original row's
    identity and RETRY_SCHEDULED status are never mutated (mirrors
    DiscoveryRun.retry_of_discovery_run_id). No stage/plan rollup call is
    needed here: spawning a new PENDING job never makes a stage's work
    "more terminal," only dispatch_ready_jobs picking it up later can."""
    now = utcnow()
    due = (
        db.query(ProviderExecution)
        .filter(
            ProviderExecution.status == ProviderExecutionStatus.RETRY_SCHEDULED.value,
            ProviderExecution.next_retry_at.isnot(None),
            ProviderExecution.next_retry_at <= now,
        )
        # Claim the rows being spawned from, so two concurrent scheduler ticks
        # cannot both spawn a retry for the same original.
        .with_for_update(skip_locked=True)
        .all()
    )
    spawned: list[ProviderExecution] = []
    for original in due:
        # A cancelled or finished run must not have its work resurrected. This
        # query selects RETRY_SCHEDULED jobs organisation-wide with no reference
        # to the run they belong to, so cancelling a run cancelled its *current*
        # jobs and the very next scheduler tick spawned fresh PENDING ones from
        # the retry schedule — the run could never leave CANCELLATION_REQUESTED,
        # and the stage cards kept flipping between "retrying…" and
        # "worker_lease_expired" indefinitely. Observed live on run f8ee58f9:
        # 8 jobs still RETRY_SCHEDULED while the run was cancelling.
        if not _run_still_accepts_work(db, original):
            original.next_retry_at = None  # consume the schedule; do not respawn
            db.add(original)
            continue

        retry_job = ProviderExecution(
            execution_stage_id=original.execution_stage_id,
            provider_id=original.provider_id,
            provider_version=original.provider_version,
            status=ProviderExecutionStatus.PENDING.value,
            attempt_number=original.attempt_number + 1,
            retry_of_provider_execution_id=original.id,
        )
        db.add(retry_job)
        # Consume the schedule. Without this the original stays RETRY_SCHEDULED
        # with a due next_retry_at, so the very next scheduler tick selects it
        # again and spawns another sibling — every 15s, forever. Observed in
        # local testing: one original produced 374 children and a single run
        # accumulated ~10,000 provider executions.
        #
        # Only next_retry_at is cleared, not the status: RETRY_SCHEDULED is the
        # historical record of what happened to this attempt, and the retry
        # chain is followed through retry_of_provider_execution_id.
        original.next_retry_at = None
        db.add(original)
        spawned.append(retry_job)
    return spawned


class ProviderExecutionRetryError(ValueError):
    def __init__(self, reason_code: str, message: str):
        self.reason_code = reason_code
        super().__init__(message)


def retry_provider_execution(
    db: Session,
    job: ProviderExecution,
    *,
    actor_user_id: int | None = None,
    acted_as_consultant: bool = False,
) -> ProviderExecution:
    """Step 4.2 Part 3 (DISC-40) — customer-triggered retry of a
    terminally FAILED job. The manual counterpart to process_due_retries's
    automatic spawn: same sibling-row convention
    (retry_of_provider_execution_id, attempt_number + 1), gated on the
    same RETRYABLE_PROVIDER_FAILURE_CODES vocabulary.

    ``actor_user_id``/``acted_as_consultant`` exist because this is the one
    retry path in this module with a real human actor — every other
    _write_audit call site here is system-triggered (scheduler/reconciler),
    correctly actor_user_id=None. Spec §15/§46 requires the audit event to
    record consultant identity when a consultant triggers this.

    Only valid while the plan is still executing. Once a plan reaches a
    terminal status, discovery_execution_scheduler_service._advance_plan_
    completion's own guard never re-evaluates that plan again — spawning a
    new job under an already-terminal plan would silently never be picked
    up or rolled up (this pipeline's own "plan is immutable once execution
    starts" design principle, DISC-17). A discovery run whose plan has
    already gone terminal must use the existing whole-run /retry route
    instead, which generates a fresh plan rather than resurrecting this
    one."""
    if job.status != ProviderExecutionStatus.FAILED.value:
        raise ProviderExecutionRetryError("not_failed", "Only a failed job can be retried.")
    if job.failure_code not in RETRYABLE_PROVIDER_FAILURE_CODES:
        raise ProviderExecutionRetryError("not_retryable", "This job's failure is not retryable.")

    stage = db.get(ExecutionStage, job.execution_stage_id)
    if stage is None:
        raise ProviderExecutionRetryError(
            "stage_not_found", "The stage for this job could not be found."
        )
    plan = db.get(DiscoveryExecutionPlan, stage.execution_plan_id)
    if plan is None or plan.status in TERMINAL_EXECUTION_PLAN_STATUSES:
        raise ProviderExecutionRetryError(
            "plan_already_terminal",
            "This discovery run has already finished — retry the whole discovery run instead.",
        )

    retry_job = ProviderExecution(
        execution_stage_id=job.execution_stage_id,
        provider_id=job.provider_id,
        provider_version=job.provider_version,
        status=ProviderExecutionStatus.PENDING.value,
        attempt_number=job.attempt_number + 1,
        retry_of_provider_execution_id=job.id,
    )
    db.add(retry_job)

    if stage.status in TERMINAL_EXECUTION_STAGE_STATUSES:
        # Re-open the stage so dispatch_ready_jobs's own
        # status == READY query finds this new job — Failure Isolation
        # already let any dependents proceed past this stage while it was
        # failed; re-opening it here doesn't re-block them, it only gives
        # the stage itself another chance.
        stage.status = ExecutionStageStatus.READY.value
        db.add(stage)

    metadata: dict = {
        "providerExecutionId": job.id,
        "retryProviderExecutionId": retry_job.id,
        "trigger": "customer",
    }
    if acted_as_consultant:
        metadata["actor_role"] = "consultant"
    # plan/stage already fetched above, so DiscoveryRun is one more direct
    # FK hop, not a fresh lookup from scratch (CA-04.8).
    run = db.get(DiscoveryRun, plan.discovery_run_id)
    _write_audit(
        db,
        organization_id=_organization_id_for_job(db, job),
        event_type=PROVIDER_EXECUTION_AUDIT_RETRY_QUEUED,
        metadata=with_lifecycle_audit_metadata(
            _with_process_context(metadata, run),
            LifecycleAuditDetails(
                object_type="provider_execution",
                object_id=retry_job.id,
                family=LifecycleFamily.EXECUTION,
                source=LifecycleTransitionSource.HUMAN_INITIATED,
                previous_state=job.status,
                current_state=retry_job.status,
            ),
        ),
        actor_user_id=actor_user_id,
    )
    return retry_job


__all__ = [
    "release_lease",
    "handle_job_failure",
    "reconcile_expired_leases",
    "process_due_retries",
    "retry_provider_execution",
    "ProviderExecutionRetryError",
]
