"""Step 4.1 — cancellation requests and retry (spec §17/§18).

Acts on an *existing* DiscoveryRun rather than creating one — kept apart
from ``discovery_run_service`` for SRP. A retry never resurrects a failed
run; it always creates a brand-new row via ``create_discovery_run`` (fresh
preconditions, fresh snapshots) linked back through
``retry_of_discovery_run_id``, per spec §18's explicit "retry must create
a new discovery run, do not reset a failed run to QUEUED."
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.discovery_run_enums import (
    DISCOVERY_RUN_ERROR_DISCOVERY_NOT_RETRYABLE,
    NON_RETRYABLE_FAILURE_CODES,
    RETRYABLE_FAILURE_CODES,
    TERMINAL_DISCOVERY_RUN_STATUSES,
    DiscoveryCancellationReasonCode,
    DiscoveryPurpose,
    DiscoveryRunStatus,
    ScannerCommandStatus,
)
from src.core.constants.discovery_execution_enums import (
    TERMINAL_PROVIDER_EXECUTION_STATUSES,
    ProviderExecutionStatus,
)
from src.core.model_defs.discovery_execution import (
    DiscoveryExecutionPlan,
    ExecutionStage,
    ProviderExecution,
)
from src.core.model_defs.discovery_run import DiscoveryRun, ScannerCommand
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.model_defs.tenant_org import Organization
from src.core.services.discovery_run_service import (
    DiscoveryRunValidationError,
    create_discovery_run,
    transition_discovery_run,
    utcnow,
)


@dataclass(frozen=True)
class DiscoveryRetryEvaluation:
    allowed: bool
    reason_code: str | None = None
    reason_message: str | None = None


def request_cancellation(
    db: Session,
    run: DiscoveryRun,
    *,
    cancelled_by_user_id: int,
    reason_code: str | None = None,
    reason_note: str | None = None,
) -> DiscoveryRun:
    if run.status in TERMINAL_DISCOVERY_RUN_STATUSES or run.status == DiscoveryRunStatus.BLOCKED.value:
        raise DiscoveryRunValidationError("This discovery run has already finished and cannot be cancelled.")

    if run.status == DiscoveryRunStatus.CANCELLATION_REQUESTED.value:
        # Asking again is not an error. Cancellation was already requested and
        # the run is waiting for outstanding work to stop; pressing the button a
        # second time used to attempt CANCELLATION_REQUESTED ->
        # CANCELLATION_REQUESTED and surface the raw state-machine message
        # ("This action is not valid for the discovery run's current state.
        # (cancellation_requested -> cancellation_requested)") on a screen an
        # executive is looking at. The caller re-applies plan cancellation and
        # finalises if nothing is left, which is what the user was asking for.
        return run

    if reason_code is not None:
        try:
            resolved_reason = DiscoveryCancellationReasonCode(reason_code)
        except ValueError:
            raise DiscoveryRunValidationError(f"'{reason_code}' is not a recognised cancellation reason.") from None
        if resolved_reason == DiscoveryCancellationReasonCode.OTHER and not (reason_note or "").strip():
            raise DiscoveryRunValidationError("A note is required when the cancellation reason is 'other'.")
        run.cancellation_reason_code = resolved_reason.value
        run.cancellation_reason_note = (reason_note or "").strip() or None

    run.cancellation_requested_at = utcnow()
    run.cancellation_requested_by_user_id = cancelled_by_user_id

    if run.status in (
        DiscoveryRunStatus.DRAFT.value,
        DiscoveryRunStatus.VALIDATING.value,
        DiscoveryRunStatus.AWAITING_APPROVAL.value,
        DiscoveryRunStatus.APPROVED.value,
        DiscoveryRunStatus.QUEUED.value,
        DiscoveryRunStatus.COMMAND_AVAILABLE.value,
    ):
        # "Before acknowledgement" (spec §17) — no command has been
        # acknowledged by the scanner yet, so cancel outright and
        # invalidate any command that was already created for this run.
        transition_discovery_run(run, DiscoveryRunStatus.CANCELLED.value)
        run.cancelled_at = utcnow()
        pending_command = (
            db.query(ScannerCommand)
            .filter(
                ScannerCommand.discovery_run_id == run.id,
                ScannerCommand.status.in_((ScannerCommandStatus.PENDING.value, ScannerCommandStatus.DELIVERED.value)),
            )
            .first()
        )
        if pending_command is not None:
            pending_command.status = ScannerCommandStatus.CANCELLED.value
            db.add(pending_command)
    else:
        # ACKNOWLEDGED / RUNNING — genuinely "after acknowledgement" (spec
        # §17). This foundation records the request; actually honouring a
        # mid-run stop depends on Step 4.2's live execution loop, which
        # does not exist yet — disclosed in TASKS.md, not silently implied
        # as complete.
        transition_discovery_run(run, DiscoveryRunStatus.CANCELLATION_REQUESTED.value)

    db.add(run)
    return run


def finalise_cancellation_if_settled(db: Session, run: DiscoveryRun) -> DiscoveryRun:
    """Complete a cancellation once nothing is still running.

    Without this a run stayed in CANCELLATION_REQUESTED forever: the transition
    to CANCELLED is legal and nothing performed it, so the panel read
    "Cancellation requested — waiting for the scanner to acknowledge and stop"
    indefinitely, even after every job had stopped. A cancellation the user
    cannot complete is not a cancellation.

    "Settled" means no job is still outstanding. Jobs that already finished keep
    their real recorded outcome — cancelling does not rewrite history — so a run
    whose work all completed before the request still cancels cleanly.
    """
    if run.status != DiscoveryRunStatus.CANCELLATION_REQUESTED.value:
        return run

    plan = (
        db.query(DiscoveryExecutionPlan)
        .filter(DiscoveryExecutionPlan.discovery_run_id == run.id)
        .first()
    )
    if plan is not None:
        stage_ids = [
            stage.id
            for stage in db.query(ExecutionStage).filter(
                ExecutionStage.execution_plan_id == plan.id
            )
        ]
        if stage_ids:
            outstanding = (
                db.query(ProviderExecution)
                .filter(
                    ProviderExecution.execution_stage_id.in_(stage_ids),
                    ProviderExecution.status.notin_(TERMINAL_PROVIDER_EXECUTION_STATUSES),
                    # A RETRY_SCHEDULED row whose schedule has been consumed will
                    # never run again: process_due_retries clears next_retry_at
                    # when it spawns the next attempt, and keeps the original's
                    # status as the historical record of that attempt. Counting
                    # it as outstanding deadlocked the cancellation — the run
                    # waited forever on work that could not happen. Observed on
                    # Søren's run: 8 such rows, cancellation stuck.
                    ~(
                        (ProviderExecution.status == ProviderExecutionStatus.RETRY_SCHEDULED.value)
                        & (ProviderExecution.next_retry_at.is_(None))
                    ),
                )
                .count()
            )
            if outstanding:
                return run

    transition_discovery_run(run, DiscoveryRunStatus.CANCELLED.value)
    run.cancelled_at = utcnow()
    db.add(run)
    return run


def evaluate_retry_eligibility(run: DiscoveryRun) -> DiscoveryRetryEvaluation:
    """Whether a fresh discovery can be started in place of this one.

    Retrying does not resume the old run — ``retry_discovery_run`` creates a
    brand new one and records the link. So the question is only "is the previous
    attempt over?", not "did it fail in a particular way".

    This used to require FAILED, which left every other ending with no way back:
    a cancelled run, a run that finished with limitations, or one that expired
    all offered nothing, and the panel's own error told the user to "retry the
    whole discovery run instead" while no control existed to do it. A run that is
    still going is a different matter — starting a second one alongside it would
    put two discoveries on the same Collector.
    """
    if run.status not in TERMINAL_DISCOVERY_RUN_STATUSES:
        return DiscoveryRetryEvaluation(
            allowed=False,
            reason_code="still_running",
            reason_message="This discovery is still running. Cancel it before starting a new one.",
        )

    # A failure the platform knows will simply happen again (e.g. scope refused)
    # stays blocked, with the same reasoning it always had — but only failures
    # carry a failure_code, so this cannot block a cancelled or completed run.
    code = run.failure_code
    if code is None:
        return DiscoveryRetryEvaluation(allowed=True)
    if code in NON_RETRYABLE_FAILURE_CODES:
        return DiscoveryRetryEvaluation(
            allowed=False, reason_code=code, reason_message=DISCOVERY_RUN_ERROR_DISCOVERY_NOT_RETRYABLE
        )
    if code in RETRYABLE_FAILURE_CODES:
        return DiscoveryRetryEvaluation(allowed=True)
    return DiscoveryRetryEvaluation(
        allowed=False,
        reason_code=code or "unknown_failure",
        reason_message=DISCOVERY_RUN_ERROR_DISCOVERY_NOT_RETRYABLE,
    )


def retry_discovery_run(
    db: Session,
    failed_run: DiscoveryRun,
    *,
    organization: Organization,
    instance: ScannerInstance,
    retried_by_user_id: int,
) -> DiscoveryRun:
    evaluation = evaluate_retry_eligibility(failed_run)
    if not evaluation.allowed:
        raise DiscoveryRunValidationError(evaluation.reason_message or DISCOVERY_RUN_ERROR_DISCOVERY_NOT_RETRYABLE)

    return create_discovery_run(
        db,
        organization=organization,
        instance=instance,
        requested_by_user_id=retried_by_user_id,
        request_source=failed_run.request_source,
        discovery_purpose=DiscoveryPurpose.RETRY.value,
        target_ids=failed_run.target_ids,
        retry_of_discovery_run_id=failed_run.id,
        retry_count=failed_run.retry_count + 1,
        # CA-04.7 — a retry must carry forward the same process/service
        # attribution as the run it replaces, not silently drop it. Note
        # this re-validates against the live ProcessScannerLink (via
        # create_discovery_run's own _resolve_process_context) rather than
        # trusting the original run's now-possibly-stale attribution — a
        # link revoked since the original run would correctly block the
        # retry too, not just silently carry a dead reference forward.
        business_process_id=failed_run.business_process_id,
        business_service_id=failed_run.business_service_id,
    )
