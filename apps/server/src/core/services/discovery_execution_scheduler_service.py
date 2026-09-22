"""Step 4.2 Part 2 — DISC-22: the DAG runner.

Two responsibilities, deliberately kept independently testable from the
Celery task that calls them (src/core/tasks/discovery_execution_tasks.py
is a thin wrapper — business logic never lives inside a @task-decorated
function itself):

* ``dispatch_ready_jobs`` — the periodic "start work" sweep: find every
  READY stage's PENDING jobs and call each registered provider's
  ``execute()``. Runs globally across every organisation's plans, with no
  tenant-scoped request context, matching the one existing precedent for
  this shape of background work in this repo (``AssetMonitoringEngine``'s
  own all-assets sweep) — this is the system's own internal orchestration,
  not a response to any one tenant's request. Caps how many PENDING jobs it
  actually dispatches per stage per sweep at that stage's own
  ``plan_definition.stagePolicies[stage].maxParallelJobs`` (DISC-21's own
  derivation, computed but left unenforced until DISC-29) — counts jobs
  already LEASED/RUNNING under the stage as occupying a slot, leaves the
  rest PENDING for a later sweep once capacity frees up.
* ``advance_stage_completion`` — called the moment a job reaches a
  terminal status (from discovery_execution_command_service, both the
  acknowledgement-reject path and the result-reporting path), not on the
  next periodic tick. Rolls a stage's status up once every one of its jobs
  is terminal, promotes dependent stages from PENDING to READY once every
  stage they depend on is itself terminal (a permanently FAILED dependency
  still unblocks what depends on it — spec's own Failure Isolation
  principle: one failed provider must never invalidate an entire
  discovery), and rolls the whole plan's status up once every stage is
  terminal.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.discovery_execution_enums import (
    EXECUTION_PLAN_AUDIT_COMPLETED,
    EXECUTION_PLAN_AUDIT_COMPLETED_WITH_WARNINGS,
    EXECUTION_PLAN_AUDIT_FAILED,
    EXECUTION_PLAN_AUDIT_PARTIALLY_COMPLETED,
    EXECUTION_STAGE_AUDIT_COMPLETED,
    EXECUTION_STAGE_AUDIT_FAILED,
    EXECUTION_STAGE_AUDIT_PARTIALLY_COMPLETED,
    EXECUTION_STAGE_AUDIT_STARTED,
    PROVIDER_EXECUTION_AUDIT_COMPLETED,
    PROVIDER_EXECUTION_AUDIT_FAILED,
    PROVIDER_EXECUTION_AUDIT_STARTED,
    TERMINAL_EXECUTION_PLAN_STATUSES,
    TERMINAL_EXECUTION_STAGE_STATUSES,
    TERMINAL_PROVIDER_EXECUTION_STATUSES,
    ExecutionMode,
    ExecutionPlanStatus,
    ExecutionStageStatus,
    ProviderExecutionStatus,
)
from src.core.constants.discovery_run_enums import (
    TERMINAL_DISCOVERY_RUN_STATUSES,
    DiscoveryRunStatus,
)
from src.core.constants.lifecycle_enums import LifecycleFamily, LifecycleTransitionSource
from src.core.model_defs.discovery_execution import (
    DiscoveryExecutionPlan,
    ExecutionStage,
    ExecutionStageDependency,
    ProviderExecution,
)
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.services.discovery_command_service import utcnow
from src.core.services.discovery_execution_plan_lifecycle_service import (
    transition_discovery_execution_plan,
)
from src.core.services.discovery_execution_retry_service import handle_job_failure
from src.core.services.discovery_providers import ProviderNotRegisteredError, get_provider
from src.core.services.discovery_run_service import transition_discovery_run
from src.core.services.lifecycle_audit_service import (
    LifecycleAuditDetails,
    with_lifecycle_audit_metadata,
)


def _write_audit(db: Session, *, organization_id: int, event_type: str, metadata: dict) -> None:
    # System-triggered (periodic sweep / cascade), never a human actor —
    # same convention as discovery_execution_agent.py's own _write_audit.
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=None,
            event_type=event_type,
            metadata_json=metadata,
        )
    )


def _with_process_context(metadata: dict, run: DiscoveryRun | None) -> dict:
    """CA-04.8 — camelCase, matching this file's own existing metadata
    keys (executionStageId, providerExecutionId, ...). run is Optional
    because a data-inconsistency case (orphaned plan/stage) must still
    produce a real audit event rather than raising — same defensive
    stance _write_audit's own organization_id=None guard already takes
    elsewhere in this codebase."""
    return {
        **metadata,
        "businessProcessId": run.business_process_id if run is not None else None,
        "businessServiceId": run.business_service_id if run is not None else None,
        "slotInstanceId": None,
    }


def _run_for_stage(db: Session, stage: ExecutionStage) -> DiscoveryRun | None:
    plan = db.get(DiscoveryExecutionPlan, stage.execution_plan_id)
    if plan is None:
        return None
    return db.get(DiscoveryRun, plan.discovery_run_id)


def _max_parallel_jobs_for_stage(plan: DiscoveryExecutionPlan, stage_key: str) -> int | None:
    """Reads plan_definition.stagePolicies[stage_key].maxParallelJobs
    (DISC-21's own per-stage derivation from registered providers' declared
    capabilities — computed at plan generation but never enforced until
    now, DISC-26/29's Gap C). Returns None (uncapped) only when the policy
    is genuinely missing — a plan generated before this existed, or a data
    inconsistency — never silently drops jobs because of a lookup gap."""
    stage_policies = plan.plan_definition.get("stagePolicies", {}) if plan.plan_definition else {}
    policy = stage_policies.get(stage_key)
    if not policy:
        return None
    return policy.get("maxParallelJobs")


def dispatch_ready_jobs(db: Session) -> list[ProviderExecution]:
    dispatched: list[ProviderExecution] = []
    ready_stages = (
        db.query(ExecutionStage)
        .filter(ExecutionStage.status == ExecutionStageStatus.READY.value)
        .all()
    )

    for stage in ready_stages:
        pending_jobs = (
            db.query(ProviderExecution)
            .filter(
                ProviderExecution.execution_stage_id == stage.id,
                ProviderExecution.status == ProviderExecutionStatus.PENDING.value,
            )
            .all()
        )
        if not pending_jobs:
            continue
        run = _run_for_stage(db, stage)
        if run is None:
            continue

        plan = db.get(DiscoveryExecutionPlan, stage.execution_plan_id)
        max_parallel = (
            _max_parallel_jobs_for_stage(plan, stage.stage_key) if plan is not None else None
        )
        if max_parallel is not None:
            in_flight_count = (
                db.query(ProviderExecution)
                .filter(
                    ProviderExecution.execution_stage_id == stage.id,
                    ProviderExecution.status.in_(
                        [
                            ProviderExecutionStatus.LEASED.value,
                            ProviderExecutionStatus.RUNNING.value,
                        ]
                    ),
                )
                .count()
            )
            available_slots = max_parallel - in_flight_count
            if available_slots <= 0:
                continue  # stage is at its concurrency cap this sweep — try again next tick
            pending_jobs = pending_jobs[:available_slots]

        if stage.started_at is None:
            # First dispatch under this stage — stage.status deliberately
            # stays READY (not a new RUNNING transition): DISC-29's own
            # concurrency cap relies on dispatch_ready_jobs's query still
            # matching this stage on a later sweep to pick up whatever
            # PENDING work the cap held back this time. started_at is the
            # one-time "has this stage begun" signal instead.
            stage.started_at = utcnow()
            db.add(stage)
            _write_audit(
                db,
                organization_id=run.organization_id,
                event_type=EXECUTION_STAGE_AUDIT_STARTED,
                metadata=_with_process_context({"executionStageId": stage.id, "stageKey": stage.stage_key}, run),
            )

        for job in pending_jobs:
            try:
                provider = get_provider(job.provider_id)
            except ProviderNotRegisteredError:
                handle_job_failure(
                    db, job, failure_code="provider_not_registered", failure_message=None
                )
                advance_stage_completion(db, stage.id)
                continue

            try:
                outcome = provider.execute(db, run=run, provider_execution=job)
            except Exception as exc:  # noqa: BLE001 — the spec's own Failure Isolation
                # principle requires this: a provider is arbitrary plugin
                # code (today Nmap, tomorrow Azure/AWS/GitHub/...), and one
                # provider's bug must never stop the sweep from dispatching
                # every other job. Matches the one existing precedent for
                # this shape of guarded background-loop boundary in this
                # repo (AssetMonitoringEngine._run_loop's own broad catch),
                # not a general habit — never used outside this one
                # plugin-call boundary.
                handle_job_failure(
                    db, job, failure_code="provider_execution_error", failure_message=str(exc)
                )
                advance_stage_completion(db, stage.id)
                continue

            if outcome.mode == ExecutionMode.DIRECT.value and outcome.result is not None:
                # A DIRECT provider's result is already known synchronously
                # — apply it now rather than waiting for a report-back that
                # will never come (that path is only for DELEGATED jobs).
                # No DIRECT provider is registered yet (every registered
                # provider today — Nmap/Subfinder/Nuclei — is DELEGATED)
                # — this branch and its audit events build the mechanism
                # for when one is, not exercised by any real provider
                # today. CA-04.5 — a FAILED result now goes through
                # handle_job_failure like every DELEGATED failure path
                # already does, closing the gap this branch previously
                # carried (a FAILED result applied verbatim, bypassing
                # retry classification entirely).
                job.started_at = job.started_at or utcnow()
                _write_audit(
                    db,
                    organization_id=run.organization_id,
                    event_type=PROVIDER_EXECUTION_AUDIT_STARTED,
                    metadata=_with_process_context({"providerExecutionId": job.id, "providerId": job.provider_id}, run),
                )
                job.checkpoint = outcome.result.checkpoint
                if outcome.result.status == ProviderExecutionStatus.FAILED.value:
                    handle_job_failure(
                        db,
                        job,
                        failure_code=outcome.result.failure_code or "direct_provider_failure",
                        failure_message=outcome.result.failure_message,
                    )
                else:
                    job.status = outcome.result.status
                    job.completed_at = utcnow()
                    db.add(job)
                    if job.status == ProviderExecutionStatus.COMPLETED.value:
                        _write_audit(
                            db,
                            organization_id=run.organization_id,
                            event_type=PROVIDER_EXECUTION_AUDIT_COMPLETED,
                            metadata=_with_process_context({"providerExecutionId": job.id}, run),
                        )
                advance_stage_completion(db, stage.id)

            dispatched.append(job)

    return dispatched


def _promote_dependent_stages(db: Session, completed_stage: ExecutionStage) -> None:
    dependent_edges = (
        db.query(ExecutionStageDependency)
        .filter(ExecutionStageDependency.depends_on_stage_id == completed_stage.id)
        .all()
    )
    for edge in dependent_edges:
        dependent_stage = db.get(ExecutionStage, edge.execution_stage_id)
        if dependent_stage is None or dependent_stage.status != ExecutionStageStatus.PENDING.value:
            continue
        remaining_edges = (
            db.query(ExecutionStageDependency)
            .filter(ExecutionStageDependency.execution_stage_id == dependent_stage.id)
            .all()
        )
        dependency_stage_ids = [edge.depends_on_stage_id for edge in remaining_edges]
        dependency_stages = (
            db.query(ExecutionStage).filter(ExecutionStage.id.in_(dependency_stage_ids)).all()
        )
        if dependency_stages and all(
            s.status in TERMINAL_EXECUTION_STAGE_STATUSES for s in dependency_stages
        ):
            dependent_stage.status = ExecutionStageStatus.READY.value
            db.add(dependent_stage)


def _advance_plan_completion(db: Session, execution_plan_id: str) -> None:
    plan = db.get(DiscoveryExecutionPlan, execution_plan_id)
    if plan is None or plan.status in TERMINAL_EXECUTION_PLAN_STATUSES:
        return
    stages = db.query(ExecutionStage).filter(ExecutionStage.execution_plan_id == plan.id).all()
    if not stages or not all(s.status in TERMINAL_EXECUTION_STAGE_STATUSES for s in stages):
        return

    # DISC-30: an optional stage's (ExecutionStage.required=False) total
    # failure must never fail the whole plan the way a required stage's
    # would — only required stages count toward COMPLETED/FAILED/
    # PARTIALLY_COMPLETED; an all-required-stages-succeeded plan where an
    # optional stage still fell short is COMPLETED_WITH_WARNINGS instead,
    # a distinct outcome from a required stage itself falling short.
    required_stages = [s for s in stages if s.required]
    optional_stages = [s for s in stages if not s.required]
    required_completed = [
        s for s in required_stages if s.status == ExecutionStageStatus.COMPLETED.value
    ]
    optional_not_fully_successful = [
        s for s in optional_stages if s.status != ExecutionStageStatus.COMPLETED.value
    ]

    previous_state = plan.status
    if len(required_completed) == len(required_stages):
        if optional_not_fully_successful:
            transition_discovery_execution_plan(
                plan, ExecutionPlanStatus.COMPLETED_WITH_WARNINGS.value
            )
            audit_event = EXECUTION_PLAN_AUDIT_COMPLETED_WITH_WARNINGS
            # No DiscoveryRunStatus.COMPLETED_WITH_WARNINGS exists (see
            # ExecutionPlanStatus's own docstring) — mapped to the closest
            # existing run-level status rather than adding one only this
            # pipeline could ever produce.
            run_status = DiscoveryRunStatus.PARTIALLY_COMPLETED.value
        else:
            transition_discovery_execution_plan(plan, ExecutionPlanStatus.COMPLETED.value)
            audit_event = EXECUTION_PLAN_AUDIT_COMPLETED
            run_status = DiscoveryRunStatus.COMPLETED.value
    elif required_completed or any(
        s.status == ExecutionStageStatus.PARTIALLY_COMPLETED.value for s in required_stages
    ):
        transition_discovery_execution_plan(plan, ExecutionPlanStatus.PARTIALLY_COMPLETED.value)
        audit_event = EXECUTION_PLAN_AUDIT_PARTIALLY_COMPLETED
        run_status = DiscoveryRunStatus.PARTIALLY_COMPLETED.value
    else:
        transition_discovery_execution_plan(plan, ExecutionPlanStatus.FAILED.value)
        audit_event = EXECUTION_PLAN_AUDIT_FAILED
        run_status = DiscoveryRunStatus.FAILED.value
    plan.completed_at = utcnow()
    db.add(plan)
    # CA-04.8 — fetched before the audit write below (not after, as this
    # cascade originally read it) purely so business_process_id/
    # business_service_id are in scope for that event's own metadata; the
    # cascade itself still only reads run.status/run_status further down.
    run = db.get(DiscoveryRun, plan.discovery_run_id)
    _write_audit(
        db,
        organization_id=plan.organization_id,
        event_type=audit_event,
        metadata=with_lifecycle_audit_metadata(
            _with_process_context({"executionPlanId": plan.id}, run),
            LifecycleAuditDetails(
                object_type="discovery_execution_plan",
                object_id=plan.id,
                family=LifecycleFamily.EXECUTION,
                source=LifecycleTransitionSource.DERIVED,
                previous_state=previous_state,
                current_state=plan.status,
            ),
        ),
    )

    # DISC-24: cascade up to the run itself — generate_execution_plan()
    # already moved it APPROVED -> RUNNING, so this is the one place that
    # closes the loop, mirroring exactly what record_status_update() does
    # for the original Step 4.1 whole-run flow's own terminal statuses.
    # ExecutionPlanStatus and DiscoveryRunStatus are separate enums (never
    # assume their string values stay aligned) — mapped explicitly above,
    # not passed through as a bare string.
    if run is not None and run.status not in TERMINAL_DISCOVERY_RUN_STATUSES:
        transition_discovery_run(run, run_status)
        if run_status == DiscoveryRunStatus.FAILED.value:
            run.failed_at = utcnow()
        else:
            run.completed_at = utcnow()
        db.add(run)


def _current_jobs_for_stage(db: Session, execution_stage_id: str) -> list[ProviderExecution]:
    """The latest attempt in each retry chain only — once DISC-27/28's
    retry engine spawns a new sibling row for a RETRY_SCHEDULED job, that
    old row is never mutated (retry_of_provider_execution_id, the same
    identity-stays-stable convention as DiscoveryRun's own retry chain), so
    it must be excluded here or a superseded RETRY_SCHEDULED row would keep
    "is every job under this stage terminal" false forever, even after its
    replacement actually completes."""
    jobs = (
        db.query(ProviderExecution)
        .filter(ProviderExecution.execution_stage_id == execution_stage_id)
        .all()
    )
    superseded_ids = {
        job.retry_of_provider_execution_id for job in jobs if job.retry_of_provider_execution_id
    }
    return [job for job in jobs if job.id not in superseded_ids]


def advance_stage_completion(db: Session, execution_stage_id: str) -> None:
    """Call once a job under this stage reaches a terminal status — from
    the acknowledgement-reject path and the result-reporting path in
    discovery_execution_command_service.py, not on a delay."""
    stage = db.get(ExecutionStage, execution_stage_id)
    if stage is None or stage.status in TERMINAL_EXECUTION_STAGE_STATUSES:
        return

    jobs = _current_jobs_for_stage(db, stage.id)
    if not jobs or not all(job.status in TERMINAL_PROVIDER_EXECUTION_STATUSES for job in jobs):
        return  # still work outstanding under this stage

    completed_jobs = [job for job in jobs if job.status == ProviderExecutionStatus.COMPLETED.value]
    if len(completed_jobs) == len(jobs):
        stage.status = ExecutionStageStatus.COMPLETED.value
        audit_event = EXECUTION_STAGE_AUDIT_COMPLETED
    elif completed_jobs:
        stage.status = ExecutionStageStatus.PARTIALLY_COMPLETED.value
        audit_event = EXECUTION_STAGE_AUDIT_PARTIALLY_COMPLETED
    else:
        stage.status = ExecutionStageStatus.FAILED.value
        audit_event = EXECUTION_STAGE_AUDIT_FAILED
    stage.completed_at = utcnow()
    db.add(stage)

    plan = db.get(DiscoveryExecutionPlan, stage.execution_plan_id)
    if plan is not None:
        run = _run_for_stage(db, stage)  # CA-04.8 — for this event's business_process_id/business_service_id only
        _write_audit(
            db,
            organization_id=plan.organization_id,
            event_type=audit_event,
            metadata=_with_process_context({"executionStageId": stage.id, "stageKey": stage.stage_key}, run),
        )

    _promote_dependent_stages(db, stage)
    _advance_plan_completion(db, stage.execution_plan_id)
