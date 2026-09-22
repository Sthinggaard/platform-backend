"""Step 4.2 Part 3 (DISC-38) — the customer execution-summary shape.

Three independent derivations that ``discovery_run.py``'s response layer
composes onto ``DiscoveryRunResponse``, matching packages/design-system's
``DiscoveryCollectorView``/``DiscoveryActionRequiredView``/
``DiscoveryEvidenceProcessingView`` byte-for-byte (DISC-42 built that UI
ahead of this backend, against mock data with this exact shape).

``resolve_action_required`` is the one genuinely non-obvious piece: a run
that failed via the Step 4.2 execution pipeline (DISC-24 onward) never
populates ``DiscoveryRun.failure_code``/``failure_message`` — those two
fields are only ever set by the original Step 4.1 pre-execution BLOCKED
path (``discovery_run_service.py``). A pipeline failure's real detail lives
on the failed ``ExecutionStage``/``ProviderExecution`` rows instead, so
this resolver checks the run-level failure first and falls back to the
plan/stage/job level — and, critically, computes ``can_retry`` from
``RETRYABLE_PROVIDER_FAILURE_CODES`` (job-level, DISC-40's new retry
route) rather than the whole-run retry eligibility, which would
incorrectly report every pipeline failure as non-retryable (its
``failure_code`` is ``None``, which is not in either the run-level
retryable or non-retryable set).
"""

from __future__ import annotations

from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.core.constants.discovery_execution_enums import (
    RETRYABLE_PROVIDER_FAILURE_CODES,
    DiscoveryCollectorStatus,
    EvidenceNormalizationStatus,
    ExecutionMode,
    ExecutionStageStatus,
    ProviderExecutionStatus,
)
from src.core.constants.discovery_failure_language import (
    provider_failure_statement,
    run_failure_statement,
)
from src.core.constants.discovery_run_enums import NON_RETRYABLE_FAILURE_CODES, RETRYABLE_FAILURE_CODES
from src.core.constants.evidence_scanner_enums import ScannerInstanceStatus
from src.core.model_defs.common import to_utc_iso
from src.core.model_defs.discovery_execution import DiscoveryExecutionPlan, EvidencePackage, ExecutionStage, ProviderExecution
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.services.evidence_scanner_service import (
    resolve_collector_restart_guidance,
    resolve_scanner_liveness,
)
from src.core.services.discovery_providers import ProviderNotRegisteredError, get_provider
from src.api.schemas.timestamps import UtcTimestamp


class DiscoveryCollectorView(BaseModel):
    required: bool
    status: str
    display_name: str | None
    last_seen_at: UtcTimestamp | None
    installed_version: str | None
    required_version: str | None
    safe_message: str | None
    # UX-DISC-06 — what to do about it. Populated only when the Collector is
    # actually stopped: guidance attached to a healthy Collector is noise, and
    # noise is how people learn to stop reading the panel.
    restart_command: str | None = None
    restart_host_label: str | None = None
    #: False when starting it is not this user's to do (consultant-assisted
    #: installs), so the view can point at the right party instead of showing a
    #: command they cannot run.
    restart_self_service: bool = True


class DiscoveryActionRequiredView(BaseModel):
    code: str
    title: str
    message: str
    affected_stage_key: str | None
    suggested_action: str | None
    can_retry: bool
    support_recommended: bool
    # None for a run-level (pre-execution BLOCKED) failure, where the
    # existing whole-run /retry route is the only retry surface. Set to
    # the specific failed job's id for a pipeline failure — the frontend
    # needs this to call DISC-40's job-level retry route rather than the
    # whole-run one, which never recognises a pipeline failure as
    # retryable (see this module's own docstring).
    provider_execution_id: str | None


class DiscoveryEvidenceProcessingView(BaseModel):
    packages_received: int
    packages_awaiting_processing: int
    packages_processing: int
    packages_processed: int
    packages_failed_processing: int


_COLLECTOR_SAFE_MESSAGES: dict[str, str] = {
    # Names the one action available, per UX-DISC-06: a user staring at a run
    # that never finishes needs to know it is waiting on their own machine, and
    # what to do about it — not just that something is "not reporting".
    DiscoveryCollectorStatus.OFFLINE.value: (
        "The secure collector has stopped reporting, so this discovery cannot continue. "
        "Start it again on the machine it is installed on."
    ),
    DiscoveryCollectorStatus.UNAVAILABLE.value: "The secure collector needs attention before discovery can continue.",
}


def _plan_requires_a_collector(db: Session, plan: DiscoveryExecutionPlan | None) -> bool:
    """DELEGATED providers (e.g. Nmap) run on the customer's own scanner;
    DIRECT providers (a future cloud connector) do not. A plan needs a
    collector if any of its jobs use a DELEGATED provider. No plan yet
    (still preparing) is treated as requiring one — every provider
    registered today (DISC-20) is DELEGATED, so this is never wrong in
    practice, and it becomes correctly derived rather than hardcoded the
    day a DIRECT-only provider exists."""
    if plan is None:
        return True
    stages = db.query(ExecutionStage).filter(ExecutionStage.execution_plan_id == plan.id).all()
    if not stages:
        return True
    stage_ids = [stage.id for stage in stages]
    provider_ids = {
        job.provider_id for job in db.query(ProviderExecution).filter(ProviderExecution.execution_stage_id.in_(stage_ids)).all()
    }
    for provider_id in provider_ids:
        try:
            if get_provider(provider_id).capabilities().execution_mode == ExecutionMode.DELEGATED.value:
                return True
        except ProviderNotRegisteredError:
            continue
    return False


def resolve_collector_view(db: Session, instance: ScannerInstance, plan: DiscoveryExecutionPlan | None) -> DiscoveryCollectorView:
    required = _plan_requires_a_collector(db, plan)
    if not required:
        return DiscoveryCollectorView(
            required=False,
            status=DiscoveryCollectorStatus.NOT_REQUIRED.value,
            display_name=None,
            last_seen_at=None,
            installed_version=None,
            required_version=None,
            safe_message=None,
        )

    # Derived, not read: instance.status only ever rises to ONLINE, so a
    # stopped Collector would otherwise report READY while the run waits on it
    # forever (BUG-DISC-05).
    effective_status = resolve_scanner_liveness(instance)

    status = (
        DiscoveryCollectorStatus.READY.value
        if effective_status == ScannerInstanceStatus.ONLINE.value
        else DiscoveryCollectorStatus.OFFLINE.value
        if effective_status == ScannerInstanceStatus.OFFLINE.value
        # DEGRADED/REGISTERED/PAUSED/REVOKED/RETIRED all fall back to the
        # generic bucket — see the enum's own docstring for why
        # UPGRADE_REQUIRED/PERMISSION_REQUIRED are never derived here.
        else DiscoveryCollectorStatus.UNAVAILABLE.value
    )

    # Only when it is genuinely not running. UNAVAILABLE covers paused, revoked
    # and retired too — states a person chose — and telling someone to start a
    # Collector they deliberately paused would be wrong.
    guidance = (
        resolve_collector_restart_guidance(instance)
        if status == DiscoveryCollectorStatus.OFFLINE.value
        else None
    )

    return DiscoveryCollectorView(
        required=True,
        status=status,
        display_name=instance.name,
        last_seen_at=to_utc_iso(instance.last_heartbeat_at) if instance.last_heartbeat_at else None,
        installed_version=instance.scanner_version,
        required_version=None,
        safe_message=_COLLECTOR_SAFE_MESSAGES.get(status),
        restart_command=guidance.command if guidance else None,
        restart_host_label=guidance.host_label if guidance else None,
        restart_self_service=guidance.self_service if guidance else True,
    )


def _current_jobs_for_stage(db: Session, execution_stage_id: str) -> list[ProviderExecution]:
    """The latest attempt in each retry chain only — mirrors
    discovery_execution_scheduler_service.py's own private helper of the
    same name/logic; duplicated rather than imported across modules with
    unrelated responsibilities (that helper is scheduler-internal)."""
    jobs = db.query(ProviderExecution).filter(ProviderExecution.execution_stage_id == execution_stage_id).all()
    superseded_ids = {job.retry_of_provider_execution_id for job in jobs if job.retry_of_provider_execution_id}
    return [job for job in jobs if job.id not in superseded_ids]


def _find_most_relevant_failed_job(db: Session, plan: DiscoveryExecutionPlan) -> tuple[ProviderExecution, ExecutionStage] | None:
    stages = (
        db.query(ExecutionStage)
        .filter(
            ExecutionStage.execution_plan_id == plan.id,
            ExecutionStage.required.is_(True),
            ExecutionStage.status.in_([ExecutionStageStatus.FAILED.value, ExecutionStageStatus.PARTIALLY_COMPLETED.value]),
        )
        .all()
    )
    for stage in stages:
        for job in _current_jobs_for_stage(db, stage.id):
            if job.status == ProviderExecutionStatus.FAILED.value:
                return job, stage
    return None


def resolve_action_required(db: Session, run: DiscoveryRun, plan: DiscoveryExecutionPlan | None) -> DiscoveryActionRequiredView | None:
    if run.failure_code:
        can_retry = run.failure_code in RETRYABLE_FAILURE_CODES
        return DiscoveryActionRequiredView(
            code=run.failure_code,
            title="Discovery could not be requested",
            # UX-DISC-02 (#128) — composed from the code, never from
            # run.failure_message: that field carries the Collector's own
            # rejection text, which the platform did not author.
            message=run_failure_statement(run.failure_code),
            affected_stage_key=None,
            suggested_action="Try running discovery again." if can_retry else "Contact Risklence support for help resolving this.",
            can_retry=can_retry,
            support_recommended=run.failure_code in NON_RETRYABLE_FAILURE_CODES or not can_retry,
            provider_execution_id=None,
        )

    if plan is not None:
        # Deliberately not gated on plan.status being terminal — a
        # required stage can fail while sibling stages are still running
        # (the plan hasn't cascaded yet), and that failed job is exactly
        # DISC-40's in-flight retry target. Gating on plan.status here
        # would hide actionRequired for that whole window.
        found = _find_most_relevant_failed_job(db, plan)
        if found is not None:
            job, stage = found
            code = job.failure_code or "unknown_failure"
            can_retry = code in RETRYABLE_PROVIDER_FAILURE_CODES
            return DiscoveryActionRequiredView(
                code=code,
                title="A discovery stage could not complete",
                # UX-DISC-02 (#128) — composed from the code, never from
                # job.failure_message: that field carries str(exc) from the
                # scheduler's guard and "Worker lease expired before the job
                # reported a result." from the retry service.
                message=provider_failure_statement(code),
                affected_stage_key=stage.stage_key,
                suggested_action="Try running discovery again." if can_retry else "Contact Risklence support for help resolving this.",
                can_retry=can_retry,
                support_recommended=not can_retry,
                provider_execution_id=job.id,
            )

    return None


def resolve_evidence_view(db: Session, run: DiscoveryRun) -> DiscoveryEvidenceProcessingView:
    packages = db.query(EvidencePackage).filter(EvidencePackage.discovery_run_id == run.id).all()
    counts = {status.value: 0 for status in EvidenceNormalizationStatus}
    for package in packages:
        counts[package.normalization_status] = counts.get(package.normalization_status, 0) + 1

    return DiscoveryEvidenceProcessingView(
        packages_received=len(packages),
        packages_awaiting_processing=counts[EvidenceNormalizationStatus.PENDING.value],
        packages_processing=counts[EvidenceNormalizationStatus.QUEUED.value],
        packages_processed=counts[EvidenceNormalizationStatus.NORMALIZED.value],
        packages_failed_processing=counts[EvidenceNormalizationStatus.NORMALIZATION_FAILED.value],
    )
