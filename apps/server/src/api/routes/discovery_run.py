"""Step 4.1 — Discovery Orchestration Foundation: browser-facing routes.

Nested under the same ``/api/v1/evidence-sources`` prefix as
``evidence_scanner.py`` (adapting spec §21's standalone ``/api/onboarding/
discovery-runs`` to this repo's existing evidence-source-scoped
convention — a discovery run always belongs to exactly one scanner
instance, which always belongs to exactly one evidence source). Mutations
require ``org_admin``/``admin``, matching every other onboarding-stage
route file.

Route layer coordinates two services that cannot depend on each other
(``discovery_command_service`` already depends on
``discovery_run_service``, so the reverse would cycle): after a run lands
in APPROVED status — either immediately at creation or via ``/approve`` —
this file explicitly advances it to a delivered command.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Body, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.rate_limit import discovery_execution_rate_limiter
from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.discovery_execution_enums import (
    EXECUTION_PLAN_AUDIT_CANCELLED,
    EXECUTION_PLAN_AUDIT_GENERATED,
    ExecutionPlanStatus,
)
from src.core.constants.discovery_run_enums import (
    DISCOVERY_RUN_AUDIT_APPROVAL_REQUIRED,
    DISCOVERY_RUN_AUDIT_APPROVED,
    DISCOVERY_RUN_AUDIT_BLOCKED,
    DISCOVERY_RUN_AUDIT_CANCELLATION_REQUESTED,
    DISCOVERY_RUN_AUDIT_REQUESTED,
    DISCOVERY_RUN_AUDIT_RETRY_REQUESTED,
    DISCOVERY_RUN_ERROR_DISCOVERY_RUN_NOT_FOUND,
    TERMINAL_DISCOVERY_RUN_STATUSES,
    DiscoveryRunStatus,
)
from src.core.constants.evidence_source_enums import EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED
from src.core.constants.lifecycle_enums import LifecycleFamily, LifecycleTransitionSource
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.discovery_execution import (
    DiscoveryExecutionPlan,
    ExecutionStage,
    ExecutionStageDependency,
    ProviderExecution,
)
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.discovery_scope_proposal import DiscoveryScopeProposal
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.model_defs.tenant_org import Organization
from src.core.models import AuditEvent, User
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES, UserRole
from src.core.services.auth_service import is_access_expired
from src.core.services.discovery_execution_audit_timeline_service import (
    DiscoveryTimelineEntry,
    resolve_discovery_run_timeline,
)
from src.core.services.discovery_execution_cancellation_service import cancel_execution_plan
from src.core.services.discovery_run_lifecycle_service import finalise_cancellation_if_settled
from src.core.services.discovery_execution_permissions import (
    DiscoveryExecutionPermissions,
    resolve_can_start_discovery,
    resolve_discovery_execution_permissions,
)
from src.core.services.discovery_execution_plan_service import (
    DiscoveryExecutionPlanError,
    generate_execution_plan,
)
from src.core.services.discovery_execution_readiness_service import (
    DiscoveryReadinessLayers,
    resolve_discovery_readiness_layers,
)
from src.core.services.discovery_execution_retry_service import (
    ProviderExecutionRetryError,
    retry_provider_execution,
)
from src.core.services.discovery_execution_summary_service import (
    DiscoveryActionRequiredView,
    DiscoveryCollectorView,
    DiscoveryEvidenceProcessingView,
    resolve_action_required,
    resolve_collector_view,
    resolve_evidence_view,
)
from src.core.services.discovery_results_service import get_discovery_results
from src.core.services.discovery_scope_proposal_service import (
    ScopeProposalError,
    approve_scope_proposal,
    build_scope_proposal,
    get_current_scope_proposal,
    reject_scope_proposal,
)
from src.core.services.discovery_run_lifecycle_service import (
    evaluate_retry_eligibility,
    request_cancellation,
    retry_discovery_run,
)
from src.core.services.discovery_run_service import (
    DiscoveryRunValidationError,
    approve_discovery_run,
    create_discovery_run,
    evaluate_approval_requirement,
    evaluate_discovery_readiness,
)
from src.core.services.discovery_run_snapshots import (
    build_profile_snapshot,
    resolve_approved_targets,
)
from src.core.services.lifecycle_audit_service import (
    LifecycleAuditDetails,
    with_lifecycle_audit_metadata,
)
from src.api.schemas.timestamps import UtcTimestamp

router = APIRouter(prefix="/api/v1/evidence-sources", tags=["Discovery runs"])

# DISC-50 (spec §82) — every mutating route below actually triggers real
# work (a scan, a state transition with downstream side effects), unlike
# the GET routes, which stay unlimited (read-only, no external effect,
# matching auth_rate_limiter's own precedent of only ever limiting
# writes). Per (organization, user), not per-IP — a shared office IP
# behind NAT must never throttle one user because another one on the same
# connection is busy. One shared limit constant across all five actions:
# no single action here is meaningfully more or less expensive than the
# others at the route layer (the real cost — an actual scan running — is
# already bounded elsewhere, by WorkerLease concurrency caps and the
# retry-eligibility/plan-terminal checks each service already enforces).
_DISCOVERY_MUTATION_RATE_LIMIT = 20


def _discovery_rate_limit_key(action: str, ctx: TenantContext) -> str:
    return f"discovery_run_{action}:{ctx.organization_id}:{ctx.user_id}"


class CreateDiscoveryRunRequest(BaseModel):
    target_ids: list[str] | None = None
    idempotency_key: str | None = None
    # CA-04.7 — which Business Process (and optionally Business Service
    # within it) this run counts toward. Omit for the pre-existing
    # org-wide, not-process-scoped path — zero behavior change for a
    # scanner with no ProcessScannerLink rows at all.
    business_process_id: str | None = None
    business_service_id: str | None = None


class CancelDiscoveryRunRequest(BaseModel):
    """DISC-46 — spec §16's structured cancellation reasonCode. Both
    fields optional: a caller may still cancel without giving a reason,
    same as before this ticket."""

    reason_code: str | None = None
    reason_note: str | None = None


class ScopeProposalInclusionResponse(BaseModel):
    value: str
    rationale: str | None = None


class ScopeProposalResponse(BaseModel):
    id: str
    status: str
    inclusions: list[ScopeProposalInclusionResponse] = []
    exclusions: list[str] = []
    capabilities: list[str] = []
    decided_by_user_id: int | None = None
    decision_note: str | None = None


class ScopeDecisionRequest(BaseModel):
    note: str | None = None


class CreateScopeProposalRequest(BaseModel):
    """Omit ``capabilities`` to propose everything the scanner profile already
    permits. Asking for more than the profile allows is refused, not trimmed."""

    capabilities: list[str] | None = None


class ObservedServiceResponse(BaseModel):
    """One open port, and how well it is actually known.

    `observed_services` below is a list of nmap's words with no way to tell a
    finding from a guess: `http-proxy` is nmap restating "port 8080" from its
    static table, and it rendered exactly like `https` on a port that answered
    and identified itself. Showing a guess in the same voice as an observation
    is the defect #249 was raised for.
    """

    name: str
    port: int | None = None
    #: True when nmap probed the port and concluded this; false when the name
    #: came from its port-number table and says nothing the port did not.
    probed: bool


class DiscoveredAssetResponse(BaseModel):
    asset_id: int
    display_name: str
    asset_type: str
    layer: str
    layer_label: str
    observed_services: list[str] = []
    #: Open findings the vulnerability scanner has recorded against this
    #: artefact.
    #:
    #: ⚠️ ``0`` means no scanner finding is on record — **not** "scanned and
    #: clean". Nothing yet records whether a host was scanned and matched
    #: nothing, cut at the time budget, or never reached, so a surface built on
    #: this must say what was found and stay silent about what was not.
    scan_finding_count: int = 0
    #: The same ports with their evidence. Empty for artefacts recorded before
    #: this was kept — deliberately not back-filled from `observed_services`,
    #: since inventing `probed: false` would assert something nobody observed.
    observed_service_evidence: list[ObservedServiceResponse] = []
    #: What the scan concluded this artefact is, and where it sits — the same
    #: answer the standing inventory gives. A reviewer deciding "is this ours?"
    #: was shown an address and a row of chips, which is the least useful form
    #: of every fact the platform holds about it.
    identity_name: str | None = None
    identity_basis: str | None = None
    identity_undetermined_reason: str | None = None
    identity_explanation: str | None = None
    network_address: str | None = None
    is_new: bool
    lifecycle_state: str
    review_state: str
    #: service_bearing / endpoint / undetermined — whether a business service
    #: could depend on this at all. Lets a reviewer face the handful of rows
    #: that can carry a dependency instead of every device on the network.
    candidacy: str


class DiscoveryResultsResponse(BaseModel):
    discovery_run_id: str
    empty_result_providers: list[str] = []
    evidence_package_count: int
    new_count: int
    matched_count: int
    discovered: list[DiscoveredAssetResponse] = []
    excluded_values: list[str] = []


class DiscoveryReadinessResponse(BaseModel):
    ready: bool
    scanner_instance_id: str | None
    blocking_reasons: list[str]
    # Preview of exactly what a discovery request would use right now —
    # built from the same resolve_approved_targets/build_profile_snapshot
    # helpers create_discovery_run itself calls (spec §25.2: "before
    # creating the run, show the exact selected targets... whether
    # approval is required" — never a separate, potentially-diverging
    # guess at the scope).
    target_snapshot: list[dict] = []
    profile_snapshot: dict | None = None
    approval_required: bool = False
    # DISC-52 (spec §14) — the pre-execution confirmation screen's own
    # "review scope/Collector/permissions before starting" fields.
    # resolve_collector_view(..., plan=None) already treats "no plan yet"
    # as requiring a collector (see that function's own docstring), which
    # is exactly the right default before a run — and therefore a plan —
    # exists at all.
    collector: DiscoveryCollectorView
    can_start_discovery: bool


class DiscoveryRunActionState(BaseModel):
    can_approve: bool
    can_cancel: bool
    can_retry: bool
    can_view_scope: bool


class ProviderExecutionResponse(BaseModel):
    id: str
    provider_id: str
    status: str
    attempt_number: int
    failure_code: str | None
    failure_message: str | None
    next_retry_at: UtcTimestamp | None
    started_at: UtcTimestamp | None
    completed_at: UtcTimestamp | None


class ExecutionStageResponse(BaseModel):
    id: str
    stage_key: str
    status: str
    required: bool
    depends_on_stage_ids: list[str]
    started_at: UtcTimestamp | None
    completed_at: UtcTimestamp | None
    jobs: list[ProviderExecutionResponse]


class ExecutionPlanResponse(BaseModel):
    """DISC-33 — the backend half of the parked DISC-25 UI ticket. `null`
    on DiscoveryRunResponse for a run still on the original Step 4.1
    whole-run flow (graceful degradation, not a breaking response-shape
    change) — populated once DISC-24's execution-pipeline path has
    generated a real DiscoveryExecutionPlan for the run."""

    id: str
    status: str
    generated_at: UtcTimestamp
    started_at: UtcTimestamp | None
    completed_at: UtcTimestamp | None
    stages: list[ExecutionStageResponse]


class DiscoveryRunResponse(BaseModel):
    id: str
    evidence_source_id: str
    scanner_instance_id: str
    status: str
    current_stage: str
    approval_status: str
    request_source: str
    discovery_purpose: str
    requested_by_user_id: int
    approved_by_user_id: int | None
    target_ids: list[str]
    target_snapshot: list[dict]
    profile_snapshot: dict
    business_process_id: str | None
    business_service_id: str | None
    failure_code: str | None
    failure_message: str | None
    next_action: str | None
    retry_of_discovery_run_id: str | None
    retry_count: int
    requested_at: UtcTimestamp
    approved_at: UtcTimestamp | None
    queued_at: UtcTimestamp | None
    command_available_at: UtcTimestamp | None
    acknowledged_at: UtcTimestamp | None
    started_at: UtcTimestamp | None
    completed_at: UtcTimestamp | None
    cancelled_at: UtcTimestamp | None
    failed_at: UtcTimestamp | None
    cancellation_reason_code: str | None
    cancellation_reason_note: str | None
    action_state: DiscoveryRunActionState
    execution_plan: ExecutionPlanResponse | None
    # Step 4.2 Part 3 (DISC-38) — additive customer-safety fields, all
    # required (unlike executionPlan) since every run has a well-defined
    # answer for each, even before a plan exists.
    permissions: DiscoveryExecutionPermissions
    collector: DiscoveryCollectorView
    action_required: DiscoveryActionRequiredView | None
    evidence: DiscoveryEvidenceProcessingView
    downstream_readiness: DiscoveryReadinessLayers


def _require_org_admin(db: Session, ctx: TenantContext) -> None:
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or user.role not in ADMIN_ROLES:
        raise AuthorizationError(EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED)


def _require_org_admin_or_active_consultant(db: Session, ctx: TenantContext) -> bool:
    """Step 4.2 Part 3 spec §15/§46 — a Risklence Consultant may start or
    retry execution (never approve or cancel — see
    discovery_execution_permissions.py's own docstring for why). Returns
    whether the resolved actor is a consultant, so the caller can tag the
    audit event with actor_role for the spec's "action is taken on behalf
    of the setup programme" traceability requirement."""
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or is_access_expired(user):
        raise AuthorizationError(EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED)
    if user.role in ADMIN_ROLES:
        return False
    if user.role == UserRole.CONSULTANT.value:
        return True
    raise AuthorizationError(EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED)


def _write_audit(
    db: Session,
    *,
    ctx: TenantContext,
    event_type: str,
    metadata: dict,
    lifecycle: LifecycleAuditDetails | None = None,
) -> None:
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=event_type,
            metadata_json=with_lifecycle_audit_metadata(metadata, lifecycle)
            if lifecycle
            else metadata,
        )
    )


def _with_process_context(metadata: dict, run: DiscoveryRun) -> dict:
    """CA-04.8 — every DiscoveryRun lifecycle audit event also carries its
    own process/service attribution (CA-04.7's business_process_id/
    business_service_id, snapshotted at run creation) plus a
    slot_instance_id placeholder that stays None until CA-09A's own
    dependency-slot mapping genuinely exists and is approved — never
    inferred here."""
    return {
        **metadata,
        "business_process_id": run.business_process_id,
        "business_service_id": run.business_service_id,
        "slot_instance_id": None,
    }


def _with_actor_role(metadata: dict, acted_as_consultant: bool) -> dict:
    """Spec §15/§46 — "the audit event records consultant identity". The
    row's own actor_user_id already identifies exactly who; this adds the
    "acting as consultant, on behalf of the setup programme" distinction a
    plain user id can't convey on its own."""
    if not acted_as_consultant:
        return metadata
    return {**metadata, "actor_role": "consultant"}


def _require_source(db: Session, *, ctx: TenantContext, source_id: str) -> EvidenceSource:
    source = TenantRepository(db, EvidenceSource, ctx.organization_id).get_by_id(source_id)
    if source is None:
        raise ResourceNotFoundError("Evidence source not found")
    return source


def _require_instance(db: Session, *, ctx: TenantContext, source_id: str) -> ScannerInstance:
    matches = TenantRepository(db, ScannerInstance, ctx.organization_id).filter_by(
        evidence_source_id=source_id
    )
    if not matches:
        raise ResourceNotFoundError(
            "Scanner instance not found — install the scanner for this evidence source first"
        )
    return matches[0]


def _require_organization(db: Session, ctx: TenantContext) -> Organization:
    organization = db.query(Organization).filter(Organization.id == ctx.organization_id).first()
    if organization is None:
        raise ResourceNotFoundError("Organisation not found")
    return organization


def _require_run(db: Session, *, ctx: TenantContext, run_id: str) -> DiscoveryRun:
    run = TenantRepository(db, DiscoveryRun, ctx.organization_id).get_by_id(run_id)
    if run is None:
        raise ResourceNotFoundError(DISCOVERY_RUN_ERROR_DISCOVERY_RUN_NOT_FOUND)
    return run


def _require_job_for_run(db: Session, run: DiscoveryRun, job_id: str) -> ProviderExecution:
    """Job-to-run scoping goes through the plan, not organization_id
    directly — ProviderExecution carries no organization_id of its own
    (see EvidencePackage's own comment on why it duplicates one; this
    model doesn't). ``run`` is already tenant-scoped by ``_require_run``,
    so this closes the loop without a second explicit org check."""
    job = (
        db.query(ProviderExecution)
        .join(ExecutionStage, ProviderExecution.execution_stage_id == ExecutionStage.id)
        .join(DiscoveryExecutionPlan, ExecutionStage.execution_plan_id == DiscoveryExecutionPlan.id)
        .filter(ProviderExecution.id == job_id, DiscoveryExecutionPlan.discovery_run_id == run.id)
        .first()
    )
    if job is None:
        raise ResourceNotFoundError("Job not found for this discovery run")
    return job


def _action_state(run: DiscoveryRun) -> DiscoveryRunActionState:
    return DiscoveryRunActionState(
        can_approve=run.status == DiscoveryRunStatus.AWAITING_APPROVAL.value,
        can_cancel=run.status not in TERMINAL_DISCOVERY_RUN_STATUSES
        and run.status != DiscoveryRunStatus.BLOCKED.value,
        can_retry=run.status == DiscoveryRunStatus.FAILED.value
        and evaluate_retry_eligibility(run).allowed,
        can_view_scope=True,
    )


def _execution_plan_response(
    db: Session, plan: DiscoveryExecutionPlan | None
) -> ExecutionPlanResponse | None:
    if plan is None:
        return None

    stages = db.query(ExecutionStage).filter(ExecutionStage.execution_plan_id == plan.id).all()
    stage_ids = [stage.id for stage in stages]

    depends_on_by_stage: dict[str, list[str]] = {}
    if stage_ids:
        for edge in (
            db.query(ExecutionStageDependency)
            .filter(ExecutionStageDependency.execution_stage_id.in_(stage_ids))
            .all()
        ):
            depends_on_by_stage.setdefault(edge.execution_stage_id, []).append(
                edge.depends_on_stage_id
            )

    jobs_by_stage: dict[str, list[ProviderExecution]] = {}
    if stage_ids:
        for job in (
            db.query(ProviderExecution)
            .filter(ProviderExecution.execution_stage_id.in_(stage_ids))
            .all()
        ):
            jobs_by_stage.setdefault(job.execution_stage_id, []).append(job)

    return ExecutionPlanResponse(
        id=plan.id,
        status=plan.status,
        generated_at=plan.generated_at,
        started_at=plan.started_at,
        completed_at=plan.completed_at,
        stages=[
            ExecutionStageResponse(
                id=stage.id,
                stage_key=stage.stage_key,
                status=stage.status,
                required=stage.required,
                depends_on_stage_ids=depends_on_by_stage.get(stage.id, []),
                started_at=stage.started_at,
                completed_at=stage.completed_at,
                jobs=[
                    ProviderExecutionResponse(
                        id=job.id,
                        provider_id=job.provider_id,
                        status=job.status,
                        attempt_number=job.attempt_number,
                        failure_code=job.failure_code,
                        failure_message=job.failure_message,
                        next_retry_at=job.next_retry_at,
                        started_at=job.started_at,
                        completed_at=job.completed_at,
                    )
                    for job in jobs_by_stage.get(stage.id, [])
                ],
            )
            for stage in stages
        ],
    )


def _run_response(db: Session, ctx: TenantContext, run: DiscoveryRun) -> DiscoveryRunResponse:
    plan = (
        db.query(DiscoveryExecutionPlan)
        .filter(DiscoveryExecutionPlan.discovery_run_id == run.id)
        .first()
    )
    instance = TenantRepository(db, ScannerInstance, ctx.organization_id).get_by_id(
        run.scanner_instance_id
    )
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)

    return DiscoveryRunResponse(
        id=run.id,
        evidence_source_id=run.evidence_source_id,
        scanner_instance_id=run.scanner_instance_id,
        status=run.status,
        current_stage=run.current_stage,
        approval_status=run.approval_status,
        request_source=run.request_source,
        discovery_purpose=run.discovery_purpose,
        requested_by_user_id=run.requested_by_user_id,
        approved_by_user_id=run.approved_by_user_id,
        target_ids=run.target_ids,
        target_snapshot=run.target_snapshot,
        profile_snapshot=run.profile_snapshot,
        business_process_id=run.business_process_id,
        business_service_id=run.business_service_id,
        failure_code=run.failure_code,
        failure_message=run.failure_message,
        next_action=run.next_action,
        retry_of_discovery_run_id=run.retry_of_discovery_run_id,
        retry_count=run.retry_count,
        requested_at=run.requested_at,
        approved_at=run.approved_at,
        queued_at=run.queued_at,
        command_available_at=run.command_available_at,
        acknowledged_at=run.acknowledged_at,
        started_at=run.started_at,
        completed_at=run.completed_at,
        cancelled_at=run.cancelled_at,
        failed_at=run.failed_at,
        cancellation_reason_code=run.cancellation_reason_code,
        cancellation_reason_note=run.cancellation_reason_note,
        action_state=_action_state(run),
        execution_plan=_execution_plan_response(db, plan),
        permissions=resolve_discovery_execution_permissions(user, run),
        collector=resolve_collector_view(db, instance, plan),
        action_required=resolve_action_required(db, run, plan),
        evidence=resolve_evidence_view(db, run),
        downstream_readiness=resolve_discovery_readiness_layers(db, run, plan),
    )


def _advance_if_approved(db: Session, ctx: TenantContext, run: DiscoveryRun) -> None:
    """DISC-24: the execution-pipeline path is now the trigger for every
    approved run — generates the DiscoveryExecutionPlan, which itself
    moves the run APPROVED -> RUNNING. The original Step 4.1 whole-run
    path (discovery_command_service.create_command_for_run) is no longer
    called from here, though the function itself is kept, not deleted —
    retiring it entirely is a separate, deliberate follow-up, not bundled
    into this cutover."""
    if run.status != DiscoveryRunStatus.APPROVED.value:
        return
    try:
        plan = generate_execution_plan(db, run)
    except DiscoveryExecutionPlanError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=EXECUTION_PLAN_AUDIT_GENERATED,
        metadata=_with_process_context({"discovery_run_id": run.id, "execution_plan_id": plan.id}, run),
        lifecycle=LifecycleAuditDetails(
            object_type="discovery_execution_plan",
            object_id=plan.id,
            family=LifecycleFamily.EXECUTION,
            source=LifecycleTransitionSource.SYSTEM_EXECUTED,
            current_state=plan.status,
        ),
    )


def _cancel_execution_plan_if_any(db: Session, ctx: TenantContext, run: DiscoveryRun) -> None:
    """DISC-31: the disclosed follow-up from DISC-24 — cancelling a RUNNING
    run previously only ever set DiscoveryRun.status, leaving an in-flight
    DiscoveryExecutionPlan to keep executing untouched. A no-op if this run
    never generated a plan, or its plan is already terminal."""
    existing_plan = (
        db.query(DiscoveryExecutionPlan)
        .filter(DiscoveryExecutionPlan.discovery_run_id == run.id)
        .first()
    )
    previous_state = existing_plan.status if existing_plan is not None else None
    plan = cancel_execution_plan(db, run)
    if plan is None or plan.status != ExecutionPlanStatus.CANCELLED.value:
        return
    _write_audit(
        db,
        ctx=ctx,
        event_type=EXECUTION_PLAN_AUDIT_CANCELLED,
        metadata=_with_process_context({"discovery_run_id": run.id, "execution_plan_id": plan.id}, run),
        lifecycle=LifecycleAuditDetails(
            object_type="discovery_execution_plan",
            object_id=plan.id,
            family=LifecycleFamily.EXECUTION,
            source=LifecycleTransitionSource.HUMAN_INITIATED,
            previous_state=previous_state,
            current_state=plan.status,
        ),
    )


@router.get("/{source_id}/discovery-readiness", response_model=DiscoveryReadinessResponse)
def get_discovery_readiness_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> DiscoveryReadinessResponse:
    organization = _require_organization(db, ctx)
    instance = _require_instance(db, ctx=ctx, source_id=source_id)
    blocking_reasons = evaluate_discovery_readiness(db, organization, instance)

    _, target_snapshot, _ = resolve_approved_targets(
        db, evidence_source_id=instance.evidence_source_id, target_ids=None
    )
    profile_snapshot = build_profile_snapshot(instance) if instance.scan_profile else None
    approval_required = False
    if profile_snapshot is not None:
        approval_required = evaluate_approval_requirement(
            db, organization.id, profile_snapshot, target_snapshot
        ).required

    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)

    return DiscoveryReadinessResponse(
        ready=not blocking_reasons,
        scanner_instance_id=instance.id,
        blocking_reasons=blocking_reasons,
        target_snapshot=target_snapshot,
        profile_snapshot=profile_snapshot,
        approval_required=approval_required,
        collector=resolve_collector_view(db, instance, None),
        can_start_discovery=resolve_can_start_discovery(user),
    )


@router.post("/{source_id}/discovery-runs", response_model=DiscoveryRunResponse)
def create_discovery_run_route(
    source_id: str,
    body: CreateDiscoveryRunRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DiscoveryRunResponse:
    acted_as_consultant = _require_org_admin_or_active_consultant(db, ctx)
    discovery_execution_rate_limiter.check(
        _discovery_rate_limit_key("create", ctx), limit=_DISCOVERY_MUTATION_RATE_LIMIT
    )
    organization = _require_organization(db, ctx)
    instance = _require_instance(db, ctx=ctx, source_id=source_id)
    try:
        run = create_discovery_run(
            db,
            organization=organization,
            instance=instance,
            requested_by_user_id=ctx.user_id,
            target_ids=body.target_ids,
            idempotency_key=body.idempotency_key,
            business_process_id=body.business_process_id,
            business_service_id=body.business_service_id,
        )
    except DiscoveryRunValidationError as exc:
        raise ValidationError(str(exc)) from exc

    _write_audit(
        db,
        ctx=ctx,
        event_type=DISCOVERY_RUN_AUDIT_REQUESTED,
        metadata=_with_process_context(_with_actor_role({"discovery_run_id": run.id}, acted_as_consultant), run),
        lifecycle=LifecycleAuditDetails(
            object_type="discovery_run",
            object_id=run.id,
            family=LifecycleFamily.APPROVAL,
            source=LifecycleTransitionSource.HUMAN_INITIATED,
            current_state=run.status,
        ),
    )
    if run.status == DiscoveryRunStatus.BLOCKED.value:
        _write_audit(
            db,
            ctx=ctx,
            event_type=DISCOVERY_RUN_AUDIT_BLOCKED,
            metadata=_with_process_context({"discovery_run_id": run.id, "reason": run.failure_code}, run),
        )
    elif run.status == DiscoveryRunStatus.AWAITING_APPROVAL.value:
        _write_audit(
            db,
            ctx=ctx,
            event_type=DISCOVERY_RUN_AUDIT_APPROVAL_REQUIRED,
            metadata=_with_process_context({"discovery_run_id": run.id}, run),
        )
    else:
        _advance_if_approved(db, ctx, run)

    db.commit()
    db.refresh(run)
    return _run_response(db, ctx, run)


@router.get("/{source_id}/discovery-runs", response_model=list[DiscoveryRunResponse])
def list_discovery_runs_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[DiscoveryRunResponse]:
    _require_source(db, ctx=ctx, source_id=source_id)
    runs = TenantRepository(db, DiscoveryRun, ctx.organization_id).filter_by(
        evidence_source_id=source_id
    )
    runs = sorted(runs, key=lambda r: r.requested_at, reverse=True)
    return [_run_response(db, ctx, r) for r in runs]


@router.get("/{source_id}/discovery-runs/{run_id}", response_model=DiscoveryRunResponse)
def get_discovery_run_route(
    source_id: str,
    run_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DiscoveryRunResponse:
    run = _require_run(db, ctx=ctx, run_id=run_id)
    return _run_response(db, ctx, run)


@router.post("/{source_id}/discovery-runs/{run_id}/approve", response_model=DiscoveryRunResponse)
def approve_discovery_run_route(
    source_id: str,
    run_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DiscoveryRunResponse:
    _require_org_admin(db, ctx)
    discovery_execution_rate_limiter.check(
        _discovery_rate_limit_key("approve", ctx), limit=_DISCOVERY_MUTATION_RATE_LIMIT
    )
    run = _require_run(db, ctx=ctx, run_id=run_id)
    previous_state = run.status
    try:
        approve_discovery_run(db, run, approved_by_user_id=ctx.user_id)
    except DiscoveryRunValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=DISCOVERY_RUN_AUDIT_APPROVED,
        metadata=_with_process_context({"discovery_run_id": run.id}, run),
        lifecycle=LifecycleAuditDetails(
            object_type="discovery_run",
            object_id=run.id,
            family=LifecycleFamily.APPROVAL,
            source=LifecycleTransitionSource.HUMAN_APPROVED,
            previous_state=previous_state,
            current_state=run.status,
        ),
    )
    _advance_if_approved(db, ctx, run)
    db.commit()
    db.refresh(run)
    return _run_response(db, ctx, run)


@router.post("/{source_id}/discovery-runs/{run_id}/cancel", response_model=DiscoveryRunResponse)
def cancel_discovery_run_route(
    source_id: str,
    run_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
    body: CancelDiscoveryRunRequest | None = Body(default=None),
) -> DiscoveryRunResponse:
    _require_org_admin(db, ctx)
    discovery_execution_rate_limiter.check(
        _discovery_rate_limit_key("cancel", ctx), limit=_DISCOVERY_MUTATION_RATE_LIMIT
    )
    run = _require_run(db, ctx=ctx, run_id=run_id)
    # isinstance rather than a truthy check on body: called directly (this
    # domain's own test convention) rather than through FastAPI's DI, the
    # Body(default=None) sentinel itself is passed as body, not None
    # (matching bundle_validation_routes.validate_bundle's own precedent).
    reason_code = body.reason_code if isinstance(body, CancelDiscoveryRunRequest) else None
    reason_note = body.reason_note if isinstance(body, CancelDiscoveryRunRequest) else None
    previous_state = run.status
    try:
        request_cancellation(
            db,
            run,
            cancelled_by_user_id=ctx.user_id,
            reason_code=reason_code,
            reason_note=reason_note,
        )
    except DiscoveryRunValidationError as exc:
        raise ValidationError(str(exc)) from exc
    audit_metadata = {"discovery_run_id": run.id}
    if reason_code is not None:
        audit_metadata["reason_code"] = reason_code
    _write_audit(
        db,
        ctx=ctx,
        event_type=DISCOVERY_RUN_AUDIT_CANCELLATION_REQUESTED,
        metadata=_with_process_context(audit_metadata, run),
        lifecycle=LifecycleAuditDetails(
            object_type="discovery_run",
            object_id=run.id,
            family=LifecycleFamily.APPROVAL,
            source=LifecycleTransitionSource.HUMAN_INITIATED,
            previous_state=previous_state,
            current_state=run.status,
            reason_code=reason_code,
        ),
    )
    _cancel_execution_plan_if_any(db, ctx, run)
    # Cancelling stops the work; this is what lets the cancellation itself
    # finish. Without it the run sat in CANCELLATION_REQUESTED indefinitely.
    finalise_cancellation_if_settled(db, run)
    db.commit()
    db.refresh(run)
    return _run_response(db, ctx, run)


@router.post("/{source_id}/discovery-runs/{run_id}/retry", response_model=DiscoveryRunResponse)
def retry_discovery_run_route(
    source_id: str,
    run_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DiscoveryRunResponse:
    acted_as_consultant = _require_org_admin_or_active_consultant(db, ctx)
    discovery_execution_rate_limiter.check(
        _discovery_rate_limit_key("retry", ctx), limit=_DISCOVERY_MUTATION_RATE_LIMIT
    )
    organization = _require_organization(db, ctx)
    failed_run = _require_run(db, ctx=ctx, run_id=run_id)
    instance = _require_instance(db, ctx=ctx, source_id=source_id)
    try:
        run = retry_discovery_run(
            db,
            failed_run,
            organization=organization,
            instance=instance,
            retried_by_user_id=ctx.user_id,
        )
    except DiscoveryRunValidationError as exc:
        raise ValidationError(str(exc)) from exc

    _write_audit(
        db,
        ctx=ctx,
        event_type=DISCOVERY_RUN_AUDIT_RETRY_REQUESTED,
        metadata=_with_process_context(
            _with_actor_role(
                {"discovery_run_id": run.id, "retry_of_discovery_run_id": failed_run.id},
                acted_as_consultant,
            ),
            run,
        ),
        lifecycle=LifecycleAuditDetails(
            object_type="discovery_run",
            object_id=run.id,
            family=LifecycleFamily.APPROVAL,
            source=LifecycleTransitionSource.HUMAN_INITIATED,
            current_state=run.status,
        ),
    )
    if run.status == DiscoveryRunStatus.BLOCKED.value:
        _write_audit(
            db,
            ctx=ctx,
            event_type=DISCOVERY_RUN_AUDIT_BLOCKED,
            metadata=_with_process_context({"discovery_run_id": run.id, "reason": run.failure_code}, run),
        )
    elif run.status == DiscoveryRunStatus.AWAITING_APPROVAL.value:
        _write_audit(
            db,
            ctx=ctx,
            event_type=DISCOVERY_RUN_AUDIT_APPROVAL_REQUIRED,
            metadata=_with_process_context({"discovery_run_id": run.id}, run),
        )
    else:
        _advance_if_approved(db, ctx, run)

    db.commit()
    db.refresh(run)
    return _run_response(db, ctx, run)


@router.get(
    "/{source_id}/discovery-runs/{run_id}/timeline", response_model=list[DiscoveryTimelineEntry]
)
def get_discovery_run_timeline_route(
    source_id: str,
    run_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[DiscoveryTimelineEntry]:
    """Step 4.2 Part 3 (DISC-41) — the first-ever audit-event read route in
    this codebase (AuditEvent is written prolifically elsewhere, never
    queried back until now). Read-only diagnostics: gated on
    can_view_diagnostics (every active org member), not can_view_scope's
    admin-only sibling."""
    run = _require_run(db, ctx=ctx, run_id=run_id)
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if not resolve_discovery_execution_permissions(user, run).can_view_diagnostics:
        raise AuthorizationError(
            "You do not have access to this organisation's discovery activity."
        )
    plan = (
        db.query(DiscoveryExecutionPlan)
        .filter(DiscoveryExecutionPlan.discovery_run_id == run.id)
        .first()
    )
    return resolve_discovery_run_timeline(db, ctx.organization_id, run, plan)


def _proposal_response(db: Session, proposal) -> ScopeProposalResponse:
    rationale = proposal.rationale or {}
    # #248 moved the capability bag onto a PermissionProfile, and this read went
    # in filtered by id alone. The id comes from a proposal that was itself
    # fetched tenant-scoped, so it is guarded upstream — but "guarded upstream"
    # is the reasoning behind every isolation defect that ever shipped, and the
    # organisation is right here on the proposal. Scoped explicitly.
    profile = (
        db.query(PermissionProfile)
        .filter(
            PermissionProfile.organization_id == proposal.organization_id,
            PermissionProfile.id == proposal.permission_profile_id,
        )
        .first()
    )
    return ScopeProposalResponse(
        id=proposal.id,
        status=proposal.status,
        inclusions=[
            ScopeProposalInclusionResponse(value=value, rationale=rationale.get(value))
            for value in (proposal.inclusions or [])
        ],
        exclusions=list(proposal.exclusions or []),
        capabilities=list(profile.discovery_capabilities or []) if profile else [],
        decided_by_user_id=proposal.decided_by_user_id,
        decision_note=proposal.decision_note,
    )


@router.get("/{source_id}/scope-proposal", response_model=ScopeProposalResponse | None)
def get_scope_proposal_route(
    source_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ScopeProposalResponse | None:
    """CA-05.B — the boundary the reviewer should see: the one in force, or one
    still awaiting their decision.

    Read-only, so open to any active org member: seeing which boundary governs
    discovery is not the authority to change it.
    """
    _require_source(db, ctx=ctx, source_id=source_id)
    current = get_current_scope_proposal(
        db, organization_id=ctx.organization_id, evidence_source_id=source_id
    )
    return _proposal_response(db, current) if current else None


@router.post("/{source_id}/scope-proposal", response_model=ScopeProposalResponse)
def create_scope_proposal_route(
    source_id: str,
    payload: CreateScopeProposalRequest = Body(default=CreateScopeProposalRequest()),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ScopeProposalResponse:
    """Propose a boundary from what the organisation already has on record.

    Proposing is not scanning: this creates no DiscoveryRun and contacts no
    Collector. It is still admin-gated and rate-limited because it supersedes
    any open proposal, which changes what a reviewer is being asked to decide.
    """
    _require_org_admin(db, ctx)
    discovery_execution_rate_limiter.check(
        _discovery_rate_limit_key("scope_propose", ctx), limit=_DISCOVERY_MUTATION_RATE_LIMIT
    )
    instance = _require_instance(db, ctx=ctx, source_id=source_id)
    try:
        proposal = build_scope_proposal(
            db,
            organization_id=ctx.organization_id,
            evidence_source_id=source_id,
            profile_snapshot=build_profile_snapshot(instance),
            requested_capabilities=payload.capabilities,
        )
    except ScopeProposalError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(proposal)
    return _proposal_response(db, proposal)


@router.post(
    "/{source_id}/scope-proposal/{proposal_id}/approve", response_model=ScopeProposalResponse
)
def approve_scope_proposal_route(
    source_id: str,
    proposal_id: str,
    payload: ScopeDecisionRequest = Body(default=ScopeDecisionRequest()),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ScopeProposalResponse:
    """Approve the proposed boundary.

    Authorisation is deliberately *not* the usual org_admin check: the contract
    names the Technical Setup Owner as the approver, and the service enforces
    that identity. Admins who are not the owner are refused there.
    """
    _require_source(db, ctx=ctx, source_id=source_id)
    discovery_execution_rate_limiter.check(
        _discovery_rate_limit_key("scope_approve", ctx), limit=_DISCOVERY_MUTATION_RATE_LIMIT
    )
    return _decide_scope(
        db,
        ctx=ctx,
        proposal_id=proposal_id,
        note=payload.note,
        decide=approve_scope_proposal,
    )


@router.post(
    "/{source_id}/scope-proposal/{proposal_id}/reject", response_model=ScopeProposalResponse
)
def reject_scope_proposal_route(
    source_id: str,
    proposal_id: str,
    payload: ScopeDecisionRequest = Body(default=ScopeDecisionRequest()),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ScopeProposalResponse:
    """Reject the proposed boundary. Technical Setup Owner only, as above."""
    _require_source(db, ctx=ctx, source_id=source_id)
    discovery_execution_rate_limiter.check(
        _discovery_rate_limit_key("scope_reject", ctx), limit=_DISCOVERY_MUTATION_RATE_LIMIT
    )
    return _decide_scope(
        db,
        ctx=ctx,
        proposal_id=proposal_id,
        note=payload.note,
        decide=reject_scope_proposal,
    )


def _decide_scope(db: Session, *, ctx: TenantContext, proposal_id: str, note: str | None, decide):
    try:
        decide(
            db,
            organization_id=ctx.organization_id,
            proposal_id=proposal_id,
            actor_user_id=ctx.user_id,
            note=note,
        )
    except ScopeProposalError as exc:
        # "not found" is a genuinely missing/other-tenant row; everything else
        # is a refused decision (wrong actor, illegal transition).
        if "not found" in str(exc).lower():
            raise ResourceNotFoundError(str(exc)) from exc
        raise AuthorizationError(str(exc)) from exc
    db.commit()
    proposal = TenantRepository(db, DiscoveryScopeProposal, ctx.organization_id).get_by_id(
        proposal_id
    )
    return _proposal_response(db, proposal)


@router.get(
    "/{source_id}/discovery-runs/{run_id}/results", response_model=DiscoveryResultsResponse
)
def get_discovery_run_results_route(
    source_id: str,
    run_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DiscoveryResultsResponse:
    """CA-05.C — what this run actually found: discovered hosts/services, how
    many are new to the organisation, and what stayed excluded.

    Read-only, so gated on ``can_view_diagnostics`` (every active org member)
    rather than the admin-only scope permission — matching the timeline route
    above. Seeing the result of an approved run is not the same authority as
    changing what may be scanned.
    """
    run = _require_run(db, ctx=ctx, run_id=run_id)
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if not resolve_discovery_execution_permissions(user, run).can_view_diagnostics:
        raise AuthorizationError(
            "You do not have access to this organisation's discovery activity."
        )
    summary = get_discovery_results(
        db, organization_id=ctx.organization_id, discovery_run_id=run.id
    )
    return DiscoveryResultsResponse(
        discovery_run_id=summary.discovery_run_id,
        evidence_package_count=summary.evidence_package_count,
        new_count=summary.new_count,
        matched_count=summary.matched_count,
        discovered=[
            DiscoveredAssetResponse(
                asset_id=asset.asset_id,
                display_name=asset.display_name,
                asset_type=asset.asset_type,
                layer=asset.layer,
                layer_label=asset.layer_label,
                observed_services=list(asset.observed_services),
                scan_finding_count=asset.scan_finding_count,
                observed_service_evidence=[
                    ObservedServiceResponse(name=item.name, port=item.port, probed=item.probed)
                    for item in asset.observed_service_evidence
                ],
                identity_name=asset.identity_name,
                identity_basis=asset.identity_basis,
                identity_undetermined_reason=asset.identity_undetermined_reason,
                identity_explanation=asset.identity_explanation,
                network_address=asset.network_address,
                is_new=asset.is_new,
                lifecycle_state=asset.lifecycle_state,
                review_state=asset.review_state,
                candidacy=asset.candidacy,
            )
            for asset in summary.discovered
        ],
        excluded_values=list(summary.excluded_values),
        empty_result_providers=list(summary.empty_result_providers),
    )


@router.post(
    "/{source_id}/discovery-runs/{run_id}/jobs/{job_id}/retry", response_model=DiscoveryRunResponse
)
def retry_provider_execution_route(
    source_id: str,
    run_id: str,
    job_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DiscoveryRunResponse:
    """Step 4.2 Part 3 (DISC-40) — stage/job-level customer retry, the
    only real retry path for a Step 4.2 execution-pipeline failure (the
    whole-run retry route above only recognises DiscoveryRunStatus.FAILED
    with a run-level failure_code, which the pipeline never sets — see
    discovery_execution_summary_service.resolve_action_required)."""
    acted_as_consultant = _require_org_admin_or_active_consultant(db, ctx)
    discovery_execution_rate_limiter.check(
        _discovery_rate_limit_key("job_retry", ctx), limit=_DISCOVERY_MUTATION_RATE_LIMIT
    )
    run = _require_run(db, ctx=ctx, run_id=run_id)
    job = _require_job_for_run(db, run, job_id)
    try:
        retry_provider_execution(
            db, job, actor_user_id=ctx.user_id, acted_as_consultant=acted_as_consultant
        )
    except ProviderExecutionRetryError as exc:
        raise ValidationError(str(exc)) from exc

    db.commit()
    db.refresh(run)
    return _run_response(db, ctx, run)
