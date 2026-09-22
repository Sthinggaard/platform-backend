"""Step 4.1 — Discovery Orchestration Foundation: request creation.

Governs *requesting* a discovery run — preconditions, immutable execution
snapshots (spec §10, built by ``discovery_run_snapshots``), the
deterministic approval policy (§13), and the guarded state machine (§11).
Never executes a scan or parses its results. Cancellation and retry live
in ``discovery_run_lifecycle_service`` (SRP — those act on an existing
run rather than creating one); the signed command envelope a run hands
off to once approved lives in ``discovery_command_service``.

A discovery run always uses the scanner instance's *currently confirmed*
``scan_profile`` rather than an independently chosen ``profileId`` — v1
supports exactly one active profile per scanner instance (Step 3.5), not a
catalogue of selectable profiles, so there is nothing else a request could
legitimately choose. This closes the loop between what Step 3.5 configured
and what Step 4 runs, and is disclosed in TASKS.md as a deliberate
simplification of spec §9's independent ``profileId``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from src.core.constants.discovery_run_enums import (
    ALLOWED_DISCOVERY_RUN_TRANSITIONS,
    DISCOVERY_APPROVAL_REASON_PRODUCTION_NETWORK,
    DISCOVERY_APPROVAL_REASON_VULNERABILITY_PROFILE,
    DISCOVERY_RUN_ERROR_BOUNDARY_APPROVAL_REQUIRED,
    DISCOVERY_RUN_ERROR_DISCOVERY_ALREADY_RUNNING,
    DISCOVERY_RUN_ERROR_INVALID_TRANSITION,
    DISCOVERY_RUN_ERROR_PROCESS_NOT_LINKED,
    DISCOVERY_RUN_ERROR_PROCESS_SCAN_SCOPE_NOT_APPROVED,
    DISCOVERY_RUN_ERROR_SERVICE_REQUIRES_PROCESS,
    DISCOVERY_RUN_ERROR_TARGET_EXCLUDED_BY_BOUNDARY,
    TERMINAL_DISCOVERY_RUN_STATUSES,
    DiscoveryApprovalStatus,
    DiscoveryPurpose,
    DiscoveryRequestSource,
    DiscoveryRunStatus,
    DiscoveryStage,
)
from src.core.constants.evidence_scanner_enums import (
    ScannerInstanceStatus,
    ScannerNetworkType,
    ScannerProfile,
)
from src.core.model_defs.common import utcnow as _aware_utcnow
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.model_defs.process_scan_scope import ProcessScanScope
from src.core.model_defs.tenant_org import Organization
from src.core.models import User
from src.core.roles import ADMIN_ROLES
from src.core.services.discovery_boundary_matching import is_within
from src.core.services.discovery_run_snapshots import (
    build_profile_snapshot,
    resolve_approved_targets,
)
from src.core.services.evidence_scanner_readiness_service import required_tools_available
from src.core.services.process_scan_scope_service import resolve_effective_process_scan_scope
from src.core.services.process_scanner_link_service import (
    ProcessScannerLinkNotFoundError,
    ProcessScannerLinkValidationError,
    get_active_link,
    require_business_process,
    require_service_belongs_to_process,
)

_SCANNER_CONNECTED_STATUSES = frozenset({ScannerInstanceStatus.ONLINE.value, ScannerInstanceStatus.DEGRADED.value})


class DiscoveryRunValidationError(ValueError):
    """Raised when a discovery-run request or transition cannot proceed at all
    (concurrency conflicts, invalid transitions) — as opposed to a
    precondition gap, which is recorded as a real BLOCKED run instead of
    raising (spec's own UI wants a queryable, explainable blocked resource,
    not a bare error)."""


def utcnow():
    """This module's DB DateTime columns are naive-UTC (established repo
    convention, e.g. evidence_scanner_service._naive_utc) but
    model_defs.common.utcnow() returns a timezone-aware value — comparing
    a DB-loaded naive datetime against an aware one raises TypeError.
    Shadowed here so every call site in this module gets a naive value."""
    return _aware_utcnow().replace(tzinfo=None)


@dataclass(frozen=True)
class DiscoveryApprovalEvaluation:
    required: bool
    reasons: list[dict] = field(default_factory=list)
    eligible_approver_user_ids: list[int] = field(default_factory=list)


def can_transition_discovery_run(run: DiscoveryRun, to_status: str) -> bool:
    """Whether ``to_status`` is legal from the run's current state.

    Exists so a caller can *ask* instead of catching — the transition table stays
    the single authority, and no call site re-encodes a copy of it. Added for
    BUG-DISC-04, where the expiry path assumed EXPIRED was always reachable and
    raised out of an agent-facing route when it was not.
    """
    return to_status in ALLOWED_DISCOVERY_RUN_TRANSITIONS.get(run.status, frozenset())


def transition_discovery_run(run: DiscoveryRun, to_status: str) -> None:
    """The guarded transition function spec §11 requires — no status is ever
    assigned to a DiscoveryRun outside this function."""
    allowed = ALLOWED_DISCOVERY_RUN_TRANSITIONS.get(run.status, frozenset())
    if to_status not in allowed:
        raise DiscoveryRunValidationError(f"{DISCOVERY_RUN_ERROR_INVALID_TRANSITION} ({run.status} -> {to_status})")
    run.status = to_status
    run.updated_at = utcnow()


def _eligible_approver_user_ids(db: Session, organization_id: int) -> list[int]:
    users = (
        db.query(User)
        .filter(User.organization_id == organization_id, User.is_active.is_(True), User.role.in_(ADMIN_ROLES))
        .all()
    )
    return [u.id for u in users]


def evaluate_approval_requirement(
    db: Session, organization_id: int, profile_snapshot: dict, target_snapshot: list[dict]
) -> DiscoveryApprovalEvaluation:
    """Deterministic, testable per spec §13 — deliberately narrow. Only two
    of spec §13's example conditions are backed by real, existing data in
    this repo: the profile being a vulnerability assessment, and any
    included network target being classified PRODUCTION. Maintenance
    windows, an org-level dual-control policy flag, and "scope never
    scanned before" are not modelled anywhere in this codebase and are not
    fabricated here — see TASKS.md for the disclosure. No distinct
    approver role exists either (spec §7 itself says reuse the existing
    role system, and this repo's only exists as a flat org_admin tier), so
    eligible approvers are simply every active org_admin-tier user."""
    reasons: list[dict] = []
    if profile_snapshot.get("profileType") == ScannerProfile.VULNERABILITY_ASSESSMENT.value:
        reasons.append(
            {
                "code": DISCOVERY_APPROVAL_REASON_VULNERABILITY_PROFILE,
                "message": "Vulnerability assessment scans require approval before they can start.",
            }
        )
    if any(target.get("networkType") == ScannerNetworkType.PRODUCTION.value for target in target_snapshot):
        reasons.append(
            {
                "code": DISCOVERY_APPROVAL_REASON_PRODUCTION_NETWORK,
                "message": "The approved scope includes a production network and requires approval before it can start.",
            }
        )
    if not reasons:
        return DiscoveryApprovalEvaluation(required=False)
    return DiscoveryApprovalEvaluation(
        required=True,
        reasons=reasons,
        eligible_approver_user_ids=_eligible_approver_user_ids(db, organization_id),
    )



def _evaluate_approved_boundary(
    db: Session, *, organization_id: int, evidence_source_id: str, target_snapshot: list[dict]
) -> list[str]:
    """CA-05.B — honour the boundary a human approved.

    An approved boundary is **mandatory** (Søren, 2026-08-11): every discovery
    run must trace back to a boundary a human signed off, because that
    traceability is the platform's audit argument. Surfaced as a readiness
    blocker alongside technical_owner_required, so an organisation is told what
    to do rather than hitting a bare refusal.

    Only exclusions are enforced. A proposal's inclusions are the *newly*
    uncovered values it added, not the whole boundary — targets already approved
    before the proposal are legitimately absent from that list, so treating
    inclusions as an allow-list would block them. Exclusions are the human's
    explicit "never scan this", and that is what must bind.
    """
    from src.core.services.discovery_scope_proposal_service import get_approved_scope

    boundary = get_approved_scope(
        db, organization_id=organization_id, evidence_source_id=evidence_source_id
    )
    if boundary is None:
        return [DISCOVERY_RUN_ERROR_BOUNDARY_APPROVAL_REQUIRED]

    exclusions = list(boundary.exclusions or [])
    if not exclusions:
        return []

    for target in target_snapshot:
        value = str(target.get("approvedValue") or "").strip()
        if value and is_within(value, exclusions):
            return [DISCOVERY_RUN_ERROR_TARGET_EXCLUDED_BY_BOUNDARY]
    return []

def _evaluate_preconditions(
    db: Session, organization: Organization, instance: ScannerInstance
) -> list[str]:
    blocking: list[str] = []
    if organization.technical_setup_owner_user_id is None:
        blocking.append("technical_owner_required")
    if instance.status in (ScannerInstanceStatus.REVOKED.value, ScannerInstanceStatus.RETIRED.value):
        blocking.append("scanner_not_activated")
    elif instance.status not in _SCANNER_CONNECTED_STATUSES:
        blocking.append("scanner_offline")
    if instance.scan_profile is None:
        blocking.append("discovery_profile_required")
    elif not required_tools_available(db, instance):
        blocking.append("scanner_capability_required")
    return blocking


def evaluate_discovery_readiness(db: Session, organization: Organization, instance: ScannerInstance) -> list[str]:
    """Read-only precondition check for the Step 4 landing state (spec
    §25.1) — reuses the exact same checks ``create_discovery_run`` gates
    on, so "ready" here always means a real request would succeed."""
    _, _, scope_blocking = resolve_approved_targets(db, evidence_source_id=instance.evidence_source_id, target_ids=None)
    return _evaluate_preconditions(db, organization, instance) + scope_blocking


def _has_active_run(db: Session, *, scanner_instance_id: str) -> bool:
    """Row-locked concurrency check (spec §19) — serialised within the
    same transaction as the insert via SELECT ... FOR UPDATE on the
    scanner instance itself, since there is no partial-unique-index
    guaranteed portable across this repo's Postgres-prod/SQLite-test split."""
    db.query(ScannerInstance).filter(ScannerInstance.id == scanner_instance_id).with_for_update().first()
    existing = (
        db.query(DiscoveryRun)
        .filter(
            DiscoveryRun.scanner_instance_id == scanner_instance_id,
            DiscoveryRun.status.notin_(TERMINAL_DISCOVERY_RUN_STATUSES),
        )
        .first()
    )
    return existing is not None


def _resolve_process_context(
    db: Session, *, organization_id: int, scanner_instance_id: str, business_process_id: str | None,
    business_service_id: str | None,
) -> ProcessScanScope | None:
    """CA-04.7 — validates (never assumes) a run's own process/service
    attribution before it gets snapshotted onto the run row. A business
    service always requires a process (it narrows the process's own
    scope, it does not stand alone); the process itself must be backed by
    a real, currently ACTIVE ProcessScannerLink for this exact scanner
    instance — a process the scanner was never (or no longer) authorized
    to scan cannot be claimed by a new run just because the caller named
    its id.

    CA-10 — a process-scoped run additionally requires an approved,
    currently-effective ProcessScanScope; the resolved scope is returned so
    the caller can snapshot its id/version onto the run (the two placeholder
    columns DiscoveryRun has carried since CA-04.7)."""
    if business_process_id is None:
        if business_service_id is not None:
            raise DiscoveryRunValidationError(DISCOVERY_RUN_ERROR_SERVICE_REQUIRES_PROCESS)
        return None

    try:
        require_business_process(db, organization_id=organization_id, business_process_id=business_process_id)
    except ProcessScannerLinkNotFoundError as exc:
        raise DiscoveryRunValidationError(str(exc)) from exc

    if get_active_link(db, scanner_instance_id=scanner_instance_id, business_process_id=business_process_id) is None:
        raise DiscoveryRunValidationError(DISCOVERY_RUN_ERROR_PROCESS_NOT_LINKED)

    if business_service_id is not None:
        try:
            require_service_belongs_to_process(
                db,
                organization_id=organization_id,
                business_service_id=business_service_id,
                business_process_id=business_process_id,
            )
        except (ProcessScannerLinkNotFoundError, ProcessScannerLinkValidationError) as exc:
            raise DiscoveryRunValidationError(str(exc)) from exc

    scope = resolve_effective_process_scan_scope(
        db, organization_id=organization_id, business_process_id=business_process_id
    )
    if scope is None:
        raise DiscoveryRunValidationError(DISCOVERY_RUN_ERROR_PROCESS_SCAN_SCOPE_NOT_APPROVED)
    return scope


def create_discovery_run(
    db: Session,
    *,
    organization: Organization,
    instance: ScannerInstance,
    requested_by_user_id: int,
    request_source: str = DiscoveryRequestSource.ONBOARDING.value,
    discovery_purpose: str = DiscoveryPurpose.FIRST_ORGANISATION_DISCOVERY.value,
    target_ids: list[str] | None = None,
    idempotency_key: str | None = None,
    retry_of_discovery_run_id: str | None = None,
    retry_count: int = 0,
    business_process_id: str | None = None,
    business_service_id: str | None = None,
) -> DiscoveryRun:
    if idempotency_key:
        existing = (
            db.query(DiscoveryRun)
            .filter(
                DiscoveryRun.organization_id == organization.id,
                DiscoveryRun.requested_by_user_id == requested_by_user_id,
                DiscoveryRun.idempotency_key == idempotency_key,
            )
            .first()
        )
        if existing is not None:
            return existing

    if _has_active_run(db, scanner_instance_id=instance.id):
        raise DiscoveryRunValidationError(DISCOVERY_RUN_ERROR_DISCOVERY_ALREADY_RUNNING)

    process_scan_scope = _resolve_process_context(
        db,
        organization_id=organization.id,
        scanner_instance_id=instance.id,
        business_process_id=business_process_id,
        business_service_id=business_service_id,
    )

    resolved_ids, target_snapshot, scope_blocking = resolve_approved_targets(
        db, evidence_source_id=instance.evidence_source_id, target_ids=target_ids
    )
    profile_snapshot = build_profile_snapshot(instance)
    blocking_reasons = (
        _evaluate_preconditions(db, organization, instance)
        + scope_blocking
        + _evaluate_approved_boundary(
            db,
            organization_id=organization.id,
            evidence_source_id=instance.evidence_source_id,
            target_snapshot=target_snapshot,
        )
    )

    run = DiscoveryRun(
        organization_id=organization.id,
        evidence_source_id=instance.evidence_source_id,
        scanner_instance_id=instance.id,
        requested_by_user_id=requested_by_user_id,
        request_source=request_source,
        discovery_purpose=discovery_purpose,
        profile_snapshot=profile_snapshot,
        target_ids=resolved_ids,
        target_snapshot=target_snapshot,
        business_process_id=business_process_id,
        business_service_id=business_service_id,
        process_scan_scope_id=process_scan_scope.id if process_scan_scope else None,
        process_scan_scope_revision=process_scan_scope.revision if process_scan_scope else None,
        status=DiscoveryRunStatus.DRAFT.value,
        current_stage=DiscoveryStage.PREPARING.value,
        approval_status=DiscoveryApprovalStatus.NOT_REQUIRED.value,
        idempotency_key=idempotency_key,
        retry_of_discovery_run_id=retry_of_discovery_run_id,
        retry_count=retry_count,
    )
    db.add(run)
    db.flush()  # populate run.id (client-side UUID default) before anything reads it
    transition_discovery_run(run, DiscoveryRunStatus.VALIDATING.value)

    if blocking_reasons:
        transition_discovery_run(run, DiscoveryRunStatus.BLOCKED.value)
        run.failure_code = blocking_reasons[0]
        run.next_action = "Resolve the listed blockers, then request discovery again."
        return run

    approval = evaluate_approval_requirement(db, organization.id, profile_snapshot, target_snapshot)
    if approval.required:
        transition_discovery_run(run, DiscoveryRunStatus.AWAITING_APPROVAL.value)
        run.approval_status = DiscoveryApprovalStatus.PENDING.value
        run.next_action = "An organisation administrator must approve this request before it can start."
        return run

    transition_discovery_run(run, DiscoveryRunStatus.APPROVED.value)
    run.approved_at = utcnow()
    return run


def approve_discovery_run(db: Session, run: DiscoveryRun, *, approved_by_user_id: int) -> DiscoveryRun:
    if run.status != DiscoveryRunStatus.AWAITING_APPROVAL.value:
        raise DiscoveryRunValidationError(DISCOVERY_RUN_ERROR_INVALID_TRANSITION)
    transition_discovery_run(run, DiscoveryRunStatus.APPROVED.value)
    run.approval_status = DiscoveryApprovalStatus.APPROVED.value
    run.approved_by_user_id = approved_by_user_id
    run.approved_at = utcnow()
    run.next_action = None
    db.add(run)
    return run
