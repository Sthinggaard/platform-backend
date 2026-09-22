"""Risk appetite policy routes — organisation, process override, decision exception.

Writes are append-only supersedes with approval provenance; reads return the
resolved appetite for a process with its full provenance chain. The dashboard
projection consumes the same resolution service — this is its write surface.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.schemas.timestamps import UtcTimestamp
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.risk_appetite_policy import (
    APPETITE_AUDIT_APPROVED,
    APPETITE_AUDIT_DRAFT_CREATED,
    APPETITE_AUDIT_ORGANISATION_ACCEPTED,
    APPETITE_AUDIT_REJECTED,
    APPETITE_AUDIT_SUBMITTED,
    APPETITE_ERROR_ADMIN_REQUIRED,
    APPETITE_ERROR_LEADERSHIP_SPONSOR_REQUIRED,
    APPETITE_ERROR_ORGANISATION_DRAFT_REQUIRED,
    APPETITE_ERROR_POLICY_NOT_FOUND,
    APPETITE_ERROR_PROCESS_DRAFT_REQUIRED,
    APPETITE_SCOPE_BUSINESS_PROCESS,
    APPETITE_SCOPE_DECISION_EXCEPTION,
    APPETITE_SCOPE_ORGANISATION,
    RiskAppetitePolicy,
)
from src.core.models import AuditEvent, BusinessService, Organization, User, ValueStream
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES
from src.core.services.effective_process_bia_service import (
    resolve_effective_process_bia_by_process,
)
from src.core.services.leadership_authorization_service import get_active_leadership_authorization
from src.core.services.organisation_appetite_recommendation_service import (
    recommend_organisation_appetite,
)
from src.core.services.peer_appetite_benchmark_service import (
    org_peer_appetite_benchmark,
    peer_appetite_benchmark,
)
from src.core.services.process_appetite_recommendation_service import recommend_process_appetite
from src.core.services.process_ownership_service import (
    ProcessOwnershipValidationError,
    require_accepted_process_owner,
)
from src.core.services.risk_appetite_resolution_service import (
    AppetitePolicyValidationError,
    approve_appetite_draft,
    create_appetite_draft,
    list_active_process_appetite_reviews,
    reject_appetite_draft,
    resolve_process_appetite,
    set_appetite_policy,
    submit_appetite_draft,
)
from src.core.services.service_appetite_reassessment_service import (
    list_approved_reassessment_reviews,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/risk-appetite", tags=["Risk appetite"])


class AppetitePolicyWriteRequest(BaseModel):
    answers: dict
    approved_by: str
    note: str | None = None


class AppetiteExceptionWriteRequest(AppetitePolicyWriteRequest):
    effective_to: UtcTimestamp
    review_at: UtcTimestamp
    decision_reference: str | None = None


class AppetitePolicyResponse(BaseModel):
    policy_id: str
    scope: str
    process_id: str | None = None
    version: int
    status: str
    answers: dict | None = None
    note: str | None = None
    prepared_by: str | None = None
    submitted_by: str | None = None
    submitted_at: UtcTimestamp | None = None
    approved_by: str | None = None
    approved_at: UtcTimestamp | None = None
    rejected_by: str | None = None
    rejected_at: UtcTimestamp | None = None
    rejection_reason: str | None = None
    effective_from: UtcTimestamp | None = None
    effective_to: UtcTimestamp | None = None
    review_at: UtcTimestamp | None = None


class AppetiteGovernanceStatusResponse(BaseModel):
    active: AppetitePolicyResponse | None = None
    pending: AppetitePolicyResponse | None = None
    history: list[AppetitePolicyResponse] = []

    #: The appetite this business process is registered against, if its owner
    #: has decided — the organisation's policy where they accepted the inherited
    #: baseline, their own where they proposed a deviation.
    #:
    #: ⚠️ **Not derivable from the three fields above.** Accepting the inherited
    #: baseline writes no process-scoped policy, so `active` and `pending` are
    #: both null and a decided process looks exactly like one that was never
    #: asked. That is what made the workspace ask again on every load
    #: (Søren, 2026-09-11). Organisation-scope status never carries it.
    registered_policy_id: str | None = None


class AppetiteDraftRequest(BaseModel):
    answers: dict
    review_at: UtcTimestamp
    note: str | None = None


class AppetiteRecommendationAcceptanceRequest(BaseModel):
    answers: dict
    review_at: UtcTimestamp
    note: str | None = None


class AppetiteApprovalRequest(BaseModel):
    approval_reference: str | None = None
    effective_from: UtcTimestamp | None = None


class AppetiteRejectionRequest(BaseModel):
    rejection_reason: str


class ResolvedAppetiteResponse(BaseModel):
    resolved: bool
    answers: dict | None = None
    source_scope: str | None = None
    policy_id: str | None = None
    version: int | None = None
    approved_by: str | None = None
    effective_to: UtcTimestamp | None = None
    review_at: UtcTimestamp | None = None
    decision_reference: str | None = None
    expired_exception_reference: str | None = None


class DimensionGroundsResponse(BaseModel):
    """Why one dimension is recommended at the level it is, as facts."""

    #: What the organisation policy already gives this process, if anything.
    inherited_level: int | None = None
    #: What is being proposed.
    recommended_level: int
    #: Risklence's own read, present **only when it differs** from the inherited
    #: level. The live part: the platform disagreeing with what was inherited.
    suggested_level: int | None = None
    #: Each a finished clause. Never joined — how they read is the interface's.
    grounds: list[str] = []


class ProcessAppetiteRecommendationResponse(BaseModel):
    answers: dict[str, int]
    #: ⚠️ Kept because it is the note submitted to leadership and read back from
    #: the audit trail. For **display**, use `grounds` — a single sentence per
    #: dimension cannot be placed beside the thing it explains.
    reasons: dict[str, str]
    grounds: dict[str, DimensionGroundsResponse] = {}
    confidence: str
    missing_inputs: list[str]


class OrganisationAppetiteRecommendationResponse(BaseModel):
    answers: dict[str, int]
    reasons: dict[str, str]
    confidence: str
    missing_inputs: list[str]


def _policy_response(policy) -> AppetitePolicyResponse:
    return AppetitePolicyResponse(
        policy_id=policy.id,
        scope=policy.scope,
        process_id=policy.process_id,
        version=policy.version,
        status=policy.status,
        answers=policy.answers or None,
        note=policy.note,
        prepared_by=policy.prepared_by,
        submitted_by=policy.submitted_by,
        submitted_at=policy.submitted_at.isoformat() if policy.submitted_at else None,
        approved_by=policy.approved_by,
        approved_at=policy.approved_at.isoformat() if policy.approved_at else None,
        rejected_by=policy.rejected_by,
        rejected_at=policy.rejected_at.isoformat() if policy.rejected_at else None,
        rejection_reason=policy.rejection_reason,
        effective_from=policy.effective_from.isoformat() if policy.effective_from else None,
        effective_to=policy.effective_to.isoformat() if policy.effective_to else None,
        review_at=policy.review_at.isoformat() if policy.review_at else None,
    )


def _require_org_admin(db: Session, ctx: TenantContext) -> None:
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or user.role not in ADMIN_ROLES:
        raise AuthorizationError(APPETITE_ERROR_ADMIN_REQUIRED)


def _require_leadership_sponsor(db: Session, ctx: TenantContext) -> None:
    """Risk appetite (organisation and business-process scope alike) is
    approved by the organisation's named leadership sponsor — the same real
    account LeadershipAuthorization already names as accountable for the
    onboarding programme — never the generic Approver/Escalation Contact
    mandate role appetite used before this cascade redesign."""
    authorization = get_active_leadership_authorization(db, ctx.organization_id)
    if authorization is None or ctx.user_id != authorization.sponsor_user_id:
        raise AuthorizationError(APPETITE_ERROR_LEADERSHIP_SPONSOR_REQUIRED)


def _require_process_owner(db: Session, ctx: TenantContext, process_id: str) -> None:
    try:
        require_accepted_process_owner(
            db, organization_id=ctx.organization_id, process_id=process_id, user_id=ctx.user_id
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc


def _require_organisation_policy(
    db: Session,
    *,
    ctx: TenantContext,
    policy_id: str,
) -> RiskAppetitePolicy:
    policy = TenantRepository(db, RiskAppetitePolicy, ctx.organization_id).get_by_id(policy_id)
    if policy is None or policy.scope != APPETITE_SCOPE_ORGANISATION:
        raise ResourceNotFoundError(APPETITE_ERROR_POLICY_NOT_FOUND)
    return policy


def _require_process_policy(
    db: Session,
    *,
    ctx: TenantContext,
    process_id: str,
    policy_id: str,
) -> RiskAppetitePolicy:
    policy = TenantRepository(db, RiskAppetitePolicy, ctx.organization_id).get_by_id(policy_id)
    if (
        policy is None
        or policy.scope != APPETITE_SCOPE_BUSINESS_PROCESS
        or policy.process_id != process_id
    ):
        raise ResourceNotFoundError(APPETITE_ERROR_POLICY_NOT_FOUND)
    return policy


def _write_appetite_audit(
    db: Session,
    *,
    ctx: TenantContext,
    event_type: str,
    policy: RiskAppetitePolicy,
    process_id: str | None = None,
) -> None:
    """Record an appetite decision in the audit trail.

    ⚠️ **Name the process.** Accepting the organisation's appetite for a process
    recorded the *organisation* policy and nothing else, so the event could not
    say which process the owner had decided for — a decision documented in a
    form nobody could attribute, against the product's own rule that it always
    documents. `policy.process_id` carries it for process-scoped policies;
    `process_id` carries it for the inherited case, where the policy is the
    organisation's.
    """
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=event_type,
            metadata_json={
                "policy_id": policy.id,
                "scope": policy.scope,
                "version": policy.version,
                "status": policy.status,
                "process_id": process_id or policy.process_id,
            },
        )
    )


def _require_process(db: Session, organization_id: int, process_id: str) -> ValueStream:
    process = (
        db.query(ValueStream)
        .filter(ValueStream.id == process_id, ValueStream.organization_id == organization_id)
        .first()
    )
    if process is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Business process not found")
    return process


def _build_process_appetite_recommendation(
    db: Session,
    *,
    organization_id: int,
    process: ValueStream,
):
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    peers = peer_appetite_benchmark(
        db, library_item_id=process.library_item_id, exclude_organization_id=organization_id
    )
    resolved = resolve_process_appetite(db, organization_id=organization_id, process_id=process.id)
    # The BIA a process *effectively* has: its own attested exception, else the
    # organisation baseline it inherits. Reading ``process.bia_answers`` here
    # left every inheriting process recommending from no BIA at all.
    effective_bia = resolve_effective_process_bia_by_process(
        db,
        organization_id=organization_id,
        processes=[process],
    ).get(process.id)
    return recommend_process_appetite(
        bia_answers=effective_bia.answers if effective_bia is not None else None,
        required_frameworks=list(org.required_frameworks or []) if org else [],
        process_priority=process.priority,
        peer_benchmark=peers,
        cascaded_org_answers=resolved.answers if resolved is not None else None,
    )


def _write(db: Session, ctx: TenantContext, *, scope: str, process_id: str | None, body) -> AppetitePolicyResponse:
    try:
        policy = set_appetite_policy(
            db,
            organization_id=ctx.organization_id,
            scope=scope,
            process_id=process_id,
            answers=body.answers,
            approved_by=body.approved_by,
            note=body.note,
            effective_to=getattr(body, "effective_to", None),
            review_at=getattr(body, "review_at", None),
            decision_reference=getattr(body, "decision_reference", None),
        )
    except AppetitePolicyValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    db.commit()
    db.refresh(policy)
    logger.info(
        "risk_appetite_policy_written",
        org_id=ctx.organization_id,
        scope=scope,
        process_id=process_id,
        policy_id=policy.id,
        version=policy.version,
    )
    return _policy_response(policy)


@router.get("/organisation/recommendation", response_model=OrganisationAppetiteRecommendationResponse)
def get_organisation_appetite_recommendation(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> OrganisationAppetiteRecommendationResponse:
    """Risklence's suggested Organisation Risk Appetite — a recommendation for
    leadership to review and correct, never an activation."""
    org = db.query(Organization).filter(Organization.id == ctx.organization_id).first()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
    peers = org_peer_appetite_benchmark(db, nace_code=org.nace_code, exclude_organization_id=ctx.organization_id)
    recommendation = recommend_organisation_appetite(
        required_frameworks=list(org.required_frameworks or []), peer_benchmark=peers
    )
    return OrganisationAppetiteRecommendationResponse(
        answers=recommendation.answers,
        reasons=recommendation.reasons,
        confidence=recommendation.confidence,
        missing_inputs=recommendation.missing_inputs,
    )


@router.post("/organisation/drafts", response_model=AppetitePolicyResponse)
def create_organisation_appetite_draft(
    body: AppetiteDraftRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetitePolicyResponse:
    _require_org_admin(db, ctx)
    try:
        policy = create_appetite_draft(
            db,
            organization_id=ctx.organization_id,
            scope=APPETITE_SCOPE_ORGANISATION,
            answers=body.answers,
            prepared_by=str(ctx.user_id),
            review_at=body.review_at,
            note=body.note,
        )
    except AppetitePolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_appetite_audit(db, ctx=ctx, event_type=APPETITE_AUDIT_DRAFT_CREATED, policy=policy)
    db.commit()
    db.refresh(policy)
    return _policy_response(policy)


@router.post("/organisation/drafts/{policy_id}/submit", response_model=AppetitePolicyResponse)
def submit_organisation_appetite_draft(
    policy_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetitePolicyResponse:
    _require_org_admin(db, ctx)
    policy = _require_organisation_policy(db, ctx=ctx, policy_id=policy_id)
    try:
        submit_appetite_draft(db, policy, submitted_by=str(ctx.user_id))
    except AppetitePolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_appetite_audit(db, ctx=ctx, event_type=APPETITE_AUDIT_SUBMITTED, policy=policy)
    db.commit()
    db.refresh(policy)
    return _policy_response(policy)


@router.post("/organisation/drafts/{policy_id}/approve", response_model=AppetitePolicyResponse)
def approve_organisation_appetite_draft(
    policy_id: str,
    body: AppetiteApprovalRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetitePolicyResponse:
    _require_leadership_sponsor(db, ctx)
    policy = _require_organisation_policy(db, ctx=ctx, policy_id=policy_id)
    try:
        approve_appetite_draft(
            db,
            policy,
            approved_by=str(ctx.user_id),
            approval_reference=body.approval_reference,
            effective_from=body.effective_from,
        )
    except AppetitePolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_appetite_audit(db, ctx=ctx, event_type=APPETITE_AUDIT_APPROVED, policy=policy)
    db.commit()
    db.refresh(policy)
    return _policy_response(policy)


@router.post("/organisation/drafts/{policy_id}/reject", response_model=AppetitePolicyResponse)
def reject_organisation_appetite_draft(
    policy_id: str,
    body: AppetiteRejectionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetitePolicyResponse:
    _require_leadership_sponsor(db, ctx)
    policy = _require_organisation_policy(db, ctx=ctx, policy_id=policy_id)
    try:
        reject_appetite_draft(
            db,
            policy,
            rejected_by=str(ctx.user_id),
            rejection_reason=body.rejection_reason,
        )
    except AppetitePolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_appetite_audit(db, ctx=ctx, event_type=APPETITE_AUDIT_REJECTED, policy=policy)
    db.commit()
    db.refresh(policy)
    return _policy_response(policy)


@router.get("/processes/{process_id}/recommendation", response_model=ProcessAppetiteRecommendationResponse)
def get_process_appetite_recommendation(
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessAppetiteRecommendationResponse:
    """Risklence's suggested Process Risk Appetite. The starting answers are whatever this process currently
    effectively has (its own approved override, or the cascaded organisation
    policy) — the BIA/regulatory/peer analysis surfaces as a suggested
    deviation, not a fresh independent starting point, once an organisation
    policy exists to cascade from."""
    process = _require_process(db, ctx.organization_id, process_id)
    recommendation = _build_process_appetite_recommendation(
        db, organization_id=ctx.organization_id, process=process
    )
    return ProcessAppetiteRecommendationResponse(
        answers=recommendation.answers,
        reasons=recommendation.reasons,
        grounds={
            dim: DimensionGroundsResponse(
                inherited_level=g.inherited_level,
                recommended_level=g.recommended_level,
                suggested_level=g.suggested_level,
                grounds=g.grounds,
            )
            for dim, g in recommendation.grounds.items()
        },
        confidence=recommendation.confidence,
        missing_inputs=recommendation.missing_inputs,
    )


@router.post("/processes/{process_id}/accept-recommendation", response_model=AppetitePolicyResponse)
def accept_process_appetite_recommendation(
    process_id: str,
    body: AppetiteRecommendationAcceptanceRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetitePolicyResponse:
    """Record the Process Owner's response to the recommendation.

    Søren, 2026-08-30, two rules that meet here:

    * The owner may accept the organisation-wide appetite for their process.
      Leadership already approved that policy, so there is nothing new to
      approve — no process override is written and the process keeps
      inheriting. The decision to inherit is still recorded.
    * Any deviation from it is a change to the threshold governing the process,
      and **always** needs leadership approval. It is submitted for review and
      does not govern until leadership approves it.

    A changed answer is rejected outright and must go through the ordinary
    draft lifecycle. The comparison is repeated on the server so the client
    cannot claim an answer was unchanged when it was not.
    """
    process = _require_process(db, ctx.organization_id, process_id)
    _require_process_owner(db, ctx, process_id)
    recommendation = _build_process_appetite_recommendation(
        db, organization_id=ctx.organization_id, process=process
    )
    if body.answers != recommendation.answers:
        raise ValidationError("Changed appetite answers must be submitted for leadership review.")

    inherited = resolve_process_appetite(
        db, organization_id=ctx.organization_id, process_id=process_id
    )
    if (
        inherited is not None
        and inherited.source_scope == APPETITE_SCOPE_ORGANISATION
        and body.answers == inherited.answers
    ):
        organisation_policy = TenantRepository(
            db, RiskAppetitePolicy, ctx.organization_id
        ).get_by_id(inherited.policy_id)
        if organisation_policy is None:
            raise ResourceNotFoundError(APPETITE_ERROR_POLICY_NOT_FOUND)
        _write_appetite_audit(
            db,
            ctx=ctx,
            event_type=APPETITE_AUDIT_ORGANISATION_ACCEPTED,
            policy=organisation_policy,
            process_id=process_id,
        )
        # ⚠️ **The decision, recorded on the process.** Accepting the inherited
        # baseline deliberately writes no process override, so before this the
        # only trace was an audit line that did not carry the process id —
        # nothing could tell a process whose owner had decided to inherit from
        # one that had never been asked, and the workspace asked again on every
        # load (Søren, 2026-09-11).
        process.risk_appetite_policy_id = organisation_policy.id
        db.commit()
        db.refresh(organisation_policy)
        return _policy_response(organisation_policy)

    try:
        policy = create_appetite_draft(
            db,
            organization_id=ctx.organization_id,
            scope=APPETITE_SCOPE_BUSINESS_PROCESS,
            process_id=process_id,
            answers=body.answers,
            prepared_by=str(ctx.user_id),
            review_at=body.review_at,
            note=body.note,
        )
        _write_appetite_audit(db, ctx=ctx, event_type=APPETITE_AUDIT_DRAFT_CREATED, policy=policy)
        submit_appetite_draft(db, policy, submitted_by=str(ctx.user_id))
    except AppetitePolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_appetite_audit(db, ctx=ctx, event_type=APPETITE_AUDIT_SUBMITTED, policy=policy)
    # ⚠️ **The link is the association, not the lifecycle.** Søren, 2026-09-11:
    # *"creating a new risk appetite creates a new save to db and links that new
    # uuid fk to the business process."* Whether that appetite yet *governs* is
    # the policy's own `status` — a draft awaiting leadership is still the
    # appetite this process is working on, and the reader is asked to set one
    # only while nothing is linked at all.
    process.risk_appetite_policy_id = policy.id
    db.commit()
    db.refresh(policy)
    return _policy_response(policy)


@router.post("/processes/{process_id}/drafts", response_model=AppetitePolicyResponse)
def create_process_appetite_draft(
    process_id: str,
    body: AppetiteDraftRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetitePolicyResponse:
    """The Process Owner proposes a Process Risk Appetite; leadership approves it separately."""
    process = _require_process(db, ctx.organization_id, process_id)
    _require_process_owner(db, ctx, process_id)
    try:
        policy = create_appetite_draft(
            db,
            organization_id=ctx.organization_id,
            scope=APPETITE_SCOPE_BUSINESS_PROCESS,
            process_id=process_id,
            answers=body.answers,
            prepared_by=str(ctx.user_id),
            review_at=body.review_at,
            note=body.note,
        )
    except AppetitePolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_appetite_audit(db, ctx=ctx, event_type=APPETITE_AUDIT_DRAFT_CREATED, policy=policy)
    # ⚠️ **The link is the association, not the lifecycle.** Søren, 2026-09-11:
    # *"creating a new risk appetite creates a new save to db and links that new
    # uuid fk to the business process."* Whether that appetite yet *governs* is
    # the policy's own `status` — a draft awaiting leadership is still the
    # appetite this process is working on, and the reader is asked to set one
    # only while nothing is linked at all.
    process.risk_appetite_policy_id = policy.id
    db.commit()
    db.refresh(policy)
    return _policy_response(policy)


@router.post("/processes/{process_id}/drafts/{policy_id}/submit", response_model=AppetitePolicyResponse)
def submit_process_appetite_draft(
    process_id: str,
    policy_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetitePolicyResponse:
    _require_process(db, ctx.organization_id, process_id)
    _require_process_owner(db, ctx, process_id)
    policy = _require_process_policy(db, ctx=ctx, process_id=process_id, policy_id=policy_id)
    try:
        submit_appetite_draft(db, policy, submitted_by=str(ctx.user_id))
    except AppetitePolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_appetite_audit(db, ctx=ctx, event_type=APPETITE_AUDIT_SUBMITTED, policy=policy)
    db.commit()
    db.refresh(policy)
    return _policy_response(policy)


@router.post("/processes/{process_id}/drafts/{policy_id}/approve", response_model=AppetitePolicyResponse)
def approve_process_appetite_draft(
    process_id: str,
    policy_id: str,
    body: AppetiteApprovalRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetitePolicyResponse:
    """Leadership (a mapped Approver/Escalation Contact) approves — never the Process Owner who proposed it."""
    process = _require_process(db, ctx.organization_id, process_id)
    _require_leadership_sponsor(db, ctx)
    policy = _require_process_policy(db, ctx=ctx, process_id=process_id, policy_id=policy_id)
    try:
        approve_appetite_draft(
            db,
            policy,
            approved_by=str(ctx.user_id),
            approval_reference=body.approval_reference,
            effective_from=body.effective_from,
        )
    except AppetitePolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_appetite_audit(db, ctx=ctx, event_type=APPETITE_AUDIT_APPROVED, policy=policy)
    # Already linked when it was proposed; set again so a later version that
    # supersedes an earlier one moves the process onto it.
    process.risk_appetite_policy_id = policy.id
    db.commit()
    db.refresh(policy)
    return _policy_response(policy)


@router.post("/processes/{process_id}/drafts/{policy_id}/reject", response_model=AppetitePolicyResponse)
def reject_process_appetite_draft(
    process_id: str,
    policy_id: str,
    body: AppetiteRejectionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetitePolicyResponse:
    _require_process(db, ctx.organization_id, process_id)
    _require_leadership_sponsor(db, ctx)
    policy = _require_process_policy(db, ctx=ctx, process_id=process_id, policy_id=policy_id)
    try:
        reject_appetite_draft(
            db,
            policy,
            rejected_by=str(ctx.user_id),
            rejection_reason=body.rejection_reason,
        )
    except AppetitePolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_appetite_audit(db, ctx=ctx, event_type=APPETITE_AUDIT_REJECTED, policy=policy)
    db.commit()
    db.refresh(policy)
    return _policy_response(policy)


@router.put("/organisation", response_model=AppetitePolicyResponse)
def set_organisation_policy(
    body: AppetitePolicyWriteRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetitePolicyResponse:
    """Block the legacy direct-activation path for organisation appetite."""
    raise ValidationError(APPETITE_ERROR_ORGANISATION_DRAFT_REQUIRED)


@router.put("/processes/{process_id}", response_model=AppetitePolicyResponse)
def set_process_override(
    process_id: str,
    body: AppetitePolicyWriteRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetitePolicyResponse:
    """Block the direct-activation path — Process Risk Appetite must go through the draft/approve flow."""
    raise ValidationError(APPETITE_ERROR_PROCESS_DRAFT_REQUIRED)


@router.post("/processes/{process_id}/exceptions", response_model=AppetitePolicyResponse)
def create_decision_exception(
    process_id: str,
    body: AppetiteExceptionWriteRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetitePolicyResponse:
    """Record a temporary decision-specific appetite exception (expiry + review required)."""
    _require_process(db, ctx.organization_id, process_id)
    return _write(db, ctx, scope=APPETITE_SCOPE_DECISION_EXCEPTION, process_id=process_id, body=body)


def _governance_status(
    db: Session, *, organization_id: int, scope: str, process_id: str | None
) -> AppetiteGovernanceStatusResponse:
    policies = (
        db.query(RiskAppetitePolicy)
        .filter(
            RiskAppetitePolicy.organization_id == organization_id,
            RiskAppetitePolicy.scope == scope,
            RiskAppetitePolicy.process_id == process_id,
        )
        .order_by(RiskAppetitePolicy.version.desc())
        .all()
    )
    active = next((p for p in policies if p.status == "active"), None)
    pending = next((p for p in policies if p.status in ("draft", "leadership_review")), None)
    return AppetiteGovernanceStatusResponse(
        active=_policy_response(active) if active else None,
        pending=_policy_response(pending) if pending else None,
        history=[_policy_response(p) for p in policies],
    )


@router.get("/organisation", response_model=AppetiteGovernanceStatusResponse)
def get_organisation_appetite_status(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetiteGovernanceStatusResponse:
    """The organisation appetite's full governance state: active, pending, history."""
    return _governance_status(
        db, organization_id=ctx.organization_id, scope=APPETITE_SCOPE_ORGANISATION, process_id=None
    )


@router.get("/processes/{process_id}/drafts", response_model=AppetiteGovernanceStatusResponse)
def get_process_appetite_status(
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetiteGovernanceStatusResponse:
    """The Process Risk Appetite's full governance state: active, pending, history.

    Plus the appetite the process is registered against, which is the only thing
    that distinguishes an owner who decided to inherit from one who was never
    asked — see `AppetiteGovernanceStatusResponse.registered_policy_id`.
    """
    process = _require_process(db, ctx.organization_id, process_id)
    status_response = _governance_status(
        db,
        organization_id=ctx.organization_id,
        scope=APPETITE_SCOPE_BUSINESS_PROCESS,
        process_id=process_id,
    )
    status_response.registered_policy_id = process.risk_appetite_policy_id
    return status_response


@router.get("/processes/{process_id}", response_model=ResolvedAppetiteResponse)
def get_resolved_process_appetite(
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ResolvedAppetiteResponse:
    """The effective appetite for a process with full provenance, or unresolved."""
    _require_process(db, ctx.organization_id, process_id)
    resolved = resolve_process_appetite(db, organization_id=ctx.organization_id, process_id=process_id)
    if resolved is None:
        return ResolvedAppetiteResponse(resolved=False)
    return ResolvedAppetiteResponse(
        resolved=True,
        answers=resolved.answers,
        source_scope=resolved.source_scope,
        policy_id=resolved.policy_id,
        version=resolved.version,
        approved_by=resolved.approved_by,
        effective_to=resolved.effective_to.isoformat() if resolved.effective_to else None,
        review_at=resolved.review_at.isoformat() if resolved.review_at else None,
        decision_reference=resolved.decision_reference,
        expired_exception_reference=resolved.expired_exception_reference,
    )


class AppetiteReviewItem(BaseModel):
    """One review-dated appetite record, org-wide — for the Governance Control
    Centre's Health/Exceptions sections. Never invents a review date; only
    records that already carry one appear here."""

    kind: str  # "business_process" | "business_service"
    policy_id: str
    process_id: str | None = None
    process_name: str | None = None
    business_service_id: str | None = None
    business_service_name: str | None = None
    review_at: str


@router.get("/reviews", response_model=list[AppetiteReviewItem])
def list_appetite_reviews(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[AppetiteReviewItem]:
    """Every review-dated Process Risk Appetite + approved Service Appetite
    reassessment, org-wide — the only real "decision review" data that
    exists today (ONB-GOV-10 Governance Control Centre)."""
    process_reviews = list_active_process_appetite_reviews(db, organization_id=ctx.organization_id)
    reassessment_reviews = list_approved_reassessment_reviews(db, organization_id=ctx.organization_id)

    process_ids = {row.process_id for row in process_reviews if row.process_id}
    process_ids |= {row.process_id for row in reassessment_reviews if row.process_id}
    process_name_by_id = {
        row.id: row.name
        for row in db.query(ValueStream)
        .filter(ValueStream.organization_id == ctx.organization_id, ValueStream.id.in_(process_ids))
        .all()
    } if process_ids else {}

    service_ids = {row.business_service_id for row in reassessment_reviews}
    service_name_by_id = {
        row.id: row.name
        for row in db.query(BusinessService)
        .filter(BusinessService.organization_id == ctx.organization_id, BusinessService.id.in_(service_ids))
        .all()
    } if service_ids else {}

    items = [
        AppetiteReviewItem(
            kind="business_process",
            policy_id=row.id,
            process_id=row.process_id,
            process_name=process_name_by_id.get(row.process_id) if row.process_id else None,
            review_at=row.review_at.isoformat(),
        )
        for row in process_reviews
    ]
    items += [
        AppetiteReviewItem(
            kind="business_service",
            policy_id=row.id,
            process_id=row.process_id,
            process_name=process_name_by_id.get(row.process_id) if row.process_id else None,
            business_service_id=row.business_service_id,
            business_service_name=service_name_by_id.get(row.business_service_id),
            review_at=row.review_at.isoformat(),
        )
        for row in reassessment_reviews
    ]
    return items
