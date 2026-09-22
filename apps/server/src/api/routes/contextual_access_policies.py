"""CA-07.0 — the write surface for the organisation's contextual-access decisions.

Mirrors ``leadership_authorization`` and ``risk_appetite_policies``: the
Organisation Administrator prepares and submits; the organisation's named
leadership sponsor — the same real account ``LeadershipAuthorization`` already
names as accountable — approves or rejects. There is deliberately no update or
delete route: changing the decision means approving a new version, which
supersedes the old one and leaves it readable.

Reads answer three different questions and are kept apart on purpose:
``/operating-mode`` and ``/artefact-default`` say what was decided (``resolved:
false`` when nothing was), ``/artefact-choices`` says what a person may still
choose — always all five — and ``/status`` carries the full governance history.
"""

from __future__ import annotations


import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.contextual_access_enums import (
    CONTEXTUAL_ACCESS_AUDIT_APPROVED,
    CONTEXTUAL_ACCESS_AUDIT_DRAFT_CREATED,
    CONTEXTUAL_ACCESS_AUDIT_REJECTED,
    CONTEXTUAL_ACCESS_AUDIT_SUBMITTED,
    CONTEXTUAL_ACCESS_ERROR_ADMIN_REQUIRED,
    CONTEXTUAL_ACCESS_ERROR_LEADERSHIP_SPONSOR_REQUIRED,
    CONTEXTUAL_ACCESS_ERROR_NOT_FOUND,
    ContextualAccessDecision,
    ContextualAccessPolicyStatus,
)
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.contextual_access_policy import ContextualAccessPolicy
from src.core.models import AuditEvent, User
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES
from src.core.services.contextual_access_policy_service import (
    ContextualAccessPolicyValidationError,
    approve_policy_draft,
    available_artefact_access_choices,
    consequence_for,
    create_policy_draft,
    deviates_from_default,
    get_active_policy,
    reject_policy_draft,
    submit_policy_draft,
)
from src.core.services.leadership_authorization_service import get_active_leadership_authorization
from src.api.schemas.timestamps import UtcTimestamp

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/contextual-access", tags=["Contextual access"])


class ContextualAccessDraftRequest(BaseModel):
    decision: ContextualAccessDecision
    choice: str
    review_at: UtcTimestamp | None = None
    effective_to: UtcTimestamp | None = None
    note: str | None = None


class ContextualAccessApprovalRequest(BaseModel):
    # Not defaulted to True: the approver states that the consequence was shown
    # and accepted. A default would let the acknowledgement be assumed, which is
    # the one thing this field exists to prevent.
    consequence_acknowledged: bool
    approval_reference: str | None = None


class ContextualAccessRejectionRequest(BaseModel):
    rejection_reason: str


class ContextualAccessPolicyResponse(BaseModel):
    id: str
    decision: str
    choice: str
    status: str
    version: int
    consequence_statement: str
    consequence_acknowledged: bool
    prepared_by: str | None = None
    submitted_by: str | None = None
    submitted_at: UtcTimestamp | None = None
    approved_by: str | None = None
    approved_at: UtcTimestamp | None = None
    approval_reference: str | None = None
    rejected_by: str | None = None
    rejected_at: UtcTimestamp | None = None
    rejection_reason: str | None = None
    note: str | None = None
    effective_from: UtcTimestamp | None = None
    effective_to: UtcTimestamp | None = None
    review_at: UtcTimestamp | None = None
    superseded_by_id: str | None = None


class ResolvedDecisionResponse(BaseModel):
    """``resolved: false`` says the organisation has not decided.

    Never a default value — a decision nobody made must not read as one
    somebody did.
    """

    resolved: bool
    policy: ContextualAccessPolicyResponse | None = None


class ArtefactAccessChoiceOption(BaseModel):
    choice: str
    consequence: str
    is_standing_default: bool
    requires_reasoning: bool


class ArtefactAccessChoicesResponse(BaseModel):
    """Every choice, always — with the standing default marked, not enforced."""

    standing_default: str | None = None
    choices: list[ArtefactAccessChoiceOption]


class ContextualAccessGovernanceStatusResponse(BaseModel):
    active: ContextualAccessPolicyResponse | None = None
    pending: ContextualAccessPolicyResponse | None = None
    history: list[ContextualAccessPolicyResponse] = []


def _response(policy: ContextualAccessPolicy) -> ContextualAccessPolicyResponse:
    return ContextualAccessPolicyResponse(
        id=policy.id,
        decision=policy.decision,
        choice=policy.choice,
        status=policy.status,
        version=policy.version,
        consequence_statement=policy.consequence_statement,
        consequence_acknowledged=bool(policy.consequence_acknowledged),
        prepared_by=policy.prepared_by,
        submitted_by=policy.submitted_by,
        submitted_at=policy.submitted_at,
        approved_by=policy.approved_by,
        approved_at=policy.approved_at,
        approval_reference=policy.approval_reference,
        rejected_by=policy.rejected_by,
        rejected_at=policy.rejected_at,
        rejection_reason=policy.rejection_reason,
        note=policy.note,
        effective_from=policy.effective_from,
        effective_to=policy.effective_to,
        review_at=policy.review_at,
        superseded_by_id=policy.superseded_by_id,
    )


def _require_org_admin(db: Session, ctx: TenantContext) -> None:
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or user.role not in ADMIN_ROLES:
        raise AuthorizationError(CONTEXTUAL_ACCESS_ERROR_ADMIN_REQUIRED)


def _require_leadership_sponsor(db: Session, ctx: TenantContext) -> None:
    """Approval belongs to the organisation's named accountable sponsor.

    Mode A means a usable credential lives on a Collector and is used with
    nobody watching. That is a leadership-grade risk acceptance, held to the
    same bar as the risk appetite it operates under.
    """
    authorization = get_active_leadership_authorization(db, ctx.organization_id)
    if authorization is None or ctx.user_id != authorization.sponsor_user_id:
        raise AuthorizationError(CONTEXTUAL_ACCESS_ERROR_LEADERSHIP_SPONSOR_REQUIRED)


def _require_policy(db: Session, *, ctx: TenantContext, policy_id: str) -> ContextualAccessPolicy:
    policy = TenantRepository(db, ContextualAccessPolicy, ctx.organization_id).get_by_id(policy_id)
    if policy is None:
        raise ResourceNotFoundError(CONTEXTUAL_ACCESS_ERROR_NOT_FOUND)
    return policy


def _write_audit(
    db: Session, *, ctx: TenantContext, event_type: str, policy: ContextualAccessPolicy
) -> None:
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=event_type,
            metadata_json={
                "policy_id": policy.id,
                "decision": policy.decision,
                "choice": policy.choice,
                "version": policy.version,
                "status": policy.status,
            },
        )
    )


@router.post("/drafts", response_model=ContextualAccessPolicyResponse)
def create_draft(
    body: ContextualAccessDraftRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ContextualAccessPolicyResponse:
    _require_org_admin(db, ctx)
    try:
        policy = create_policy_draft(
            db,
            organization_id=ctx.organization_id,
            decision=body.decision.value,
            choice=body.choice,
            prepared_by=str(ctx.user_id),
            review_at=body.review_at,
            effective_to=body.effective_to,
            note=body.note,
        )
    except ContextualAccessPolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=CONTEXTUAL_ACCESS_AUDIT_DRAFT_CREATED, policy=policy)
    db.commit()
    db.refresh(policy)
    return _response(policy)


@router.post("/drafts/{policy_id}/submit", response_model=ContextualAccessPolicyResponse)
def submit_draft(
    policy_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ContextualAccessPolicyResponse:
    _require_org_admin(db, ctx)
    policy = _require_policy(db, ctx=ctx, policy_id=policy_id)
    try:
        submit_policy_draft(db, policy, submitted_by=str(ctx.user_id))
    except ContextualAccessPolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=CONTEXTUAL_ACCESS_AUDIT_SUBMITTED, policy=policy)
    db.commit()
    db.refresh(policy)
    return _response(policy)


@router.post("/drafts/{policy_id}/approve", response_model=ContextualAccessPolicyResponse)
def approve_draft(
    policy_id: str,
    body: ContextualAccessApprovalRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ContextualAccessPolicyResponse:
    policy = _require_policy(db, ctx=ctx, policy_id=policy_id)
    _require_leadership_sponsor(db, ctx)
    try:
        approve_policy_draft(
            db,
            policy,
            approved_by=str(ctx.user_id),
            consequence_acknowledged=body.consequence_acknowledged,
            approval_reference=body.approval_reference,
        )
    except ContextualAccessPolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=CONTEXTUAL_ACCESS_AUDIT_APPROVED, policy=policy)
    db.commit()
    db.refresh(policy)
    return _response(policy)


@router.post("/drafts/{policy_id}/reject", response_model=ContextualAccessPolicyResponse)
def reject_draft(
    policy_id: str,
    body: ContextualAccessRejectionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ContextualAccessPolicyResponse:
    policy = _require_policy(db, ctx=ctx, policy_id=policy_id)
    _require_leadership_sponsor(db, ctx)
    try:
        reject_policy_draft(
            db,
            policy,
            rejected_by=str(ctx.user_id),
            rejection_reason=body.rejection_reason,
        )
    except ContextualAccessPolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=CONTEXTUAL_ACCESS_AUDIT_REJECTED, policy=policy)
    db.commit()
    db.refresh(policy)
    return _response(policy)


@router.get("/operating-mode", response_model=ResolvedDecisionResponse)
def get_operating_mode(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ResolvedDecisionResponse:
    """How this organisation has decided deeper access runs — or that it hasn't."""
    policy = get_active_policy(
        db, ctx.organization_id, ContextualAccessDecision.ACCESS_OPERATING_MODE.value
    )
    if policy is None:
        return ResolvedDecisionResponse(resolved=False)
    return ResolvedDecisionResponse(resolved=True, policy=_response(policy))


@router.get("/artefact-default", response_model=ResolvedDecisionResponse)
def get_artefact_default(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ResolvedDecisionResponse:
    """The organisation's standing default answer for per-artefact access."""
    policy = get_active_policy(
        db, ctx.organization_id, ContextualAccessDecision.DEEPER_ACCESS_DEFAULT.value
    )
    if policy is None:
        return ResolvedDecisionResponse(resolved=False)
    return ResolvedDecisionResponse(resolved=True, policy=_response(policy))


@router.get("/artefact-choices", response_model=ArtefactAccessChoicesResponse)
def get_artefact_choices(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArtefactAccessChoicesResponse:
    """Every per-artefact access choice, with the standing default marked.

    The list never shrinks. A standing policy sets which answer is free and
    which owes a reason; it does not withdraw an option (``CLAUDE.md:217``).
    """
    active = get_active_policy(
        db, ctx.organization_id, ContextualAccessDecision.DEEPER_ACCESS_DEFAULT.value
    )
    standing_default = active.choice if active else None
    return ArtefactAccessChoicesResponse(
        standing_default=standing_default,
        choices=[
            ArtefactAccessChoiceOption(
                choice=choice,
                consequence=consequence_for(choice),
                is_standing_default=choice == standing_default,
                requires_reasoning=deviates_from_default(standing_default, choice),
            )
            for choice in available_artefact_access_choices()
        ],
    )


@router.get("/status", response_model=ContextualAccessGovernanceStatusResponse)
def get_status(
    decision: ContextualAccessDecision,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ContextualAccessGovernanceStatusResponse:
    """One decision's full governance state: active, pending, and history."""
    policies = (
        db.query(ContextualAccessPolicy)
        .filter(
            ContextualAccessPolicy.organization_id == ctx.organization_id,
            ContextualAccessPolicy.decision == decision.value,
        )
        .order_by(ContextualAccessPolicy.version.desc())
        .all()
    )
    active = next(
        (p for p in policies if p.status == ContextualAccessPolicyStatus.ACTIVE.value), None
    )
    pending = next(
        (
            p
            for p in policies
            if p.status
            in (
                ContextualAccessPolicyStatus.DRAFT.value,
                ContextualAccessPolicyStatus.LEADERSHIP_REVIEW.value,
            )
        ),
        None,
    )
    return ContextualAccessGovernanceStatusResponse(
        active=_response(active) if active else None,
        pending=_response(pending) if pending else None,
        history=[_response(p) for p in policies],
    )


__all__ = ["router"]
