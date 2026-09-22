"""Leadership authorisation routes — the first gate of onboarding governance.

Writes are append-only supersedes with approval provenance, mirroring
``risk_appetite_policies``: the Organisation Administrator prepares and
submits a draft naming an accountable sponsor; only that named sponsor — a
real Risklence user, never free text — may approve or reject it. Naming
someone accountable for something they can never see or act on isn't real
accountability, so the sponsor must be able to log in and review this
themselves. Activating a new version supersedes the previous one rather
than mutating history.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.leadership_authorization_enums import (
    LEADERSHIP_AUTHORIZATION_AUDIT_APPROVED,
    LEADERSHIP_AUTHORIZATION_AUDIT_DRAFT_CREATED,
    LEADERSHIP_AUTHORIZATION_AUDIT_REJECTED,
    LEADERSHIP_AUTHORIZATION_AUDIT_SELF_AUTHORIZED,
    LEADERSHIP_AUTHORIZATION_AUDIT_SUBMITTED,
    LEADERSHIP_AUTHORIZATION_ERROR_ADMIN_REQUIRED,
    LEADERSHIP_AUTHORIZATION_ERROR_NOT_FOUND,
    LEADERSHIP_AUTHORIZATION_ERROR_SPONSOR_MUST_APPROVE,
    LeadershipApprovingBody,
    LeadershipAuthorizationStatus,
)
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.leadership_authorization import LeadershipAuthorization
from src.core.models import AuditEvent, User
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES
from src.core.services.leadership_authorization_service import (
    LeadershipAuthorizationValidationError,
    approve_leadership_authorization_draft,
    create_leadership_authorization_draft,
    get_active_leadership_authorization,
    reject_leadership_authorization_draft,
    self_authorize_leadership,
    submit_leadership_authorization_draft,
)
from src.core.services.user_display_service import user_display_name
from src.api.schemas.timestamps import UtcTimestamp

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/leadership-authorization", tags=["Leadership authorization"])


class LeadershipAuthorizationDraftRequest(BaseModel):
    sponsor_user_id: int
    approving_body: LeadershipApprovingBody
    authorized_scope: str
    note: str | None = None


class LeadershipAuthorizationSelfAuthorizeRequest(BaseModel):
    sponsor_user_id: int
    approving_body: LeadershipApprovingBody
    authorized_scope: str
    note: str | None = None


class LeadershipAuthorizationApprovalRequest(BaseModel):
    approval_reference: str | None = None


class LeadershipAuthorizationRejectionRequest(BaseModel):
    rejection_reason: str


class LeadershipAuthorizationResponse(BaseModel):
    id: str
    status: str
    version: int
    sponsor_user_id: int | None = None
    sponsor_name: str | None = None
    sponsor_title: str | None = None
    approving_body: str
    authorized_scope: str
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
    backfilled: bool


class ActiveLeadershipAuthorizationResponse(BaseModel):
    resolved: bool
    authorization: LeadershipAuthorizationResponse | None = None


class LeadershipAuthorizationGovernanceStatusResponse(BaseModel):
    active: LeadershipAuthorizationResponse | None = None
    pending: LeadershipAuthorizationResponse | None = None
    history: list[LeadershipAuthorizationResponse] = []


def _response(db: Session, authorization: LeadershipAuthorization) -> LeadershipAuthorizationResponse:
    sponsor = (
        TenantRepository(db, User, authorization.organization_id).get_by_id(authorization.sponsor_user_id)
        if authorization.sponsor_user_id is not None
        else None
    )
    return LeadershipAuthorizationResponse(
        id=authorization.id,
        status=authorization.status,
        version=authorization.version,
        sponsor_user_id=authorization.sponsor_user_id,
        sponsor_name=user_display_name(sponsor) if sponsor else None,
        sponsor_title=sponsor.title if sponsor else None,
        approving_body=authorization.approving_body,
        authorized_scope=authorization.authorized_scope,
        note=authorization.note,
        prepared_by=authorization.prepared_by,
        submitted_by=authorization.submitted_by,
        submitted_at=authorization.submitted_at.isoformat() if authorization.submitted_at else None,
        approved_by=authorization.approved_by,
        approved_at=authorization.approved_at.isoformat() if authorization.approved_at else None,
        rejected_by=authorization.rejected_by,
        rejected_at=authorization.rejected_at.isoformat() if authorization.rejected_at else None,
        rejection_reason=authorization.rejection_reason,
        effective_from=authorization.effective_from.isoformat() if authorization.effective_from else None,
        backfilled=bool(authorization.backfilled),
    )


def _require_org_admin(db: Session, ctx: TenantContext) -> None:
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or user.role not in ADMIN_ROLES:
        raise AuthorizationError(LEADERSHIP_AUTHORIZATION_ERROR_ADMIN_REQUIRED)


def _require_named_sponsor(ctx: TenantContext, authorization: LeadershipAuthorization) -> None:
    if ctx.user_id != authorization.sponsor_user_id:
        raise AuthorizationError(LEADERSHIP_AUTHORIZATION_ERROR_SPONSOR_MUST_APPROVE)


def _require_authorization(db: Session, *, ctx: TenantContext, authorization_id: str) -> LeadershipAuthorization:
    authorization = TenantRepository(db, LeadershipAuthorization, ctx.organization_id).get_by_id(
        authorization_id
    )
    if authorization is None:
        raise ResourceNotFoundError(LEADERSHIP_AUTHORIZATION_ERROR_NOT_FOUND)
    return authorization


def _write_audit(
    db: Session, *, ctx: TenantContext, event_type: str, authorization: LeadershipAuthorization
) -> None:
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=event_type,
            metadata_json={
                "authorization_id": authorization.id,
                "version": authorization.version,
                "status": authorization.status,
            },
        )
    )


@router.post("/drafts", response_model=LeadershipAuthorizationResponse)
def create_draft(
    body: LeadershipAuthorizationDraftRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LeadershipAuthorizationResponse:
    _require_org_admin(db, ctx)
    try:
        authorization = create_leadership_authorization_draft(
            db,
            organization_id=ctx.organization_id,
            sponsor_user_id=body.sponsor_user_id,
            approving_body=body.approving_body,
            authorized_scope=body.authorized_scope,
            prepared_by=str(ctx.user_id),
            note=body.note,
        )
    except LeadershipAuthorizationValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=LEADERSHIP_AUTHORIZATION_AUDIT_DRAFT_CREATED, authorization=authorization)
    db.commit()
    db.refresh(authorization)
    return _response(db, authorization)


@router.post("/self-authorize", response_model=LeadershipAuthorizationResponse)
def self_authorize(
    body: LeadershipAuthorizationSelfAuthorizeRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LeadershipAuthorizationResponse:
    """Onboarding-only: an admin names the accountable sponsor (often
    themselves, not always) and authorises in one step, no separate review.
    See ``self_authorize_leadership`` for why that's correct here rather
    than a shortcut around the draft/approve split used everywhere else."""
    _require_org_admin(db, ctx)
    try:
        authorization = self_authorize_leadership(
            db,
            organization_id=ctx.organization_id,
            acting_user_id=ctx.user_id,
            sponsor_user_id=body.sponsor_user_id,
            approving_body=body.approving_body,
            authorized_scope=body.authorized_scope,
            note=body.note,
        )
    except LeadershipAuthorizationValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=LEADERSHIP_AUTHORIZATION_AUDIT_SELF_AUTHORIZED, authorization=authorization)
    db.commit()
    db.refresh(authorization)
    return _response(db, authorization)


@router.post("/drafts/{authorization_id}/submit", response_model=LeadershipAuthorizationResponse)
def submit_draft(
    authorization_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LeadershipAuthorizationResponse:
    _require_org_admin(db, ctx)
    authorization = _require_authorization(db, ctx=ctx, authorization_id=authorization_id)
    try:
        submit_leadership_authorization_draft(db, authorization, submitted_by=str(ctx.user_id))
    except LeadershipAuthorizationValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=LEADERSHIP_AUTHORIZATION_AUDIT_SUBMITTED, authorization=authorization)
    db.commit()
    db.refresh(authorization)
    return _response(db, authorization)


@router.post("/drafts/{authorization_id}/approve", response_model=LeadershipAuthorizationResponse)
def approve_draft(
    authorization_id: str,
    body: LeadershipAuthorizationApprovalRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LeadershipAuthorizationResponse:
    authorization = _require_authorization(db, ctx=ctx, authorization_id=authorization_id)
    _require_named_sponsor(ctx, authorization)
    try:
        approve_leadership_authorization_draft(
            db,
            authorization,
            approved_by=str(ctx.user_id),
            approval_reference=body.approval_reference,
        )
    except LeadershipAuthorizationValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=LEADERSHIP_AUTHORIZATION_AUDIT_APPROVED, authorization=authorization)
    db.commit()
    db.refresh(authorization)
    return _response(db, authorization)


@router.post("/drafts/{authorization_id}/reject", response_model=LeadershipAuthorizationResponse)
def reject_draft(
    authorization_id: str,
    body: LeadershipAuthorizationRejectionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LeadershipAuthorizationResponse:
    authorization = _require_authorization(db, ctx=ctx, authorization_id=authorization_id)
    _require_named_sponsor(ctx, authorization)
    try:
        reject_leadership_authorization_draft(
            db,
            authorization,
            rejected_by=str(ctx.user_id),
            rejection_reason=body.rejection_reason,
        )
    except LeadershipAuthorizationValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=LEADERSHIP_AUTHORIZATION_AUDIT_REJECTED, authorization=authorization)
    db.commit()
    db.refresh(authorization)
    return _response(db, authorization)


@router.get("", response_model=ActiveLeadershipAuthorizationResponse)
def get_active(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ActiveLeadershipAuthorizationResponse:
    """The organisation's current active leadership authorisation, if any."""
    authorization = get_active_leadership_authorization(db, ctx.organization_id)
    if authorization is None:
        return ActiveLeadershipAuthorizationResponse(resolved=False)
    return ActiveLeadershipAuthorizationResponse(resolved=True, authorization=_response(db, authorization))


@router.get("/status", response_model=LeadershipAuthorizationGovernanceStatusResponse)
def get_status(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LeadershipAuthorizationGovernanceStatusResponse:
    """Leadership authorisation's full governance state: active, pending, history."""
    authorizations = (
        db.query(LeadershipAuthorization)
        .filter(LeadershipAuthorization.organization_id == ctx.organization_id)
        .order_by(LeadershipAuthorization.version.desc())
        .all()
    )
    active = next(
        (a for a in authorizations if a.status == LeadershipAuthorizationStatus.ACTIVE.value), None
    )
    pending = next(
        (
            a
            for a in authorizations
            if a.status
            in (LeadershipAuthorizationStatus.DRAFT.value, LeadershipAuthorizationStatus.LEADERSHIP_REVIEW.value)
        ),
        None,
    )
    return LeadershipAuthorizationGovernanceStatusResponse(
        active=_response(db, active) if active else None,
        pending=_response(db, pending) if pending else None,
        history=[_response(db, a) for a in authorizations],
    )
