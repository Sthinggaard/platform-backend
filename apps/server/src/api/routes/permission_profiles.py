"""CA-07.3 — the surface for defining and approving what a Connector may do.

Two approvals live here, and they are deliberately two endpoints rather than one
call with a flag. `POST /{id}/approve` puts the profile in force.
`POST /{id}/approve-docker-socket` grants socket access. The contract makes the
second its own decision, and a flag on the first would let one click do both —
the precise thing the rule exists to prevent.

There is no update route. Widening a profile means approving a new version,
which supersedes the old one and leaves it readable.
"""

from __future__ import annotations


import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.access_connector_enums import CONNECTOR_ERROR_NOT_FOUND
from src.core.constants.permission_profile_enums import (
    PROFILE_ERROR_ADMIN_REQUIRED,
    PROFILE_ERROR_APPROVER_REQUIRED,
    PROFILE_ERROR_NOT_FOUND,
    ConnectorCapability,
)
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.models import User
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES
from src.core.services.leadership_authorization_service import get_active_leadership_authorization
from src.core.services.permission_profile_service import (
    PermissionProfileValidationError,
    approve_docker_socket,
    approve_profile,
    create_profile_draft,
    list_profiles,
    reject_profile,
    submit_profile,
)
from src.api.schemas.timestamps import UtcTimestamp

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/permission-profiles", tags=["Permission profiles"])


class PermissionProfileDraftRequest(BaseModel):
    connector_id: str
    name: str
    capabilities: list[ConnectorCapability] = Field(min_length=1)
    note: str | None = None


class PermissionProfileRejectionRequest(BaseModel):
    rejection_reason: str


class PermissionProfileResponse(BaseModel):
    id: str
    subject_id: str
    connector_id: str | None = None
    name: str
    capabilities: list[str]
    status: str
    version: int
    prepared_by_user_id: int | None = None
    submitted_at: UtcTimestamp | None = None
    approved_by_user_id: int | None = None
    approved_at: UtcTimestamp | None = None
    rejected_by_user_id: int | None = None
    rejected_at: UtcTimestamp | None = None
    rejection_reason: str | None = None
    # Separate from `approved_at` on purpose — a reader must be able to see that
    # a profile is in force while socket access still is not.
    docker_socket_approved_by_user_id: int | None = None
    docker_socket_approved_at: UtcTimestamp | None = None
    note: str | None = None
    superseded_by_id: str | None = None


class PermissionProfileListResponse(BaseModel):
    profiles: list[PermissionProfileResponse]


class CapabilityOption(BaseModel):
    capability: str
    requires_docker_socket_approval: bool


class CapabilityCatalogueResponse(BaseModel):
    """Every capability that can be granted, and which need the extra approval."""

    capabilities: list[CapabilityOption]


def _response(
    profile: PermissionProfile, *, connector_id: str | None = None
) -> PermissionProfileResponse:
    """``connector_id`` is echoed for the caller's convenience when known.

    The profile itself bounds a *subject*; which concrete thing that is depends
    on the subject's kind, so it is passed in rather than assumed here.
    """
    return PermissionProfileResponse(
        id=profile.id,
        subject_id=profile.subject_id,
        connector_id=connector_id,
        name=profile.name,
        capabilities=list(profile.capabilities or []),
        status=profile.status,
        version=profile.version,
        prepared_by_user_id=profile.prepared_by_user_id,
        submitted_at=profile.submitted_at,
        approved_by_user_id=profile.approved_by_user_id,
        approved_at=profile.approved_at,
        rejected_by_user_id=profile.rejected_by_user_id,
        rejected_at=profile.rejected_at,
        rejection_reason=profile.rejection_reason,
        docker_socket_approved_by_user_id=profile.docker_socket_approved_by_user_id,
        docker_socket_approved_at=profile.docker_socket_approved_at,
        note=profile.note,
        superseded_by_id=profile.superseded_by_id,
    )


def _require_org_admin(db: Session, ctx: TenantContext) -> None:
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or user.role not in ADMIN_ROLES:
        raise AuthorizationError(PROFILE_ERROR_ADMIN_REQUIRED)


def _require_approver(db: Session, ctx: TenantContext) -> None:
    """Approval belongs to the organisation's named accountable sponsor.

    The same authority CA-07.0 and the risk appetite already use. Granting a
    Connector the ability to read inside a host is the same class of decision.
    """
    authorization = get_active_leadership_authorization(db, ctx.organization_id)
    if authorization is None or ctx.user_id != authorization.sponsor_user_id:
        raise AuthorizationError(PROFILE_ERROR_APPROVER_REQUIRED)


def _require_profile(db: Session, *, ctx: TenantContext, profile_id: str) -> PermissionProfile:
    profile = TenantRepository(db, PermissionProfile, ctx.organization_id).get_by_id(profile_id)
    if profile is None:
        raise ResourceNotFoundError(PROFILE_ERROR_NOT_FOUND)
    return profile


def _require_connector(db: Session, *, ctx: TenantContext, connector_id: str) -> AccessConnector:
    connector = TenantRepository(db, AccessConnector, ctx.organization_id).get_by_id(connector_id)
    if connector is None:
        raise ResourceNotFoundError(CONNECTOR_ERROR_NOT_FOUND)
    return connector


def _connector_for_subject(db: Session, *, ctx: TenantContext, subject_id: str) -> AccessConnector:
    """The Connector behind a permission subject, when the subject is one.

    The reverse lookup the supertable makes necessary — and cheap, since
    ``permission_subject_id`` is unique on the Connector.
    """
    connector = (
        db.query(AccessConnector)
        .filter(
            AccessConnector.organization_id == ctx.organization_id,
            AccessConnector.permission_subject_id == subject_id,
        )
        .one_or_none()
    )
    if connector is None:
        raise ResourceNotFoundError(CONNECTOR_ERROR_NOT_FOUND)
    return connector


@router.get("/capabilities", response_model=CapabilityCatalogueResponse)
def get_capabilities() -> CapabilityCatalogueResponse:
    """What can be granted, and which capabilities need the extra approval.

    Surfaced so the person defining a profile learns that container capabilities
    carry a second decision *before* they submit it, rather than at the point of
    refusal.
    """
    from src.core.services.permission_enforcement_service import DOCKER_SOCKET_CAPABILITIES

    return CapabilityCatalogueResponse(
        capabilities=[
            CapabilityOption(
                capability=capability.value,
                requires_docker_socket_approval=capability.value in DOCKER_SOCKET_CAPABILITIES,
            )
            for capability in ConnectorCapability
        ]
    )


@router.post("/drafts", response_model=PermissionProfileResponse)
def create_draft(
    body: PermissionProfileDraftRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> PermissionProfileResponse:
    _require_org_admin(db, ctx)
    connector = _require_connector(db, ctx=ctx, connector_id=body.connector_id)
    try:
        profile = create_profile_draft(
            db,
            subject=connector,
            name=body.name,
            capabilities=[c.value for c in body.capabilities],
            prepared_by_user_id=ctx.user_id,
            note=body.note,
        )
    except PermissionProfileValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(profile)
    return _response(profile, connector_id=connector.id)


@router.post("/drafts/{profile_id}/submit", response_model=PermissionProfileResponse)
def submit(
    profile_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> PermissionProfileResponse:
    _require_org_admin(db, ctx)
    profile = _require_profile(db, ctx=ctx, profile_id=profile_id)
    try:
        submit_profile(db, profile, submitted_by_user_id=ctx.user_id)
    except PermissionProfileValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(profile)
    return _response(profile)


@router.post("/drafts/{profile_id}/approve", response_model=PermissionProfileResponse)
def approve(
    profile_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> PermissionProfileResponse:
    """Put the profile in force. Does **not** grant Docker socket access."""
    profile = _require_profile(db, ctx=ctx, profile_id=profile_id)
    _require_approver(db, ctx)
    try:
        approve_profile(db, profile, approved_by_user_id=ctx.user_id)
    except PermissionProfileValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(profile)
    return _response(profile)


@router.post("/drafts/{profile_id}/reject", response_model=PermissionProfileResponse)
def reject(
    profile_id: str,
    body: PermissionProfileRejectionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> PermissionProfileResponse:
    profile = _require_profile(db, ctx=ctx, profile_id=profile_id)
    _require_approver(db, ctx)
    try:
        reject_profile(
            db, profile, rejected_by_user_id=ctx.user_id, rejection_reason=body.rejection_reason
        )
    except PermissionProfileValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(profile)
    return _response(profile)


@router.post("/{profile_id}/approve-docker-socket", response_model=PermissionProfileResponse)
def approve_socket(
    profile_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> PermissionProfileResponse:
    """The contract's separate, explicit approval for Docker socket access.

    Its own endpoint rather than a flag on `/approve`, so that granting it is
    always a distinct act with its own approver and its own audit event.
    """
    profile = _require_profile(db, ctx=ctx, profile_id=profile_id)
    _require_approver(db, ctx)
    connector = _connector_for_subject(db, ctx=ctx, subject_id=profile.subject_id)
    try:
        approve_docker_socket(db, profile, connector, approved_by_user_id=ctx.user_id)
    except PermissionProfileValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(profile)
    return _response(profile)


@router.get("", response_model=PermissionProfileListResponse)
def list_for_connector(
    connector_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> PermissionProfileListResponse:
    connector = _require_connector(db, ctx=ctx, connector_id=connector_id)
    return PermissionProfileListResponse(
        profiles=[
            _response(p, connector_id=connector_id)
            for p in list_profiles(
                db,
                organization_id=ctx.organization_id,
                subject_id=connector.permission_subject_id,
            )
        ]
    )


__all__ = ["router"]
