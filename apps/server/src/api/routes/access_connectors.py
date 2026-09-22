"""CA-07.2 — the Connector write surface, which cannot accept a credential.

Every request model below is part of the story's central claim: there is no
field here that could carry a password, key, token or passphrase, and
``test_access_connector.py`` asserts that structurally against these very
classes rather than trusting review to catch a future addition.

A Collector-resident credential is registered by **fingerprint** — public
identifying material, computed where the credential already lives. The platform
learns which credential is in use and nothing more.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.schemas.access_connector_schemas import (
    AccessConnectorListResponse,
    AccessConnectorResponse,
    to_connector_response,
)
from src.core.constants.access_connector_enums import (
    CONNECTOR_ERROR_ADMIN_REQUIRED,
    CONNECTOR_ERROR_NOT_FOUND,
    CONNECTOR_ERROR_SCANNER_NOT_FOUND,
    CONNECTOR_FINGERPRINT_MAX_LENGTH,
    CONNECTOR_FINGERPRINT_MIN_LENGTH,
    AccessConnectorType,
    ConnectorCredentialModel,
)
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.models import User
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES
from src.core.services.access_connector_service import (
    AccessConnectorValidationError,
    create_connector,
    list_connectors,
    resolve_permitted_credential_model,
    rotate_connector_fingerprint,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/access-connectors", tags=["Access connectors"])


class AccessConnectorCreateRequest(BaseModel):
    """Note the absence: no credential field of any kind, by design."""

    scanner_instance_id: str
    connector_type: AccessConnectorType
    target_host: str
    target_port: int | None = Field(default=None, ge=1, le=65535)
    target_username: str | None = None
    asset_id: int | None = None
    credential_model: ConnectorCredentialModel | None = None
    # Public identifying material only — never the credential.
    credential_fingerprint: str | None = Field(
        default=None,
        min_length=CONNECTOR_FINGERPRINT_MIN_LENGTH,
        max_length=CONNECTOR_FINGERPRINT_MAX_LENGTH,
    )
    requires_docker_socket: bool = False
    note: str | None = None


class AccessConnectorRotateRequest(BaseModel):
    credential_fingerprint: str = Field(
        min_length=CONNECTOR_FINGERPRINT_MIN_LENGTH,
        max_length=CONNECTOR_FINGERPRINT_MAX_LENGTH,
    )


class PermittedCredentialModelResponse(BaseModel):
    """Where a credential may live here — read from CA-07.0's approved mode."""

    credential_model: str


def require_org_admin(db: Session, ctx: TenantContext) -> None:
    """Public — CA-07.4's lifecycle and access-test routers call this too.

    Shared rather than copied, on the precedent ``require_scanner_instance``
    already set: a second copy is how one Connector surface quietly ends up
    with a weaker check than the others.
    """
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or user.role not in ADMIN_ROLES:
        raise AuthorizationError(CONNECTOR_ERROR_ADMIN_REQUIRED)


def require_connector(db: Session, *, ctx: TenantContext, connector_id: str) -> AccessConnector:
    """Public — the tenant-scoped lookup every Connector route starts from."""
    connector = TenantRepository(db, AccessConnector, ctx.organization_id).get_by_id(connector_id)
    if connector is None:
        raise ResourceNotFoundError(CONNECTOR_ERROR_NOT_FOUND)
    return connector


@router.get("/permitted-credential-model", response_model=PermittedCredentialModelResponse)
def get_permitted_credential_model(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> PermittedCredentialModelResponse:
    """Where this organisation's approved mode allows a credential to live.

    Errors rather than defaulting when no mode has been approved — that is
    CA-07.0's gate, surfaced so the UI can send someone to the decision instead
    of presenting a choice the organisation has not made.
    """
    try:
        model = resolve_permitted_credential_model(db, ctx.organization_id)
    except AccessConnectorValidationError as exc:
        raise ValidationError(str(exc)) from exc
    return PermittedCredentialModelResponse(credential_model=model)


@router.post("", response_model=AccessConnectorResponse)
def create(
    body: AccessConnectorCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AccessConnectorResponse:
    require_org_admin(db, ctx)
    instance = TenantRepository(db, ScannerInstance, ctx.organization_id).get_by_id(
        body.scanner_instance_id
    )
    if instance is None:
        raise ResourceNotFoundError(CONNECTOR_ERROR_SCANNER_NOT_FOUND)
    try:
        connector = create_connector(
            db,
            organization_id=ctx.organization_id,
            scanner_instance_id=body.scanner_instance_id,
            connector_type=body.connector_type.value,
            target_host=body.target_host,
            target_port=body.target_port,
            target_username=body.target_username,
            asset_id=body.asset_id,
            credential_model=body.credential_model.value if body.credential_model else None,
            credential_fingerprint=body.credential_fingerprint,
            requires_docker_socket=body.requires_docker_socket,
            note=body.note,
            created_by_user_id=ctx.user_id,
        )
    except AccessConnectorValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(connector)
    return to_connector_response(connector)


@router.post("/{connector_id}/rotate-fingerprint", response_model=AccessConnectorResponse)
def rotate_fingerprint(
    connector_id: str,
    body: AccessConnectorRotateRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AccessConnectorResponse:
    """Record that the Collector's credential changed, by its new fingerprint."""
    require_org_admin(db, ctx)
    connector = require_connector(db, ctx=ctx, connector_id=connector_id)
    try:
        rotate_connector_fingerprint(
            db,
            connector,
            credential_fingerprint=body.credential_fingerprint,
            rotated_by_user_id=ctx.user_id,
        )
    except AccessConnectorValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(connector)
    return to_connector_response(connector)


@router.get("", response_model=AccessConnectorListResponse)
def list_all(
    scanner_instance_id: str | None = None,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AccessConnectorListResponse:
    return AccessConnectorListResponse(
        connectors=[
            to_connector_response(c)
            for c in list_connectors(
                db,
                organization_id=ctx.organization_id,
                scanner_instance_id=scanner_instance_id,
            )
        ]
    )


@router.get("/{connector_id}", response_model=AccessConnectorResponse)
def get_one(
    connector_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AccessConnectorResponse:
    return to_connector_response(require_connector(db, ctx=ctx, connector_id=connector_id))


__all__ = ["router"]
