"""CA-07.4 — the surface for withdrawing access, one endpoint per verb.

Four endpoints rather than one ``PATCH {"status": ...}``, for the same reason
CA-07.3 gave Docker socket approval its own route: a single endpoint with a
status field makes revoking and pausing the same gesture with a different string
in the body, and they are not the same gesture. Separate routes give each verb
its own required inputs, its own authority, and its own audit event.

**Revocation is the one that needs a different authority.** Pausing and
disconnecting are operational and belong to an organisation administrator.
Revoking withdraws an authorisation permanently, so it belongs to the same named
leadership sponsor who approved the permission profile in the first place —
whoever can grant this should be the one who takes it away.

There is no delete route, and there will not be one. Revocation keeps the record
of what was once granted; deleting it would destroy the evidence that access was
ever held, which is the opposite of what withdrawing it is meant to show.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.routes.access_connectors import require_connector, require_org_admin
from src.api.schemas.access_connector_schemas import (
    AccessConnectorResponse,
    to_connector_response,
)
from src.core.constants.permission_profile_enums import PROFILE_ERROR_APPROVER_REQUIRED
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ValidationError
from src.core.services.access_connector_lifecycle_service import (
    disconnect_connector,
    pause_connector,
    resume_connector,
    revoke_connector,
)
from src.core.services.access_connector_service import AccessConnectorValidationError
from src.core.services.leadership_authorization_service import (
    get_active_leadership_authorization,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/access-connectors", tags=["Access connectors"])


class ConnectorRevocationRequest(BaseModel):
    """A reason is required, not optional.

    Revocation outlives everyone who remembers it. ``min_length`` is on the field
    so an empty string cannot satisfy the requirement by being present.
    """

    revocation_reason: str = Field(min_length=1)


def _require_revocation_authority(db: Session, ctx: TenantContext) -> None:
    """Withdrawing an authorisation belongs to whoever could grant it.

    The same named leadership sponsor CA-07.0, the risk appetite and CA-07.3's
    profile approval already use — so the answer to "who is accountable for this
    access?" is one person, not one per verb.
    """
    authorization = get_active_leadership_authorization(db, ctx.organization_id)
    if authorization is None or ctx.user_id != authorization.sponsor_user_id:
        raise AuthorizationError(PROFILE_ERROR_APPROVER_REQUIRED)


@router.post("/{connector_id}/pause", response_model=AccessConnectorResponse)
def pause(
    connector_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AccessConnectorResponse:
    """Stop using this Connector for now. The grant is untouched, and it resumes."""
    require_org_admin(db, ctx)
    connector = require_connector(db, ctx=ctx, connector_id=connector_id)
    try:
        pause_connector(db, connector, paused_by_user_id=ctx.user_id)
    except AccessConnectorValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(connector)
    return to_connector_response(connector)


@router.post("/{connector_id}/resume", response_model=AccessConnectorResponse)
def resume(
    connector_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AccessConnectorResponse:
    """Put a paused Connector back into use. Only pause is reversible."""
    require_org_admin(db, ctx)
    connector = require_connector(db, ctx=ctx, connector_id=connector_id)
    try:
        resume_connector(db, connector, resumed_by_user_id=ctx.user_id)
    except AccessConnectorValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(connector)
    return to_connector_response(connector)


@router.post("/{connector_id}/revoke", response_model=AccessConnectorResponse)
def revoke(
    connector_id: str,
    body: ConnectorRevocationRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AccessConnectorResponse:
    """Withdraw the authorisation permanently, with a stated reason.

    Not deletion: the Connector and everything it ever did stay readable. What
    changes is that enforcement now refuses it — see
    ``permission_enforcement_service``, which asks the subject whether it is
    still usable before it reads any profile.
    """
    connector = require_connector(db, ctx=ctx, connector_id=connector_id)
    _require_revocation_authority(db, ctx)
    try:
        revoke_connector(
            db,
            connector,
            revoked_by_user_id=ctx.user_id,
            revocation_reason=body.revocation_reason,
        )
    except AccessConnectorValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(connector)
    return to_connector_response(connector)


@router.post("/{connector_id}/disconnect", response_model=AccessConnectorResponse)
def disconnect(
    connector_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AccessConnectorResponse:
    """Record that the Collector no longer holds this Connector's credential.

    An operational act. It does not withdraw the authorisation, and on an already
    revoked Connector it leaves the status ``revoked`` — cleaning up a credential
    must not read, months later, as though that were all that happened.
    """
    require_org_admin(db, ctx)
    connector = require_connector(db, ctx=ctx, connector_id=connector_id)
    try:
        disconnect_connector(db, connector, disconnected_by_user_id=ctx.user_id)
    except AccessConnectorValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(connector)
    return to_connector_response(connector)


__all__ = ["router"]
