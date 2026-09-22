"""How a Connector is described to a caller — defined once, read by three routers.

CA-07.2 configures a Connector, CA-07.4 withdraws and resumes one, and both hand
back the same thing. Extracted here when the second router arrived rather than
copied, because a second definition of this shape is how the lifecycle fields
end up visible on one surface and missing on the other.

Nothing in here can carry secret material: the fingerprint is truncated to a
preview, and there is no field for a credential because the Connector has no
column for one. See ``access_connector_enums.CONNECTOR_FORBIDDEN_FIELD_FRAGMENTS``
— asserted structurally against this module, not left to review.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from src.core.model_defs.access_connector import AccessConnector
from src.api.schemas.timestamps import UtcTimestamp

#: Enough to answer "is this still the credential I registered?", and no more. A
#: fingerprint is not a secret, but a full one is a stable identifier for a key,
#: and a read surface should hand out only what the question needs.
FINGERPRINT_PREVIEW_LENGTH = 12


class AccessConnectorResponse(BaseModel):
    id: str
    scanner_instance_id: str
    asset_id: int | None = None
    connector_type: str
    credential_model: str
    target_host: str
    target_port: int | None = None
    target_username: str | None = None
    credential_fingerprint_preview: str | None = None
    credential_registered_at: UtcTimestamp | None = None
    credential_rotated_at: UtcTimestamp | None = None
    requires_docker_socket: bool
    status: str
    # CA-07.4. Three separate facts rather than one "withdrawn on" field, because
    # revoking and disconnecting are independent acts and a reader must be able
    # to see that a Connector was revoked *and* that its credential was later
    # cleaned off the Collector — or that only one of the two ever happened.
    paused_at: UtcTimestamp | None = None
    revoked_at: UtcTimestamp | None = None
    revoked_by_user_id: int | None = None
    revocation_reason: str | None = None
    disconnected_at: UtcTimestamp | None = None
    note: str | None = None


class AccessConnectorListResponse(BaseModel):
    connectors: list[AccessConnectorResponse]


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _preview(fingerprint: str | None) -> str | None:
    return f"{fingerprint[:FINGERPRINT_PREVIEW_LENGTH]}…" if fingerprint else None


def to_connector_response(connector: AccessConnector) -> AccessConnectorResponse:
    return AccessConnectorResponse(
        id=connector.id,
        scanner_instance_id=connector.scanner_instance_id,
        asset_id=connector.asset_id,
        connector_type=connector.connector_type,
        credential_model=connector.credential_model,
        target_host=connector.target_host,
        target_port=connector.target_port,
        target_username=connector.target_username,
        credential_fingerprint_preview=_preview(connector.credential_fingerprint),
        credential_registered_at=_iso(connector.credential_registered_at),
        credential_rotated_at=_iso(connector.credential_rotated_at),
        requires_docker_socket=bool(connector.requires_docker_socket),
        status=connector.status,
        paused_at=_iso(connector.paused_at),
        revoked_at=_iso(connector.revoked_at),
        revoked_by_user_id=connector.revoked_by_user_id,
        revocation_reason=connector.revocation_reason,
        disconnected_at=_iso(connector.disconnected_at),
        note=connector.note,
    )


__all__ = [
    "AccessConnectorListResponse",
    "AccessConnectorResponse",
    "to_connector_response",
]
