"""CA-07.2 — configuring restricted access without ever receiving a credential.

Three rules carry this story, and each is enforced in exactly one place here.

1. **The platform never receives secret material.** There is no parameter on any
   function below that takes a credential. A Collector-resident credential is
   registered by *fingerprint*, computed where the credential already lives.
   Hashing on arrival would be too late: a secret the platform accepts has
   already existed in a request body, in process memory, and in whatever traced
   the request.

2. **Where the credential may live is CA-07.0's decision, not this story's.**
   ``_require_credential_model`` reads the organisation's approved operating
   mode. Nothing is inferred — an organisation that has not decided cannot
   configure a Connector, because the question "where is this key allowed to
   sit?" has no default answer.

3. **``CredentialEncryption`` is not imported here, and must not be.** It is
   complete, tested, and stores secrets the platform can decrypt, so reaching
   for it looks like good reuse and breaks the contract. ``ScannerCredential``'s
   hash-only rule is the precedent; this goes one step further.

The caller owns the transaction (commit).
"""

from __future__ import annotations

import re

from sqlalchemy.orm import Session

from src.core.constants.access_connector_enums import (
    CONNECTOR_AUDIT_CREATED,
    CONNECTOR_AUDIT_CREDENTIAL_REGISTERED,
    CONNECTOR_AUDIT_CREDENTIAL_ROTATED,
    CONNECTOR_ERROR_FINGERPRINT_MALFORMED,
    CONNECTOR_ERROR_FINGERPRINT_NOT_PERMITTED,
    CONNECTOR_ERROR_FINGERPRINT_REQUIRED,
    CONNECTOR_ERROR_MODE_A_REQUIRES_RESIDENT_CREDENTIAL,
    CONNECTOR_ERROR_NO_OPERATING_MODE,
    CONNECTOR_ERROR_TARGET_REQUIRED,
    CONNECTOR_FINGERPRINT_MAX_LENGTH,
    CONNECTOR_FINGERPRINT_MIN_LENGTH,
    AccessConnectorStatus,
    AccessConnectorType,
    ConnectorCredentialModel,
)
from src.core.constants.contextual_access_enums import AccessOperatingMode
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.common import utcnow
from src.core.services.audit_service import append_audit_event
from src.core.constants.permission_profile_enums import PermissionSubjectKind
from src.core.services.contextual_access_policy_service import resolve_operating_mode
from src.core.services.permission_subject_service import register_permission_subject

# A fingerprint is public identifying material: hex, base64, or the
# colon-separated form SSH prints. Bounded so a pasted private key cannot
# masquerade as one and get itself persisted.
_FINGERPRINT_PATTERN = re.compile(r"^[A-Za-z0-9+/:_=-]+$")


class AccessConnectorValidationError(ValueError):
    """Raised when a Connector configuration is invalid or unauthorised."""


def _validate_fingerprint(fingerprint: str) -> str:
    cleaned = fingerprint.strip()
    if not (
        CONNECTOR_FINGERPRINT_MIN_LENGTH <= len(cleaned) <= CONNECTOR_FINGERPRINT_MAX_LENGTH
        and _FINGERPRINT_PATTERN.match(cleaned)
    ):
        raise AccessConnectorValidationError(CONNECTOR_ERROR_FINGERPRINT_MALFORMED)
    # A PEM header is the clearest sign somebody pasted the key itself. Refused
    # loudly rather than stored, because a private key that reaches the database
    # is not fixed by rejecting it next time.
    if "BEGIN" in cleaned.upper() or "PRIVATE" in cleaned.upper():
        raise AccessConnectorValidationError(CONNECTOR_ERROR_FINGERPRINT_MALFORMED)
    return cleaned


def resolve_permitted_credential_model(db: Session, organization_id: int) -> str:
    """Where a credential may live for this organisation, per its approved mode.

    Raises rather than defaulting. An organisation that has not decided how
    deeper access operates has not decided where its keys may sit either, and
    guessing would be the system deciding.
    """
    mode = resolve_operating_mode(db, organization_id)
    if mode is None:
        raise AccessConnectorValidationError(CONNECTOR_ERROR_NO_OPERATING_MODE)
    if mode == AccessOperatingMode.SCHEDULED_AUTONOMOUS.value:
        # Nobody is present at run time, so nobody can hand a credential over.
        return ConnectorCredentialModel.COLLECTOR_RESIDENT.value
    return ConnectorCredentialModel.OPERATOR_SUPPLIED.value


def _require_credential_model(db: Session, organization_id: int, requested: str | None) -> str:
    permitted = resolve_permitted_credential_model(db, organization_id)
    if requested is None:
        return permitted
    if requested == permitted:
        return requested
    # Mode B organisations may legitimately keep a credential on the Collector —
    # a person being present does not forbid it. Mode A organisations cannot do
    # the reverse, because there is no person to supply one.
    if (
        permitted == ConnectorCredentialModel.OPERATOR_SUPPLIED.value
        and requested == ConnectorCredentialModel.COLLECTOR_RESIDENT.value
    ):
        return requested
    raise AccessConnectorValidationError(CONNECTOR_ERROR_MODE_A_REQUIRES_RESIDENT_CREDENTIAL)


def create_connector(
    db: Session,
    *,
    organization_id: int,
    scanner_instance_id: str,
    connector_type: str,
    target_host: str,
    target_port: int | None = None,
    target_username: str | None = None,
    asset_id: int | None = None,
    credential_model: str | None = None,
    credential_fingerprint: str | None = None,
    requires_docker_socket: bool = False,
    note: str | None = None,
    created_by_user_id: int | None = None,
) -> AccessConnector:
    """Configure restricted access to one target, via one Collector.

    Note what this signature does **not** accept: no password, no key, no token,
    no secret of any kind. That is the story's central claim expressed as an
    interface rather than as a promise.
    """
    if connector_type not in tuple(t.value for t in AccessConnectorType):
        raise AccessConnectorValidationError(f"Unknown Connector type '{connector_type}'.")
    if not target_host.strip():
        raise AccessConnectorValidationError(CONNECTOR_ERROR_TARGET_REQUIRED)

    resolved_model = _require_credential_model(db, organization_id, credential_model)

    if resolved_model == ConnectorCredentialModel.COLLECTOR_RESIDENT.value:
        if not credential_fingerprint:
            raise AccessConnectorValidationError(CONNECTOR_ERROR_FINGERPRINT_REQUIRED)
        fingerprint = _validate_fingerprint(credential_fingerprint)
    else:
        # Nothing durable is held, so there is nothing to identify. Accepting a
        # fingerprint here would quietly create a record of a credential the
        # organisation was told is never stored.
        if credential_fingerprint:
            raise AccessConnectorValidationError(CONNECTOR_ERROR_FINGERPRINT_NOT_PERMITTED)
        fingerprint = None

    now = utcnow()
    # Registered before the Connector exists, so "everything permissionable has
    # exactly one subject" holds from the first moment rather than being
    # repaired later. CA-07.3 / Epic C4.
    subject = register_permission_subject(
        db,
        organization_id=organization_id,
        subject_kind=PermissionSubjectKind.ACCESS_CONNECTOR,
    )
    connector = AccessConnector(
        organization_id=organization_id,
        permission_subject_id=subject.id,
        scanner_instance_id=scanner_instance_id,
        asset_id=asset_id,
        connector_type=connector_type,
        credential_model=resolved_model,
        target_host=target_host.strip(),
        target_port=target_port,
        target_username=target_username.strip() if target_username else None,
        credential_fingerprint=fingerprint,
        credential_registered_at=now if fingerprint else None,
        # Declared, never granted. CA-07.3 owns the approval this needs.
        requires_docker_socket=bool(requires_docker_socket)
        or connector_type == AccessConnectorType.DOCKER_READONLY.value,
        status=AccessConnectorStatus.CONFIGURED.value,
        note=note,
        created_by_user_id=created_by_user_id,
    )
    db.add(connector)
    db.flush()

    append_audit_event(
        db,
        organization_id,
        CONNECTOR_AUDIT_CREATED,
        actor_user_id=created_by_user_id,
        metadata=_audit_metadata(connector),
    )
    if fingerprint:
        append_audit_event(
            db,
            organization_id,
            CONNECTOR_AUDIT_CREDENTIAL_REGISTERED,
            actor_user_id=created_by_user_id,
            metadata=_audit_metadata(connector),
        )
    return connector


def rotate_connector_fingerprint(
    db: Session,
    connector: AccessConnector,
    *,
    credential_fingerprint: str,
    rotated_by_user_id: int | None = None,
) -> AccessConnector:
    """Record that the Collector's credential changed, by its new fingerprint.

    The rotation happens where the credential lives. This only updates what the
    platform knows about *which* credential is in use — it neither performs nor
    witnesses the change.
    """
    if connector.credential_model != ConnectorCredentialModel.COLLECTOR_RESIDENT.value:
        raise AccessConnectorValidationError(CONNECTOR_ERROR_FINGERPRINT_NOT_PERMITTED)
    connector.credential_fingerprint = _validate_fingerprint(credential_fingerprint)
    connector.credential_rotated_at = utcnow()
    db.add(connector)
    append_audit_event(
        db,
        connector.organization_id,
        CONNECTOR_AUDIT_CREDENTIAL_ROTATED,
        actor_user_id=rotated_by_user_id,
        metadata=_audit_metadata(connector),
    )
    return connector


def _audit_metadata(connector: AccessConnector) -> dict:
    """What the audit trail may carry about a Connector.

    Deliberately narrow, and deliberately without the fingerprint. The trail
    answers "what was configured, reaching what, as whom" — it never needs to
    identify the key itself, and an audit table is exactly the sort of
    long-lived, widely-read place a credential identifier should not accumulate.
    """
    return {
        "connector_id": connector.id,
        "connector_type": connector.connector_type,
        "credential_model": connector.credential_model,
        "scanner_instance_id": connector.scanner_instance_id,
        "target_host": connector.target_host,
        "target_username": connector.target_username,
        "requires_docker_socket": connector.requires_docker_socket,
    }


def list_connectors(
    db: Session, *, organization_id: int, scanner_instance_id: str | None = None
) -> list[AccessConnector]:
    query = db.query(AccessConnector).filter(
        AccessConnector.organization_id == organization_id
    )
    if scanner_instance_id is not None:
        query = query.filter(AccessConnector.scanner_instance_id == scanner_instance_id)
    return query.order_by(AccessConnector.created_at.desc()).all()
