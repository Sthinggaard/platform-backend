"""CA-07.4 — withdrawing access, in three verbs that mean three different things.

The story's criterion is that pause, revoke and disconnect **behave** distinctly,
not merely that three buttons exist. What each one is for:

- ``pause_connector`` — temporarily not in use. Resumable, and the grant still
  stands. The everyday verb: a maintenance window, a noisy host, a change freeze.
- ``revoke_connector`` — the authorisation is withdrawn. A governance act,
  permanent, requiring a stated reason, and **not deletion**: the record of what
  was granted survives it, because "what did we once allow, and who stopped it?"
  is exactly what an auditor asks.
- ``disconnect_connector`` — the technical link is gone; the Collector no longer
  holds the credential. An operational act.

**Revocation and disconnection are independent, and the model says so.** A
Connector can be revoked while its credential still sits on the Collector
awaiting cleanup, and a Collector can be rebuilt while the authorisation stands.
So ``status`` carries the strongest standing withdrawal and the timestamps record
each act in its own right — disconnecting a revoked Connector stamps
``disconnected_at`` and leaves the status ``revoked``, rather than letting the
operational act quietly erase the governance one.

**None of these verbs is enforcement.** They change the record; what stops a
withdrawn Connector being *used* is
``permission_enforcement_service.assert_capability_permitted``, which asks the
subject whether it is still usable before it reads any profile. Both halves are
needed: a status nothing checks is a note, and a check with nothing to read is a
guess.

The caller owns the transaction (commit).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.access_connector_enums import (
    CONNECTOR_AUDIT_DISCONNECTED,
    CONNECTOR_AUDIT_PAUSED,
    CONNECTOR_AUDIT_RESUMED,
    CONNECTOR_AUDIT_REVOKED,
    CONNECTOR_ERROR_ALREADY_DISCONNECTED,
    CONNECTOR_ERROR_ALREADY_REVOKED,
    CONNECTOR_ERROR_NOT_CONFIGURED,
    CONNECTOR_ERROR_NOT_PAUSED,
    CONNECTOR_ERROR_REVOCATION_REASON_REQUIRED,
    CONNECTOR_ERROR_REVOKED_CANNOT_RESUME,
    AccessConnectorStatus,
)
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.common import utcnow
from src.core.services.access_connector_service import AccessConnectorValidationError
from src.core.services.audit_service import append_audit_event


def pause_connector(
    db: Session, connector: AccessConnector, *, paused_by_user_id: int | None = None
) -> AccessConnector:
    """Stop using this Connector for now. The grant is untouched."""
    if connector.status != AccessConnectorStatus.CONFIGURED.value:
        raise AccessConnectorValidationError(CONNECTOR_ERROR_NOT_CONFIGURED)
    connector.status = AccessConnectorStatus.PAUSED.value
    connector.paused_at = utcnow()
    return _record(db, connector, CONNECTOR_AUDIT_PAUSED, actor_user_id=paused_by_user_id)


def resume_connector(
    db: Session, connector: AccessConnector, *, resumed_by_user_id: int | None = None
) -> AccessConnector:
    """Put a paused Connector back into use.

    Only pause is reversible. Offering a way back from revocation would make the
    two verbs indistinguishable, which is the distinction the story exists to
    make — so a revoked Connector is refused here with its own message rather
    than the generic "not paused", because the two send an operator to different
    places.
    """
    if connector.status == AccessConnectorStatus.REVOKED.value:
        raise AccessConnectorValidationError(CONNECTOR_ERROR_REVOKED_CANNOT_RESUME)
    if connector.status != AccessConnectorStatus.PAUSED.value:
        raise AccessConnectorValidationError(CONNECTOR_ERROR_NOT_PAUSED)
    connector.status = AccessConnectorStatus.CONFIGURED.value
    connector.paused_at = None
    return _record(db, connector, CONNECTOR_AUDIT_RESUMED, actor_user_id=resumed_by_user_id)


def revoke_connector(
    db: Session,
    connector: AccessConnector,
    *,
    revoked_by_user_id: int,
    revocation_reason: str,
) -> AccessConnector:
    """Withdraw the authorisation, permanently, with a stated reason.

    Deliberately **not** deletion. The Connector, its fingerprint history and
    every access test it ever ran stay readable, because destroying them would
    destroy the evidence that access was ever held — which is the opposite of
    what withdrawing it is meant to demonstrate.

    Reachable from any state, including ``disconnected``: pulling the technical
    link does not withdraw the grant, so an organisation that rebuilt a Collector
    must still be able to say "and we are not granting this again."
    """
    if connector.status == AccessConnectorStatus.REVOKED.value:
        raise AccessConnectorValidationError(CONNECTOR_ERROR_ALREADY_REVOKED)
    if not revocation_reason.strip():
        raise AccessConnectorValidationError(CONNECTOR_ERROR_REVOCATION_REASON_REQUIRED)
    connector.status = AccessConnectorStatus.REVOKED.value
    connector.revoked_at = utcnow()
    connector.revoked_by_user_id = revoked_by_user_id
    connector.revocation_reason = revocation_reason.strip()
    return _record(
        db,
        connector,
        CONNECTOR_AUDIT_REVOKED,
        actor_user_id=revoked_by_user_id,
        extra={"revocation_reason": connector.revocation_reason},
    )


def disconnect_connector(
    db: Session, connector: AccessConnector, *, disconnected_by_user_id: int | None = None
) -> AccessConnector:
    """Record that the Collector no longer holds this Connector's credential.

    An operational fact, not a governance one — so it stamps ``disconnected_at``
    and only takes over ``status`` when nothing stronger is standing there. A
    revoked Connector that is then cleaned up stays *revoked*: the operational
    act must not overwrite the permanent statement, or the record would say the
    link was dropped when what actually happened was that access was withdrawn.
    """
    if connector.disconnected_at is not None:
        raise AccessConnectorValidationError(CONNECTOR_ERROR_ALREADY_DISCONNECTED)
    connector.disconnected_at = utcnow()
    if connector.status != AccessConnectorStatus.REVOKED.value:
        connector.status = AccessConnectorStatus.DISCONNECTED.value
    return _record(
        db, connector, CONNECTOR_AUDIT_DISCONNECTED, actor_user_id=disconnected_by_user_id
    )


def _record(
    db: Session,
    connector: AccessConnector,
    event: str,
    *,
    actor_user_id: int | None,
    extra: dict | None = None,
) -> AccessConnector:
    """One audit event per verb, never a shared "connector changed".

    A trail that recorded all four as the same event would lose exactly the
    distinction the verbs exist to make, and the distinction is the story.

    Carries no fingerprint, for the reason ``_audit_metadata`` gives: an audit
    table is a long-lived, widely-read place, and a credential identifier should
    not accumulate in one.
    """
    db.add(connector)
    append_audit_event(
        db,
        connector.organization_id,
        event,
        actor_user_id=actor_user_id,
        metadata={
            "connector_id": connector.id,
            "status": connector.status,
            "connector_type": connector.connector_type,
            "target_host": connector.target_host,
            **(extra or {}),
        },
    )
    return connector
