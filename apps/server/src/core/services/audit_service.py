"""Audit logging utilities."""

from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from src.core.constants.secret_redaction import redact
from src.core.logging_config import get_logger
from src.core.models import AuditEvent, User

logger = get_logger(__name__)


def _actor_time_and_place(
    db: Session, organization_id: int, actor_user_id: Optional[int]
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Where the actor was and what clock they were on, right now.

    Read here rather than joined at display time, for the same reason the
    redaction above happens here: a call site can forget, a choke point cannot.
    And the value has to be *copied* — the user row changes, and a person who
    relocates must not retroactively move where a past decision was made.

    A failure to read it is not a failure to write the event. An audit trail
    that refuses to record what happened because it could not decorate it would
    be trading the fact for the annotation.
    """
    if actor_user_id is None:
        return None, None, None
    try:
        actor = (
            db.query(User)
            .filter(User.id == actor_user_id, User.organization_id == organization_id)
            .one_or_none()
        )
    except Exception:  # pragma: no cover - defensive; never blocks the event
        logger.warning("audit_actor_context_unavailable", actor_user_id=actor_user_id)
        return None, None, None
    if actor is None:
        return None, None, None
    return actor.timezone, actor.location_country, actor.location_city


def append_audit_event(
    db: Session,
    organization_id: int,
    event_type: str,
    actor_user_id: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditEvent:
    actor_timezone, actor_country, actor_city = _actor_time_and_place(
        db, organization_id, actor_user_id
    )
    event = AuditEvent(
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type=event_type,
        # #284 (TZ-6) — frozen at write time, never resolved at read time.
        actor_timezone=actor_timezone,
        actor_location_country=actor_country,
        actor_location_city=actor_city,
        # CA-07.6 (#240) — redacted here rather than at each call site, because
        # this is the one place every audit event in the platform passes
        # through. The metadata bag is a free-shaped dict: nothing about it
        # stops a caller putting a Collector's failure text or a person's typed
        # note into it, and an audit trail is the worst place to learn that
        # afterwards. A call site can forget; a choke point cannot.
        metadata_json=redact(metadata or {}),
    )
    db.add(event)
    return event


def log_audit_event(
    db: Session,
    organization_id: int,
    event_type: str,
    actor_user_id: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    append_audit_event(
        db,
        organization_id,
        event_type,
        actor_user_id=actor_user_id,
        metadata=metadata,
    )
    db.commit()
    logger.info(
        "audit_event_logged",
        event_type=event_type,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
    )
