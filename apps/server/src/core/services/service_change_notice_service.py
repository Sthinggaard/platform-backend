"""Telling the owners who depend on a service that somebody decided about it.

Søren, 2026-08-31: *"the owner of this service makes the decisions and the ones
affected by this decision is informed in the overview page via a message saying
person made this decision, please click there to read more and to mark you have
read this and are informed."*

This module writes those messages. Who receives one is
``information_duty_service``'s answer, unchanged — so "who may act" and "who is
told" cannot disagree, which is #376's acceptance criterion and only holds while
both come from the one resolver.

⚠️ **Informing is not asking.** Nothing here blocks the decision, and no caller
may treat an unacknowledged notice as a pending approval.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from src.core.model_defs.common import utcnow
from src.core.models import BusinessService, ServiceChangeNotice, ServiceChangeNoticeKind
from src.core.services.information_duty_service import resolve_information_duty
from src.core.services.service_accountability_service import resolve_service_accountability


def notify_service_decision(
    db: Session,
    *,
    organization_id: int,
    service: BusinessService,
    decided_by_user_id: int,
    title: str,
    description: str | None = None,
    owner_comment: str | None = None,
    decision_record_id: str | None = None,
) -> list[ServiceChangeNotice]:
    """Write one notice per affected process owner. Returns what was written.

    ⚠️ **An update, not an issue — and "informational" does not mean "ignorable".**

    Søren, 2026-09-04: *"It might be that the owner cannot do anything about it,
    but the issue might still affect the business process, so it might be that
    the owner needs to take action on the services in the process this
    affects."*

    So a decision is an ``UPDATE`` — the reader cannot act on the *external*
    service — but it may well require action on **their own** services, and
    nobody can know that until they have read it. That is why dismissing quiets
    the badge and never discharges the acknowledgement: see
    :func:`unacknowledged_notices_for_recipient`.

    An *issue* means the service is broken and persists until the owning team
    resolves it, which a decision never does.

    The caller owns the transaction; nothing here commits.
    """
    accountability = resolve_service_accountability(
        db, organization_id=organization_id, services=[service]
    ).get(service.id)
    if accountability is None:
        return []

    duty = resolve_information_duty(
        db,
        organization_id=organization_id,
        service=service,
        accountability=accountability,
        decided_by_user_id=decided_by_user_id,
    )

    written: list[ServiceChangeNotice] = []
    for person in duty.people:
        notice = ServiceChangeNotice(
            id=str(uuid.uuid4()),
            organization_id=organization_id,
            service_id=service.id,
            # Their process, not the service's — the message says which of the
            # reader's own processes is affected.
            process_id=person.process_id,
            recipient_user_id=person.user_id,
            kind=ServiceChangeNoticeKind.UPDATE,
            title=title,
            description=description,
            owner_comment=owner_comment,
            actor_user_id=decided_by_user_id,
            decision_record_id=decision_record_id,
        )
        db.add(notice)
        written.append(notice)

    db.flush()
    return written


def mark_notice_viewed(notice: ServiceChangeNotice, *, at: datetime | None = None) -> None:
    """Record that the reader opened it. Clears the update badge, nothing else.

    Søren, 2026-09-04: *"It is not to do any actions on the service, it is a 100%
    read action."* So this is free to happen on open — it is a what's-new marker,
    not the governance record below.
    """
    if notice.viewed_at is None:
        notice.viewed_at = at or utcnow()


def acknowledge_notice(
    notice: ServiceChangeNotice, *, user_id: int, at: datetime | None = None
) -> None:
    """Record that the reader said they are informed.

    ⚠️ Only ever from an explicit act — #375: *"acknowledging is a human action
    and is never inferred from having opened a page."* And it records that they
    were **told**, never that they agreed.
    """
    if notice.recipient_user_id != user_id:
        raise ValueError("Only the person a notice was written for can acknowledge it.")
    if notice.acknowledged_at is None:
        notice.acknowledged_at = at or utcnow()
        mark_notice_viewed(notice, at=notice.acknowledged_at)


def unacknowledged_notices_for_recipient(
    db: Session, *, organization_id: int, recipient_user_id: int
) -> list[ServiceChangeNotice]:
    """Everything this person has been told and not yet confirmed being told.

    ⚠️ **The overview page's list, and a different question from the process
    map's.** The map asks *what is new since I looked*; this asks *what have I
    still not confirmed I was informed of*. Dismissing a digest quiets the badge
    and leaves this untouched — a decision waved away unread is still owed an
    answer, because the reader may need to act on their own services because of
    it (Søren, 2026-09-04).
    """
    return (
        db.query(ServiceChangeNotice)
        .filter(
            ServiceChangeNotice.organization_id == organization_id,
            ServiceChangeNotice.recipient_user_id == recipient_user_id,
            ServiceChangeNotice.acknowledged_at.is_(None),
            ServiceChangeNotice.resolved_at.is_(None),
        )
        .order_by(ServiceChangeNotice.created_at.asc())
        .all()
    )


def unresolved_notices_for_recipient(
    db: Session, *, organization_id: int, recipient_user_id: int
) -> list[ServiceChangeNotice]:
    """What is outstanding for this person across **every** process they carry.

    The overview's banner asks the same question the map's does — *what is new
    since I looked* — but without a process in hand, so an issue stays until the
    owning team resolves it and an update drops out once opened.

    ⚠️ **Not the same as :func:`unacknowledged_notices_for_recipient`.** That one
    is the governance list: what this person has never confirmed being told, and
    reading does not shorten it. Two lists, two questions, deliberately not one.

    ⚠️ **Acknowledged notices drop out of this list.** Søren, 2026-09-05: *"when
    I have looked through the information and marked done the notification should
    disappear in the business process and in the overview."* Saying "I have been
    told" is the one act that discharges the duty, so it clears both surfaces —
    including an open **issue**, whose marker otherwise persists however often it
    is read.

    That is a real trade and it is his call: the service may still be broken
    after the reader confirms they know. What the marker tracks is *whether this
    person has been informed*, not whether the owning team has finished — those
    are different questions and only the first one is this reader's to close.
    """
    notices = (
        db.query(ServiceChangeNotice)
        .filter(
            ServiceChangeNotice.organization_id == organization_id,
            ServiceChangeNotice.recipient_user_id == recipient_user_id,
            ServiceChangeNotice.resolved_at.is_(None),
            ServiceChangeNotice.acknowledged_at.is_(None),
        )
        .order_by(ServiceChangeNotice.created_at.asc())
        .all()
    )
    return [
        notice
        for notice in notices
        if notice.kind == ServiceChangeNoticeKind.ISSUE or notice.viewed_at is None
    ]


def notices_for_process(
    db: Session, *, organization_id: int, process_id: str, recipient_user_id: int
) -> list[ServiceChangeNotice]:
    """**The record**: everything this reader has been told about this process.

    ⚠️ **Unfiltered on purpose.** Søren, 2026-09-05: *"the record of notification
    in the service should still be in the tab. It is just the notification strips
    that need to be hidden when there are no unseen notifications."* So the
    service's Notifications tab is a log — what was said, by whom, and when —
    and it does not empty as the reader catches up with it.

    What is *unseen* is a question asked of these same rows, not a different
    query: each carries ``viewed_at``, ``acknowledged_at`` and ``resolved_at``,
    and the page decides from them which markers and which banner to draw. One
    read, two questions, and they cannot disagree about what exists.
    """
    return (
        db.query(ServiceChangeNotice)
        .filter(
            ServiceChangeNotice.organization_id == organization_id,
            ServiceChangeNotice.process_id == process_id,
            ServiceChangeNotice.recipient_user_id == recipient_user_id,
        )
        .order_by(ServiceChangeNotice.created_at.asc())
        .all()
    )
