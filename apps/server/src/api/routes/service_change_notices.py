"""What a reader has been told about services their process depends on (#375).

Two questions, two surfaces, and they are deliberately different endpoints —
collapsing them is how a change gets waved away unread:

- ``/processes/{id}/notices`` — **what is new on this map since I looked.**
  Feeds the node markers and the "while you were away" digest.
- ``/notices/mine`` — **what have I still not confirmed I was told.** The
  overview page's list; a dismissed digest leaves it untouched.

⚠️ **Being informed is not being asked.** Nothing here is an approval step and
no caller may render it as one.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.database import get_db
from src.core.exceptions import ResourceNotFoundError
from src.core.models import BusinessService, ServiceChangeNotice, User, ValueStream
from src.core.repository import TenantRepository
from src.core.services.service_change_notice_service import (
    acknowledge_notice,
    mark_notice_viewed,
    unacknowledged_notices_for_recipient,
    notices_for_process,
    unresolved_notices_for_recipient,
)

router = APIRouter(prefix="/api/v1/service-notices", tags=["Service change notices"])


class ServiceChangeNoticeResponse(BaseModel):
    id: str
    service_id: str
    process_id: str
    #: ``issue`` or ``update`` — states of one thing, not a severity scale.
    kind: str
    title: str
    description: str | None
    #: The deciding owner's own words, carried verbatim.
    owner_comment: str | None
    actor_name: str | None
    decision_record_id: str | None
    created_at: datetime
    viewed_at: datetime | None
    acknowledged_at: datetime | None
    #: Set when the **owning team** closed it — not something this reader can do.
    resolved_at: datetime | None


def _to_response(notice: ServiceChangeNotice, actor_name: str | None) -> ServiceChangeNoticeResponse:
    return ServiceChangeNoticeResponse(
        id=notice.id,
        service_id=notice.service_id,
        process_id=notice.process_id,
        kind=notice.kind,
        title=notice.title,
        description=notice.description,
        owner_comment=notice.owner_comment,
        actor_name=actor_name,
        decision_record_id=notice.decision_record_id,
        created_at=notice.created_at,
        viewed_at=notice.viewed_at,
        acknowledged_at=notice.acknowledged_at,
        resolved_at=notice.resolved_at,
    )


def _actor_names(
    db: Session, notices: list[ServiceChangeNotice], *, organization_id: int
) -> dict[int, str]:
    """Who decided, named — the message says "X decided this", never "somebody".

    ⚠️ Tenant-scoped, and the checker caught it unscoped first. A lookup by id
    alone would happily name a person from another organisation, which is a
    cross-tenant read dressed up as a display detail.
    """
    ids = {notice.actor_user_id for notice in notices if notice.actor_user_id is not None}
    if not ids:
        return {}
    return {
        user.id: (f"{user.first_name or ''} {user.last_name or ''}".strip() or user.email)
        for user in db.query(User)
        .filter(User.organization_id == organization_id, User.id.in_(ids))
        .all()
    }


@router.get("/processes/{process_id}", response_model=list[ServiceChangeNoticeResponse])
def list_process_notices(
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[ServiceChangeNoticeResponse]:
    """**The record** for this process, for the person asking.

    Everything they have been told here, in the order it was said — the service
    panel's Notifications tab is a log and does not empty as they catch up
    (Søren, 2026-09-05). Which of these still counts as *unseen* — and so draws a
    marker on a node or keeps the banner up — is decided by the page from the
    timestamps on each row, not by a second query that could disagree about what
    exists.

    Always scoped to the caller: a notice is written to a person, and showing
    somebody else's would be reporting a duty that is not theirs.
    """
    if ctx.user_id is None:
        return []
    notices = notices_for_process(
        db,
        organization_id=ctx.organization_id,
        process_id=process_id,
        recipient_user_id=ctx.user_id,
    )
    names = _actor_names(db, notices, organization_id=ctx.organization_id)
    return [_to_response(n, names.get(n.actor_user_id or -1)) for n in notices]


@router.get("/mine", response_model=list[ServiceChangeNoticeResponse])
def list_my_unacknowledged_notices(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[ServiceChangeNoticeResponse]:
    """Everything this person has been told and not yet confirmed being told.

    ⚠️ Dismissing a digest does not shorten this list. A change waved away unread
    may still require action on the reader's *own* services (Søren, 2026-09-04).
    """
    if ctx.user_id is None:
        return []
    notices = unacknowledged_notices_for_recipient(
        db, organization_id=ctx.organization_id, recipient_user_id=ctx.user_id
    )
    names = _actor_names(db, notices, organization_id=ctx.organization_id)
    return [_to_response(n, names.get(n.actor_user_id or -1)) for n in notices]


class OutstandingServiceNoticeResponse(ServiceChangeNoticeResponse):
    """A notice plus the two names the overview has to print.

    The overview spans every process the reader carries, so unlike the map it
    cannot name a process or a service from what it already has. Resolved here,
    in one tenant-scoped pass, rather than leaving the page to fetch a name per
    row.
    """

    process_name: str | None
    service_name: str | None


def _names(
    db: Session, model, ids: set[str], *, organization_id: int
) -> dict[str, str]:
    """Ids to names, always filtered by organisation.

    ⚠️ Tenant-scoped for the same reason ``_actor_names`` is: a lookup by id
    alone would happily name a row from another organisation, which is a
    cross-tenant read wearing a display detail as a disguise.
    """
    if not ids:
        return {}
    return {
        row.id: row.name
        for row in db.query(model)
        .filter(model.organization_id == organization_id, model.id.in_(ids))
        .all()
    }


@router.get("/outstanding", response_model=list[OutstandingServiceNoticeResponse])
def list_outstanding_notices(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[OutstandingServiceNoticeResponse]:
    """What is new for this reader across every process they carry.

    Feeds the overview's "while you were away" banner. Same question the map
    asks — an issue persists, an update drops out once opened — but unscoped,
    because the overview is where a reader sees work spanning processes.

    ⚠️ Always the caller's own. A notice is written to a person, and showing
    somebody else's would be reporting a duty that is not theirs.
    """
    if ctx.user_id is None:
        return []
    notices = unresolved_notices_for_recipient(
        db, organization_id=ctx.organization_id, recipient_user_id=ctx.user_id
    )
    actors = _actor_names(db, notices, organization_id=ctx.organization_id)
    processes = _names(
        db, ValueStream, {n.process_id for n in notices}, organization_id=ctx.organization_id
    )
    services = _names(
        db, BusinessService, {n.service_id for n in notices}, organization_id=ctx.organization_id
    )
    return [
        OutstandingServiceNoticeResponse(
            **_to_response(notice, actors.get(notice.actor_user_id or -1)).model_dump(),
            process_name=processes.get(notice.process_id),
            service_name=services.get(notice.service_id),
        )
        for notice in notices
    ]


def _require_own_notice(notice_id: str, ctx: TenantContext, db: Session) -> ServiceChangeNotice:
    notice = TenantRepository(db, ServiceChangeNotice, ctx.organization_id).get_by_id(notice_id)
    if notice is None or notice.recipient_user_id != ctx.user_id:
        # Not 403: a notice written to somebody else is not this reader's to
        # know about, and saying "forbidden" would confirm it exists.
        raise ResourceNotFoundError("Notice not found")
    return notice


@router.post(
    "/{notice_id}/viewed",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def mark_viewed(
    notice_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> Response:
    """Record that the reader opened it. Clears the update marker, nothing else.

    Søren, 2026-09-04: *"it is a 100% read action."* So this is free to happen on
    open — it is not the governance record below.
    """
    mark_notice_viewed(_require_own_notice(notice_id, ctx, db))
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{notice_id}/acknowledge",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def acknowledge(
    notice_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> Response:
    """Record that the reader said they are informed.

    ⚠️ Only from an explicit act, and it records that they were **told** — never
    that they agreed.
    """
    acknowledge_notice(_require_own_notice(notice_id, ctx, db), user_id=ctx.user_id)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
