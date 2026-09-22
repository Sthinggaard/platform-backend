"""#242 — the surface that makes a recurrence the organisation's, not the platform's.

Criterion 1 rules out a recurrence that exists only as a Celery beat entry
"invisible to the organisation that approved it". This is what makes it visible:
the next occurrence before it happens, the occurrence ledger including what was
missed, and pause/resume/cancel that touch the schedule without touching the
access it runs under.

Pausing is deliberately separate from anything that revokes access — criterion
2 — so nothing here reaches into the approval it reads.
"""

from __future__ import annotations


import structlog
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.contextual_access_enums import CONTEXTUAL_ACCESS_ERROR_NOT_FOUND
from src.core.constants.recurrence_enums import (
    RECURRENCE_ERROR_ADMIN_REQUIRED,
    RECURRENCE_ERROR_SCHEDULE_NOT_FOUND,
    RECURRENCE_ERROR_COLLECTOR_REQUIRED,
    RECURRENCE_MIN_INTERVAL,
    RecurrenceCadenceType,
)
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.contextual_access_policy import ContextualAccessPolicy
from src.core.model_defs.recurrence_schedule import RecurrenceOccurrence, RecurrenceSchedule
from src.core.models import User
from src.core.services.user_locale_service import resolve_reader_timezone
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES
from src.core.services.recurrence_occurrence_service import (
    RECURRENCE_OCCURRENCE_PAGE_SIZE,
    count_occurrences,
    list_occurrences,
)
from src.core.services.recurrence_schedule_service import (
    RecurrenceScheduleValidationError,
    cancel_schedule,
    create_schedule,
    list_schedules,
    pause_schedule,
    resume_schedule,
    supersede_schedule,
)
from src.api.schemas.timestamps import UtcTimestamp

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/recurrence-schedules", tags=["Recurrence schedules"])


class RecurrenceScheduleCreateRequest(BaseModel):
    authorizing_policy_id: str
    cadence_type: RecurrenceCadenceType = RecurrenceCadenceType.INTERVAL_DAYS
    #: #265 — the N in "every N days/weeks/months/years". The unit comes from
    #: `cadence_type`. Bounds are per shape and enforced by `build_cadence_spec`
    #: rather than here, so the message can name the unit: "every 2 years" is
    #: ordinary, and the old days-based limit called it out of range.
    cadence_interval: int = Field(default=7, ge=RECURRENCE_MIN_INTERVAL)
    #: Monday is 0, matching datetime.weekday(). A *set*: "every Monday and
    #: Thursday" is one cadence. Required for a weekly cadence, cleared on the
    #: shapes that do not name weekdays.
    cadence_weekdays: list[int] | None = Field(default=None)
    #: Monthly and yearly. 31 is accepted for every month; a shorter month runs
    #: on its last day.
    cadence_day_of_month: int | None = Field(default=None, ge=1, le=31)
    #: Yearly only — a monthly cadence recurs in every month and names none.
    cadence_month: int | None = Field(default=None, ge=1, le=12)
    #: #260 — required: a schedule is made for a Collector.
    scanner_instance_id: str
    purpose: str | None = None
    starts_at: UtcTimestamp | None = None


class RecurrenceOccurrenceResponse(BaseModel):
    id: str
    scheduled_for: str
    status: str
    materialized_at: UtcTimestamp
    claimed_at: UtcTimestamp | None = None
    created_work_ref: str | None = None
    resolved_at: UtcTimestamp | None = None
    failure_reason: str | None = None


class RecurrenceScheduleResponse(BaseModel):
    id: str
    authorizing_policy_id: str
    scanner_instance_id: str | None = None
    # #246/#265 — the shape, so a reader is told "every Monday and Thursday"
    # rather than being left to infer it from a 7. Named members, never a cron
    # string: the point is that the cadence can be read back to whoever chose it.
    cadence_type: str
    cadence_interval: int
    cadence_weekdays: list[int]
    cadence_day_of_month: int | None = None
    cadence_month: int | None = None
    # #285 — the zone the cadence is computed in. Sent alongside the instant, not
    # instead of it: a reader in another country needs their own clock *and* the
    # anchor, because "Monday 14:30 CEST" and "18:00 your time" are both true and
    # hiding either one makes the schedule unreadable to somebody.
    anchor_timezone: str
    status: str
    # The point of criterion 2: readable before it happens.
    next_occurrence_at: UtcTimestamp
    last_occurrence_at: UtcTimestamp | None = None
    purpose: str | None = None
    created_by_user_id: int | None = None
    paused_at: UtcTimestamp | None = None
    cancelled_at: UtcTimestamp | None = None
    lapsed_at: UtcTimestamp | None = None
    lapsed_reason: str | None = None
    supersedes_schedule_id: str | None = None
    superseded_by_id: str | None = None
    superseded_at: UtcTimestamp | None = None


class RecurrenceScheduleDetailResponse(BaseModel):
    schedule: RecurrenceScheduleResponse
    occurrences: list[RecurrenceOccurrenceResponse]
    # #276 — what the ledger holds, not what this page returned. Without it a
    # full page and a complete history are indistinguishable, and the screen
    # presented a truncated list as the whole story.
    occurrence_total: int
    occurrence_offset: int


class RecurrenceScheduleListResponse(BaseModel):
    schedules: list[RecurrenceScheduleResponse]


def _schedule_response(schedule: RecurrenceSchedule) -> RecurrenceScheduleResponse:
    return RecurrenceScheduleResponse(
        id=schedule.id,
        authorizing_policy_id=schedule.authorizing_policy_id,
        scanner_instance_id=schedule.scanner_instance_id,
        cadence_type=schedule.cadence_type,
        cadence_interval=schedule.cadence_interval,
        cadence_weekdays=list(schedule.cadence_weekdays or ()),
        cadence_day_of_month=schedule.cadence_day_of_month,
        cadence_month=schedule.cadence_month,
        anchor_timezone=schedule.anchor_timezone,
        status=schedule.status,
        next_occurrence_at=schedule.next_occurrence_at.isoformat(),
        last_occurrence_at=schedule.last_occurrence_at,
        purpose=schedule.purpose,
        created_by_user_id=schedule.created_by_user_id,
        paused_at=schedule.paused_at,
        cancelled_at=schedule.cancelled_at,
        lapsed_at=schedule.lapsed_at,
        lapsed_reason=schedule.lapsed_reason,
        supersedes_schedule_id=schedule.supersedes_schedule_id,
        superseded_by_id=schedule.superseded_by_id,
        superseded_at=schedule.superseded_at,
    )


def _occurrence_response(occurrence: RecurrenceOccurrence) -> RecurrenceOccurrenceResponse:
    return RecurrenceOccurrenceResponse(
        id=occurrence.id,
        scheduled_for=occurrence.scheduled_for.isoformat(),
        status=occurrence.status,
        materialized_at=occurrence.materialized_at.isoformat(),
        claimed_at=occurrence.claimed_at,
        created_work_ref=occurrence.created_work_ref,
        resolved_at=occurrence.resolved_at,
        failure_reason=occurrence.failure_reason,
    )


def _require_org_admin(db: Session, ctx: TenantContext) -> None:
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or user.role not in ADMIN_ROLES:
        raise AuthorizationError(RECURRENCE_ERROR_ADMIN_REQUIRED)


def _creator_timezone(db: Session, ctx: TenantContext) -> str:
    """The zone the schedule is anchored to: its creator's, resolved once here.

    #285 — captured at creation rather than read per request, so the cadence
    means one instant. ``resolve_reader_timezone`` is the same rule TZ-1 gives a
    person, including its fallback, so a creator who never set a zone still
    produces a schedule anchored somewhere nameable.
    """
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    return resolve_reader_timezone(user)


def _require_schedule(db: Session, *, ctx: TenantContext, schedule_id: str) -> RecurrenceSchedule:
    schedule = TenantRepository(db, RecurrenceSchedule, ctx.organization_id).get_by_id(schedule_id)
    if schedule is None:
        raise ResourceNotFoundError(RECURRENCE_ERROR_SCHEDULE_NOT_FOUND)
    return schedule


@router.post("", response_model=RecurrenceScheduleResponse)
def create(
    body: RecurrenceScheduleCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> RecurrenceScheduleResponse:
    _require_org_admin(db, ctx)
    policy = TenantRepository(db, ContextualAccessPolicy, ctx.organization_id).get_by_id(
        body.authorizing_policy_id
    )
    if policy is None:
        raise ResourceNotFoundError(CONTEXTUAL_ACCESS_ERROR_NOT_FOUND)
    try:
        schedule = create_schedule(
            db,
            organization_id=ctx.organization_id,
            authorizing_policy=policy,
            cadence_type=body.cadence_type.value,
            cadence_interval=body.cadence_interval,
            cadence_weekdays=body.cadence_weekdays,
            cadence_day_of_month=body.cadence_day_of_month,
            cadence_month=body.cadence_month,
            created_by_user_id=ctx.user_id,
            scanner_instance_id=body.scanner_instance_id,
            purpose=body.purpose,
            starts_at=body.starts_at,
            anchor_timezone=_creator_timezone(db, ctx),
        )
    except RecurrenceScheduleValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(schedule)
    return _schedule_response(schedule)


@router.post("/{schedule_id}/supersede", response_model=RecurrenceScheduleResponse)
def supersede(
    schedule_id: str,
    body: RecurrenceScheduleCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> RecurrenceScheduleResponse:
    _require_org_admin(db, ctx)
    schedule = _require_schedule(db, ctx=ctx, schedule_id=schedule_id)
    policy = TenantRepository(db, ContextualAccessPolicy, ctx.organization_id).get_by_id(
        body.authorizing_policy_id
    )
    if policy is None:
        raise ResourceNotFoundError(CONTEXTUAL_ACCESS_ERROR_NOT_FOUND)
    try:
        replacement = supersede_schedule(
            db,
            schedule,
            authorizing_policy=policy,
            cadence_type=body.cadence_type.value,
            cadence_interval=body.cadence_interval,
            cadence_weekdays=body.cadence_weekdays,
            cadence_day_of_month=body.cadence_day_of_month,
            cadence_month=body.cadence_month,
            purpose=body.purpose,
            starts_at=body.starts_at,
            superseded_by_user_id=ctx.user_id,
        )
    except RecurrenceScheduleValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(replacement)
    return _schedule_response(replacement)


@router.post("/{schedule_id}/pause", response_model=RecurrenceScheduleResponse)
def pause(
    schedule_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> RecurrenceScheduleResponse:
    """Stop the cadence. The access it runs under is untouched."""
    _require_org_admin(db, ctx)
    schedule = _require_schedule(db, ctx=ctx, schedule_id=schedule_id)
    try:
        pause_schedule(db, schedule, paused_by_user_id=ctx.user_id)
    except RecurrenceScheduleValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(schedule)
    return _schedule_response(schedule)


@router.post("/{schedule_id}/resume", response_model=RecurrenceScheduleResponse)
def resume(
    schedule_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> RecurrenceScheduleResponse:
    """Resume from now. Occurrences skipped while paused are not backfilled."""
    _require_org_admin(db, ctx)
    schedule = _require_schedule(db, ctx=ctx, schedule_id=schedule_id)
    try:
        resume_schedule(db, schedule, resumed_by_user_id=ctx.user_id)
    except RecurrenceScheduleValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(schedule)
    return _schedule_response(schedule)


@router.post("/{schedule_id}/cancel", response_model=RecurrenceScheduleResponse)
def cancel(
    schedule_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> RecurrenceScheduleResponse:
    """End the cadence permanently. The access it runs under is untouched."""
    _require_org_admin(db, ctx)
    schedule = _require_schedule(db, ctx=ctx, schedule_id=schedule_id)
    try:
        cancel_schedule(db, schedule, cancelled_by_user_id=ctx.user_id)
    except RecurrenceScheduleValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(schedule)
    return _schedule_response(schedule)


@router.get("", response_model=RecurrenceScheduleListResponse)
def list_all(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> RecurrenceScheduleListResponse:
    return RecurrenceScheduleListResponse(
        schedules=[
            _schedule_response(s) for s in list_schedules(db, organization_id=ctx.organization_id)
        ]
    )


@router.get("/{schedule_id}", response_model=RecurrenceScheduleDetailResponse)
def get_detail(
    schedule_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> RecurrenceScheduleDetailResponse:
    """The schedule with its occurrence ledger — including the missed ones.

    Criterion 3 is only met if what did *not* happen is as readable as what did,
    so missed and failed occurrences are returned alongside the rest rather than
    filtered out of the happy path.
    """
    schedule = _require_schedule(db, ctx=ctx, schedule_id=schedule_id)
    return RecurrenceScheduleDetailResponse(
        schedule=_schedule_response(schedule),
        occurrences=[
            _occurrence_response(o)
            for o in list_occurrences(
                db,
                organization_id=ctx.organization_id,
                schedule_id=schedule.id,
                limit=limit,
                offset=offset,
            )
        ],
        occurrence_total=count_occurrences(
            db, organization_id=ctx.organization_id, schedule_id=schedule.id
        ),
        occurrence_offset=offset,
    )


__all__ = ["router"]
