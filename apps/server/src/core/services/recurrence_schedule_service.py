"""#242 — a recurrence schedule's own lifecycle, and the authority it runs under.

The schedule side of the primitive: create, pause, resume, cancel, and the one
rule that gives the story its point — a schedule is only ever as durable as the
approval behind it, read live rather than copied, so the two cannot drift.

Occurrences (the sweep, missed reporting, and the consumer seam) live in
``recurrence_occurrence_service``. Same reason the two tables are separate: what
is *meant* to happen and what *actually came round* are different questions.

The caller owns the transaction (commit).
"""

from __future__ import annotations

from collections.abc import Sequence

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from src.core.constants.contextual_access_enums import AccessOperatingMode, ContextualAccessPolicyStatus
from src.core.constants.recurrence_enums import (
    RECURRENCE_AUDIT_SCHEDULE_CANCELLED,
    RECURRENCE_AUDIT_SCHEDULE_CREATED,
    RECURRENCE_AUDIT_SCHEDULE_LAPSED,
    RECURRENCE_AUDIT_SCHEDULE_SUPERSEDED,
    RECURRENCE_AUDIT_SCHEDULE_PAUSED,
    RECURRENCE_AUDIT_SCHEDULE_RESUMED,
    RECURRENCE_ERROR_ALREADY_TERMINAL,
    RECURRENCE_ERROR_CANNOT_SUPERSEDE,
    RECURRENCE_ERROR_AUTHORITY_EXPIRES_BEFORE_FIRST_RUN,
    RECURRENCE_ERROR_AUTHORITY_NOT_ACTIVE,
    RECURRENCE_ERROR_SCHEDULED_MODE_REQUIRED,
    RECURRENCE_ERROR_START_IN_THE_PAST,
    RECURRENCE_ERROR_CADENCE_OUT_OF_RANGE,
    RECURRENCE_ERROR_COLLECTOR_REQUIRED,
    RECURRENCE_ERROR_NOT_ACTIVE,
    RECURRENCE_ERROR_NOT_PAUSED,
    RECURRENCE_ERROR_UNKNOWN_CADENCE_TYPE,
    RECURRENCE_ERROR_WEEKDAY_OUT_OF_RANGE,
    RECURRENCE_ERROR_WEEKDAY_REQUIRED,
    RECURRENCE_MAX_CADENCE_DAYS,
    RECURRENCE_MIN_CADENCE_DAYS,
    RecurrenceCadenceType,
    RecurrenceScheduleStatus,
)
from src.core.model_defs.common import naive_utc, utcnow
from src.core.services.recurrence_cadence import (
    first_occurrence_at_or_after,
    next_occurrence_after,
)
from src.core.services.recurrence_cadence_spec import (
    CadenceValidationError,
    build_cadence_spec,
    spec_from_schedule,
)
from src.core.constants.user_locale import DEFAULT_TIMEZONE
from src.core.services.user_locale_service import validate_timezone
from src.core.model_defs.contextual_access_policy import ContextualAccessPolicy
from src.core.model_defs.recurrence_schedule import RecurrenceSchedule
from src.core.services.audit_service import append_audit_event


class RecurrenceScheduleValidationError(ValueError):
    """Raised when a recurrence schedule transition is invalid."""


def authority_lapse_reason(policy: ContextualAccessPolicy | None, at: datetime) -> str | None:
    """Why this authority can no longer carry a schedule, or ``None`` if it can.

    One definition of "the approval is still good", used by creation, resume and
    the sweep alike — so a schedule can never be created under a rule the sweep
    would later judge differently.
    """
    if policy is None:
        return "The approval this schedule ran under no longer exists."
    if policy.status != ContextualAccessPolicyStatus.ACTIVE.value:
        return f"The approval this schedule ran under is no longer active (it is {policy.status})."
    if policy.effective_to is not None and naive_utc(policy.effective_to) <= naive_utc(at):
        return "The approval this schedule ran under has expired."
    return None


def create_schedule(
    db: Session,
    *,
    organization_id: int,
    authorizing_policy: ContextualAccessPolicy,
    cadence_type: str = RecurrenceCadenceType.INTERVAL_DAYS.value,
    cadence_interval: int = 7,
    cadence_weekdays: Sequence[int] | None = None,
    cadence_day_of_month: int | None = None,
    cadence_month: int | None = None,
    created_by_user_id: int | None = None,
    scanner_instance_id: str,
    purpose: str | None = None,
    starts_at: datetime | None = None,
    anchor_timezone: str | None = None,
) -> RecurrenceSchedule:
    """Create a schedule under an approval that is active right now.

    #265 — five cadence shapes, chosen explicitly, each validated by
    ``build_cadence_spec`` rather than here. ``cadence_interval`` is the N in
    "every N days/weeks/months/years" and takes its unit from the shape, which
    is what removed the meaningless ``cadence_days=7`` a weekday schedule used
    to carry.
    """
    # #260 — a schedule is made *for* a Collector, so one without it is not an
    # incomplete record, it is a meaningless one. Refused at creation rather
    # than allowed and rendered nowhere.
    if not scanner_instance_id:
        raise RecurrenceScheduleValidationError(RECURRENCE_ERROR_COLLECTOR_REQUIRED)
    try:
        spec = build_cadence_spec(
            cadence_type=cadence_type,
            interval=cadence_interval,
            weekdays=cadence_weekdays,
            day_of_month=cadence_day_of_month,
            month=cadence_month,
        )
    except CadenceValidationError as exc:
        raise RecurrenceScheduleValidationError(str(exc)) from exc

    if authorizing_policy.organization_id != organization_id:
        raise RecurrenceScheduleValidationError(RECURRENCE_ERROR_AUTHORITY_NOT_ACTIVE)

    if authorizing_policy.choice != AccessOperatingMode.SCHEDULED_AUTONOMOUS.value:
        raise RecurrenceScheduleValidationError(RECURRENCE_ERROR_SCHEDULED_MODE_REQUIRED)

    # #285 — the cadence is computed in the creator's zone, captured now. Not
    # resolved per reader: a recurring job happens at a single moment, and
    # "every Monday at 14:30" resolved per reader would mean a different instant
    # for each of them. Validated through the same rule TZ-1 applies to a person,
    # so a schedule cannot be anchored to `CET` or an offset either.
    anchor = validate_timezone(anchor_timezone) if anchor_timezone else DEFAULT_TIMEZONE

    now = utcnow()
    if authority_lapse_reason(authorizing_policy, now) is not None:
        raise RecurrenceScheduleValidationError(RECURRENCE_ERROR_AUTHORITY_NOT_ACTIVE)

    # The first occurrence lands on the schedule's own anchor, using the same
    # function the sweep advances with — so "every Monday" starts on a Monday
    # rather than a week from today whatever day that is.
    #
    # #267 — a chosen start is the earliest moment the schedule may run, never a
    # run in its own right. It used to be taken verbatim: "every Monday" with a
    # Thursday start ran on the Thursday and snapped to Mondays forever after,
    # and nothing in the record showed it. Now the first run is the first moment
    # at or after the start that the cadence would itself produce.
    if starts_at is not None:
        requested_start = naive_utc(starts_at)
        if requested_start <= naive_utc(now):
            raise RecurrenceScheduleValidationError(RECURRENCE_ERROR_START_IN_THE_PAST)
        first = first_occurrence_at_or_after(
            spec=spec, at=requested_start, anchor_timezone=anchor
        )
    else:
        first = next_occurrence_after(spec=spec, after=naive_utc(now), anchor_timezone=anchor)
    # A schedule whose first occurrence falls after its approval expires would be
    # created only to lapse untouched — better to refuse it than to file it.
    if (
        authorizing_policy.effective_to is not None
        and naive_utc(authorizing_policy.effective_to) <= first
    ):
        raise RecurrenceScheduleValidationError(RECURRENCE_ERROR_AUTHORITY_EXPIRES_BEFORE_FIRST_RUN)

    schedule = RecurrenceSchedule(
        organization_id=organization_id,
        authorizing_policy_id=authorizing_policy.id,
        scanner_instance_id=scanner_instance_id,
        cadence_type=spec.cadence_type,
        cadence_interval=spec.interval,
        cadence_weekdays=list(spec.weekdays),
        cadence_day_of_month=spec.day_of_month,
        cadence_month=spec.month,
        anchor_timezone=anchor,
        status=RecurrenceScheduleStatus.ACTIVE.value,
        next_occurrence_at=first,
        purpose=purpose,
        created_by_user_id=created_by_user_id,
    )
    db.add(schedule)
    db.flush()
    append_audit_event(
        db,
        organization_id,
        RECURRENCE_AUDIT_SCHEDULE_CREATED,
        actor_user_id=created_by_user_id,
        metadata={
            "schedule_id": schedule.id,
            "cadence_type": spec.cadence_type,
            "cadence_interval": spec.interval,
            "cadence_weekdays": list(spec.weekdays),
            "cadence_day_of_month": spec.day_of_month,
            "cadence_month": spec.month,
            "authorizing_policy_id": authorizing_policy.id,
            "next_occurrence_at": first.isoformat(),
        },
    )
    return schedule


def pause_schedule(
    db: Session, schedule: RecurrenceSchedule, *, paused_by_user_id: int | None = None
) -> RecurrenceSchedule:
    """Stop occurrences without touching the access underneath — criterion 2."""
    if schedule.status != RecurrenceScheduleStatus.ACTIVE.value:
        raise RecurrenceScheduleValidationError(RECURRENCE_ERROR_NOT_ACTIVE)
    schedule.status = RecurrenceScheduleStatus.PAUSED.value
    schedule.paused_at = utcnow()
    schedule.paused_by_user_id = paused_by_user_id
    db.add(schedule)
    append_audit_event(
        db,
        schedule.organization_id,
        RECURRENCE_AUDIT_SCHEDULE_PAUSED,
        actor_user_id=paused_by_user_id,
        metadata={"schedule_id": schedule.id},
    )
    return schedule


def resume_schedule(
    db: Session, schedule: RecurrenceSchedule, *, resumed_by_user_id: int | None = None
) -> RecurrenceSchedule:
    """Resume from now, without backfilling what did not happen while paused.

    Inventing the occurrences a pause skipped would be the system deciding that
    work nobody did should be treated as due.
    """
    if schedule.status != RecurrenceScheduleStatus.PAUSED.value:
        raise RecurrenceScheduleValidationError(RECURRENCE_ERROR_NOT_PAUSED)

    now = utcnow()
    policy = db.get(ContextualAccessPolicy, schedule.authorizing_policy_id)
    reason = authority_lapse_reason(policy, now)
    if reason is not None:
        # Nothing resumes onto expired permission. Lapse it instead, honestly.
        return lapse_schedule(db, schedule, reason=reason, at=naive_utc(now))

    schedule.status = RecurrenceScheduleStatus.ACTIVE.value
    schedule.paused_at = None
    schedule.paused_by_user_id = None
    if naive_utc(schedule.next_occurrence_at) <= naive_utc(now):
        # #265 — through the cadence, not `now + N days`. Adding raw days here
        # was the same mistake #246 fixed in the sweep: it ignores the shape, so
        # resuming a "every Monday" schedule on a Wednesday moved it to a
        # Wednesday, and resuming a monthly one advanced it by a single day.
        schedule.next_occurrence_at = next_occurrence_after(
            spec=spec_from_schedule(schedule),
            after=naive_utc(now),
            anchor_timezone=schedule.anchor_timezone,
        )
    db.add(schedule)
    append_audit_event(
        db,
        schedule.organization_id,
        RECURRENCE_AUDIT_SCHEDULE_RESUMED,
        actor_user_id=resumed_by_user_id,
        metadata={
            "schedule_id": schedule.id,
            "next_occurrence_at": schedule.next_occurrence_at.isoformat(),
        },
    )
    return schedule


def cancel_schedule(
    db: Session, schedule: RecurrenceSchedule, *, cancelled_by_user_id: int | None = None
) -> RecurrenceSchedule:
    """End the schedule permanently, leaving the access it ran under alone."""
    if schedule.status in (
        RecurrenceScheduleStatus.CANCELLED.value,
        RecurrenceScheduleStatus.LAPSED.value,
    ):
        raise RecurrenceScheduleValidationError(RECURRENCE_ERROR_ALREADY_TERMINAL)
    schedule.status = RecurrenceScheduleStatus.CANCELLED.value
    schedule.cancelled_at = utcnow()
    schedule.cancelled_by_user_id = cancelled_by_user_id
    db.add(schedule)
    append_audit_event(
        db,
        schedule.organization_id,
        RECURRENCE_AUDIT_SCHEDULE_CANCELLED,
        actor_user_id=cancelled_by_user_id,
        metadata={"schedule_id": schedule.id},
    )
    return schedule


def supersede_schedule(
    db: Session,
    schedule: RecurrenceSchedule,
    *,
    authorizing_policy: ContextualAccessPolicy,
    cadence_type: str,
    cadence_interval: int,
    # Defaulted: only the shapes that name them need them, and a caller
    # replacing an interval cadence should not have to pass three nulls.
    cadence_weekdays: Sequence[int] | None = None,
    cadence_day_of_month: int | None = None,
    cadence_month: int | None = None,
    purpose: str | None,
    # #272 — a replacement can move its anchor as well as its cadence. Without
    # this the editor collected a start date and the supersede path dropped it,
    # so a person moved the start and nothing happened.
    starts_at: datetime | None = None,
    superseded_by_user_id: int | None = None,
) -> RecurrenceSchedule:
    """Replace a live cadence while preserving its historical ledger."""
    if schedule.status not in (
        RecurrenceScheduleStatus.ACTIVE.value,
        RecurrenceScheduleStatus.PAUSED.value,
    ):
        raise RecurrenceScheduleValidationError(RECURRENCE_ERROR_CANNOT_SUPERSEDE)

    replacement = create_schedule(
        db,
        organization_id=schedule.organization_id,
        authorizing_policy=authorizing_policy,
        cadence_type=cadence_type,
        cadence_interval=cadence_interval,
        cadence_weekdays=cadence_weekdays,
        cadence_day_of_month=cadence_day_of_month,
        cadence_month=cadence_month,
        created_by_user_id=superseded_by_user_id,
        scanner_instance_id=schedule.scanner_instance_id,
        purpose=purpose,
        starts_at=starts_at,
        # #285 — the replacement keeps the anchor it is replacing. Superseding is
        # how a cadence is *edited* (D2, Søren 2026-08-19), and an edit by an
        # admin in another country must not silently move every future run by
        # that country's offset. Changing the anchor is a decision of its own.
        anchor_timezone=schedule.anchor_timezone,
    )
    now = utcnow()
    schedule.status = RecurrenceScheduleStatus.SUPERSEDED.value
    schedule.superseded_by_id = replacement.id
    schedule.superseded_at = now
    schedule.superseded_by_user_id = superseded_by_user_id
    replacement.supersedes_schedule_id = schedule.id
    db.add_all([schedule, replacement])
    append_audit_event(
        db,
        schedule.organization_id,
        RECURRENCE_AUDIT_SCHEDULE_SUPERSEDED,
        actor_user_id=superseded_by_user_id,
        metadata={"schedule_id": schedule.id, "replacement_id": replacement.id},
    )
    return replacement


def lapse_schedule(
    db: Session, schedule: RecurrenceSchedule, *, reason: str, at: datetime
) -> RecurrenceSchedule:
    """Close a schedule whose approval ran out.

    Never a human action, and deliberately distinct from cancellation: "we
    stopped this" and "the permission ran out" are different facts, and a reader
    six months later needs to be able to tell them apart.
    """
    schedule.status = RecurrenceScheduleStatus.LAPSED.value
    schedule.lapsed_at = naive_utc(at)
    schedule.lapsed_reason = reason
    db.add(schedule)
    append_audit_event(
        db,
        schedule.organization_id,
        RECURRENCE_AUDIT_SCHEDULE_LAPSED,
        metadata={
            "schedule_id": schedule.id,
            "authorizing_policy_id": schedule.authorizing_policy_id,
            "reason": reason,
        },
    )
    return schedule


def list_schedules(db: Session, *, organization_id: int) -> list[RecurrenceSchedule]:
    return (
        db.query(RecurrenceSchedule)
        .filter(RecurrenceSchedule.organization_id == organization_id)
        .order_by(RecurrenceSchedule.created_at.desc())
        .all()
    )
