"""#242 — what actually came round, and what became of it.

The occurrence side of the primitive. The sweep is the only thing here that runs
on a clock, and it does four things in a deliberate order:

1. **Lapse first.** Every due schedule's authority is re-read *before* anything
   is materialised. A schedule whose approval expired or stopped being active is
   closed there and then and produces nothing. Checking afterwards would create
   the very occurrence the rule exists to prevent.
2. **Report what was missed.** An earlier occurrence still sitting ``DUE`` when
   the next comes round is marked ``MISSED`` and audited, never quietly
   overtaken.
3. **Materialise** the occurrence as ``DUE``, and audit it.
4. **Advance** ``next_occurrence_at`` by the cadence.

**Recurrence creates work; it does not execute it.** ``claim_due_occurrences``
is a pull seam, not a dispatch — no handler registry, nothing scheduled, and
Step 4.2 untouched. That is #242's own non-goal, kept structurally rather than
by intention.

The caller owns the transaction (commit).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from src.core.constants.recurrence_enums import (
    RECURRENCE_AUDIT_OCCURRENCE_CLAIMED,
    RECURRENCE_AUDIT_OCCURRENCE_DUE,
    RECURRENCE_AUDIT_OCCURRENCE_FAILED,
    RECURRENCE_AUDIT_OCCURRENCE_MISSED,
    RecurrenceOccurrenceStatus,
    RecurrenceScheduleStatus,
)
from src.core.model_defs.common import naive_utc, utcnow
from src.core.services.recurrence_cadence import advance_to_future
from src.core.services.recurrence_cadence_spec import spec_from_schedule
from src.core.model_defs.contextual_access_policy import ContextualAccessPolicy
from src.core.model_defs.recurrence_schedule import RecurrenceOccurrence, RecurrenceSchedule
from src.core.services.audit_service import append_audit_event
from src.core.services.recurrence_schedule_service import (
    RecurrenceScheduleValidationError,
    authority_lapse_reason,
    lapse_schedule,
)

MISSED_OCCURRENCE_REASON = "Nothing claimed this occurrence before the next one came round."


def _report_missed_occurrences(
    db: Session, schedule: RecurrenceSchedule, *, at: datetime
) -> list[RecurrenceOccurrence]:
    """Mark still-``DUE`` occurrences from earlier windows as ``MISSED``.

    Criterion 3. An occurrence that quietly vanished is indistinguishable from
    one that was never due, so the skipped row is kept and reported rather than
    overwritten by the next window.
    """
    stale = (
        db.query(RecurrenceOccurrence)
        .filter(
            RecurrenceOccurrence.organization_id == schedule.organization_id,
            RecurrenceOccurrence.schedule_id == schedule.id,
            RecurrenceOccurrence.status == RecurrenceOccurrenceStatus.DUE.value,
        )
        .all()
    )
    missed: list[RecurrenceOccurrence] = []
    for occurrence in stale:
        occurrence.status = RecurrenceOccurrenceStatus.MISSED.value
        occurrence.resolved_at = at
        occurrence.failure_reason = MISSED_OCCURRENCE_REASON
        db.add(occurrence)
        append_audit_event(
            db,
            schedule.organization_id,
            RECURRENCE_AUDIT_OCCURRENCE_MISSED,
            metadata={
                "schedule_id": schedule.id,
                "occurrence_id": occurrence.id,
                "scheduled_for": occurrence.scheduled_for.isoformat(),
            },
        )
        missed.append(occurrence)
    return missed


def materialize_due_occurrences(
    db: Session, *, now: datetime | None = None
) -> list[RecurrenceOccurrence]:
    """Turn every due schedule into an occurrence — after checking its authority.

    Platform-wide, like every other beat-driven sweep here. Tenant scoping lives
    on each row rather than in the query: a sweep that only ran for one
    organisation at a time would silently stop running for all the others.
    """
    at = naive_utc(now or utcnow())
    due_schedules = (
        db.query(RecurrenceSchedule)
        .filter(
            RecurrenceSchedule.status == RecurrenceScheduleStatus.ACTIVE.value,
            RecurrenceSchedule.next_occurrence_at <= at,
        )
        .order_by(RecurrenceSchedule.next_occurrence_at)
        .all()
    )

    created: list[RecurrenceOccurrence] = []
    for schedule in due_schedules:
        policy = db.get(ContextualAccessPolicy, schedule.authorizing_policy_id)
        reason = authority_lapse_reason(policy, at)
        if reason is not None:
            # Criterion 4, and the reason this check comes first: a schedule that
            # outlives its approval must produce nothing at all — not one last
            # occurrence on the way out.
            lapse_schedule(db, schedule, reason=reason, at=at)
            continue

        _report_missed_occurrences(db, schedule, at=at)

        occurrence = RecurrenceOccurrence(
            organization_id=schedule.organization_id,
            schedule_id=schedule.id,
            # When it was *due*, not when the sweep noticed. A sweep running late
            # must not make an occurrence look punctual.
            scheduled_for=naive_utc(schedule.next_occurrence_at),
            materialized_at=at,
            status=RecurrenceOccurrenceStatus.DUE.value,
        )
        db.add(occurrence)
        db.flush()

        schedule.last_occurrence_at = naive_utc(schedule.next_occurrence_at)
        # #246 — from the time that was due, not from `at`. See
        # _advance_schedule_anchor for what the old `at + cadence` cost.
        schedule.next_occurrence_at = advance_to_future(
            spec=spec_from_schedule(schedule),
            next_occurrence_at=naive_utc(schedule.next_occurrence_at),
            at=at,
            # #285 — the schedule's own zone, never the sweep's. The sweep runs
            # wherever the worker happens to be; the cadence belongs to whoever
            # approved it.
            anchor_timezone=schedule.anchor_timezone,
        )
        db.add(schedule)

        append_audit_event(
            db,
            schedule.organization_id,
            RECURRENCE_AUDIT_OCCURRENCE_DUE,
            metadata={
                "schedule_id": schedule.id,
                "occurrence_id": occurrence.id,
                "scheduled_for": occurrence.scheduled_for.isoformat(),
                "next_occurrence_at": schedule.next_occurrence_at.isoformat(),
            },
        )
        created.append(occurrence)

    return created


def claim_due_occurrences(
    db: Session, *, organization_id: int, limit: int = 50
) -> list[RecurrenceOccurrence]:
    """Occurrences waiting for a consumer to turn into work.

    A pull seam rather than a dispatch: recurrence hands work over and knows
    nothing about what the work is. Reading this claims nothing — the consumer
    records what it created via :func:`record_occurrence_claimed`.
    """
    return (
        db.query(RecurrenceOccurrence)
        .filter(
            RecurrenceOccurrence.organization_id == organization_id,
            RecurrenceOccurrence.status == RecurrenceOccurrenceStatus.DUE.value,
        )
        .order_by(RecurrenceOccurrence.scheduled_for)
        .limit(limit)
        .all()
    )


def record_occurrence_claimed(
    db: Session, occurrence: RecurrenceOccurrence, *, created_work_ref: str
) -> RecurrenceOccurrence:
    """A consumer took this occurrence and created work for it."""
    if occurrence.status != RecurrenceOccurrenceStatus.DUE.value:
        raise RecurrenceScheduleValidationError("Only a due occurrence can be claimed.")
    if not created_work_ref.strip():
        raise RecurrenceScheduleValidationError(
            "A claim must say what work it created, or the occurrence cannot be traced to it."
        )
    occurrence.status = RecurrenceOccurrenceStatus.CLAIMED.value
    occurrence.claimed_at = utcnow()
    occurrence.created_work_ref = created_work_ref.strip()
    db.add(occurrence)
    append_audit_event(
        db,
        occurrence.organization_id,
        RECURRENCE_AUDIT_OCCURRENCE_CLAIMED,
        metadata={
            "schedule_id": occurrence.schedule_id,
            "occurrence_id": occurrence.id,
            "created_work_ref": occurrence.created_work_ref,
        },
    )
    return occurrence


def record_occurrence_failed(
    db: Session, occurrence: RecurrenceOccurrence, *, failure_reason: str
) -> RecurrenceOccurrence:
    """A failed occurrence is reported, not rolled into the next window."""
    if not failure_reason.strip():
        raise RecurrenceScheduleValidationError("A failure reason is required.")
    occurrence.status = RecurrenceOccurrenceStatus.FAILED.value
    occurrence.resolved_at = utcnow()
    occurrence.failure_reason = failure_reason.strip()
    db.add(occurrence)
    append_audit_event(
        db,
        occurrence.organization_id,
        RECURRENCE_AUDIT_OCCURRENCE_FAILED,
        metadata={
            "schedule_id": occurrence.schedule_id,
            "occurrence_id": occurrence.id,
            "failure_reason": occurrence.failure_reason,
        },
    )
    return occurrence


#: The ledger's page size. Modest on purpose (#276): a collapsed schedule row
#: must not fetch a year of history to render, and a reader who wants more asks
#: for it. It is a *page*, not a cap — `count_occurrences` says how many there
#: really are, so a truncated list is never presented as a complete one.
RECURRENCE_OCCURRENCE_PAGE_SIZE = 50


def list_occurrences(
    db: Session,
    *,
    organization_id: int,
    schedule_id: str,
    limit: int = RECURRENCE_OCCURRENCE_PAGE_SIZE,
    offset: int = 0,
) -> list[RecurrenceOccurrence]:
    """One page of a schedule's ledger, newest first.

    #276 — this silently returned the fifty most recent and said nothing about
    the rest. A weekly schedule crosses fifty inside a year, so from then on the
    screen showed a truncated history that looked complete. The page is still
    fifty; what changed is that the caller can now ask for the next one and can
    find out how many there are.
    """
    return (
        db.query(RecurrenceOccurrence)
        .filter(
            RecurrenceOccurrence.organization_id == organization_id,
            RecurrenceOccurrence.schedule_id == schedule_id,
        )
        .order_by(RecurrenceOccurrence.scheduled_for.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def count_occurrences(db: Session, *, organization_id: int, schedule_id: str) -> int:
    """How many times this schedule has come round, in total.

    Counted rather than inferred from the page: a page that happens to be full
    tells you nothing about whether anything follows it.
    """
    return (
        db.query(RecurrenceOccurrence)
        .filter(
            RecurrenceOccurrence.organization_id == organization_id,
            RecurrenceOccurrence.schedule_id == schedule_id,
        )
        .count()
    )
