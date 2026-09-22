"""#246, #285 — when a schedule is next due, computed in its own anchor zone.

Its own module because both recurrence services need it and neither can own it:
``recurrence_occurrence_service`` already imports from
``recurrence_schedule_service``, so putting it in the occurrence service and
importing it back closes a cycle. It is also the one piece of recurrence logic
that is genuinely pure — no session, no row — which is what makes the defects it
fixes testable at the boundary that matters.

**The first defect (#246).** The sweep advanced schedules with ``at + cadence``,
where ``at`` is when the sweep *noticed*, not when the occurrence was *due*.
Every bit of lateness was folded into the schedule permanently. The beat runs
every five minutes so the steady-state drift is small — but a worker down for
two days moved a weekly schedule two days later **forever**: "every Monday"
became "every Wednesday" and stayed there.

The occurrence row already recorded ``scheduled_for`` separately from
``materialized_at``, precisely so a late sweep could not make an occurrence look
punctual. The next time was then computed from the wrong one of the two.

**The second defect (#285).** The arithmetic ran on naive UTC, and this module
guaranteed that "every shape adds whole days, so a schedule anchored at 09:00
stays at 09:00". Adding 24 hours does not keep a wall clock: across a European
spring-forward a 09:00 schedule becomes 10:00 and stays there, and back again in
October. The guarantee now holds in the terms that make it true — **whole days
are added to the wall clock of the schedule's anchor zone**, and the instant is
resolved afterwards.

A schedule carries its own anchor zone rather than resolving against whoever is
looking, because a recurring job happens at a single moment. Resolved per reader,
"every Monday at 14:30" would mean a different instant for each of them.

**Both boundaries are naive UTC**, matching how the columns store time today.
Making the columns timezone-aware is TZ-4's job and does not change this
contract.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from src.core.constants.recurrence_enums import RecurrenceCadenceType
from src.core.services.recurrence_cadence_spec import CadenceSpec, clamp_day_of_month


def _local_wall_clock(instant_utc: datetime, zone: ZoneInfo) -> datetime:
    """The naive wall clock an anchor-zone reader would see at ``instant_utc``."""
    return instant_utc.replace(tzinfo=timezone.utc).astimezone(zone).replace(tzinfo=None)


def _to_instant(wall_clock: datetime, zone: ZoneInfo) -> datetime:
    """The naive UTC instant for a wall clock that may not exist, or exist twice.

    Both DST anomalies have a decided answer rather than whatever the library
    happens to do:

    **The clock that never happens.** On the March night the clocks jump 02:00 to
    03:00, so a schedule anchored at 02:30 has no 02:30 to run at. It runs at
    03:30 — the instant that wall clock maps onto once the jump is applied. A run
    an hour late beats a month skipped, and skipping is the only other answer.

    **The clock that happens twice.** On the October night 02:30 comes round
    again an hour later. The schedule takes the **first** of the two, so it never
    waits an extra hour and never fires twice for one due time. ``fold=0`` is
    that choice, stated here rather than inherited silently.
    """
    aware = wall_clock.replace(tzinfo=zone, fold=0)
    # A wall clock inside a spring-forward gap does not survive the round trip:
    # it comes back as the time the clock jumped to, which is what we want.
    normalised = aware.astimezone(timezone.utc).astimezone(zone)
    if normalised.replace(tzinfo=None) != wall_clock:
        return normalised.astimezone(timezone.utc).replace(tzinfo=None)
    return aware.astimezone(timezone.utc).replace(tzinfo=None)


def _next_weekday_wall_clock(local: datetime, spec: CadenceSpec) -> datetime:
    """The next of the cadence's weekdays, honouring its week interval.

    Within the current week the next named weekday is simply the next one; the
    interval only applies once the week is exhausted, which is what makes
    "every 2 weeks on Monday and Thursday" mean Mon+Thu, then a week off — and
    not Mon, skip, Thu.
    """
    weekdays = spec.effective_weekdays
    # `local` is the previous occurrence, so it is always inside a week the
    # cadence runs in. Any named weekday still to come in that week is next.
    later_this_week = [day for day in weekdays if day > local.weekday()]
    if later_this_week:
        return local + timedelta(days=later_this_week[0] - local.weekday())
    # The week is exhausted, so the interval applies — counted in whole weeks
    # from the start of this one, not from today. Counting from today would make
    # "every 2 weeks on Monday and Thursday" land a fortnight after *Thursday*,
    # which is a different cadence from the one that was approved.
    start_of_this_week = local - timedelta(days=local.weekday())
    return start_of_this_week + timedelta(weeks=max(spec.interval, 1), days=weekdays[0])


def _next_monthly_wall_clock(local: datetime, spec: CadenceSpec) -> datetime:
    """The same day of the month, ``interval`` months on, clamped if short."""
    day = spec.day_of_month or local.day
    month_index = local.year * 12 + (local.month - 1) + max(spec.interval, 1)
    year, month = divmod(month_index, 12)
    month += 1
    return local.replace(
        year=year, month=month, day=clamp_day_of_month(year=year, month=month, day=day)
    )


def _next_yearly_wall_clock(local: datetime, spec: CadenceSpec) -> datetime:
    """The same date, ``interval`` years on. 29 February clamps to the 28th."""
    year = local.year + max(spec.interval, 1)
    month = spec.month or local.month
    day = spec.day_of_month or local.day
    return local.replace(
        year=year, month=month, day=clamp_day_of_month(year=year, month=month, day=day)
    )


def next_occurrence_after(
    *,
    spec: CadenceSpec,
    after: datetime,
    anchor_timezone: str,
) -> datetime:
    """The next due time strictly after ``after``, on the schedule's own anchor.

    ``after`` and the return value are both naive UTC. Time of day is preserved
    in the anchor zone by construction: every shape moves whole days, weeks,
    months or years on the wall clock, so a schedule anchored at 09:00 local
    stays at 09:00 local however late anything runs and whichever side of a DST
    change it falls.

    An unrecognised shape advances by its interval in days rather than stalling.
    A schedule that stopped moving would sit permanently due and be swept every
    five minutes.
    """
    zone = ZoneInfo(anchor_timezone)
    local = _local_wall_clock(after, zone)

    if spec.cadence_type == RecurrenceCadenceType.MONTHLY.value:
        return _to_instant(_next_monthly_wall_clock(local, spec), zone)
    if spec.cadence_type == RecurrenceCadenceType.YEARLY.value:
        return _to_instant(_next_yearly_wall_clock(local, spec), zone)
    if spec.effective_weekdays:
        return _to_instant(_next_weekday_wall_clock(local, spec), zone)
    return _to_instant(local + timedelta(days=max(spec.interval, 1)), zone)


def advance_to_future(
    *,
    spec: CadenceSpec,
    next_occurrence_at: datetime,
    at: datetime,
    anchor_timezone: str,
) -> datetime:
    """Move a schedule to its next *future* due time, keeping its anchor.

    Advances in whole cadence steps from the time that was **due**. Loops rather
    than adding one step, because after a long outage a single step can still be
    in the past — and looping keeps the anchor *and* satisfies the criterion that
    a burst of back-dated occurrences is never produced. The windows stepped over
    are skipped; occurrences already materialised for them are reported MISSED by
    the sweep, which is the behaviour #242 already built.

    Still bounded now that the steps are zone-aware and the shapes are calendar
    ones. The smallest step any shape takes is a whole day on the wall clock,
    which moves the instant by 23, 24 or 25 hours depending on the DST boundary
    crossed — never zero and never backwards — so the loop advances strictly and
    cannot spin however far behind the sweep is. The month-end clamp cannot
    stall it either: clamping only ever moves a date *earlier within its own
    month*, and that month is already at least one interval ahead.
    """
    result = next_occurrence_at
    while result <= at:
        result = next_occurrence_after(
            spec=spec, after=result, anchor_timezone=anchor_timezone
        )
    return result


def matches_cadence(*, spec: CadenceSpec, at: datetime, anchor_timezone: str) -> bool:
    """Whether ``at`` is a moment this cadence would itself have produced.

    An interval cadence matches any moment: "every 30 days" is relative, so it
    has no calendar to disagree with. The calendar shapes each check the part of
    the date they name, and nothing else — a monthly cadence cares about the day
    of the month and not which month it is.
    """
    zone = ZoneInfo(anchor_timezone)
    local = _local_wall_clock(at, zone)

    if spec.cadence_type == RecurrenceCadenceType.MONTHLY.value:
        day = spec.day_of_month or local.day
        return local.day == clamp_day_of_month(year=local.year, month=local.month, day=day)
    if spec.cadence_type == RecurrenceCadenceType.YEARLY.value:
        if spec.month is not None and local.month != spec.month:
            return False
        day = spec.day_of_month or local.day
        return local.day == clamp_day_of_month(year=local.year, month=local.month, day=day)
    if spec.effective_weekdays:
        return local.weekday() in spec.effective_weekdays
    return True


def first_occurrence_at_or_after(
    *, spec: CadenceSpec, at: datetime, anchor_timezone: str
) -> datetime:
    """The first run a schedule starting at ``at`` will actually produce.

    #267 — ``starts_at`` used to be taken verbatim as the first occurrence, with
    nothing checking that it agreed with the cadence. "Every Monday" with a
    Thursday start ran on the Thursday, then snapped to Mondays forever, and the
    record gave no sign of it.

    **The rule: a start date is the earliest moment the schedule may run, not a
    run in itself.** If it already matches the cadence it *is* the first run;
    otherwise the first run is the next moment the cadence produces. Chosen over
    refusing a mismatch because a person picking "every Monday" and a Thursday
    start has said something coherent — begin after Thursday — and refusing it
    would be the system insisting they say it a different way. What must never
    happen is the silent version: honouring the Thursday once and never again.
    """
    if matches_cadence(spec=spec, at=at, anchor_timezone=anchor_timezone):
        return at
    return next_occurrence_after(spec=spec, after=at, anchor_timezone=anchor_timezone)
