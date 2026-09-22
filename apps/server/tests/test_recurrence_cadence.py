"""#246 — the cadence keeps its anchor, and can say "every Monday".

Two defects in the primitive #242 shipped, both asserted here.

The drift one is the reason this module is pure. `at + cadence` folded every bit
of sweep lateness into the schedule permanently: the beat runs every five
minutes so steady-state drift is small, but a worker down for two days moved a
weekly schedule two days later **forever** — "every Monday" became "every
Wednesday" and stayed there. Testing that needs a sweep running arbitrarily
late, which is trivial against a pure function and awkward against a database.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from src.core.constants.recurrence_enums import RecurrenceCadenceType
from src.core.services.recurrence_cadence import (
    advance_to_future,
    first_occurrence_at_or_after,
    matches_cadence,
    next_occurrence_after,
)
from src.core.services.recurrence_cadence_spec import CadenceSpec, clamp_day_of_month

MONDAY = datetime(2026, 8, 17, 9, 0)  # a real Monday, 09:00
INTERVAL = RecurrenceCadenceType.INTERVAL_DAYS.value
WEEKLY = RecurrenceCadenceType.DAY_OF_WEEK.value


# #285 — these cases are about the anchor, not the zone, so they run in UTC.
# That is also what the migration claims about every schedule created before the
# column existed, so this suite doubles as the assertion that the claim holds.
UTC = "UTC"
COPENHAGEN = "Europe/Copenhagen"


def _weekly(after: datetime, weekday: int = 0, zone: str = UTC) -> datetime:
    return next_occurrence_after(
        spec=CadenceSpec(WEEKLY, interval=1, weekdays=(weekday,)),
        after=after,
        anchor_timezone=zone,
    )


def _interval(after: datetime, days: int, zone: str = UTC) -> datetime:
    return next_occurrence_after(
        spec=CadenceSpec(INTERVAL, interval=days), after=after, anchor_timezone=zone
    )


def _advance(spec: CadenceSpec, due: datetime, at: datetime, zone: str = UTC) -> datetime:
    return advance_to_future(
        spec=spec, next_occurrence_at=due, at=at, anchor_timezone=zone
    )


def _local(instant_utc: datetime, zone: str) -> datetime:
    """The wall clock a reader in ``zone`` sees, for asserting on it."""
    return instant_utc.replace(tzinfo=timezone.utc).astimezone(ZoneInfo(zone))


# --- The shapes ---------------------------------------------------------------


def test_an_interval_advances_by_its_own_number_of_days():
    assert _interval(MONDAY, 30) == datetime(2026, 9, 16, 9, 0)


def test_a_weekday_cadence_lands_on_that_weekday():
    for weekday in range(7):
        assert _weekly(MONDAY, weekday).weekday() == weekday


def test_landing_on_the_same_weekday_means_next_week_not_now():
    """`% 7 or 7` rather than a branch on zero — the off-by-one that would make
    a weekly schedule fire twice on the same day."""
    assert _weekly(MONDAY, 0) == MONDAY + timedelta(days=7)


def test_every_shape_preserves_the_time_of_day():
    """Every shape adds whole days, so a schedule anchored at 09:00 stays at
    09:00 however late anything runs."""
    for result in (_weekly(MONDAY, 3), _interval(MONDAY, 30), _interval(MONDAY, 1)):
        assert (result.hour, result.minute) == (9, 0)


# --- The drift defect ---------------------------------------------------------


def test_a_late_sweep_does_not_move_the_schedule():
    """The defect, at its smallest. The sweep notices six hours late; the next
    occurrence is still due a whole cadence after the time it *was* due."""
    due = MONDAY
    swept_late = due + timedelta(hours=6)

    result = _advance(CadenceSpec(INTERVAL, interval=7), due, swept_late)

    assert result == due + timedelta(days=7)
    # The old behaviour, kept as the thing that must not happen again.
    assert result != swept_late + timedelta(days=7)


def test_two_days_of_downtime_does_not_move_a_weekly_schedule_off_its_weekday():
    """The failure named in the ticket: a worker down for two days turned
    "every Monday" into "every Wednesday", permanently."""
    due = MONDAY
    swept_two_days_late = due + timedelta(days=2)

    result = _advance(CadenceSpec(WEEKLY, interval=1, weekdays=(0,)), due, swept_two_days_late)

    assert result.weekday() == 0, "still a Monday"
    assert result == due + timedelta(days=7)


def test_a_schedule_swept_repeatedly_late_still_lands_on_its_original_anchor():
    """The regression test the acceptance criteria name.

    Fifty windows, each swept a few hours late, and the schedule must still be
    on its original weekday at its original time — because every advance is
    computed from the due time and never from the sweep.
    """
    anchor = MONDAY
    due = MONDAY
    for _ in range(50):
        swept_late = due + timedelta(hours=5, minutes=37)
        due = _advance(CadenceSpec(WEEKLY, interval=1, weekdays=(0,)), due, swept_late)

    assert due.weekday() == anchor.weekday()
    assert (due.hour, due.minute) == (anchor.hour, anchor.minute)
    assert (due - anchor).days == 50 * 7


def test_a_long_outage_produces_one_future_time_not_a_burst_of_back_dated_ones():
    """Criterion 3. After three weeks down the schedule must be *ahead* of now,
    so the next sweep materialises one occurrence rather than three."""
    due = MONDAY
    swept_three_weeks_late = due + timedelta(days=21)

    result = _advance(CadenceSpec(WEEKLY, interval=1, weekdays=(0,)), due, swept_three_weeks_late)

    assert result > swept_three_weeks_late
    assert result.weekday() == 0


@pytest.mark.parametrize("days_late", [0, 1, 3, 9, 40, 400])
def test_the_advance_always_ends_in_the_future_whatever_the_lateness(days_late: int):
    due = MONDAY
    at = due + timedelta(days=days_late)
    result = _advance(CadenceSpec(INTERVAL, interval=7), due, at)
    assert result > at


def test_an_unknown_cadence_type_falls_back_to_the_interval_rather_than_stalling():
    """A shape this build does not recognise must still advance. A schedule that
    stopped moving would sit permanently due and be swept every five minutes."""
    result = next_occurrence_after(
        spec=CadenceSpec("lunar_month", interval=7), after=MONDAY, anchor_timezone=UTC
    )
    assert result == MONDAY + timedelta(days=7)


# --- #285: the cadence is computed in the schedule's own zone -----------------
#
# The 2026 European transitions, which every case below is anchored around:
#   29 March   — 02:00 becomes 03:00. Wall clocks 02:00–02:59 do not happen.
#   25 October — 03:00 becomes 02:00. Wall clocks 02:00–02:59 happen twice.


def test_a_wall_clock_survives_the_spring_forward():
    """The defect this story exists for. 09:00 in Copenhagen is 08:00 UTC in
    winter and 07:00 UTC in summer; naive arithmetic kept the UTC time and so
    moved the schedule to 10:00 local, permanently."""
    friday_0900_cet = datetime(2026, 3, 27, 8, 0)  # 09:00 CET

    result = _interval(friday_0900_cet, 7, COPENHAGEN)

    assert _local(result, COPENHAGEN).strftime("%H:%M") == "09:00"
    assert result == datetime(2026, 4, 3, 7, 0), "an hour earlier in UTC, same hour locally"


def test_every_monday_at_1430_stays_1430_across_the_change():
    """The sentence in the acceptance criteria, asserted literally."""
    monday_1430_cet = datetime(2026, 3, 23, 13, 30)

    result = _weekly(monday_1430_cet, 0, COPENHAGEN)

    assert _local(result, COPENHAGEN).weekday() == 0
    assert _local(result, COPENHAGEN).strftime("%H:%M") == "14:30"


def test_a_wall_clock_survives_the_autumn_change_too():
    monday_1430_cest = datetime(2026, 10, 19, 12, 30)

    result = _weekly(monday_1430_cest, 0, COPENHAGEN)

    assert _local(result, COPENHAGEN).strftime("%H:%M") == "14:30"


def test_a_run_at_0230_on_the_night_that_time_does_not_exist_runs_at_0330():
    """The March edge case. 02:30 has no instant on 29 March, so the schedule
    takes the instant the clock jumped to rather than skipping the day."""
    saturday_0230_cet = datetime(2026, 3, 28, 1, 30)

    result = _interval(saturday_0230_cet, 1, COPENHAGEN)

    local = _local(result, COPENHAGEN)
    assert local.date() == date(2026, 3, 29), "the day is not skipped"
    assert local.strftime("%H:%M") == "03:30"


def test_a_run_at_0230_on_the_night_that_time_happens_twice_takes_the_first():
    """The October edge case. 02:30 comes round twice; the schedule takes the
    earlier instant, so it neither waits an extra hour nor fires twice."""
    saturday_0230_cest = datetime(2026, 10, 24, 0, 30)

    result = _interval(saturday_0230_cest, 1, COPENHAGEN)

    local = _local(result, COPENHAGEN)
    assert local.strftime("%H:%M") == "02:30"
    assert local.utcoffset() == timedelta(hours=2), "the first 02:30, still CEST"


def test_the_anchor_zone_decides_the_weekday_not_utc():
    """23:30 in Copenhagen on a Sunday is 21:30 UTC the same day, but a zone far
    enough east makes the two disagree — and the schedule must follow its own."""
    sunday_late_utc = datetime(2026, 8, 16, 23, 30)  # Monday 09:30 in Auckland

    assert _local(sunday_late_utc, "Pacific/Auckland").weekday() == 0
    result = _weekly(sunday_late_utc, 0, "Pacific/Auckland")
    assert _local(result, "Pacific/Auckland").weekday() == 0


def test_advance_terminates_and_holds_the_wall_clock_across_a_long_outage():
    """The bound restated for zone-aware steps: a whole local day is 23, 24 or
    25 hours, never zero, so the loop still cannot spin — and the anchor holds
    over a five-month outage that crosses a transition."""
    due = datetime(2026, 1, 5, 13, 30)  # Monday 14:30 CET
    swept_five_months_late = datetime(2026, 6, 1, 0, 0)

    result = _advance(
        CadenceSpec(WEEKLY, interval=1, weekdays=(0,)), due, swept_five_months_late, COPENHAGEN
    )

    assert result > swept_five_months_late
    assert _local(result, COPENHAGEN).weekday() == 0
    assert _local(result, COPENHAGEN).strftime("%H:%M") == "14:30"


def test_a_utc_anchor_behaves_exactly_as_the_naive_arithmetic_did():
    """What the migration claims about every pre-#285 row. If this fails, the
    backfill moved existing schedules."""
    assert _interval(MONDAY, 30, UTC) == MONDAY + timedelta(days=30)
    assert _weekly(MONDAY, 3, UTC) == MONDAY + timedelta(days=3)


# --- #265: the five shapes the editor offers ---------------------------------

MONTHLY = RecurrenceCadenceType.MONTHLY.value
YEARLY = RecurrenceCadenceType.YEARLY.value
EVERY_WEEKDAY = RecurrenceCadenceType.EVERY_WEEKDAY.value


def _series(spec: CadenceSpec, start: datetime, count: int, zone: str = UTC) -> list[datetime]:
    out, cur = [], start
    for _ in range(count):
        cur = next_occurrence_after(spec=spec, after=cur, anchor_timezone=zone)
        out.append(cur)
    return out


def test_a_weekday_set_fires_on_every_day_it_names():
    """The criterion: weekday selection holds a set, not a single day. "Every
    Monday and Thursday" is one cadence, not two schedules."""
    spec = CadenceSpec(WEEKLY, interval=1, weekdays=(0, 3))

    days = [d.weekday() for d in _series(spec, MONDAY, 4)]

    assert days == [3, 0, 3, 0]


def test_the_interval_applies_to_weeks_not_only_to_days():
    """The criterion the old model could not express: the multiplier has to work
    on weekly, monthly and yearly, not just on days."""
    spec = CadenceSpec(WEEKLY, interval=2, weekdays=(0, 3))

    dates = _series(spec, MONDAY, 4)

    assert [d.weekday() for d in dates] == [3, 0, 3, 0]
    # Mon and Thu in the same week, then a whole week skipped — not a fortnight
    # measured from Thursday, which would be a different cadence.
    assert (dates[1] - dates[0]).days == 11
    assert (dates[2] - dates[1]).days == 3


def test_every_weekday_means_monday_to_friday_and_never_a_weekend():
    spec = CadenceSpec(EVERY_WEEKDAY)

    days = [d.weekday() for d in _series(spec, MONDAY, 10)]

    assert set(days) <= {0, 1, 2, 3, 4}
    assert days == [1, 2, 3, 4, 0, 1, 2, 3, 4, 0]


def test_a_monthly_cadence_on_the_31st_clamps_in_a_short_month():
    """The month-end rule, decided in the model rather than in production. The
    31st has no February, and skipping would drop five runs a year from a
    schedule somebody approved as twelve."""
    spec = CadenceSpec(MONTHLY, interval=1, day_of_month=31)

    dates = _series(spec, datetime(2026, 1, 31, 9, 0), 4)

    assert [(d.month, d.day) for d in dates] == [(2, 28), (3, 31), (4, 30), (5, 31)]


def test_the_clamp_does_not_permanently_degrade_the_schedule():
    """The trap the clamp would set if the next date were derived from the last
    one: February would pull the schedule to the 28th and it would stay there."""
    spec = CadenceSpec(MONTHLY, interval=1, day_of_month=31)

    dates = _series(spec, datetime(2026, 1, 31, 9, 0), 12)

    assert max(d.day for d in dates) == 31, "it recovers to the 31st"


def test_29_february_on_a_yearly_cadence_follows_the_same_clamp():
    spec = CadenceSpec(YEARLY, interval=1, day_of_month=29, month=2)

    dates = _series(spec, datetime(2028, 2, 29, 9, 0), 4)

    assert [(d.year, d.month, d.day) for d in dates] == [
        (2029, 2, 28), (2030, 2, 28), (2031, 2, 28), (2032, 2, 29),
    ]


def test_a_multi_year_cadence_is_expressible_at_all():
    """The note in the ticket: RECURRENCE_MAX_CADENCE_DAYS was in days, so
    "every 2 years" was 730 and over the limit while being ordinary."""
    spec = CadenceSpec(YEARLY, interval=2, day_of_month=1, month=6)

    dates = _series(spec, datetime(2026, 6, 1, 9, 0), 3)

    assert [d.year for d in dates] == [2028, 2030, 2032]


def test_clamp_day_of_month_is_stated_rather_than_inferred():
    assert clamp_day_of_month(year=2026, month=2, day=31) == 28
    assert clamp_day_of_month(year=2028, month=2, day=31) == 29, "leap year"
    assert clamp_day_of_month(year=2026, month=4, day=31) == 30
    assert clamp_day_of_month(year=2026, month=1, day=31) == 31, "never lengthens"


def test_every_new_shape_still_holds_its_wall_clock_across_a_dst_change():
    """#285's guarantee has to survive the shapes #265 adds, or a monthly
    schedule silently moves an hour in March."""
    for spec in (
        CadenceSpec(MONTHLY, interval=1, day_of_month=15),
        CadenceSpec(WEEKLY, interval=1, weekdays=(0, 3)),
        CadenceSpec(EVERY_WEEKDAY),
    ):
        for result in _series(spec, datetime(2026, 3, 15, 8, 0), 3, COPENHAGEN):
            assert _local(result, COPENHAGEN).strftime("%H:%M") == "09:00"


def test_the_advance_terminates_for_every_shape():
    """The bound restated for calendar steps: the clamp only ever moves a date
    earlier *within its own month*, which is already an interval ahead."""
    at = datetime(2030, 1, 1)
    for spec in (
        CadenceSpec(MONTHLY, interval=1, day_of_month=31),
        CadenceSpec(YEARLY, interval=1, day_of_month=29, month=2),
        CadenceSpec(EVERY_WEEKDAY),
        CadenceSpec(WEEKLY, interval=3, weekdays=(0, 2, 4)),
    ):
        assert _advance(spec, datetime(2026, 1, 31, 9, 0), at) > at


# --- #266: every new shape keeps its anchor under a late sweep ----------------
#
# #246's defect, re-asserted for the shapes #265 added. It was proved once for
# an interval and once for a weekday; monthly and yearly are the first shapes
# that cannot be expressed as "add N days", so the proof does not carry over.


def test_a_late_sweep_does_not_move_a_monthly_schedule_off_its_day():
    """Two days of downtime must not turn "the 15th" into "the 17th" forever."""
    due = datetime(2026, 1, 15, 9, 0)
    spec = CadenceSpec(MONTHLY, interval=1, day_of_month=15)

    result = _advance(spec, due, due + timedelta(days=2))

    assert (result.month, result.day) == (2, 15)
    assert result != due + timedelta(days=2, weeks=4), "not measured from the sweep"


def test_a_late_sweep_does_not_move_a_yearly_schedule_off_its_date():
    due = datetime(2026, 6, 1, 9, 0)
    spec = CadenceSpec(YEARLY, interval=1, day_of_month=1, month=6)

    result = _advance(spec, due, due + timedelta(days=5))

    assert (result.year, result.month, result.day) == (2027, 6, 1)


def test_a_late_sweep_does_not_move_an_every_weekday_schedule_off_its_time():
    due = datetime(2026, 8, 17, 9, 0)  # a Monday
    spec = CadenceSpec(EVERY_WEEKDAY)

    result = _advance(spec, due, due + timedelta(hours=30))

    assert result.weekday() in {0, 1, 2, 3, 4}
    assert (result.hour, result.minute) == (9, 0), "the sweep's lateness is not folded in"


def test_a_long_outage_leaves_a_monthly_schedule_on_its_own_day():
    """Eight months down, and the schedule is still the 15th at 09:00 — the
    property #246 exists to protect, for a shape that is not "add N days"."""
    due = datetime(2026, 1, 15, 9, 0)
    spec = CadenceSpec(MONTHLY, interval=1, day_of_month=15)

    result = _advance(spec, due, datetime(2026, 9, 3, 4, 17))

    assert (result.month, result.day) == (9, 15)
    assert (result.hour, result.minute) == (9, 0)


def test_time_of_day_survives_months_of_different_length():
    """A 31st schedule crosses 28-, 30- and 31-day months. The clamp moves the
    date; it must never move the clock."""
    spec = CadenceSpec(MONTHLY, interval=1, day_of_month=31)

    dates = _series(spec, datetime(2026, 1, 31, 9, 0), 12)

    assert {(d.hour, d.minute) for d in dates} == {(9, 0)}
    assert {d.day for d in dates} == {28, 30, 31}, "February, the 30-day months, the rest"


@pytest.mark.parametrize(
    "spec",
    [
        CadenceSpec(MONTHLY, interval=1, day_of_month=15),
        CadenceSpec(MONTHLY, interval=3, day_of_month=31),
        CadenceSpec(YEARLY, interval=1, day_of_month=29, month=2),
        CadenceSpec(EVERY_WEEKDAY),
        CadenceSpec(WEEKLY, interval=2, weekdays=(0, 3)),
        CadenceSpec(INTERVAL, interval=30),
    ],
)
def test_the_advance_terminates_from_a_far_past_anchor(spec: CadenceSpec):
    """The bound was documented as "every shape adds at least one whole day",
    which became an assumption once the shapes stopped being days. Asserted from
    an anchor eight years back, so a shape that failed to advance would hang
    rather than quietly return the past."""
    at = datetime(2034, 1, 1)

    result = _advance(spec, datetime(2026, 1, 31, 9, 0), at)

    assert result > at


# --- #267: a start date is the earliest moment, not a run of its own ----------


def test_a_start_that_already_matches_the_cadence_is_the_first_run():
    spec = CadenceSpec(WEEKLY, interval=1, weekdays=(0,))
    monday = datetime(2026, 8, 17, 9, 0)

    assert first_occurrence_at_or_after(
        spec=spec, at=monday, anchor_timezone=UTC
    ) == monday


def test_a_start_that_disagrees_with_the_cadence_moves_to_the_cadence():
    """The defect #267 exists for. "Every Monday" with a Thursday start ran on
    the Thursday, then snapped to Mondays forever, and the record showed
    nothing. The start now means "not before this", never "run on this"."""
    spec = CadenceSpec(WEEKLY, interval=1, weekdays=(0,))
    thursday = datetime(2026, 8, 20, 9, 0)

    first = first_occurrence_at_or_after(spec=spec, at=thursday, anchor_timezone=UTC)

    assert first.weekday() == 0, "the following Monday"
    assert first == datetime(2026, 8, 24, 9, 0)
    assert first > thursday


def test_a_monthly_start_moves_to_the_day_it_names():
    spec = CadenceSpec(MONTHLY, interval=1, day_of_month=15)

    first = first_occurrence_at_or_after(
        spec=spec, at=datetime(2026, 8, 3, 9, 0), anchor_timezone=UTC
    )

    assert (first.month, first.day) == (9, 15)


def test_an_interval_cadence_accepts_any_start():
    """"Every 30 days" is relative, so it has no calendar to disagree with —
    whenever the person says is a valid first run."""
    spec = CadenceSpec(INTERVAL, interval=30)
    whenever = datetime(2026, 8, 20, 14, 37)

    assert first_occurrence_at_or_after(
        spec=spec, at=whenever, anchor_timezone=UTC
    ) == whenever


def test_every_weekday_refuses_to_start_on_a_weekend():
    spec = CadenceSpec(EVERY_WEEKDAY)
    saturday = datetime(2026, 8, 22, 9, 0)

    first = first_occurrence_at_or_after(spec=spec, at=saturday, anchor_timezone=UTC)

    assert first.weekday() == 0, "the Monday"


def test_matching_is_judged_in_the_anchor_zone_not_utc():
    """A Sunday evening in UTC is already Monday in Auckland. The cadence's own
    zone decides, or a schedule would start a day out for half the world."""
    spec = CadenceSpec(WEEKLY, interval=1, weekdays=(0,))
    sunday_late_utc = datetime(2026, 8, 16, 23, 30)  # Monday 11:30 in Auckland

    assert matches_cadence(spec=spec, at=sunday_late_utc, anchor_timezone="Pacific/Auckland")
    assert not matches_cadence(spec=spec, at=sunday_late_utc, anchor_timezone=UTC)
