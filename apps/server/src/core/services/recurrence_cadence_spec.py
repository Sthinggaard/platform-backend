"""#265 — what a cadence *is*, as one contract instead of five loose arguments.

The shapes a schedule can take grew from two to five, and each needs different
fields: a weekly cadence names weekdays, a monthly one names a day of the month,
a yearly one names a date. Passing those as parallel keyword arguments meant
every caller had to know which combinations were meaningful, and the meaningless
ones were filled with placeholders — ``cadence_days=7`` on a weekday schedule
being the one #265 names.

So the cadence is a value, validated once at the edge, and every consumer takes
the whole thing. A dataclass rather than a dict because a dict as a contract
between modules is the anti-pattern that lets a typo become a silent default.

**The month-end rule, decided here rather than discovered in production.**
"Monthly on the 31st" has no 31st in February. The two honest answers are to
skip the month or to clamp to its last day. This clamps:

- A monthly cadence promises *a run every month*. Skipping quietly drops
  February, April, June, September and November for a 31st schedule — seven runs
  a year for a schedule somebody approved as twelve.
- The record can say the clamped date out loud: "the 31st, or the last day in
  months that are shorter". "Sometimes February is missed" is not a sentence
  anybody would approve.

29 February on a yearly cadence follows the same rule and lands on 28 February
in common years, for the same reason.
"""

from __future__ import annotations

import calendar
from collections.abc import Sequence
from dataclasses import dataclass, field

from src.core.constants.recurrence_enums import (
    RECURRENCE_ERROR_DAY_OF_MONTH_OUT_OF_RANGE,
    RECURRENCE_ERROR_DAY_OF_MONTH_REQUIRED,
    RECURRENCE_ERROR_INTERVAL_OUT_OF_RANGE,
    RECURRENCE_ERROR_MONTH_OUT_OF_RANGE,
    RECURRENCE_ERROR_UNKNOWN_CADENCE_TYPE,
    RECURRENCE_ERROR_WEEKDAY_OUT_OF_RANGE,
    RECURRENCE_ERROR_WEEKDAYS_REQUIRED,
    RECURRENCE_ERROR_YEARLY_DATE_REQUIRED,
    RECURRENCE_MAX_CADENCE_DAYS,
    RECURRENCE_MAX_DAY_OF_MONTH,
    RECURRENCE_MAX_INTERVAL_BY_SHAPE,
    RECURRENCE_MAX_MONTH,
    RECURRENCE_MIN_DAY_OF_MONTH,
    RECURRENCE_MIN_INTERVAL,
    RECURRENCE_MIN_MONTH,
    RECURRENCE_WORKING_WEEK,
    RecurrenceCadenceType,
)


def clamp_day_of_month(*, year: int, month: int, day: int) -> int:
    """The requested day, or the last day of that month when it is shorter.

    The 31st in February is the 28th, or the 29th in a leap year. See the module
    docstring for why this clamps rather than skipping the month.
    """
    return min(day, calendar.monthrange(year, month)[1])


@dataclass(frozen=True)
class CadenceSpec:
    """One cadence, complete. Built and validated at the edge, read everywhere.

    ``interval`` is the N in "every N days/weeks/months/years" and is always 1
    for :attr:`RecurrenceCadenceType.EVERY_WEEKDAY`, which is not an interval
    shape. The unit is implied by ``cadence_type`` rather than stored, which is
    what removes the meaningless ``cadence_days=7`` a weekday schedule used to
    carry.
    """

    cadence_type: str
    interval: int = 1
    #: Sorted, deduplicated, and empty unless the shape names weekdays. A set
    #: rather than a single day (#265) — "every Monday and Thursday" is one
    #: cadence, not two schedules a reader has to notice are related.
    weekdays: tuple[int, ...] = field(default_factory=tuple)
    day_of_month: int | None = None
    #: Only a yearly cadence names one; a monthly cadence recurs in every month.
    month: int | None = None

    @property
    def effective_weekdays(self) -> tuple[int, ...]:
        """The weekdays this cadence lands on, whichever shape expresses them.

        ``EVERY_WEEKDAY`` is Monday to Friday by definition rather than by a
        stored set, so a reader cannot be shown a "weekday" schedule that has
        quietly had Wednesday removed.
        """
        if self.cadence_type == RecurrenceCadenceType.EVERY_WEEKDAY.value:
            return RECURRENCE_WORKING_WEEK
        return self.weekdays


class CadenceValidationError(ValueError):
    """A cadence that cannot be stored because it does not describe anything.

    Its own type so the service layer can translate it to the API's validation
    error without catching every ``ValueError`` the call might raise.
    """


def build_cadence_spec(
    *,
    cadence_type: str,
    interval: int = 1,
    weekdays: Sequence[int] | None = None,
    day_of_month: int | None = None,
    month: int | None = None,
) -> CadenceSpec:
    """Validate a cadence once, at the edge, and hand back the value.

    Every shape's requirements live here rather than in the service, so a second
    caller cannot construct a cadence that the sweep then cannot advance. The
    fields a shape does not use are cleared rather than ignored: a weekday left
    on a monthly cadence would be a second, silent opinion about when it runs.
    """
    if cadence_type not in {member.value for member in RecurrenceCadenceType}:
        raise CadenceValidationError(
            RECURRENCE_ERROR_UNKNOWN_CADENCE_TYPE.format(cadence_type=cadence_type)
        )

    maximum = RECURRENCE_MAX_INTERVAL_BY_SHAPE.get(cadence_type, RECURRENCE_MAX_CADENCE_DAYS)
    if cadence_type == RecurrenceCadenceType.EVERY_WEEKDAY.value:
        # Not an interval shape. "Every 2 weekdays" is not a sentence anybody
        # means, so it is normalised rather than refused.
        interval = 1
    if not RECURRENCE_MIN_INTERVAL <= interval <= maximum:
        raise CadenceValidationError(
            RECURRENCE_ERROR_INTERVAL_OUT_OF_RANGE.format(
                interval=interval, minimum=RECURRENCE_MIN_INTERVAL, maximum=maximum
            )
        )

    chosen_days: tuple[int, ...] = ()
    if cadence_type == RecurrenceCadenceType.DAY_OF_WEEK.value:
        chosen_days = tuple(sorted(set(weekdays or ())))
        if not chosen_days:
            raise CadenceValidationError(RECURRENCE_ERROR_WEEKDAYS_REQUIRED)
        if any(day < 0 or day > 6 for day in chosen_days):
            raise CadenceValidationError(RECURRENCE_ERROR_WEEKDAY_OUT_OF_RANGE)

    chosen_day_of_month: int | None = None
    chosen_month: int | None = None
    if cadence_type in (
        RecurrenceCadenceType.MONTHLY.value,
        RecurrenceCadenceType.YEARLY.value,
    ):
        if day_of_month is None:
            raise CadenceValidationError(
                RECURRENCE_ERROR_YEARLY_DATE_REQUIRED
                if cadence_type == RecurrenceCadenceType.YEARLY.value
                else RECURRENCE_ERROR_DAY_OF_MONTH_REQUIRED
            )
        if not RECURRENCE_MIN_DAY_OF_MONTH <= day_of_month <= RECURRENCE_MAX_DAY_OF_MONTH:
            raise CadenceValidationError(RECURRENCE_ERROR_DAY_OF_MONTH_OUT_OF_RANGE)
        chosen_day_of_month = day_of_month

    if cadence_type == RecurrenceCadenceType.YEARLY.value:
        if month is None:
            raise CadenceValidationError(RECURRENCE_ERROR_YEARLY_DATE_REQUIRED)
        if not RECURRENCE_MIN_MONTH <= month <= RECURRENCE_MAX_MONTH:
            raise CadenceValidationError(RECURRENCE_ERROR_MONTH_OUT_OF_RANGE)
        chosen_month = month

    return CadenceSpec(
        cadence_type=cadence_type,
        interval=interval,
        weekdays=chosen_days,
        day_of_month=chosen_day_of_month,
        month=chosen_month,
    )


def spec_from_schedule(schedule: object) -> CadenceSpec:
    """The cadence a stored schedule describes.

    Reads the row rather than reconstructing the arguments it was created from,
    so the sweep and the editor cannot disagree about what a schedule means.
    """
    return CadenceSpec(
        cadence_type=schedule.cadence_type,
        interval=schedule.cadence_interval,
        weekdays=tuple(schedule.cadence_weekdays or ()),
        day_of_month=schedule.cadence_day_of_month,
        month=schedule.cadence_month,
    )
