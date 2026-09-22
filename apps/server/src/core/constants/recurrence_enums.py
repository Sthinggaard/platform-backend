"""#242 — the vocabulary of a first-class, organisation-visible recurrence.

Celery beat already exists, and every entry in it is a *platform* cadence:
dispatch every 15 seconds, normalise every 60, prune every hour. Those are
infrastructure sweeps, invisible to any organisation and identical for all of
them. None of it can express "this organisation approved deeper access every 30
days", which is why #242 records the primitive as absent rather than as a
configuration gap.

The distinction this module keeps is between the **schedule** — a record an
organisation can see, pause and cancel, owned by whoever approved it — and the
**sweep** that materialises it, which stays a beat entry because that is what
beat is for. A schedule is not a beat entry; a beat entry is how schedules get
noticed.
"""

from enum import StrEnum


class RecurrenceScheduleStatus(StrEnum):
    ACTIVE = "active"
    # Paused stops occurrences without touching the access it runs under —
    # criterion 2. Resuming does not backfill the occurrences that would have
    # happened while paused; a scan nobody ran did not happen, and inventing it
    # would be the system deciding what should have been done.
    PAUSED = "paused"
    CANCELLED = "cancelled"
    SUPERSEDED = "superseded"
    # Reached automatically when the authorising approval expires or stops being
    # active. Distinct from CANCELLED, which is somebody's decision — the
    # difference between "we stopped this" and "the permission ran out" matters
    # to whoever reads it later.
    LAPSED = "lapsed"


class RecurrenceOccurrenceStatus(StrEnum):
    # Materialised and waiting for a consumer to claim it.
    DUE = "due"
    CLAIMED = "claimed"
    # Still unclaimed when the next one came round. Recorded rather than
    # skipped: an occurrence that quietly vanished is indistinguishable from one
    # that never was due, and the whole point of a schedule is being able to say
    # what did not happen.
    MISSED = "missed"
    FAILED = "failed"
    COMPLETED = "completed"


# A terminal occurrence is never revisited by the sweep.
RECURRENCE_OCCURRENCE_TERMINAL = (
    RecurrenceOccurrenceStatus.MISSED.value,
    RecurrenceOccurrenceStatus.FAILED.value,
    RecurrenceOccurrenceStatus.COMPLETED.value,
)

# The shortest cadence this primitive accepts. Recurrence here means "every N
# days" — an organisational cadence, reviewed by a person. Anything faster is a
# platform sweep and belongs in beat, not in a record somebody approves.
class RecurrenceCadenceType(StrEnum):
    """The shapes a cadence can take — a closed, named set (#246).

    #242 shipped only an interval, and its non-goal said *no cron expressions*
    on the reasoning that an organisational cadence is something a person
    reviews. That reasoning is unchanged and this is not an argument against it:
    it is that *"every Monday"* is a sentence people say, and an interval cannot
    express it. ``cadence_days=7`` from a Monday approximates it and stops being
    true the first time a sweep runs late.

    Named members rather than a string, so the cadence can be **read back to the
    person who chose it**. That is the property a cron expression gives up, and
    the reason cron stays out.
    """

    #: Every N days from the last due time. The original shape; still the default.
    INTERVAL_DAYS = "interval_days"
    #: Every N weeks on one or more named weekdays — calendar-anchored, so it
    #: stays on those weekdays. The stored value is unchanged from when this
    #: shape held a single day, so no row has to be rewritten to gain the set.
    DAY_OF_WEEK = "day_of_week"
    #: Every N months on a named day of the month. See ``clamp_day_of_month``
    #: for what the 31st does in February — it is decided here, not in production.
    MONTHLY = "monthly"
    #: Every N years on a named date. 29 February follows the same clamp.
    YEARLY = "yearly"
    #: Monday to Friday. Not an interval: "every weekday" is one cadence people
    #: say, and "every 2 weekdays" is not a sentence anybody means.
    EVERY_WEEKDAY = "every_weekday"


#: Monday is 0, matching ``datetime.weekday()``. Stated because the other
#: convention (Sunday 0) is equally common and silently off by one.
RECURRENCE_WEEKDAY_LABELS: dict[int, str] = {
    0: "Monday",
    1: "Tuesday",
    2: "Wednesday",
    3: "Thursday",
    4: "Friday",
    5: "Saturday",
    6: "Sunday",
}

RECURRENCE_MIN_CADENCE_DAYS = 1
RECURRENCE_MAX_CADENCE_DAYS = 365

#: The interval multiplier — the N in "every N days/weeks/months/years". Its
#: bound is expressed per unit rather than in days, because #265 found the old
#: ``RECURRENCE_MAX_CADENCE_DAYS`` could not police "every 2 years": 730 days is
#: past the limit while being an ordinary organisational cadence.
RECURRENCE_MIN_INTERVAL = 1
RECURRENCE_MAX_INTERVAL_BY_SHAPE: dict[str, int] = {
    RecurrenceCadenceType.INTERVAL_DAYS.value: 365,
    RecurrenceCadenceType.DAY_OF_WEEK.value: 52,
    RecurrenceCadenceType.MONTHLY.value: 12,
    RecurrenceCadenceType.YEARLY.value: 5,
    # Not an interval shape; the multiplier is always 1.
    RecurrenceCadenceType.EVERY_WEEKDAY.value: 1,
}

#: Monday to Friday, as ``datetime.weekday()`` numbers them.
RECURRENCE_WORKING_WEEK = (0, 1, 2, 3, 4)

RECURRENCE_MIN_DAY_OF_MONTH = 1
#: 31 is accepted for every month. A month that is shorter clamps to its last
#: day rather than skipping — see ``clamp_day_of_month``.
RECURRENCE_MAX_DAY_OF_MONTH = 31
RECURRENCE_MIN_MONTH = 1
RECURRENCE_MAX_MONTH = 12


# --- Audit events ---------------------------------------------------------

RECURRENCE_AUDIT_SCHEDULE_CREATED = "recurrence_schedule_created"
RECURRENCE_AUDIT_SCHEDULE_PAUSED = "recurrence_schedule_paused"
RECURRENCE_AUDIT_SCHEDULE_RESUMED = "recurrence_schedule_resumed"
RECURRENCE_AUDIT_SCHEDULE_CANCELLED = "recurrence_schedule_cancelled"
RECURRENCE_AUDIT_SCHEDULE_SUPERSEDED = "recurrence_schedule_superseded"
RECURRENCE_AUDIT_SCHEDULE_LAPSED = "recurrence_schedule_lapsed"
RECURRENCE_AUDIT_OCCURRENCE_DUE = "recurrence_occurrence_due"
RECURRENCE_AUDIT_OCCURRENCE_CLAIMED = "recurrence_occurrence_claimed"
RECURRENCE_AUDIT_OCCURRENCE_MISSED = "recurrence_occurrence_missed"
RECURRENCE_AUDIT_OCCURRENCE_FAILED = "recurrence_occurrence_failed"


# --- Errors ---------------------------------------------------------------

RECURRENCE_ERROR_ADMIN_REQUIRED = (
    "Organisation administrator access is required to manage a recurrence schedule"
)
RECURRENCE_ERROR_SCHEDULE_NOT_FOUND = "Recurrence schedule not found"
RECURRENCE_ERROR_COLLECTOR_REQUIRED = (
    "A schedule runs a collector, so it has to say which one"
)
RECURRENCE_ERROR_WEEKDAY_REQUIRED = (
    "A weekly cadence has to say which day it runs on"
)
RECURRENCE_ERROR_WEEKDAY_OUT_OF_RANGE = (
    "The day of the week must be Monday through Sunday"
)
RECURRENCE_ERROR_UNKNOWN_CADENCE_TYPE = "'{cadence_type}' is not a cadence this platform offers"
RECURRENCE_ERROR_CADENCE_OUT_OF_RANGE = (
    f"A cadence must be between {RECURRENCE_MIN_CADENCE_DAYS} and "
    f"{RECURRENCE_MAX_CADENCE_DAYS} days"
)
#: #265 — the bound is per unit, so the message names the unit rather than
#: converting to days, which is what made "every 2 years" look out of range.
RECURRENCE_ERROR_INTERVAL_OUT_OF_RANGE = (
    "'Every {interval}' is outside what this cadence allows — it must be between "
    "{minimum} and {maximum}"
)
RECURRENCE_ERROR_DAY_OF_MONTH_REQUIRED = (
    "A monthly cadence has to say which day of the month it runs on"
)
RECURRENCE_ERROR_DAY_OF_MONTH_OUT_OF_RANGE = (
    f"The day of the month must be between {RECURRENCE_MIN_DAY_OF_MONTH} and "
    f"{RECURRENCE_MAX_DAY_OF_MONTH}. A month that is shorter runs on its last day"
)
RECURRENCE_ERROR_YEARLY_DATE_REQUIRED = (
    "A yearly cadence has to say which date it runs on"
)
RECURRENCE_ERROR_MONTH_OUT_OF_RANGE = "The month must be January through December"
RECURRENCE_ERROR_WEEKDAYS_REQUIRED = (
    "A weekly cadence has to say which days it runs on"
)
#: #267 — a start in the past is refused rather than quietly moved forward.
#: Silently starting somewhere the person did not choose is the system deciding;
#: saying so lets them choose again.
RECURRENCE_ERROR_START_IN_THE_PAST = (
    "A schedule cannot start in the past. Choose a date and time still to come"
)
# The failure this primitive exists to prevent. A schedule is only ever as
# durable as the approval it runs under.
RECURRENCE_ERROR_AUTHORITY_NOT_ACTIVE = (
    "A recurrence schedule requires an active approval to run under — a schedule that outlives "
    "its approval would keep acting on permission nobody currently holds"
)
RECURRENCE_ERROR_SCHEDULED_MODE_REQUIRED = (
    "An unattended-access approval is required before a collector can run on a schedule"
)
RECURRENCE_ERROR_AUTHORITY_EXPIRES_BEFORE_FIRST_RUN = (
    "This approval expires before the first occurrence would run, so the schedule would never "
    "produce anything"
)
RECURRENCE_ERROR_NOT_PAUSED = "Only a paused recurrence schedule can be resumed"
RECURRENCE_ERROR_NOT_ACTIVE = "Only an active recurrence schedule can be paused"
RECURRENCE_ERROR_ALREADY_TERMINAL = (
    "This recurrence schedule has already been cancelled or has lapsed"
)
RECURRENCE_ERROR_CANNOT_SUPERSEDE = "Only an active or paused schedule can be replaced"


#: The zone assumed for schedules created before #285 gave them one. UTC rather
#: than a place, because that is what their arithmetic actually did — it ran on
#: naive UTC. Naming a city would record an intent nobody expressed, and would
#: silently move every one of those schedules by an offset.
RECURRENCE_LEGACY_ANCHOR_TIMEZONE = "UTC"
