import enum
from datetime import datetime, timezone

from sqlalchemy import Enum


def utcnow() -> datetime:
    """Get current UTC time (replacement for deprecated datetime.utcnow)."""
    return datetime.now(timezone.utc)


def naive_utc(value: datetime) -> datetime:
    """Drop the offset from a UTC instant so it can be compared to a stored one.

    The mirror of :func:`to_utc_iso`. Timestamps are written by :func:`utcnow`
    (timezone-aware) into ``timestamp without time zone`` columns and read back
    naive, so comparing a freshly-made ``utcnow()`` against a stored value raises
    ``TypeError: can't compare offset-naive and offset-aware datetimes``.

    Lives here rather than as a private helper in each service that needs it —
    several had already grown their own identical ``_naive_utc``, which is one
    rule in several places.
    """
    return value.replace(tzinfo=None) if value.tzinfo is not None else value


def to_utc_iso(value: datetime) -> str:
    """Serialise a stored timestamp with an explicit UTC offset.

    Timestamps are written by :func:`utcnow` (timezone-aware) but stored in
    ``timestamp without time zone`` columns, so they come back **naive**. A bare
    ``.isoformat()`` then yields ``2026-08-14T13:25:10.877799`` — a UTC instant
    with nothing saying so.

    Every client has to guess from there, and the usual guess is silently wrong:
    ECMAScript parses a date-time carrying no offset as *local* time, so a
    browser in CEST renders a 15:25 event as 13:25. Not a formatting preference
    — the value is two hours out, and only for users outside UTC, which is
    exactly the kind of error nobody catches in a UTC-based test suite.

    Lives next to :func:`utcnow` because it is the same concern from the other
    end: that function is how a UTC instant enters the system, this is how one
    leaves it.
    """
    return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value).isoformat()


class SeverityLevel(enum.Enum):
    """Severity levels for findings and controls."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ENUM = Enum(
    SeverityLevel,
    values_callable=lambda enum_cls: [member.value for member in enum_cls],
)


class ScanStatus(enum.Enum):
    """Status of scan runs."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingStatus(enum.Enum):
    """Status of security findings."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class JiraTicketStatus(enum.Enum):
    """Jira ticket statuses."""

    CREATED = "created"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class UserStatus(enum.Enum):
    """User lifecycle states."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    INVITED = "invited"
    DELETED = "deleted"


USER_STATUS_ENUM = Enum(
    UserStatus,
    values_callable=lambda enum_cls: [member.value for member in enum_cls],
)


class OnboardingStatus(enum.Enum):
    """UC-6 onboarding state machine."""

    DRAFT = "draft"
    IN_PROGRESS = "in_progress"
    CREATED = "created"
    COLLECTING_PROFILE = "collecting_profile"
    COLLECTING_COMPLIANCE = "collecting_compliance"
    COLLECTING_ASSETS = "collecting_assets"
    GENERATING_DOCS = "generating_docs"
    ACTIVATING_SCANS = "activating_scans"
    COMPLETED = "completed"
    FAILED = "failed"


__all__ = [
    "FindingStatus",
    "JiraTicketStatus",
    "OnboardingStatus",
    "SEVERITY_ENUM",
    "ScanStatus",
    "SeverityLevel",
    "USER_STATUS_ENUM",
    "UserStatus",
    "naive_utc",
    "to_utc_iso",
    "utcnow",
]
