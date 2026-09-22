"""#279 (TZ-1) — the one place that decides what clock a person reads.

Business logic asks this module, never the model. ``resolve_reader_timezone`` is
the named accessor the epic requires: a caller that reaches into
``user.timezone`` itself has to decide for itself what an unset value means, and
one of them will decide differently.

Validation lives here too, so "is this a real zone?" has a single answer.
Pydantic request models and any service that accepts a zone call the same
function.
"""

from __future__ import annotations

import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from src.core.constants.user_locale import (
    CITY_MAX_LENGTH,
    COUNTRY_CODE_LENGTH,
    DEFAULT_TIMEZONE,
    UNAMBIGUOUS_COUNTRY_TIMEZONES,
    USER_LOCALE_ERROR_CITY_TOO_LONG,
    USER_LOCALE_ERROR_COUNTRY_FORMAT,
    USER_LOCALE_ERROR_NOT_A_PLACE_TIMEZONE,
    USER_LOCALE_ERROR_UNKNOWN_TIMEZONE,
)

#: The only identifier without a region that this accepts. Someone genuinely on
#: UTC is making a real choice, and UTC has no clock change to be wrong about.
_ZONE_WITHOUT_A_PLACE = "UTC"

_COUNTRY_SHAPED = re.compile(r"^[A-Za-z]{2}$")


class UserLocaleValidationError(ValueError):
    """Raised when a timezone or location cannot be accepted."""


def validate_timezone(value: str) -> str:
    """Return the identifier, or explain why it is not one.

    Checked against the running ``zoneinfo`` database rather than a list this
    repository maintains: the tz database changes when governments change their
    clocks, and a hand-kept copy is wrong from the first amendment onwards.
    """
    candidate = (value or "").strip()
    if not candidate:
        raise UserLocaleValidationError(USER_LOCALE_ERROR_UNKNOWN_TIMEZONE.format(value=value))

    # A real identifier names a place: `Europe/Copenhagen`, `America/Nuuk`. An
    # offset, an abbreviation or a legacy alias is refused *before* the lookup
    # and with its own message,
    # because "not recognised" would send somebody hunting for a typo instead of
    # telling them the shape itself is wrong.
    #
    # This deliberately also refuses values the tz database *does* accept:
    # `CET`, `EST`, `GB`, `Japan`. They are legacy aliases, and `CET` in
    # particular is the exact mistake this epic exists to prevent — it names a
    # winter offset that Denmark leaves in March. The person picks
    # `Europe/Copenhagen` instead, which is one extra decision and never wrong.
    if candidate != _ZONE_WITHOUT_A_PLACE and "/" not in candidate:
        raise UserLocaleValidationError(
            USER_LOCALE_ERROR_NOT_A_PLACE_TIMEZONE.format(value=candidate)
        )

    if candidate not in available_timezones():
        raise UserLocaleValidationError(
            USER_LOCALE_ERROR_UNKNOWN_TIMEZONE.format(value=candidate)
        )
    try:
        ZoneInfo(candidate)
    except (ZoneInfoNotFoundError, ValueError) as exc:  # pragma: no cover - defensive
        raise UserLocaleValidationError(
            USER_LOCALE_ERROR_UNKNOWN_TIMEZONE.format(value=candidate)
        ) from exc
    return candidate


def validate_country(value: str) -> str:
    """Normalise a two-letter country code, upper-cased."""
    candidate = (value or "").strip()
    if not _COUNTRY_SHAPED.match(candidate):
        raise UserLocaleValidationError(USER_LOCALE_ERROR_COUNTRY_FORMAT)
    return candidate.upper()


def validate_city(value: str | None) -> str | None:
    """Normalise a city name, or ``None`` when none was given.

    Free text on purpose: a city list is a maintenance burden that is wrong for
    somebody on the day it ships, and this value is read by people rather than
    matched by machines.
    """
    if value is None:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if len(candidate) > CITY_MAX_LENGTH:
        raise UserLocaleValidationError(USER_LOCALE_ERROR_CITY_TOO_LONG)
    return candidate


def propose_timezone_for_country(country: str | None) -> str | None:
    """A zone to *offer*, or ``None`` when the country cannot settle it.

    Returns nothing rather than guessing for any country with more than one
    zone. Greenland has four and the United States has nine; a guess there is
    wrong for most of the population and invisible to the person accepting it.
    """
    if not country:
        return None
    code = country.strip().upper()
    if len(code) != COUNTRY_CODE_LENGTH:
        return None
    return UNAMBIGUOUS_COUNTRY_TIMEZONES.get(code)


def resolve_reader_timezone(user: object | None) -> str:
    """The zone to render a timestamp in for this person.

    The named accessor the epic requires. Callers ask here so that "what does an
    unset timezone mean?" has exactly one answer — and so the fallback can be
    reported as a fallback rather than passed off as the person's own setting
    (see :func:`is_fallback_timezone`).
    """
    configured = getattr(user, "timezone", None) if user is not None else None
    if isinstance(configured, str) and configured.strip():
        return configured.strip()
    return DEFAULT_TIMEZONE


def is_fallback_timezone(user: object | None) -> bool:
    """True when the zone shown is the platform's default, not the person's.

    TZ-2's screen has to say so. A default presented as a choice is how somebody
    ends up reading an audit trail in a clock they never picked.
    """
    configured = getattr(user, "timezone", None) if user is not None else None
    return not (isinstance(configured, str) and configured.strip())


__all__ = [
    "UserLocaleValidationError",
    "is_fallback_timezone",
    "propose_timezone_for_country",
    "resolve_reader_timezone",
    "validate_city",
    "validate_country",
    "validate_timezone",
]
