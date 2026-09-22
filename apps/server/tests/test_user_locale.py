"""#279 (TZ-1) — a person's location and timezone, and what must not be inferred.

The rules under test are the ones that would otherwise be re-decided per caller:
what counts as a timezone, what a country may and may not settle, and what an
unset zone means.
"""

from __future__ import annotations

import pytest

from src.core.constants.user_locale import (
    DEFAULT_TIMEZONE,
    UNAMBIGUOUS_COUNTRY_TIMEZONES,
)
from src.core.services.user_locale_service import (
    UserLocaleValidationError,
    is_fallback_timezone,
    propose_timezone_for_country,
    resolve_reader_timezone,
    validate_country,
    validate_timezone,
)


class _Person:
    """A stand-in for a User row — this module never touches the database."""

    def __init__(self, timezone: str | None = None) -> None:
        self.timezone = timezone


@pytest.mark.parametrize(
    "identifier",
    ["Europe/Copenhagen", "America/Nuuk", "Atlantic/Faroe", "UTC", "America/Argentina/Buenos_Aires"],
)
def test_a_place_naming_identifier_is_accepted(identifier: str) -> None:
    assert validate_timezone(identifier) == identifier


@pytest.mark.parametrize("value", ["CET", "CEST", "+02:00", "UTC+2", "GMT-5", "Japan", "GB", ""])
def test_anything_that_does_not_name_a_place_is_refused(value: str) -> None:
    """Including values the tz database itself accepts.

    `CET` is the mistake this epic exists to prevent: it names a winter offset
    that Denmark leaves in March, so a record stored under it is an hour wrong
    for seven months of the year.
    """
    with pytest.raises(UserLocaleValidationError):
        validate_timezone(value)


def test_refusing_an_offset_says_why_rather_than_suggesting_a_typo() -> None:
    with pytest.raises(UserLocaleValidationError) as caught:
        validate_timezone("CET")
    message = str(caught.value)
    assert "does not name a place" in message
    assert "Europe/Copenhagen" in message


def test_an_unknown_place_is_refused_separately_from_a_bad_shape() -> None:
    with pytest.raises(UserLocaleValidationError) as caught:
        validate_timezone("Europe/Nowhere")
    assert "not a time zone this platform recognises" in str(caught.value)


def test_a_single_zone_country_proposes_one() -> None:
    assert propose_timezone_for_country("DK") == "Europe/Copenhagen"
    assert propose_timezone_for_country("dk") == "Europe/Copenhagen"


@pytest.mark.parametrize("country", ["GL", "US", "RU", "AU", "BR", "CA", "ZZ", "", None])
def test_a_country_that_cannot_settle_the_zone_proposes_nothing(country: str | None) -> None:
    """Silence rather than a guess.

    Greenland spans four zones and the United States nine. A guess there is
    wrong for most of the population and invisible to whoever accepts it.
    """
    assert propose_timezone_for_country(country) is None


def test_the_proposal_table_only_holds_countries_it_cannot_be_wrong_about() -> None:
    """A guard on the table itself, not on a caller.

    The table is useful precisely because everything in it is unambiguous. The
    way it stops being useful is somebody adding a big country to make a form
    feel more helpful.
    """
    for forbidden in ("US", "RU", "AU", "BR", "CA", "GL", "CN", "MX", "ID", "KZ"):
        assert forbidden not in UNAMBIGUOUS_COUNTRY_TIMEZONES

    # Every proposal must itself be a valid identifier — a typo here would be a
    # silently wrong default rather than a visible error.
    for identifier in UNAMBIGUOUS_COUNTRY_TIMEZONES.values():
        assert validate_timezone(identifier) == identifier


def test_a_country_is_recorded_as_a_two_letter_code() -> None:
    assert validate_country("dk") == "DK"
    with pytest.raises(UserLocaleValidationError):
        validate_country("Denmark")


def test_a_person_without_a_zone_reads_the_stated_default() -> None:
    assert resolve_reader_timezone(_Person(None)) == DEFAULT_TIMEZONE
    assert resolve_reader_timezone(None) == DEFAULT_TIMEZONE


def test_a_person_with_a_zone_reads_their_own() -> None:
    assert resolve_reader_timezone(_Person("Asia/Kolkata")) == "Asia/Kolkata"


def test_the_fallback_is_reportable_as_a_fallback() -> None:
    """So a screen can say "we are guessing" instead of implying a choice.

    A default presented as a setting is how somebody ends up reading an audit
    trail in a clock they never picked.
    """
    assert is_fallback_timezone(_Person(None)) is True
    assert is_fallback_timezone(_Person("   ")) is True
    assert is_fallback_timezone(_Person("Europe/Copenhagen")) is False


def test_the_default_is_itself_a_valid_identifier() -> None:
    assert validate_timezone(DEFAULT_TIMEZONE) == DEFAULT_TIMEZONE
