"""#279 (TZ-1) — where a person is, and what clock they read.

Two facts, deliberately kept apart. **Location** answers *where is this person
based* and is business-level — a country, and a city where it matters.
**Timezone** answers *what clock do they read* and is an IANA identifier. They
are related, they change at different times, and they fail differently.

**The zone is an identifier, never an offset.** Denmark is CET (UTC+1) in winter
and CEST (UTC+2) from late March to late October, so a stored ``"CET"`` would be
an hour wrong for seven months of the year — in the audit trail, in the first
market, which is the failure the whole epic exists to prevent.
``Europe/Copenhagen`` carries the transitions with it and stays true through
every clock change, past and future.

**A country cannot produce a zone.** Greenland alone spans four
(``America/Nuuk``, ``America/Danmarkshavn``, ``America/Scoresbysund``,
``America/Thule``); the United States spans nine. The Danish realm is three
separate country codes — ``DK``, ``FO``, ``GL`` — with different zones, so
knowing an organisation is Danish says nothing about where its Faroese
subsidiary reads its clock. Location may therefore **propose** a zone and the
person confirms it. A proposal is a good default; a derivation is a silent
wrong answer.
"""

from __future__ import annotations

#: Where a reader lands when nothing better is known. The first market is
#: Denmark, and this is a stated default rather than an inference — TZ-2 asks
#: every person to confirm their own, and a screen showing a fallback says so
#: rather than presenting it as fact.
DEFAULT_TIMEZONE = "Europe/Copenhagen"

#: Countries whose zone is unambiguous, used only to **propose** a default.
#:
#: Deliberately small and deliberately incomplete. A country belongs here only
#: when it has exactly one IANA zone, so a proposal can never be quietly wrong;
#: anything absent returns nothing and the person is asked. Growing this table
#: to cover multi-zone countries would turn the proposal back into the
#: derivation this module exists to refuse — ``GL`` and ``US`` must never
#: appear here.
UNAMBIGUOUS_COUNTRY_TIMEZONES: dict[str, str] = {
    "DK": "Europe/Copenhagen",
    "FO": "Atlantic/Faroe",
    "SE": "Europe/Stockholm",
    "NO": "Europe/Oslo",
    "FI": "Europe/Helsinki",
    "IS": "Atlantic/Reykjavik",
    "NL": "Europe/Amsterdam",
    "BE": "Europe/Brussels",
    "LU": "Europe/Luxembourg",
    "IE": "Europe/Dublin",
    "GB": "Europe/London",
    "DE": "Europe/Berlin",
    "PL": "Europe/Warsaw",
    "CZ": "Europe/Prague",
    "AT": "Europe/Vienna",
    "CH": "Europe/Zurich",
    "IT": "Europe/Rome",
    "SG": "Asia/Singapore",
    "JP": "Asia/Tokyo",
    "KR": "Asia/Seoul",
    "NZ": "Pacific/Auckland",
}

#: Longest ISO 3166-1 alpha-2 code, and the longest IANA identifier this will
#: ever have to hold (``America/Argentina/ComodRivadavia`` is 33).
COUNTRY_CODE_LENGTH = 2
TIMEZONE_MAX_LENGTH = 64
CITY_MAX_LENGTH = 120


# --- Errors ---------------------------------------------------------------

USER_LOCALE_ERROR_UNKNOWN_TIMEZONE = (
    "'{value}' is not a time zone this platform recognises. Use an IANA identifier such as "
    "'Europe/Copenhagen'."
)
#: The mistake worth its own message, because it is the one somebody makes on
#: purpose thinking they are being clearer. Covers offsets (``+02:00``),
#: abbreviations (``CET``) and legacy single-word aliases (``Japan``) alike —
#: all three fail for the same reason, which is that they do not name a place.
USER_LOCALE_ERROR_NOT_A_PLACE_TIMEZONE = (
    "'{value}' does not name a place. A time zone has to say where, so it knows when that "
    "place changes its clocks — Denmark is CET in winter and CEST in summer, so 'CET' is an "
    "hour wrong for much of the year. Use an identifier such as 'Europe/Copenhagen'."
)
USER_LOCALE_ERROR_COUNTRY_FORMAT = (
    "A country is recorded as its two-letter code, for example 'DK'"
)
USER_LOCALE_ERROR_CITY_TOO_LONG = (
    f"A city name can be at most {CITY_MAX_LENGTH} characters"
)


# --- Audit events ---------------------------------------------------------

#: One event type, not three. Changing where you are and changing your clock are
#: the same act from an audit trail's point of view — "this person restated
#: where they work from" — and splitting it would make a relocation read as two
#: unrelated edits.
USER_LOCALE_AUDIT_UPDATED = "user_locale_updated"


# --- Copy -----------------------------------------------------------------

#: Said on the screen, not only in a docstring. Somebody changing their zone
#: reasonably fears they are about to rewrite history; they are not.
USER_LOCALE_NOTE_NOTHING_IS_REWRITTEN = (
    "Changing this changes how times are shown to you. It does not change when anything "
    "happened, and it does not alter any record."
)

__all__ = [
    "CITY_MAX_LENGTH",
    "USER_LOCALE_AUDIT_UPDATED",
    "USER_LOCALE_ERROR_CITY_TOO_LONG",
    "USER_LOCALE_NOTE_NOTHING_IS_REWRITTEN",
    "COUNTRY_CODE_LENGTH",
    "DEFAULT_TIMEZONE",
    "TIMEZONE_MAX_LENGTH",
    "UNAMBIGUOUS_COUNTRY_TIMEZONES",
    "USER_LOCALE_ERROR_COUNTRY_FORMAT",
    "USER_LOCALE_ERROR_NOT_A_PLACE_TIMEZONE",
    "USER_LOCALE_ERROR_UNKNOWN_TIMEZONE",
]
