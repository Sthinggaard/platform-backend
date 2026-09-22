"""#281 (TZ-3) — the one place a timestamp becomes a string a client can trust.

**The defect this closes.** Timestamps are written by :func:`utcnow` (timezone-aware)
into ``timestamp without time zone`` columns and read back **naive**. A bare
``.isoformat()`` then yields ``2026-08-14T13:25:10`` — a UTC instant with nothing
saying so — and ECMAScript parses a date-time carrying no offset as *local* time.
A browser in CEST renders a 15:25 event as 13:25. The value is two hours out, only
for readers outside UTC, which is exactly the kind of error a UTC-based test suite
never catches.

**Why an annotated type rather than a convention.** :func:`to_utc_iso` has existed
in ``core.model_defs.common`` since the defect was first understood, and its
docstring describes this precise failure. It was used in three files. There were
125 bare ``.isoformat()`` call sites across 52 of them, and four separate private
``_iso()`` helpers each re-implementing the same wrong rule. A convention that has
already been forgotten 125 times is not a fix — so the rule moves into the *type*,
where a response field cannot opt out of it by being written the usual way.

**It does not reformat, it delegates.** The formatting rule stays in
:func:`to_utc_iso`; this module only decides where it is applied. Two definitions
of "how a UTC instant leaves the system" is the same DRY failure one layer up.

Timezone *display* is not this module's job. A reader sees their own clock, which
is TZ-5's concern in the tenant app. This makes the instant on the wire
unambiguous, which is what any correct display has to start from.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import PlainSerializer

from src.core.model_defs.common import to_utc_iso

#: A timestamp that always leaves the API with an explicit UTC offset.
#:
#: Use for **every** timestamp on a response model. A bare ``datetime`` field
#: serialises without an offset when the stored value is naive, and a ``str``
#: field has already lost the chance — both are refused by the boundary test in
#: ``tests/test_timestamp_boundary.py``.
UtcTimestamp = Annotated[
    datetime,
    PlainSerializer(to_utc_iso, return_type=str, when_used="json"),
]

__all__ = ["UtcTimestamp"]
