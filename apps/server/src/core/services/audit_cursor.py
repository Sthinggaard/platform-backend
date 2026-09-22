"""Epic A3 — keyset pagination cursor for the new audit/provenance read
endpoints.

No pagination convention exists anywhere else in this codebase (DISC-41
itself is a single 200-row-capped fetch with no paging at all), so this is a
new, small, independently-testable utility: an opaque cursor over
``(created_at, id)``, always applied against an already tenant-scoped query.
Tampering with a cursor's contents can only ever narrow or fail the *already
tenant-scoped* result set — it can never be used to escape the base
``organization_id`` filter a caller applies before this cursor is used.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import and_, or_
from sqlalchemy.sql.elements import ColumnElement


class InvalidCursorError(ValueError):
    """Raised when a client-supplied pagination cursor cannot be decoded."""


@dataclass(frozen=True)
class Cursor:
    created_at: datetime
    id: str


def encode_cursor(created_at: datetime, id_: int | str) -> str:
    payload = f"{created_at.isoformat()}|{id_}"
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")


def decode_cursor(cursor: str) -> Cursor:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        created_at_raw, id_raw = raw.split("|", 1)
        created_at = datetime.fromisoformat(created_at_raw)
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise InvalidCursorError("Malformed pagination cursor.") from exc
    if not id_raw:
        raise InvalidCursorError("Malformed pagination cursor.")
    return Cursor(created_at=created_at, id=id_raw)


def keyset_filter(
    created_at_col: ColumnElement,
    id_col: ColumnElement,
    cursor: Cursor,
    *,
    id_cast: type = int,
) -> ColumnElement:
    """Newest-first keyset predicate: rows strictly older than the cursor,
    or exactly as old but with a strictly smaller id (stable tiebreak for
    rows sharing one ``created_at`` timestamp)."""
    cursor_id = id_cast(cursor.id)
    return or_(
        created_at_col < cursor.created_at,
        and_(created_at_col == cursor.created_at, id_col < cursor_id),
    )
