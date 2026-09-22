"""Epic A3 — keyset pagination cursor: round-trip and tamper resistance."""

from __future__ import annotations

import base64
from datetime import datetime, timezone

import pytest
from sqlalchemy import Column, DateTime, Integer, MetaData, Table, and_, create_engine, or_, select
from sqlalchemy.pool import StaticPool

from src.core.services.audit_cursor import InvalidCursorError, decode_cursor, encode_cursor, keyset_filter


def test_cursor_round_trip_int_id():
    created_at = datetime(2026, 7, 27, 10, 0, 0, tzinfo=timezone.utc)
    encoded = encode_cursor(created_at, 42)
    decoded = decode_cursor(encoded)
    assert decoded.created_at == created_at
    assert decoded.id == "42"


def test_cursor_round_trip_str_id():
    created_at = datetime(2026, 7, 27, 10, 0, 0, tzinfo=timezone.utc)
    encoded = encode_cursor(created_at, "dr-abc-123")
    decoded = decode_cursor(encoded)
    assert decoded.id == "dr-abc-123"


def _raw_cursor(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii")


@pytest.mark.parametrize(
    "malformed",
    [
        "not-base64-!!!",
        "",
        _raw_cursor(b"no-separator-at-all"),
        _raw_cursor(b"not-a-timestamp|42"),
        _raw_cursor(b"2026-07-27T10:00:00+00:00|"),  # missing id segment
    ],
)
def test_decode_cursor_rejects_malformed_input_cleanly(malformed: str):
    with pytest.raises(InvalidCursorError):
        decode_cursor(malformed)


def test_keyset_filter_excludes_current_and_newer_rows():
    metadata = MetaData()
    table = Table("t", metadata, Column("id", Integer, primary_key=True), Column("created_at", DateTime))
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    metadata.create_all(engine)

    base = datetime(2026, 7, 27, 10, 0, 0)
    rows = [
        {"id": 1, "created_at": datetime(2026, 7, 27, 9, 0, 0)},   # older — should remain
        {"id": 2, "created_at": base},                              # same timestamp, smaller id — should remain
        {"id": 3, "created_at": base},                              # cursor row itself — should be excluded
        {"id": 4, "created_at": base},                              # same timestamp, larger id — should be excluded
        {"id": 5, "created_at": datetime(2026, 7, 27, 11, 0, 0)},  # newer — should be excluded
    ]
    with engine.begin() as conn:
        conn.execute(table.insert(), rows)

    cursor = decode_cursor(encode_cursor(base, 3))
    stmt = select(table.c.id).where(keyset_filter(table.c.created_at, table.c.id, cursor, id_cast=int))
    with engine.connect() as conn:
        result = sorted(row[0] for row in conn.execute(stmt))

    assert result == [1, 2]
