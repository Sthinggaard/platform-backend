"""#281 (TZ-3) — no timestamp leaves this API without saying what it means.

The rule this enforces is not a formatting preference. A naive timestamp on the
wire is read by ECMAScript as *local* time, so a 15:25 CEST event renders as
13:25 and only for readers outside UTC — invisible to a UTC-based suite, and
wrong in the audit trail a compliance customer is buying.

Enforced by **introspecting every registered route's response model** rather
than by exercising endpoints. A per-endpoint test only covers the endpoints
somebody remembered to write one for, and the failure mode here is precisely
that 125 call sites were written the usual way. This fails when a route is
*added* wrongly, which is the moment it is cheap to fix.
"""

from __future__ import annotations

import datetime as dt
import json
import typing

import pytest
from pydantic import BaseModel
from pydantic.fields import FieldInfo
from pydantic.functional_serializers import PlainSerializer

from src.api.main import app
from src.core.model_defs.common import to_utc_iso

#: A ``str`` field whose name reads like a timestamp has already thrown away the
#: offset before Pydantic could add one, so the type cannot save it.
#:
#: ``_from`` and ``_to`` are here because the first pass without them missed
#: seven ``effective_from`` / ``effective_to`` fields — the governance windows
#: that decide whether an approval is still valid, which is the last place an
#: ambiguous timestamp should survive.
#: **camelCase is here because leaving it out hid 24 fields.** The first pass
#: checked snake_case only, so `occurredAt` on the audit timeline — the one
#: surface this whole epic is about — passed a test written to catch exactly
#: that. A boundary test that only sees one naming convention is a boundary
#: with a door in it.
TIMESTAMP_NAME_SUFFIXES = (
    "_at",
    "_time",
    "_timestamp",
    "_on",
    "_from",
    "_to",
    "_until",
    "_since",
    "_date",
    "At",
    "Time",
    "Timestamp",
    "On",
    "From",
    "Until",
    "Since",
    "Date",
)

#: Names that end in a timestamp suffix without being timestamps. Kept explicit
#: and small — an allowlist that grows without argument is how a boundary test
#: stops meaning anything.
NOT_TIMESTAMPS: frozenset[str] = frozenset(
    {
        # ``Threat.resolved_on`` is Column(String(30)) holding a rendered
        # display date such as "22 May 2026" — never a persisted instant, so
        # there is no offset to attach. Remove this the day it becomes a
        # real timestamp column.
        "resolvedOn",
    }
)


def _unwrap(annotation: typing.Any) -> list[typing.Any]:
    """Every concrete type inside an annotation, flattened."""
    origin = typing.get_origin(annotation)
    if origin is None:
        return [annotation]
    found: list[typing.Any] = []
    for arg in typing.get_args(annotation):
        if arg is type(None):
            continue
        found.extend(_unwrap(arg))
    return found


def _annotated_metadata(annotation: typing.Any) -> list[typing.Any]:
    """Every piece of ``Annotated`` metadata anywhere in an annotation.

    Written recursively because ``UtcTimestamp | None`` puts the metadata on the
    inner ``Annotated``, not on the ``FieldInfo`` — reading only
    ``field.metadata`` reports every optional timestamp as unprotected, which is
    most of them.
    """
    found: list[typing.Any] = []
    if typing.get_origin(annotation) is typing.Annotated:
        args = typing.get_args(annotation)
        found.extend(args[1:])
        found.extend(_annotated_metadata(args[0]))
        return found
    for arg in typing.get_args(annotation):
        found.extend(_annotated_metadata(arg))
    return found


def _is_utc_serialised(field: FieldInfo) -> bool:
    """True when the field carries the one serialiser this codebase permits."""
    candidates = list(field.metadata) + _annotated_metadata(field.annotation)
    return any(
        isinstance(meta, PlainSerializer) and meta.func is to_utc_iso
        for meta in candidates
    )


def _models_reachable_from(model: type[BaseModel], seen: set[type]) -> list[type[BaseModel]]:
    if model in seen:
        return []
    seen.add(model)
    found = [model]
    for field in model.model_fields.values():
        for inner in _unwrap(field.annotation):
            if isinstance(inner, type) and issubclass(inner, BaseModel):
                found.extend(_models_reachable_from(inner, seen))
    return found


def _response_models() -> list[type[BaseModel]]:
    seen: set[type] = set()
    models: list[type[BaseModel]] = []
    for route in app.routes:
        model = getattr(route, "response_model", None)
        if isinstance(model, type) and issubclass(model, BaseModel):
            models.extend(_models_reachable_from(model, seen))
    return models


def _offenders() -> list[str]:
    problems: list[str] = []
    for model in _response_models():
        for name, field in model.model_fields.items():
            inner = _unwrap(field.annotation)
            if any(t is dt.datetime for t in inner):
                if not _is_utc_serialised(field):
                    problems.append(
                        f"{model.__name__}.{name}: bare datetime — use UtcTimestamp, "
                        f"or it serialises with no offset when the stored value is naive"
                    )
            elif any(t is str for t in inner) and name not in NOT_TIMESTAMPS:
                if name.endswith(TIMESTAMP_NAME_SUFFIXES):
                    problems.append(
                        f"{model.__name__}.{name}: timestamp already stringified — "
                        f"type it UtcTimestamp and stop calling .isoformat() in the route"
                    )
    return sorted(set(problems))


def test_no_response_field_leaks_an_ambiguous_timestamp() -> None:
    problems = _offenders()
    assert not problems, (
        f"{len(problems)} response field(s) would put an ambiguous timestamp on the wire:\n"
        + "\n".join(f"  - {p}" for p in problems)
    )


def test_utc_timestamp_attaches_an_offset_to_a_naive_value() -> None:
    """The seam itself, asserted directly.

    A stored value is naive because the column is ``timestamp without time
    zone``; the offset has to be attached on the way out or it is never added.
    """
    from src.api.schemas.timestamps import UtcTimestamp

    class Sample(BaseModel):
        at: UtcTimestamp

    naive = dt.datetime(2026, 8, 19, 13, 25, 10)
    assert Sample(at=naive).model_dump_json() == '{"at":"2026-08-19T13:25:10+00:00"}'


def test_utc_timestamp_keeps_an_aware_value_on_the_same_instant() -> None:
    """An already-aware value keeps its own offset, and that is fine.

    ``to_utc_iso`` does not normalise to ``+00:00``; it guarantees an offset is
    present. ``15:25+02:00`` and ``13:25+00:00`` are the same instant and both
    unambiguous, which is the whole requirement. Asserted on the parsed instant
    rather than the string, so this test states the rule instead of pinning a
    formatting choice nothing depends on.
    """
    from src.api.schemas.timestamps import UtcTimestamp

    class Sample(BaseModel):
        at: UtcTimestamp

    aware = dt.datetime(2026, 8, 19, 15, 25, 10, tzinfo=dt.timezone(dt.timedelta(hours=2)))
    emitted = json.loads(Sample(at=aware).model_dump_json())["at"]

    parsed = dt.datetime.fromisoformat(emitted)
    assert parsed.tzinfo is not None, "an instant with no offset is the defect this closes"
    assert parsed == dt.datetime(2026, 8, 19, 13, 25, 10, tzinfo=dt.timezone.utc)


def test_a_naive_value_and_its_aware_twin_land_on_the_same_instant() -> None:
    """The stored-naive case and the aware case must not disagree.

    Every column is ``timestamp without time zone``, so what comes back from the
    database is naive and what a service just computed is aware. If those two
    serialised to different instants, the same moment would read two ways
    depending on which code path produced it.
    """
    from src.api.schemas.timestamps import UtcTimestamp

    class Sample(BaseModel):
        at: UtcTimestamp

    naive = dt.datetime(2026, 8, 19, 13, 25, 10)
    aware = dt.datetime(2026, 8, 19, 13, 25, 10, tzinfo=dt.timezone.utc)

    from_naive = dt.datetime.fromisoformat(json.loads(Sample(at=naive).model_dump_json())["at"])
    from_aware = dt.datetime.fromisoformat(json.loads(Sample(at=aware).model_dump_json())["at"])
    assert from_naive == from_aware
