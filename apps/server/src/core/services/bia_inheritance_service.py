"""Process -> Service Business Impact Assessment inheritance (BSP-04).

Per the risklence-business-service-profiles skill's BIA scaling rule: ask the
full assessment once at the Business Process level; a Business Service
inherits those answers by default and only needs its own entry where it
genuinely diverges from the process (an exception), never a blank re-ask of
the same questionnaire.

    Business Process impact assessment
    -> Business Service inherits assumptions
    -> User reviews only exceptions

This module is the single source of truth for that merge rule so
`processes.py` (readiness/resilience derivation) and `services.py` (the BIA
edit surface) can never disagree about what "the answers in force" are for a
given service.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol

BIA_FIELD_KEYS: frozenset[str] = frozenset(
    {
        "impact1h",
        "impact4h",
        "impact24h",
        "mtd",
        "dataSensitivity",
        "workaround",
        "alternativeChannel",
    }
)

#: #463 — where the answer in force for one BIA field of a service, in one process, comes from.
PROVENANCE_INHERITED = "inherited"
PROVENANCE_EXCEPTION = "exception"
#: An answer the service held before exceptions needed a reason, carried over by migration.
PROVENANCE_RECORDED_BEFORE_REASONS = "recorded_before_reasons"


class BiaExceptionRecord(Protocol):
    """What the resolver reads from an active `ServiceBiaException`."""

    field: str
    value: str
    recorded_before_reasons: bool


#: One service's active exceptions in one process.
BiaExceptions = Sequence[BiaExceptionRecord]


def effective_service_bia(
    process_answers: dict | None, exceptions: Iterable[BiaExceptionRecord]
) -> dict | None:
    """#463 — the answers in force for a service in one process.

    Søren, 2026-09-15 (option B): the service inherits that process's BIA, and only its active
    exceptions *in that process* replace a field. `business_services.bia_answers` is not read:
    after the clean-up it still holds copies of process answers, and a copy must not count as
    the owner's own. Never fabricates a value that neither the process nor an exception set.
    """
    overrides = {
        exception.field: exception.value
        for exception in exceptions
        if exception.field in BIA_FIELD_KEYS
    }
    if not process_answers and not overrides:
        return None
    merged = dict(process_answers or {})
    merged.update(overrides)
    return merged


def service_bia_provenance(exceptions: Iterable[BiaExceptionRecord]) -> dict[str, str]:
    """#463 — per field: inherited from the process, the owner's exception, or an answer carried
    over from before reasons were required."""
    by_field = {exception.field: exception for exception in exceptions}
    provenance: dict[str, str] = {}
    for field in BIA_FIELD_KEYS:
        exception = by_field.get(field)
        if exception is None:
            provenance[field] = PROVENANCE_INHERITED
        elif exception.recorded_before_reasons:
            provenance[field] = PROVENANCE_RECORDED_BEFORE_REASONS
        else:
            provenance[field] = PROVENANCE_EXCEPTION
    return provenance


def bia_is_complete(effective_answers: dict | None) -> bool:
    if not effective_answers:
        return False
    return BIA_FIELD_KEYS.issubset(effective_answers.keys())
