"""#463 — a service's BIA is its process's, with only its exceptions in that process (pure logic).

Søren, 2026-09-15 (option B): the owner sees the process's answers and records only what differs.
The service's stored `bia_answers` is never read here: after the clean-up it still holds copies of
process answers, and a copy must not count as the owner's own.
"""

from __future__ import annotations

from types import SimpleNamespace

from src.core.services.bia_inheritance_service import (
    BIA_FIELD_KEYS,
    PROVENANCE_EXCEPTION,
    PROVENANCE_INHERITED,
    PROVENANCE_RECORDED_BEFORE_REASONS,
    bia_is_complete,
    effective_service_bia,
    service_bia_provenance,
)

_FULL = {
    "impact1h": "severe",
    "impact4h": "high",
    "impact24h": "medium",
    "mtd": "le_4h",
    "dataSensitivity": "high",
    "workaround": "partial",
    "alternativeChannel": "none",
}


def _exception(field: str, value: str, *, before_reasons: bool = False) -> SimpleNamespace:
    return SimpleNamespace(field=field, value=value, recorded_before_reasons=before_reasons)


def test_a_service_with_no_exceptions_inherits_the_process_answers():
    assert effective_service_bia(_FULL, []) == _FULL


def test_an_exception_replaces_only_its_own_field():
    merged = effective_service_bia(_FULL, [_exception("impact1h", "low")])

    assert merged["impact1h"] == "low"
    assert merged["mtd"] == _FULL["mtd"]


def test_no_process_bia_and_no_exception_stays_none():
    assert effective_service_bia(None, []) is None


def test_without_a_process_bia_the_exceptions_are_all_there_is():
    """Never fabricated: a field neither the process nor an exception set stays absent."""
    assert effective_service_bia(None, [_exception("mtd", "le_1h")]) == {"mtd": "le_1h"}


def test_an_exception_for_something_that_is_not_a_bia_answer_is_ignored():
    assert (
        effective_service_bia(_FULL, [_exception("serviceOwnerTitle", "Head of Billing")]) == _FULL
    )


def test_the_process_answers_are_not_changed():
    process_answers = dict(_FULL)

    effective_service_bia(process_answers, [_exception("impact1h", "low")])

    assert process_answers == _FULL


def test_provenance_names_inherited_exception_and_carried_over_answers():
    provenance = service_bia_provenance(
        [_exception("impact1h", "low"), _exception("mtd", "le_1h", before_reasons=True)]
    )

    assert set(provenance) == BIA_FIELD_KEYS
    assert provenance["impact1h"] == PROVENANCE_EXCEPTION
    assert provenance["mtd"] == PROVENANCE_RECORDED_BEFORE_REASONS
    assert provenance["dataSensitivity"] == PROVENANCE_INHERITED


def test_provenance_is_all_inherited_without_exceptions():
    assert set(service_bia_provenance([]).values()) == {PROVENANCE_INHERITED}


def test_bia_is_complete_requires_all_fields():
    assert bia_is_complete(_FULL) is True
    assert bia_is_complete({"impact1h": "severe"}) is False
    assert bia_is_complete(None) is False
