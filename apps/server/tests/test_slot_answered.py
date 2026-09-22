"""Whether a person has answered a slot — and why its status alone cannot say.

``ensure_slot_instances`` writes an untouched slot as ``status="unknown"``, the
value a person's *"I don't know"* also writes. Until 2026-09-13 both counted as
answers: CI/CD Pipeline read *"3 dependencies · 3 answered"* with a required
question open, and template learning counted every untouched slot as an
organisation choosing "I don't know".

``ROW_SHAPES`` holds every shape found carrying these statuses in the dev
database on that date, so each test reads the same fixtures.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.api.routes.bundle_contracts import SlotInstanceOut
from src.core.models import ServiceTemplate, SlotInstance, SlotTemplate
from src.core.services.slot_provisioning_service import (
    UNANSWERED_MAPPING_STATUS,
    UNANSWERED_STATUS,
    is_answered_slot,
)
from src.core.services.template_learning_service import _collect_slot_stats

ROW_SHAPES: dict[str, dict[str, str | None]] = {
    # Written by ensure_slot_instances. 18 rows in dev.
    "untouched": {
        "status": UNANSWERED_STATUS,
        "mapping_status": UNANSWERED_MAPPING_STATUS,
        "evidence_source": None,
        "decided_by": None,
    },
    # A person's "I don't know", through the decide route.
    "person_said_unknown": {
        "status": "unknown",
        "mapping_status": "needs_review",
        "evidence_source": "manual",
        "decided_by": "2",
    },
    # The engine's proposal awaiting a person. 15 rows in dev.
    "engine_suggestion": {
        "status": "unknown",
        "mapping_status": "suggested",
        "evidence_source": "scanner",
        "decided_by": None,
    },
    # A person refused the suggestion — not itself an answer (Step 4.1C).
    "rejected_suggestion": {
        "status": "needs_review",
        "mapping_status": "rejected",
        "evidence_source": "scanner",
        "decided_by": "2",
    },
    "mapped_by_person": {
        "status": "mapped",
        "mapping_status": "approved",
        "evidence_source": "manual",
        "decided_by": "2",
    },
    # Seeded and pre-lifecycle rows: an answer, with nothing recording who gave it.
    "mapped_without_provenance": {
        "status": "mapped",
        "mapping_status": "approved",
        "evidence_source": None,
        "decided_by": None,
    },
    "set_aside_without_provenance": {
        "status": "not_applicable",
        "mapping_status": "approved",
        "evidence_source": None,
        "decided_by": None,
    },
}

ANSWERED = frozenset(
    {
        "person_said_unknown",
        "mapped_by_person",
        "mapped_without_provenance",
        "set_aside_without_provenance",
    }
)


@pytest.mark.parametrize("shape", sorted(ROW_SHAPES))
def test_only_a_persons_answer_counts_as_answered(shape: str) -> None:
    assert is_answered_slot(**ROW_SHAPES[shape]) is (shape in ANSWERED)


@pytest.mark.parametrize("shape", sorted(ROW_SHAPES))
def test_the_slot_response_says_whether_a_person_answered(shape: str) -> None:
    out = SlotInstanceOut(
        slot_id="compute_resource", group_key="infrastructure", **ROW_SHAPES[shape]
    )

    assert out.answered is (shape in ANSWERED)


def test_a_caller_cannot_mark_an_untouched_slot_answered() -> None:
    out = SlotInstanceOut(
        slot_id="compute_resource",
        group_key="infrastructure",
        answered=True,
        **ROW_SHAPES["untouched"],
    )

    assert out.answered is False


class _RowsQuery:
    """Just the query chain `_collect_slot_stats` uses, returning fixed rows."""

    def __init__(self, rows: list[SlotInstance]) -> None:
        self._rows = rows

    def join(self, *_args: object, **_kwargs: object) -> _RowsQuery:
        return self

    def filter(self, *_args: object, **_kwargs: object) -> _RowsQuery:
        return self

    def all(self) -> list[SlotInstance]:
        return list(self._rows)


class _RowsDB:
    def __init__(self, rows: list[SlotInstance]) -> None:
        self._rows = rows

    def query(self, _model: object) -> _RowsQuery:
        return _RowsQuery(self._rows)


def _row(organization_id: int, shape: str) -> SlotInstance:
    return SlotInstance(
        organization_id=organization_id,
        service_id=f"svc-{organization_id}",
        slot_id="compute_resource",
        group_key="infrastructure",
        updated_at=datetime(2026, 9, 13, tzinfo=timezone.utc) + timedelta(minutes=organization_id),
        **ROW_SHAPES[shape],
    )


def test_template_learning_counts_answers_not_untouched_slots() -> None:
    rows = [
        _row(1, "untouched"),
        _row(2, "person_said_unknown"),
        _row(3, "mapped_without_provenance"),
    ]
    slot = SlotTemplate(slot_id="compute_resource", required=True, expected_asset_types=[])

    stats = _collect_slot_stats(
        _RowsDB(rows),  # type: ignore[arg-type]  # a stand-in for the one query chain the function runs
        "ci_cd_pipeline",
        ServiceTemplate(service_key="ci_cd_pipeline", version=1),
        [slot],
    )["compute_resource"]

    assert (stats.total_decisions, stats.unknown, stats.mapped) == (2, 1, 1)
