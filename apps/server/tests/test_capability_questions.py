"""Every dependency question a reader is asked can be answered.

Søren, manual testing, 2026-09-13, on *CI/CD Pipeline*: answering "Teams
responsible for this service" said *"This dependency has no slot to record an
answer against."* Nothing tied a template's questions to its slots, and they had
drifted three ways: ``teams`` was asked by every archetype and answered by none;
``platform_infrastructure``'s two required slots sat under a question it never
asked; and the ``required`` literals disagreed with the rule ``get_template``
applied. These tests are that tie.
"""

from __future__ import annotations

import uuid

import pytest

from src.core.constants.dependency_templates import (
    ARCHETYPE_PATTERN_EXPECTATIONS,
    ARCHETYPE_TEMPLATES,
    PATTERN_GROUP_BY_KEY,
    get_template,
)
from src.core.models import SlotTemplate
from src.core.services.capability_question_service import resolve_capability_questions

ARCHETYPES = sorted(ARCHETYPE_TEMPLATES)


def _answered_by_slots(archetype: str) -> dict[str, bool]:
    """Question key → whether any slot answering it is required, for one archetype."""
    expectations = ARCHETYPE_PATTERN_EXPECTATIONS[archetype]
    groups: dict[str, bool] = {}
    for pattern in expectations["required"]:
        groups[PATTERN_GROUP_BY_KEY[pattern]] = True
    for pattern in expectations["optional"]:
        groups.setdefault(PATTERN_GROUP_BY_KEY[pattern], False)
    return groups


def _slot(slot_id: str, group_key: str, *, required: bool = False) -> SlotTemplate:
    return SlotTemplate(
        id=str(uuid.uuid4()),
        service_template_id="template-1",
        slot_id=slot_id,
        label=slot_id,
        purpose="",
        capability_group_key=group_key,
        required=required,
        display_order=0,
    )


# ── The constants agree with themselves ──────────────────────────────────────


@pytest.mark.parametrize("archetype", ARCHETYPES)
def test_every_slot_pattern_names_the_question_it_answers(archetype: str) -> None:
    # The seed falls back to "systems" for a pattern with no group, which files a
    # slot under a question silently. A missing entry must fail here instead.
    expectations = ARCHETYPE_PATTERN_EXPECTATIONS[archetype]
    patterns = expectations["required"] + expectations["optional"]
    assert [p for p in patterns if p not in PATTERN_GROUP_BY_KEY] == []


@pytest.mark.parametrize("archetype", ARCHETYPES)
def test_every_question_has_a_slot_that_can_answer_it(archetype: str) -> None:
    asked = {group["key"] for group in ARCHETYPE_TEMPLATES[archetype]}
    assert sorted(asked - set(_answered_by_slots(archetype))) == []


@pytest.mark.parametrize("archetype", ARCHETYPES)
def test_every_slot_is_under_a_question_that_is_asked(archetype: str) -> None:
    asked = {group["key"] for group in ARCHETYPE_TEMPLATES[archetype]}
    assert sorted(set(_answered_by_slots(archetype)) - asked) == []


@pytest.mark.parametrize("archetype", ARCHETYPES)
def test_a_question_is_required_exactly_when_one_of_its_slots_is(archetype: str) -> None:
    slots = _answered_by_slots(archetype)
    disagreeing = {
        group["key"]: group["required"]
        for group in ARCHETYPE_TEMPLATES[archetype]
        if group["required"] != slots.get(group["key"])
    }
    assert disagreeing == {}


@pytest.mark.parametrize("archetype", ARCHETYPES)
def test_get_template_asks_exactly_what_the_constants_state(archetype: str) -> None:
    stated = [(group["key"], group["required"]) for group in ARCHETYPE_TEMPLATES[archetype]]
    served = [(group["key"], group["required"]) for group in get_template(archetype) or []]
    assert served == stated


@pytest.mark.parametrize("archetype", ARCHETYPES)
def test_no_archetype_asks_for_a_team_as_a_dependency(archetype: str) -> None:
    # Søren, 2026-09-13: "the team accountable is also the ones who needs to
    # restore it". A team is derived from accountability, not picked as an artefact.
    assert "teams" not in {group["key"] for group in ARCHETYPE_TEMPLATES[archetype]}


# ── A stored template is read through its slots ─────────────────────────────


def test_a_stored_question_no_slot_can_answer_is_not_asked() -> None:
    stored = [
        {
            "key": "systems",
            "label": "Systems",
            "question": "Which?",
            "description": "",
            "required": True,
        },
        {"key": "teams", "label": "Teams", "question": "Who?", "description": "", "required": True},
    ]

    questions = resolve_capability_questions(
        stored, [_slot("monitoring_service", "systems")], "platform_infrastructure"
    )

    assert [q["key"] for q in questions] == ["systems"]


def test_a_slot_brings_in_the_question_the_stored_template_never_asked() -> None:
    # CI/CD Pipeline's stored v1 template, exactly as the dev database holds it.
    stored = [
        {
            "key": "systems",
            "label": "Systems that deliver this capability",
            "question": "",
            "description": "",
            "required": True,
        },
        {
            "key": "data",
            "label": "Data and configuration storage",
            "question": "",
            "description": "",
            "required": False,
        },
        {
            "key": "teams",
            "label": "Teams responsible for this service",
            "question": "",
            "description": "",
            "required": False,
        },
    ]
    slots = [
        _slot("compute_resource", "infrastructure", required=True),
        _slot("network_connectivity", "infrastructure", required=True),
        _slot("monitoring_service", "systems"),
        _slot("general_data_store", "data"),
    ]

    questions = {
        q["key"]: q for q in resolve_capability_questions(stored, slots, "platform_infrastructure")
    }

    assert list(questions) == ["systems", "data", "infrastructure"]
    assert questions["infrastructure"]["label"] == "Infrastructure this service runs on"
    assert questions["infrastructure"]["required"] is True
    # Stored as required, but its only slot is optional: the slot decides.
    assert questions["systems"]["required"] is False
    assert questions["systems"]["label"] == "Systems that deliver this capability"


def test_a_question_worded_nowhere_is_labelled_by_its_key_rather_than_left_blank() -> None:
    questions = resolve_capability_questions([], [_slot("x", "vendor_contracts")], archetype=None)

    assert questions == [
        {
            "key": "vendor_contracts",
            "required": False,
            "label": "Vendor contracts",
            "question": "",
            "description": "",
        }
    ]


def test_a_template_with_no_slots_asks_nothing() -> None:
    stored = [
        {"key": "systems", "label": "Systems", "question": "", "description": "", "required": True}
    ]

    assert resolve_capability_questions(stored, [], "platform_infrastructure") == []
