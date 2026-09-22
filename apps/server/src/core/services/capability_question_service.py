"""Which dependency questions a service is asked — decided by its slots.

A question exists because a slot needs answering. Until 2026-09-13 the questions
came from one list and the slots from another, with nothing tying them together,
and they had drifted:

- **A question with no slot.** ``teams`` was asked on all 60 service templates
  and no slot belonged to it, so an answer had nowhere to be recorded. Søren hit
  it in manual testing on *CI/CD Pipeline*: *"This dependency has no slot to
  record an answer against."*
- **Slots under a question never asked.** ``platform_infrastructure`` put its
  two *required* slots under ``infrastructure``, which its template did not ask —
  gaps the readiness count reported and no reader could close.

The fix is applied where the questions are **read**, not only where they are
seeded, because a stored template keeps the list it was created with: every
existing database and every learned template version is corrected without a data
migration and without editing a tenant's copy.

The stored template still supplies the **wording** and the **order**. The slots
decide **which** questions exist and **whether** each is required. Pure: no I/O.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from src.core.constants.dependency_templates import get_template
from src.core.models import SlotTemplate

#: The fields a question carries, as ``ServiceTemplate.capability_groups`` stores them.
_QUESTION_TEXT_FIELDS = ("label", "question", "description")


def resolve_capability_questions(
    stored_groups: Sequence[Mapping[str, Any]],
    slot_rows: Iterable[SlotTemplate],
    archetype: str | None,
) -> list[dict[str, Any]]:
    """The questions a reader is asked, in the shape ``capability_groups`` stores.

    - A stored question with no slot is dropped — nothing could record its answer.
    - A slot whose question the stored template never asked brings that question
      in, worded as the archetype words it, after the stored ones.
    - A question is required exactly when one of its slots is. Framework-driven
      promotions are applied later by the caller, as before.
    """
    slots = list(slot_rows)
    slot_group_keys = list(dict.fromkeys(slot.capability_group_key for slot in slots))
    answerable = set(slot_group_keys)
    required_keys = {slot.capability_group_key for slot in slots if slot.required}

    questions: list[dict[str, Any]] = []
    asked: set[str] = set()

    for stored in stored_groups:
        key = stored.get("key")
        if not isinstance(key, str) or key not in answerable or key in asked:
            continue
        questions.append(_question(key, stored, required=key in required_keys))
        asked.add(key)

    implied = [key for key in slot_group_keys if key not in asked]
    if implied:
        archetype_wording = (
            {group["key"]: group for group in (get_template(archetype) or [])} if archetype else {}
        )
        for key in implied:
            questions.append(
                _question(key, archetype_wording.get(key), required=key in required_keys)
            )

    return questions


def _question(key: str, wording: Mapping[str, Any] | None, *, required: bool) -> dict[str, Any]:
    """One question. Without wording, its label is its key — visibly unfinished, never blank."""
    source: Mapping[str, Any] = wording or {}
    question: dict[str, Any] = {"key": key, "required": required}
    for field in _QUESTION_TEXT_FIELDS:
        question[field] = source.get(field) or ""
    if not question["label"]:
        question["label"] = key.replace("_", " ").capitalize()
    return question
