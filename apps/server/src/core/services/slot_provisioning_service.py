"""A service's dependency slots exist because its template says so.

Søren, 2026-09-03, on picking an artefact and nothing happening: *"would it not
be find artefact, select the artefact and map the FK to the dependency so it is
connected in the DB?"*

It should be, and the obstacle was that the row it maps onto did not have to
exist. Before this, a ``SlotInstance`` was created only where the suggestion
engine had a candidate (``slot_mapping_suggestion_service``) or where the old
publish-everything step wrote one. A slot the scanner had nothing to say about
had no row, so ``POST /slots/{slot_id}/decide`` — which updates a row — had
nothing to address, and the answer could not be recorded at all.

That made the engine the authority on **how many dependencies a service has**,
which is wrong: the number comes from the service's template, and the engine
only fills some of them in. This module restores that order — every canonical
slot has a row from the start, unanswered, and a decision always has somewhere
to land.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.dependency_category_enums import dependency_category_for_group
from src.core.model_defs.value_streams import SlotInstance
from src.core.models import BusinessService
from src.core.services.template_library_service import (
    list_slot_templates_for_service,
    resolve_active_service_template,
)

#: An unanswered slot. Not "approved" — the column defaults to that, and a row
#: nobody has decided must never be counted as a decision.
#:
#: ⚠️ ``"unknown"`` is also what a person's *"I don't know"* writes, so the status
#: alone cannot say whether anyone answered. ``is_answered_slot`` can.
UNANSWERED_STATUS = "unknown"
UNANSWERED_MAPPING_STATUS = "needs_review"

#: Statuses that are an answer whoever wrote them: this module never writes them.
_ANSWER_STATUSES = frozenset({"mapped", "not_applicable"})

#: An engine proposal awaiting a person. Never an answer, whatever its status.
_SUGGESTED_MAPPING_STATUS = "suggested"


def is_answered_slot(
    *,
    status: str | None,
    mapping_status: str | None,
    evidence_source: str | None,
    decided_by: str | None,
) -> bool:
    """Whether a person has answered this slot.

    Defined by what *this* module writes, so it needs no other writer's literals:
    an untouched row is ``UNANSWERED_STATUS`` with no evidence source and nobody
    deciding. Anything else carrying ``"unknown"`` was written by someone who
    answered — a person's *"I don't know"*.

    Until 2026-09-13 the worklist counted the untouched row as that answer, so
    CI/CD Pipeline read *"3 dependencies · 3 answered"* with a required question
    open, and template learning counted it as a decision.
    """
    if mapping_status == _SUGGESTED_MAPPING_STATUS:
        return False
    if status in _ANSWER_STATUSES:
        return True
    if status != UNANSWERED_STATUS:
        return False
    return evidence_source is not None or decided_by is not None


def ensure_slot_instances(db: Session, *, service: BusinessService) -> list[SlotInstance]:
    """Create a row for every canonical slot this service's template defines.

    Idempotent, and safe to call on every read path: a slot that already has a
    row — decided, suggested or untouched — is left exactly as it is. Returns
    only the rows created, so a caller can tell whether anything changed.

    ⚠️ **Adds, never removes.** A slot dropped from a newer template version
    keeps its row and its decision; deciding what happens to an answer whose
    question has gone is a template-migration question, not this one's.

    The caller owns the transaction. Nothing here commits.
    """
    service_template = resolve_active_service_template(
        db, template_key=service.template_key, archetype=service.archetype
    )
    if service_template is None:
        return []

    slot_templates = list_slot_templates_for_service(db, service_template.id)
    if not slot_templates:
        return []

    existing_slot_ids = {
        row.slot_id
        for row in db.query(SlotInstance.slot_id).filter(
            SlotInstance.organization_id == service.organization_id,
            SlotInstance.service_id == service.id,
        )
    }

    created: list[SlotInstance] = []
    for slot_template in slot_templates:
        if slot_template.slot_id in existing_slot_ids:
            continue

        row = SlotInstance(
            organization_id=service.organization_id,
            service_id=service.id,
            slot_id=slot_template.slot_id,
            group_key=slot_template.capability_group_key,
            dependency_category=(
                slot_template.dependency_category
                or dependency_category_for_group(slot_template.capability_group_key)
            ),
            template_version=service_template.version,
            status=UNANSWERED_STATUS,
            asset_id=None,
            asset_label=None,
            mapping_status=UNANSWERED_MAPPING_STATUS,
            mapping_confidence=None,
            # Nothing observed it and nobody decided it — it exists because the
            # template says this kind of service has such a dependency.
            evidence_source=None,
            provenance=None,
            decided_by=None,
            decided_at=None,
        )
        db.add(row)
        created.append(row)

    if created:
        db.flush()

    return created
