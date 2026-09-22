"""#460 — the one write path for a dependency decision.

An owner's decision about one dependency used to be written in two places. The step slide-out wrote
a slot record through `decide`. The service setup page and the service journey wrote a bundle node
through `PATCH /bundle`. The map read only nodes, so the two disagreed (#452). Søren, 2026-09-15:
**the slot record is the one live record**. Every route that records a dependency decision now
comes through here, and nothing but publish writes bundle nodes.

What lives here:
- `upsert_slot_decision`: the mapping decision (mapped, not applicable, unknown), moved from
  `bundle_slot_mapping_routes._upsert_slot_instance`, which remains as an alias.
- `record_assessment`: the resilience answers, validated against
  `core/constants/dependency_assessment_enums.py`.
- `load_service_slot_context` and `live_groups`: what a service's live dependency state is read from.
- `find_record_for_node`: the adapter from a page node to its slot record.

Nothing here commits; the caller owns the transaction.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from src.core.constants.dependency_assessment_enums import (
    IMPACT_TYPE_BY_BUSINESS_CHOICE,
    DependencyBusinessChoice,
    DependencyImpactLevel,
    FallbackStatus,
)
from src.core.constants.dependency_category_enums import dependency_category_for_group
from src.core.models import BusinessService, SlotInstance
from src.core.services.dependency_live_state_service import (
    compose_live_groups,
    is_dependency_record,
    is_template_orphaned,
    matching_template_node,
)
from src.core.services.template_library_service import (
    list_slot_templates_for_service,
    resolve_active_service_template,
)

#: Mapping decisions that are a person's final answer.
_RESOLVED_STATUSES = frozenset({"mapped", "not_applicable"})


class DependencyDecisionError(ValueError):
    """A decision that cannot be recorded, said in words the reader can act on."""


@dataclass(frozen=True)
class ServiceSlotContext:
    """Everything a service's live dependency state is composed from, read once."""

    records: list[SlotInstance]
    canonical_slot_ids: frozenset[str]
    slot_labels: dict[str, str]
    template_version: int | None

    def orphaned_records(self) -> list[SlotInstance]:
        """Dependency records whose `slot_id` has left the active template (Søren, 2026-09-15)."""
        return [
            record
            for record in self.records
            if is_dependency_record(record)
            and is_template_orphaned(record.slot_id, self.canonical_slot_ids)
        ]


def load_service_slot_context(db: Session, service: BusinessService) -> ServiceSlotContext:
    """Read a service's slot records and its active template's slots, tenant-scoped."""
    template = resolve_active_service_template(
        db, template_key=service.template_key, archetype=service.archetype
    )
    slot_templates = list_slot_templates_for_service(db, template.id) if template else []
    records = (
        db.query(SlotInstance)
        .filter(
            SlotInstance.organization_id == service.organization_id,
            SlotInstance.service_id == service.id,
        )
        .order_by(SlotInstance.slot_id.asc())
        .all()
    )
    return ServiceSlotContext(
        records=records,
        canonical_slot_ids=frozenset(slot.slot_id for slot in slot_templates),
        slot_labels={slot.slot_id: slot.label for slot in slot_templates},
        template_version=template.version if template else None,
    )


def live_groups(bundle_groups: Iterable[Any] | None, context: ServiceSlotContext) -> list[dict]:
    """The service's live dependency groups. `bundle_groups` supplies group metadata only."""
    return compose_live_groups(
        bundle_groups,
        context.records,
        canonical_slot_ids=context.canonical_slot_ids,
        slot_labels=context.slot_labels,
    )


def upsert_slot_decision(
    db: Session,
    *,
    org_id: int,
    service_id: str,
    slot_id: str,
    group_key: str,
    status: str,
    asset_id: str | None,
    asset_label: str | None,
    template_version: int | None,
    decided_by: str | None = None,
) -> SlotInstance:
    """Create or update the slot record for this org, service and slot.

    A person's path, so a resolved slot (mapped or not applicable) is recorded as owner-approved
    with full confidence. An "unknown" answer leaves the mapping in `needs_review`, with no invented
    confidence: confidence is about verification.
    """
    resolved = status in _RESOLVED_STATUSES
    lifecycle = {
        "mapping_status": "approved" if resolved else "needs_review",
        "mapping_confidence": 1.0 if resolved else None,
        "evidence_source": "manual",
        "provenance": "owner_approved" if resolved else None,
        "decided_by": decided_by,
        "decided_at": datetime.now(timezone.utc) if resolved else None,
    }
    existing: SlotInstance | None = (
        db.query(SlotInstance)
        .filter(
            SlotInstance.organization_id == org_id,
            SlotInstance.service_id == service_id,
            SlotInstance.slot_id == slot_id,
        )
        .first()
    )
    if existing is not None:
        existing.status = status
        existing.asset_id = asset_id
        existing.asset_label = asset_label
        existing.group_key = group_key
        existing.dependency_category = (
            existing.dependency_category or dependency_category_for_group(group_key)
        )
        existing.template_version = template_version
        for field, value in lifecycle.items():
            setattr(existing, field, value)
        db.add(existing)
        return existing
    record = SlotInstance(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        service_id=service_id,
        slot_id=slot_id,
        group_key=group_key,
        dependency_category=dependency_category_for_group(group_key),
        status=status,
        asset_id=asset_id,
        asset_label=asset_label,
        template_version=template_version,
        **lifecycle,
    )
    db.add(record)
    return record


def find_record_for_node(
    context: ServiceSlotContext,
    *,
    group_key: str,
    node_id: str | None,
    template_key: str | None = None,
    stored_groups: Iterable[Any] | None = None,
) -> SlotInstance | None:
    """The slot record a page node stands for.

    A live node's id is its slot record's id. A node id from before #460 (a page opened on a stored
    bundle node) is resolved through that node's `template_key`, matched within the same group. A
    `template_key` alone (adding a pattern) resolves the same way. Returns `None` rather than guessing.
    """
    in_group = [record for record in context.records if (record.group_key or "") == group_key]
    if node_id:
        for record in in_group:
            if record.id == node_id:
                return record
        for group in stored_groups or []:
            if isinstance(group, dict) and group.get("key") == group_key:
                for node in group.get("nodes") or []:
                    if isinstance(node, dict) and node.get("id") == node_id:
                        template_key = template_key or node.get("template_key")
    if not template_key:
        return None
    matches = [
        record
        for record in in_group
        if matching_template_node(record.slot_id, [{"template_key": template_key}])
    ]
    # The active template's slot wins over an orphaned record for the same pattern.
    matches.sort(key=lambda record: record.slot_id not in context.canonical_slot_ids)
    return matches[0] if matches else None


def record_assessment(record: SlotInstance, **answers: Any) -> dict[str, Any]:
    """Record resilience answers on a slot record, validated. Returns the fields as they were before.

    Accepted keywords: `spof` (bool), `fallback_status` (`FallbackStatus`), `recovery_dependent`
    (bool), `business_choice` (`DependencyBusinessChoice`, which also sets `critical_for_business`,
    `impact_type` and `business_consequence`) and `business_impact_level` (`DependencyImpactLevel`).
    """
    updates: dict[str, Any] = {}
    if "spof" in answers:
        if not isinstance(answers["spof"], bool):
            raise DependencyDecisionError("payload.spof must be true or false.")
        updates["spof"] = answers["spof"]
    if "fallback_status" in answers:
        value = answers["fallback_status"]
        if value not in {status.value for status in FallbackStatus}:
            raise DependencyDecisionError(
                "payload.fallback_status must be one of: "
                + ", ".join(f"'{status.value}'" for status in FallbackStatus)
                + "."
            )
        updates["fallback_status"] = value
    if "recovery_dependent" in answers:
        updates["recovery_dependent"] = bool(answers["recovery_dependent"])
    if "business_choice" in answers:
        choice = answers["business_choice"]
        try:
            business_choice = DependencyBusinessChoice(str(choice))
        except ValueError as exc:
            raise DependencyDecisionError(
                "payload.business_choice must be one of: "
                + ", ".join(f"'{option.value}'" for option in DependencyBusinessChoice)
                + "."
            ) from exc
        updates["critical_for_business"] = True
        updates["impact_type"] = IMPACT_TYPE_BY_BUSINESS_CHOICE[business_choice].value
        updates["business_consequence"] = business_choice.value
    if "business_impact_level" in answers:
        level = answers["business_impact_level"]
        if level not in {option.value for option in DependencyImpactLevel}:
            raise DependencyDecisionError(
                "payload.business_impact_level must be one of: "
                + ", ".join(f"'{option.value}'" for option in DependencyImpactLevel)
                + "."
            )
        updates["business_impact_level"] = level
    before = {field: getattr(record, field, None) for field in updates}
    for field, value in updates.items():
        setattr(record, field, value)
    return before
