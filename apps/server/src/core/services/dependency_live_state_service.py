"""#460 — a service's live dependency state, composed from its slot records.

Until #460 an owner's dependency decision had two homes. The step slide-out wrote a slot record, the
service setup page wrote a bundle node, and the map read only nodes, so an answer given in the
slide-out did not count (#452). Søren, 2026-09-15: **the slot record is the one live record**, and
bundle nodes are the published snapshot.

This module is the one place that turns slot records into the node shape every existing reader
understands: the bundle response, validation, publish and the process workspace projection. So
those readers move to slot records without each learning a new shape. It is pure: nothing here
queries or writes, and the caller passes what it read.

**Which slot records are dependencies**

- **A person's decision, or an answer:** answered (`is_answered_slot`), or holding any resilience
  answer. An engine suggestion is not, so it never reads as a decision.
- **Not `not_applicable`:** that is a dependency the owner removed. A group whose every record is
  `not_applicable` is rejected.
- **Not `teams`:** #434 ruled the accountable team is not a dependency question. Søren, 2026-09-15:
  those rows are kept, but not shown or counted.

**Orphaned decisions** (Søren, 2026-09-15). A record whose `slot_id` has left the service's active
template stays live and is flagged `template_orphaned`, so a reader can say *"this question is no
longer in the service's template — review"*. Folding them into current slots is #472.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from src.core.services.asset_context_service import normalise_asset_reference
from src.core.services.slot_provisioning_service import is_answered_slot

#: The group, and the slot id it was stored under, that #434 took out of dependency mapping.
TEAMS_KEY = "teams"

#: `source` on a node composed from a slot record, so a reader can tell it from a snapshot node.
SLOT_RECORD_NODE_SOURCE = "slot_record"

NOT_APPLICABLE_STATUS = "not_applicable"
MAPPED_STATUS = "mapped"
UNKNOWN_STATUS = "unknown"
NEEDS_REVIEW_MAPPING_STATUS = "needs_review"

#: The resilience answers a slot record carries (migration `20260915_slot_assessment`).
ASSESSMENT_FIELDS: tuple[str, ...] = (
    "spof",
    "fallback_status",
    "recovery_dependent",
    "impact_type",
    "business_impact_level",
    "business_consequence",
    "critical_for_business",
)

#: Group metadata carried from the bundle onto a composed group.
_GROUP_METADATA_FIELDS: tuple[str, ...] = ("key", "label", "question", "description", "required")


@dataclass(frozen=True)
class LiveDependencyBundle:
    """A service's dependency bundle as its live state: the stored bundle's identity and lifecycle,
    with groups composed from slot records. What the process workspace projection reads."""

    id: str | None
    service_id: str
    lifecycle_state: str | None
    groups: list[dict[str, Any]]


class SlotRecord(Protocol):
    """What the composer reads from a `SlotInstance`. A protocol so tests need no database."""

    id: str
    slot_id: str
    group_key: str | None
    status: str
    asset_id: str | None
    asset_label: str | None
    mapping_status: str | None
    mapping_confidence: float | None
    evidence_source: str | None
    decided_by: str | None


def is_dependency_record(record: SlotRecord) -> bool:
    """Whether a slot record is about a dependency at all. `teams` records are not (#434)."""
    return (record.group_key or "") != TEAMS_KEY and record.slot_id != TEAMS_KEY


def has_assessment(record: SlotRecord) -> bool:
    """Whether any resilience answer is recorded. `False` is an answer; only `None` is not."""
    return any(getattr(record, field, None) is not None for field in ASSESSMENT_FIELDS)


def is_live_dependency(record: SlotRecord) -> bool:
    """Whether a slot record is one of the service's dependencies right now."""
    if not is_dependency_record(record) or record.status == NOT_APPLICABLE_STATUS:
        return False
    answered = is_answered_slot(
        status=record.status,
        mapping_status=record.mapping_status,
        evidence_source=record.evidence_source,
        decided_by=record.decided_by,
    )
    return answered or has_assessment(record)


def matching_template_node(slot_id: str, template_nodes: Iterable[Any]) -> dict | None:
    """The pattern option a slot answers. Its `template_key` equals the slot id, or ends it after a dot.

    Templates namespace some slot ids (`billing_subscription_management.application.api_service`
    for the pattern `api_service`); a bare suffix is not enough (`internal_api_service` is a
    different dependency).
    """
    for option in template_nodes:
        if not isinstance(option, dict):
            continue
        key = option.get("template_key")
        if isinstance(key, str) and key and (slot_id == key or slot_id.endswith(f".{key}")):
            return option
    return None


def humanise_key(key: str) -> str:
    """A readable fallback name for a slot or group id nobody gave a label."""
    last = key.rsplit(".", 1)[-1].replace("_", " ").strip()
    return last[:1].upper() + last[1:] if last else key


def is_template_orphaned(slot_id: str, canonical_slot_ids: Iterable[str]) -> bool:
    """Whether a decision's slot has left the service's active template.

    A service with no active template has no slots to leave, so nothing on it is orphaned. Reading
    an empty template as "every slot has gone" flagged every decision on such a service for review.
    """
    canonical = frozenset(canonical_slot_ids)
    return bool(canonical) and slot_id not in canonical


def compose_live_node(
    record: SlotRecord,
    *,
    template_nodes: Iterable[Any],
    canonical_slot_ids: frozenset[str],
    slot_labels: Mapping[str, str],
) -> dict[str, Any]:
    """One slot record as a dependency node, in the shape `DependencyNodeOut` and every reader expect."""
    option = matching_template_node(record.slot_id, template_nodes) or {}
    asset = normalise_asset_reference(record.asset_id) if record.status == MAPPED_STATUS else None
    if record.mapping_status == NEEDS_REVIEW_MAPPING_STATUS:
        validation_status = "draft"
    elif record.status == MAPPED_STATUS:
        validation_status = "accepted"
    else:
        validation_status = "suggested"
    return {
        "id": record.id,
        "slot_id": record.slot_id,
        "label": slot_labels.get(record.slot_id)
        or option.get("label")
        or record.asset_label
        or humanise_key(record.slot_id),
        "linked_asset_ids": [asset] if asset else [],
        "source": SLOT_RECORD_NODE_SOURCE,
        "validation_status": validation_status,
        "confidence": record.mapping_confidence,
        "template_key": option.get("template_key"),
        "pattern_key": option.get("pattern_key"),
        **{field: getattr(record, field, None) for field in ASSESSMENT_FIELDS},
        "deferred_asset_mapping": record.status == UNKNOWN_STATUS,
        "template_orphaned": is_template_orphaned(record.slot_id, canonical_slot_ids),
    }


def compose_live_groups(
    bundle_groups: Iterable[Any] | None,
    slot_records: Iterable[SlotRecord],
    *,
    canonical_slot_ids: Iterable[str],
    slot_labels: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """A service's live dependency groups: metadata from the bundle, nodes from slot records.

    `bundle_groups` gives each group's label, question, required flag and pattern options, and is
    read for nothing else. Its stored nodes are the published snapshot, never live state.
    `canonical_slot_ids` are the active template's slot ids, and `slot_labels` their names.
    A slot record in a group the bundle does not know still counts, under a generated group.
    """
    canonical = frozenset(canonical_slot_ids)
    labels = slot_labels or {}
    groups: list[dict[str, Any]] = []
    by_key: dict[str, dict[str, Any]] = {}

    for raw in bundle_groups or []:
        if not isinstance(raw, dict):
            continue
        key = raw.get("key") or ""
        if key == TEAMS_KEY or key in by_key:
            continue
        group = {field: raw.get(field) for field in _GROUP_METADATA_FIELDS}
        group["key"] = key
        group["label"] = raw.get("label") or humanise_key(key)
        group["question"] = raw.get("question") or ""
        group["description"] = raw.get("description") or ""
        group["required"] = bool(raw.get("required", False))
        group["template_nodes"] = [
            option for option in (raw.get("template_nodes") or []) if isinstance(option, dict)
        ]
        group["nodes"] = []
        group["rejected"] = None
        groups.append(group)
        by_key[key] = group

    records_by_group: dict[str, list[SlotRecord]] = {}
    for record in sorted(slot_records, key=lambda row: row.slot_id):
        if is_dependency_record(record):
            records_by_group.setdefault(record.group_key or "", []).append(record)

    for key, records in records_by_group.items():
        group = by_key.get(key)
        if group is None:
            group = {
                "key": key,
                "label": humanise_key(key),
                "question": "",
                "description": "",
                "required": False,
                "template_nodes": [],
                "nodes": [],
                "rejected": None,
            }
            groups.append(group)
            by_key[key] = group
        group["nodes"] = [
            compose_live_node(
                record,
                template_nodes=group["template_nodes"],
                canonical_slot_ids=canonical,
                slot_labels=labels,
            )
            for record in records
            if is_live_dependency(record)
        ]
        if all(record.status == NOT_APPLICABLE_STATUS for record in records):
            group["rejected"] = True

    return groups
