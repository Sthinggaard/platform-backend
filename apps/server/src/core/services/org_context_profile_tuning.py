"""Org-context profile tuning (BSP-12).

Single source of truth for how an organisation's context — today its
``required_frameworks`` — tunes how Business Service Profiles apply to it.
Frameworks promote logical dependency slots to *required* where the framework
expects provable capability; they never touch Risk Appetite, BIA tolerance,
or observed evidence (contract rule: appetite stays separate from BIA).

The canonical slot templates stay global — tuning is applied at read time
wherever an organisation's slot requiredness is served, and every promoted
value carries the framework(s) and a business-worded reason as provenance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class FrameworkSlotRule:
    framework: str
    slot_ids: frozenset[str]
    reason: str


FRAMEWORK_SLOT_RULES: tuple[FrameworkSlotRule, ...] = (
    FrameworkSlotRule(
        framework="NIS2",
        slot_ids=frozenset({"monitoring_service", "audit_logging"}),
        reason="NIS2 expects provable disruption detection and incident evidence for essential services.",
    ),
    FrameworkSlotRule(
        framework="GDPR",
        slot_ids=frozenset({"audit_logging", "backup_recovery"}),
        reason="GDPR expects provable data-processing accountability and the ability to restore personal data.",
    ),
    FrameworkSlotRule(
        framework="DORA",
        slot_ids=frozenset({"monitoring_service", "backup_recovery", "audit_logging"}),
        reason="DORA expects tested operational resilience: disruption detection, recoverability, and audit evidence.",
    ),
    FrameworkSlotRule(
        framework="PCI-DSS",
        slot_ids=frozenset({"monitoring_service", "audit_logging", "identity_provider"}),
        reason="PCI-DSS expects controlled access and monitored, auditable handling of cardholder data.",
    ),
)


@dataclass(frozen=True)
class SlotRequirednessOverride:
    """Provenance for one promoted slot: which frameworks demand it and why."""

    frameworks: tuple[str, ...]
    reason: str


def _normalize_framework(value: str) -> str:
    """Tolerant framework matching: 'PCI-DSS' == 'pci_dss' == 'PCI DSS'."""
    return re.sub(r"[^A-Z0-9]", "", value.upper())


def slot_requiredness_overrides(
    required_frameworks: list[str] | None,
) -> dict[str, SlotRequirednessOverride]:
    """Slots promoted to required by the org's frameworks, with provenance."""
    active = {_normalize_framework(f) for f in (required_frameworks or []) if f}
    if not active:
        return {}

    frameworks_by_slot: dict[str, list[FrameworkSlotRule]] = {}
    for rule in FRAMEWORK_SLOT_RULES:
        if _normalize_framework(rule.framework) not in active:
            continue
        for slot_id in rule.slot_ids:
            frameworks_by_slot.setdefault(slot_id, []).append(rule)

    return {
        slot_id: SlotRequirednessOverride(
            frameworks=tuple(rule.framework for rule in rules),
            reason=" ".join(rule.reason for rule in rules),
        )
        for slot_id, rules in frameworks_by_slot.items()
    }


def group_requiredness_overrides(
    slot_rows, slot_overrides: dict[str, SlotRequirednessOverride]
) -> dict[str, SlotRequirednessOverride]:
    """Roll slot promotions up to their capability groups (any promoted slot promotes the group)."""
    by_group: dict[str, list[SlotRequirednessOverride]] = {}
    for row in slot_rows:
        override = slot_overrides.get(row.slot_id)
        if override is not None:
            by_group.setdefault(row.capability_group_key, []).append(override)

    merged: dict[str, SlotRequirednessOverride] = {}
    for group_key, overrides in by_group.items():
        frameworks: list[str] = []
        reasons: list[str] = []
        for override in overrides:
            for framework in override.frameworks:
                if framework not in frameworks:
                    frameworks.append(framework)
            if override.reason not in reasons:
                reasons.append(override.reason)
        merged[group_key] = SlotRequirednessOverride(
            frameworks=tuple(frameworks), reason=" ".join(reasons)
        )
    return merged
