"""Seed and lookup helpers for the persisted template library."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.business_service_profiles import (
    BUSINESS_SERVICE_PROFILES,
    BusinessServiceProfile,
)
from src.core.constants.dependency_category_enums import dependency_category_for_group
from src.core.constants.dependency_templates import (
    ARCHETYPE_PATTERN_EXPECTATIONS,
    CANONICAL_PATTERN_EXPECTED_ASSET_TYPES,
    CANONICAL_PATTERN_NAMES,
    CANONICAL_PATTERN_PURPOSES,
    PATTERN_GROUP_BY_KEY,
    get_template,
)
from src.core.constants.service_key_archetypes import SERVICE_KEY_ARCHETYPES, get_service_key_name
from src.core.constants.value_stream_library import VALUE_STREAM_LIBRARY
from src.core.models import ProcessTemplate, ServiceTemplate, SlotTemplate

INITIAL_TEMPLATE_VERSION = 1
PUBLISHED_TEMPLATE_STATUS = "published"
TOP_5_SLOT_LIBRARY_ARCHETYPES = frozenset(
    {
        "transactional_system",
        "customer_channel",
        "identity_access",
        "data_store",
        "processing_engine",
    }
)

_FAMILY_LABELS: dict[str, str] = {
    "universal": "Universal Processes",
    "customer_revenue": "Customer & Revenue",
    "supply_chain": "Supply Chain",
    "finance_compliance": "Finance & Compliance",
    "industry_specific": "Industry Specific",
}


def _new_id() -> str:
    return str(uuid.uuid4())


def _build_capability_groups(archetype: str) -> list[dict[str, object]]:
    """The questions a new service template is seeded with.

    The same rule `get_template` applies: a question only where one of the
    archetype's slots can answer it, required only where one of those slots is.
    Until 2026-09-13 this stored `ARCHETYPE_TEMPLATES` raw, which is how `teams`
    reached all 60 templates with no slot behind it.
    """
    return [
        {
            "key": group["key"],
            "label": group["label"],
            "question": group["question"],
            "description": group["description"],
            "required": group["required"],
        }
        for group in (get_template(archetype) or [])
    ]


def _build_service_slot_entry(service_key: str) -> dict[str, object]:
    return {
        "service_key": service_key,
        "service_name": get_service_key_name(service_key),
        "archetype": SERVICE_KEY_ARCHETYPES.get(service_key),
    }


def _apply_profile_to_service(
    service_template: ServiceTemplate, profile: BusinessServiceProfile
) -> None:
    """Copy the internal Business Service Profile onto the persisted template."""
    service_template.capability_statement = profile.capability_statement
    service_template.default_impact_model = dict(profile.default_impact_model)
    service_template.operational_expectations = list(profile.operational_expectations)
    service_template.common_risk_patterns = list(profile.common_risk_patterns)
    service_template.override_policy = dict(profile.override_policy)


def _enrich_slot_row(slot_row: SlotTemplate, profile: BusinessServiceProfile | None) -> None:
    if not profile:
        return
    enrichment = next(
        (entry for entry in profile.slot_enrichments if entry.pattern_key == slot_row.slot_id),
        None,
    )
    if not enrichment:
        return
    if enrichment.label_override:
        slot_row.label = enrichment.label_override
    if enrichment.required_override is not None:
        slot_row.required = enrichment.required_override
    slot_row.matching_hints = list(enrichment.matching_hints)
    slot_row.expected_evidence_types = list(enrichment.expected_evidence_types)
    slot_row.risk_patterns = list(enrichment.risk_patterns)


def _build_slot_rows(service_template: ServiceTemplate) -> list[SlotTemplate]:
    expectations = ARCHETYPE_PATTERN_EXPECTATIONS.get(
        service_template.archetype, {"required": [], "optional": []}
    )
    ordered_slot_ids = list(
        dict.fromkeys(expectations.get("required", []) + expectations.get("optional", []))
    )
    required_ids = set(expectations.get("required", []))

    profile = BUSINESS_SERVICE_PROFILES.get(service_template.service_key)
    slot_rows: list[SlotTemplate] = []
    for display_order, slot_id in enumerate(ordered_slot_ids):
        slot_rows.append(
            SlotTemplate(
                id=_new_id(),
                service_template_id=service_template.id,
                slot_id=slot_id,
                label=CANONICAL_PATTERN_NAMES.get(slot_id, slot_id.replace("_", " ").title()),
                purpose=CANONICAL_PATTERN_PURPOSES.get(
                    slot_id,
                    f"Identify what fulfills the {slot_id.replace('_', ' ')} capability.",
                ),
                expected_asset_types=list(CANONICAL_PATTERN_EXPECTED_ASSET_TYPES.get(slot_id, [])),
                required=slot_id in required_ids,
                capability_group_key=PATTERN_GROUP_BY_KEY.get(slot_id, "systems"),
                dependency_category=dependency_category_for_group(
                    PATTERN_GROUP_BY_KEY.get(slot_id, "systems")
                ),
                display_order=display_order,
            )
        )
    for slot_row in slot_rows:
        _enrich_slot_row(slot_row, profile)
    return slot_rows


def ensure_template_library_seeded(db: Session) -> None:
    """Materialise the canonical template library if the persisted tables are empty."""

    existing_process_keys = {
        (row.template_key, row.version) for row in db.query(ProcessTemplate).all()
    }
    existing_service_keys = {
        (row.service_key, row.version) for row in db.query(ServiceTemplate).all()
    }
    existing_slot_keys = {
        (row.service_template_id, row.slot_id) for row in db.query(SlotTemplate).all()
    }

    for item in VALUE_STREAM_LIBRARY:
        process_key = (item.key, INITIAL_TEMPLATE_VERSION)
        if process_key in existing_process_keys:
            continue
        db.add(
            ProcessTemplate(
                id=_new_id(),
                template_key=item.key,
                name=item.name,
                description=item.description,
                process_family=item.process_family,
                version=INITIAL_TEMPLATE_VERSION,
                status=PUBLISHED_TEMPLATE_STATUS,
                is_active=True,
                service_slots=[
                    _build_service_slot_entry(service_key) for service_key in item.core_service_keys
                ],
            )
        )

    for service_key, archetype in SERVICE_KEY_ARCHETYPES.items():
        template_key = (service_key, INITIAL_TEMPLATE_VERSION)
        if template_key in existing_service_keys:
            continue
        service_template = ServiceTemplate(
            id=_new_id(),
            service_key=service_key,
            service_name=get_service_key_name(service_key),
            archetype=archetype,
            version=INITIAL_TEMPLATE_VERSION,
            status=PUBLISHED_TEMPLATE_STATUS,
            is_active=True,
            capability_groups=_build_capability_groups(archetype),
            seeded_from=archetype,
        )
        profile = BUSINESS_SERVICE_PROFILES.get(service_key)
        if profile:
            _apply_profile_to_service(service_template, profile)
        db.add(service_template)

    db.flush()

    for service_template in db.query(ServiceTemplate).all():
        if service_template.version != INITIAL_TEMPLATE_VERSION:
            continue

        profile = BUSINESS_SERVICE_PROFILES.get(service_template.service_key)
        if profile and not service_template.capability_statement:
            _apply_profile_to_service(service_template, profile)
            for existing_slot in db.query(SlotTemplate).filter(
                SlotTemplate.service_template_id == service_template.id
            ):
                _enrich_slot_row(existing_slot, profile)

        for slot_row in _build_slot_rows(service_template):
            slot_key = (slot_row.service_template_id, slot_row.slot_id)
            if slot_key in existing_slot_keys:
                continue
            db.add(slot_row)
            existing_slot_keys.add(slot_key)

    db.commit()


def list_active_process_templates(db: Session) -> list[ProcessTemplate]:
    ensure_template_library_seeded(db)
    return (
        db.query(ProcessTemplate)
        .filter(ProcessTemplate.is_active.is_(True))
        .order_by(ProcessTemplate.process_family.asc(), ProcessTemplate.name.asc())
        .all()
    )


@dataclass(frozen=True)
class ProcessTemplateGroup:
    """Active process templates of one family, in the order the library shows them."""

    family: str
    family_label: str
    templates: list[ProcessTemplate]


def list_process_template_groups(db: Session) -> list[ProcessTemplateGroup]:
    groups: dict[str, list[ProcessTemplate]] = {}
    for template in list_active_process_templates(db):
        groups.setdefault(template.process_family, []).append(template)

    family_order = list(_FAMILY_LABELS.keys())
    return [
        ProcessTemplateGroup(
            family=family,
            family_label=_FAMILY_LABELS.get(family, family.replace("_", " ").title()),
            templates=templates,
        )
        for family, templates in sorted(
            groups.items(),
            key=lambda pair: family_order.index(pair[0]) if pair[0] in family_order else 99,
        )
    ]


def get_active_service_template(db: Session, service_key: str) -> ServiceTemplate | None:
    ensure_template_library_seeded(db)
    return (
        db.query(ServiceTemplate)
        .filter(
            ServiceTemplate.service_key == service_key,
            ServiceTemplate.is_active.is_(True),
        )
        .order_by(ServiceTemplate.version.desc())
        .first()
    )


def list_active_service_templates(db: Session) -> list[ServiceTemplate]:
    """All active service templates — one per service key (highest version)."""
    ensure_template_library_seeded(db)
    rows = (
        db.query(ServiceTemplate)
        .filter(ServiceTemplate.is_active.is_(True))
        .order_by(ServiceTemplate.service_key.asc(), ServiceTemplate.version.desc())
        .all()
    )
    latest_by_key: dict[str, ServiceTemplate] = {}
    for row in rows:
        latest_by_key.setdefault(row.service_key, row)
    return list(latest_by_key.values())


def get_active_service_template_by_archetype(db: Session, archetype: str) -> ServiceTemplate | None:
    ensure_template_library_seeded(db)
    return (
        db.query(ServiceTemplate)
        .filter(
            ServiceTemplate.archetype == archetype,
            ServiceTemplate.is_active.is_(True),
        )
        .order_by(ServiceTemplate.version.desc(), ServiceTemplate.service_key.asc())
        .first()
    )


def list_slot_templates_for_service(db: Session, service_template_id: str) -> list[SlotTemplate]:
    return (
        db.query(SlotTemplate)
        .filter(SlotTemplate.service_template_id == service_template_id)
        .order_by(SlotTemplate.display_order.asc())
        .all()
    )


def resolve_active_service_template(
    db: Session,
    *,
    template_key: str | None,
    archetype: str | None,
) -> ServiceTemplate | None:
    """Resolve the active template for a service instance.

    Prefer the persisted template key so upgrades stay within the service's
    own template family; fall back to archetype only for older rows that do
    not yet carry a template key.
    """
    if template_key:
        template = get_active_service_template(db, template_key)
        if template is not None:
            return template

    if archetype:
        return get_active_service_template_by_archetype(db, archetype)

    return None
