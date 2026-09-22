"""Template Library API backed by persisted, versioned template definitions."""

from __future__ import annotations

from collections.abc import Iterable

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.dependency_category_enums import dependency_category_for_group
from src.core.database import get_db
from src.core.models import Organization, OrgServiceConfig, SlotTemplate
from src.core.services.capability_question_service import resolve_capability_questions
from src.core.services.org_context_profile_tuning import (
    group_requiredness_overrides,
    slot_requiredness_overrides,
)
from src.core.services.template_library_service import (
    get_active_service_template,
    get_active_service_template_by_archetype,
    list_process_template_groups,
    list_slot_templates_for_service,
)

from .template_library_contracts import (
    ArchetypeTemplateResponse,
    CapabilityGroupResponse,
    ProcessServiceSlotResponse,
    ProcessTemplateGroupResponse,
    ProcessTemplateResponse,
    ProcessTemplatesResponse,
    ServiceSlotResponse,
    ServiceTemplateResponse,
)

router = APIRouter(prefix="/api/v1/template-library", tags=["Template Library"])


def _map_capability_groups(
    raw_groups: list[dict],
    slot_types_by_group: dict[str, list[str]] | None = None,
    group_overrides: dict | None = None,
) -> list[CapabilityGroupResponse]:
    overrides = group_overrides or {}
    responses: list[CapabilityGroupResponse] = []
    for group in raw_groups:
        override = overrides.get(group["key"])
        responses.append(
            CapabilityGroupResponse(
                key=group["key"],
                dependency_category=dependency_category_for_group(group["key"]),
                label=group["label"],
                question=group["question"],
                description=group["description"],
                required=bool(group["required"]) or override is not None,
                expected_asset_types=(slot_types_by_group or {}).get(group["key"], []),
                required_by_frameworks=list(override.frameworks) if override else [],
                required_reason=override.reason if override else None,
            )
        )
    return responses


def _slot_types_by_group(slot_rows: Iterable[SlotTemplate]) -> dict[str, list[str]]:
    """Aggregate expected_asset_types from slot templates, keyed by capability_group_key."""
    result: dict[str, list[str]] = {}
    for row in slot_rows:
        group_key = row.capability_group_key
        existing = result.setdefault(group_key, [])
        for t in row.expected_asset_types or []:
            if t not in existing:
                existing.append(t)
    return result


def _map_service_slots(raw_slots: list[dict]) -> list[ProcessServiceSlotResponse]:
    return [
        ProcessServiceSlotResponse(
            service_key=slot["service_key"],
            service_name=slot["service_name"],
            archetype=slot.get("archetype"),
        )
        for slot in raw_slots
    ]


def _apply_org_service_config(
    raw_groups: list[dict],
    org_config: OrgServiceConfig | None,
) -> list[dict]:
    """Filter excluded groups and append custom groups from org config."""
    if org_config is None:
        return raw_groups
    excluded = set(org_config.excluded_group_keys or [])
    filtered = [g for g in raw_groups if g.get("key") not in excluded]
    for custom in org_config.custom_groups or []:
        filtered.append(custom)
    return filtered


def _split_slots(
    slot_rows: Iterable[SlotTemplate], slot_overrides: dict | None = None
) -> tuple[list[ServiceSlotResponse], list[ServiceSlotResponse]]:
    overrides = slot_overrides or {}
    required_slots: list[ServiceSlotResponse] = []
    optional_slots: list[ServiceSlotResponse] = []
    for row in slot_rows:
        override = overrides.get(row.slot_id)
        required = bool(row.required) or override is not None
        slot = ServiceSlotResponse(
            slot_id=row.slot_id,
            dependency_category=(
                row.dependency_category
                or dependency_category_for_group(row.capability_group_key)
            ),
            label=row.label,
            required=required,
            matching_hints=list(getattr(row, "matching_hints", None) or []),
            expected_evidence_types=list(getattr(row, "expected_evidence_types", None) or []),
            risk_patterns=list(getattr(row, "risk_patterns", None) or []),
            required_by_frameworks=list(override.frameworks) if override else [],
            required_reason=override.reason if override else None,
        )
        if required:
            required_slots.append(slot)
        else:
            optional_slots.append(slot)
    return required_slots, optional_slots


def _org_slot_overrides(db: Session, organization_id: int) -> dict:
    """Framework-driven slot promotions for the requesting organisation (BSP-12)."""
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    return slot_requiredness_overrides(list(org.required_frameworks or []) if org else [])


@router.get("/processes", response_model=ProcessTemplatesResponse)
def list_process_templates(
    _ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessTemplatesResponse:
    """Return active process templates grouped by process family."""
    return ProcessTemplatesResponse(
        groups=[
            ProcessTemplateGroupResponse(
                family=group.family,
                family_label=group.family_label,
                templates=[
                    ProcessTemplateResponse(
                        key=template.template_key,
                        name=template.name,
                        description=template.description,
                        process_family=template.process_family,
                        template_version=template.version,
                        service_slots=_map_service_slots(template.service_slots or []),
                    )
                    for template in group.templates
                ],
            )
            for group in list_process_template_groups(db)
        ]
    )


@router.get("/services/{service_key}", response_model=ServiceTemplateResponse)
def get_service_template(
    service_key: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ServiceTemplateResponse:
    service_template = get_active_service_template(db, service_key)
    if service_template is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown service key: {service_key}",
        )
    slot_rows = list_slot_templates_for_service(db, service_template.id)
    slot_overrides = _org_slot_overrides(db, ctx.organization_id)
    required_slots, optional_slots = _split_slots(slot_rows, slot_overrides)

    org_config: OrgServiceConfig | None = (
        db.query(OrgServiceConfig)
        .filter(
            OrgServiceConfig.organization_id == ctx.organization_id,
            OrgServiceConfig.service_key == service_key,
        )
        .first()
    )
    questions = resolve_capability_questions(
        service_template.capability_groups or [], slot_rows, service_template.archetype
    )
    adjusted_groups = _apply_org_service_config(questions, org_config)

    return ServiceTemplateResponse(
        service_key=service_template.service_key,
        service_name=service_template.service_name,
        archetype=service_template.archetype,
        template_version=service_template.version,
        capability_statement=service_template.capability_statement,
        default_impact_model=service_template.default_impact_model,
        operational_expectations=list(service_template.operational_expectations or []),
        common_risk_patterns=list(service_template.common_risk_patterns or []),
        capability_groups=_map_capability_groups(
            adjusted_groups,
            _slot_types_by_group(slot_rows),
            group_requiredness_overrides(slot_rows, slot_overrides),
        ),
        required_slots=required_slots,
        optional_slots=optional_slots,
    )


@router.get("/archetypes/{archetype_key}", response_model=ArchetypeTemplateResponse)
def get_archetype_template(
    archetype_key: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArchetypeTemplateResponse:
    service_template = get_active_service_template_by_archetype(db, archetype_key)
    if service_template is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown archetype: {archetype_key}",
        )
    slot_rows = list_slot_templates_for_service(db, service_template.id)
    slot_overrides = _org_slot_overrides(db, ctx.organization_id)
    required_slots, optional_slots = _split_slots(slot_rows, slot_overrides)

    # Org config is keyed by service_key; use archetype_key as a fallback lookup
    # (one ServiceTemplate per archetype, so archetype_key == service_key in most cases)
    org_config: OrgServiceConfig | None = (
        db.query(OrgServiceConfig)
        .filter(
            OrgServiceConfig.organization_id == ctx.organization_id,
            OrgServiceConfig.service_key.in_([service_template.service_key, archetype_key]),
        )
        .first()
    )
    # The worklist's questions. Read through the slots, because a stored template
    # keeps whatever list it was created with — including `teams`, which no slot
    # could answer (2026-09-13).
    questions = resolve_capability_questions(
        service_template.capability_groups or [], slot_rows, service_template.archetype
    )
    adjusted_groups = _apply_org_service_config(questions, org_config)

    return ArchetypeTemplateResponse(
        archetype=archetype_key,
        template_version=service_template.version,
        capability_groups=_map_capability_groups(
            adjusted_groups,
            _slot_types_by_group(slot_rows),
            group_requiredness_overrides(slot_rows, slot_overrides),
        ),
        required_slots=required_slots,
        optional_slots=optional_slots,
    )
