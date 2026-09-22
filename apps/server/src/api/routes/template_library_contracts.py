from __future__ import annotations

from pydantic import BaseModel


class ServiceSlotResponse(BaseModel):
    slot_id: str
    dependency_category: str | None = None
    label: str
    required: bool
    # BSP-12 — org-context provenance when frameworks promote the slot to required.
    required_by_frameworks: list[str] = []
    required_reason: str | None = None
    matching_hints: list[str] = []
    expected_evidence_types: list[str] = []
    risk_patterns: list[str] = []


class CapabilityGroupResponse(BaseModel):
    key: str
    dependency_category: str | None = None
    label: str
    question: str
    description: str
    required: bool
    expected_asset_types: list[str] = []
    # BSP-12 — org-context provenance when frameworks promote the group to required.
    required_by_frameworks: list[str] = []
    required_reason: str | None = None


class ServiceTemplateResponse(BaseModel):
    service_key: str
    service_name: str
    archetype: str | None
    template_version: int
    capability_statement: str | None = None
    default_impact_model: dict | None = None
    operational_expectations: list[str] = []
    common_risk_patterns: list[str] = []
    capability_groups: list[CapabilityGroupResponse]
    required_slots: list[ServiceSlotResponse]
    optional_slots: list[ServiceSlotResponse]


class ArchetypeTemplateResponse(BaseModel):
    archetype: str
    template_version: int
    capability_groups: list[CapabilityGroupResponse]
    required_slots: list[ServiceSlotResponse]
    optional_slots: list[ServiceSlotResponse]


class ProcessServiceSlotResponse(BaseModel):
    service_key: str
    service_name: str
    archetype: str | None


class ProcessTemplateResponse(BaseModel):
    key: str
    name: str
    description: str
    process_family: str
    template_version: int
    service_slots: list[ProcessServiceSlotResponse]


class ProcessTemplateGroupResponse(BaseModel):
    family: str
    family_label: str
    templates: list[ProcessTemplateResponse]


class ProcessTemplatesResponse(BaseModel):
    groups: list[ProcessTemplateGroupResponse]
