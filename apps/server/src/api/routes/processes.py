"""Process health endpoints (Value Stream runtime read path).

GET  /api/v1/processes               — all processes with derived health summary
GET  /api/v1/processes/{process_id}  — process detail + member service rows
PUT  /api/v1/processes/{process_id}/services  — replace included template services for a process

Resilience score and financial exposure are derived at read time from member
BusinessService data — never persisted on the ValueStream row itself.

Every endpoint is tenant-scoped: organization_id comes from JWT via TenantContext.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.routes.services import BiaAnswers
from src.api.schemas.process_graph import BpmnDefinitionWrite, CreateProcessCustomServiceRequest
from src.api.schemas.timestamps import UtcTimestamp
from src.core.constants.dependency_templates import VALID_ARCHETYPES
from src.core.constants.process_graph_enums import ProcessGraphAuditEvent
from src.core.constants.process_tailoring_enums import (
    ProcessTailoringChangeType,
    ProcessTailoringRationaleCode,
    TailoringEvidenceState,
)
from src.core.constants.service_key_archetypes import (
    get_archetype_for_service_key,
    get_service_key_name,
)
from src.core.constants.service_model import (
    SERVICE_TIER_BUSINESS_CRITICAL,
    SERVICE_TIER_DEFAULT_FINANCIAL_EXPOSURE,
    SERVICE_TIER_MISSION_CRITICAL,
    SERVICE_TIER_STANDARD_CRITICAL,
    normalize_service_tier,
)
from src.core.constants.value_stream_library import VALUE_STREAM_BY_KEY
from src.core.database import get_db
from src.core.exceptions import AuthorizationError
from src.core.model_defs.business_process_recommendation import (
    BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION,
)
from src.core.model_defs.process_bia_assessment import BIA_ASSESSMENT_ATTESTED
from src.core.model_defs.risk_appetite_policy import (
    APPETITE_POLICY_DRAFT,
    APPETITE_POLICY_LEADERSHIP_REVIEW,
    APPETITE_SCOPE_BUSINESS_PROCESS,
    RiskAppetitePolicy,
)
from src.core.models import (
    AuditEvent,
    BusinessProcessDecisionAction,
    BusinessProcessDecisionLog,
    BusinessService,
    DependencyBundle,
    Organization,
    OrgProcessConfig,
    ServiceTemplate,
    SlotInstance,
    SlotTemplate,
    User,
    ValueStream,
)
from src.core.services.bia_inheritance_service import (
    BiaExceptions,
    bia_is_complete,
    effective_service_bia,
    service_bia_provenance,
)
from src.core.services.effective_process_bia_service import (
    EffectiveProcessBia,
    resolve_effective_process_bia_by_process,
)
from src.core.services.org_context_profile_tuning import slot_requiredness_overrides
from src.core.services.process_activation_readiness_service import (
    ProcessActivationReadiness,
    resolve_process_activation_readiness,
)
from src.core.services.process_bia_assessment_service import (
    ProcessBiaAssessmentValidationError,
    attest_process_bia_assessment,
    get_current_process_bia_assessment,
    prepare_process_bia_assessment,
    update_process_bia_assessment,
)
from src.core.services.process_graph_service import (
    ProcessGraphValidationError,
    invalidate_process_graph_activation,
    record_process_tailoring_signal,
    validate_process_graph,
)
from src.core.services.process_ownership_service import (
    ProcessOwnershipValidationError,
    can_process_edit,
    require_accepted_process_owner,
    require_process_editor,
)
from src.core.services.risk_appetite_resolution_service import (
    ResolvedProcessAppetite,
    resolve_appetite_for_processes,
    resolve_process_appetite,
)
from src.core.services.service_accountability_service import (
    ServiceAccountability,
    ServiceAccountabilitySource,
    resolve_service_accountability,
)
from src.core.services.service_appetite_reassessment_service import (
    resolve_effective_service_appetite,
)
from src.core.services.service_bia_exception_service import active_bia_exceptions, exceptions_for
from src.core.services.service_process_membership import (
    ServiceWouldBeOrphanedError,
    assert_removal_leaves_a_process,
)
from src.core.services.template_library_service import (
    get_active_service_template,
    get_active_service_template_by_archetype,
    list_slot_templates_for_service,
)
from src.core.services.user_display_service import user_display_name

router = APIRouter(prefix="/api/v1/processes", tags=["Processes"])

ProcessStatus = Literal["healthy", "attention", "critical", "incomplete"]

# ─── TIER → FINANCIAL EXPOSURE DEFAULT ───────────────────────────────────────
# Mirrors the frontend mappers.ts per-tier defaults so process-level exposure
# sums are consistent with the service-card values shown in the BIA view.

# ─── RESILIENCE SCORE DERIVATION ─────────────────────────────────────────────
# Mirrors deriveResilienceScoreFromBia() in apps/tenant/features/services/bia.ts

_SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "severe": 4}
_MTD_WEIGHT = {"le_1h": 4, "le_4h": 3, "le_24h": 2, "gt_24h": 1}
_DATA_WEIGHT = {"high": 2, "medium": 1, "low": 0}
_UNSET_PROCESS_BIA = object()


def _derive_resilience_score(bia: dict) -> int:
    severity_penalty = (
        _SEVERITY_WEIGHT.get(bia.get("impact1h", ""), 0) * 10
        + _SEVERITY_WEIGHT.get(bia.get("impact4h", ""), 0) * 6
        + _SEVERITY_WEIGHT.get(bia.get("impact24h", ""), 0) * 3
    )
    mtd_penalty = _MTD_WEIGHT.get(bia.get("mtd", ""), 0) * 8
    data_penalty = _DATA_WEIGHT.get(bia.get("dataSensitivity", ""), 0) * 6
    workaround = bia.get("workaround", "no")
    alt_channel = bia.get("alternativeChannel", "none")
    workaround_bonus = 10 if workaround == "yes" else 5 if workaround == "partial" else 0
    alt_bonus = 10 if alt_channel == "full" else 5 if alt_channel == "partial" else 0
    raw = 100 - severity_penalty - mtd_penalty - data_penalty + workaround_bonus + alt_bonus
    return max(35, min(95, round(raw)))


def _has_complete_bia(
    service: BusinessService,
    process: ValueStream | None = None,
    *,
    process_bia_answers: dict | None | object = _UNSET_PROCESS_BIA,
    bia_exceptions: BiaExceptions = (),
) -> bool:
    process_answers = (
        process.bia_answers
        if process_bia_answers is _UNSET_PROCESS_BIA and process
        else process_bia_answers
    )
    # #463 — this process's BIA with the service's exceptions in it; never the service's copies.
    return bia_is_complete(effective_service_bia(process_answers, bia_exceptions))


def _has_published_bundle(service: BusinessService, db: Session) -> bool:
    return (
        db.query(DependencyBundle)
        .filter(
            DependencyBundle.service_id == service.id,
            DependencyBundle.lifecycle_state == "bundle_published",
        )
        .first()
        is not None
    )


def _resolve_service_appetite(
    service: BusinessService, db: Session, process_appetite: ResolvedProcessAppetite | None
):
    """The appetite actually in force for this service: the process's resolved
    policy (exception -> process override -> organisation, already resolved by
    the caller — never re-resolved per service) overlaid with this service's
    own approved/pending reassessments. A pending reassessment does not make
    the service incomplete — the prior resolved value is still in force."""
    return resolve_effective_service_appetite(
        db,
        organization_id=service.organization_id,
        business_service_id=service.id,
        process_answers=process_appetite.answers if process_appetite else None,
    )


def _service_resilience(
    service: BusinessService,
    process: ValueStream | None = None,
    *,
    process_bia_answers: dict | None | object = _UNSET_PROCESS_BIA,
    bia_exceptions: BiaExceptions = (),
) -> int | None:
    process_answers = (
        process.bia_answers
        if process_bia_answers is _UNSET_PROCESS_BIA and process
        else process_bia_answers
    )
    effective = effective_service_bia(process_answers, bia_exceptions)
    if not bia_is_complete(effective):
        return None
    return _derive_resilience_score(effective)


def _service_exposure(service: BusinessService) -> int:
    tier = normalize_service_tier(service.tier) or SERVICE_TIER_STANDARD_CRITICAL
    return SERVICE_TIER_DEFAULT_FINANCIAL_EXPOSURE[tier]


def _process_status(score: int | None) -> ProcessStatus:
    if score is None:
        return "incomplete"
    if score >= 80:
        return "healthy"
    if score >= 60:
        return "attention"
    return "critical"


# ─── RESPONSE SCHEMAS ─────────────────────────────────────────────────────────


class ProcessSlotRow(BaseModel):
    slot_id: str
    label: str
    purpose: str
    required: bool
    # BSP-12 — org-context provenance when frameworks promote the slot to required.
    required_by_frameworks: list[str] = []
    status: str  # "mapped" | "not_applicable" | "unknown" | "empty"
    asset_id: str | None
    asset_label: str | None


class ProcessCapabilityGroupRow(BaseModel):
    group_key: str
    group_name: str
    slots: list[ProcessSlotRow]


class ProcessServiceRow(BaseModel):
    service_id: str
    service_name: str
    library_item_id: str | None
    tier: str
    archetype: str | None
    owner_user_id: int | None = None
    owner_name: str | None = None
    owner_email: str | None = None
    owner_title: str | None = None
    owner_source: str | None = None
    resilience_score: int | None
    financial_exposure: int
    bia_complete: bool
    bia_provenance: dict[str, str] = Field(default_factory=dict)
    bundle_complete: bool
    appetite_complete: bool
    appetite_answers: dict[str, int] | None = None
    appetite_provenance: dict[str, str] = Field(default_factory=dict)
    linked_asset_ids: list[str] = Field(default_factory=list)
    # Template structure — populated in the detail view; empty in the list view.
    capability_groups: list[ProcessCapabilityGroupRow] = Field(default_factory=list)


class ProcessHealthResponse(BaseModel):
    process_id: str
    library_item_id: str | None
    core_service_keys: list[str]
    name: str
    description: str | None = None
    priority: str
    status: ProcessStatus
    resilience_score: int | None
    financial_exposure: int | None
    service_count: int
    configured_service_count: int
    weakest_service_name: str | None
    weakest_service_score: int | None
    services: list[ProcessServiceRow]
    owner_user_id: int | None = None
    owner_name: str | None = None
    ownership_accepted: bool = False
    bia_attested: bool = False
    appetite_status: Literal["not_set", "pending_review", "active"] = "not_set"


class ProcessesListResponse(BaseModel):
    processes: list[ProcessHealthResponse]
    unassigned_services: list[ProcessServiceRow]


class ProcessDetailResponse(BaseModel):
    process_id: str
    library_item_id: str | None
    core_service_keys: list[str]
    name: str
    description: str | None = None
    priority: str
    status: ProcessStatus
    resilience_score: int | None
    financial_exposure: int | None
    service_count: int
    configured_service_count: int
    weakest_service_name: str | None
    weakest_service_score: int | None
    services: list[ProcessServiceRow]
    bpmn_definition: dict | None = None
    # Process-level BIA is exposed as a review projection. The assessment is
    # the canonical lifecycle record; effective answers describe the context
    # currently inherited by member services.
    bia_assessment: "ProcessBiaAssessmentResponse | None" = None
    bia_effective_answers: dict | None = None
    bia_effective_source: str | None = None
    # The list route has carried this since #379; the detail route never did,
    # so the process page's own map header read "appetite not configured" for
    # every process, including one with its own active policy. Same field,
    # same derivation, so both routes answer the question the same way.
    appetite_status: Literal["not_set", "pending_review", "active"] = "not_set"
    can_edit: bool = False


class ProcessBiaAssessmentResponse(BaseModel):
    id: str
    status: str
    answers: dict
    source: str
    confidence: str
    assumption_state: str
    prepared_by_user_id: int | None = None
    # UtcTimestamp, not bare datetime: these columns are `timestamp without
    # time zone`, so a bare datetime serialises with no offset and a browser
    # outside UTC reads the instant as local time — two hours out in CEST. #281.
    prepared_at: UtcTimestamp | None = None
    attested_by_user_id: int | None = None
    attested_at: UtcTimestamp | None = None
    review_at: UtcTimestamp | None = None


class UpdateProcessServicesRequest(BaseModel):
    included_service_keys: list[str]
    rationale_code: ProcessTailoringRationaleCode | None = None
    evidence_state: TailoringEvidenceState | None = None


# ─── HELPERS ─────────────────────────────────────────────────────────────────


#: How a service's accountability was reached, in the vocabulary the API already
#: uses for `owner_source`. A lookup, so the wire value and the resolution cannot
#: drift apart.
_OWNER_SOURCE_BY_ACCOUNTABILITY: dict[ServiceAccountabilitySource, str] = {
    ServiceAccountabilitySource.STATED: "delegated",
    ServiceAccountabilitySource.PROCESS_CHAIN: "process_owner",
    # A proposal awaiting an answer, not a settled owner — several processes
    # carry this service and the reader has not said which maintains it.
    ServiceAccountabilitySource.PROCESS_CHAIN_ASSUMED: "process_owner_assumed",
}


def _owner_source_for(
    resolved: ServiceAccountability | None,
    service: BusinessService,
    owner: User | None,
) -> str | None:
    """Say how this owner was arrived at, not merely that there is one.

    A delegate and a process owner are both accountable and are not the same
    answer — the reader is entitled to know which they are looking at.
    """
    if resolved is not None and resolved.holder_user_id is not None:
        return _OWNER_SOURCE_BY_ACCOUNTABILITY.get(resolved.source)
    return service.owner_source or ("platform" if owner else None)


def _build_service_row(
    service: BusinessService,
    db: Session,
    process: ValueStream | None = None,
    *,
    process_appetite: ResolvedProcessAppetite | None = None,
    effective_process_bia: EffectiveProcessBia | None = None,
    accountability: ServiceAccountability | None = None,
    bia_exceptions: BiaExceptions = (),
) -> ProcessServiceRow:
    process_bia_answers = (
        effective_process_bia.answers
        if effective_process_bia is not None
        else process.bia_answers
        if process
        else None
    )
    bia_done = _has_complete_bia(
        service, process, process_bia_answers=process_bia_answers, bia_exceptions=bia_exceptions
    )
    bundle_done = _has_published_bundle(service, db)
    appetite = _resolve_service_appetite(service, db, process_appetite)
    # `appetite.status` says "inherited" even when there is nothing to
    # inherit (no active process/org policy and no reassessment) — `answers`
    # being populated is the real "something is actually set" signal, the
    # same rule the frontend already applies to this same backend field.
    appetite_done = appetite.answers is not None and appetite.status in ("inherited", "reassessed")
    score = _service_resilience(
        service, process, process_bia_answers=process_bia_answers, bia_exceptions=bia_exceptions
    )
    # ⚠️ **Who is accountable, not who is written in the legacy column.**
    #
    # This read `service.owner_user_id`, which 23 of 24 services in a live
    # organisation leave null — so the process map's step panel said "No
    # accountable owner assigned to this step" about services that plainly have
    # one. Søren, 2026-09-04: *"if a service has no owner but has a process
    # owner, that process owner owns the service... and is always the owner."*
    #
    # `resolve_service_accountability` answers that: the stated delegate where
    # there is one, otherwise the owner of the service's single process. The
    # legacy column is the fallback only where the chain cannot answer, so an
    # organisation that set it keeps working.
    resolved = accountability or resolve_service_accountability(
        db,
        organization_id=service.organization_id,
        services=[service],
        # Asked from inside this process, so a service several processes carry
        # resolves to this one's owner rather than reporting nobody.
        as_seen_from_process_id=process.id if process is not None else None,
    ).get(service.id)
    owner_user_id = (
        resolved.holder_user_id
        if resolved is not None and resolved.holder_user_id is not None
        else service.owner_user_id
    )
    owner: User | None = db.get(User, owner_user_id) if owner_user_id is not None else None
    owner_source = _owner_source_for(resolved, service, owner)
    return ProcessServiceRow(
        service_id=service.id,
        service_name=service.name,
        library_item_id=service.library_item_id,
        tier=service.tier,
        archetype=service.archetype,
        owner_user_id=owner_user_id,
        owner_name=user_display_name(owner) if owner else None,
        owner_email=owner.email if owner else None,
        owner_title=owner.title if owner else None,
        owner_source=owner_source,
        resilience_score=score,
        financial_exposure=_service_exposure(service),
        bia_complete=bia_done,
        bia_provenance=service_bia_provenance(bia_exceptions),
        bundle_complete=bundle_done,
        appetite_complete=appetite_done,
        appetite_answers=appetite.answers,
        appetite_provenance=appetite.provenance,
        linked_asset_ids=[
            asset_id
            for asset_id in (service.l1 or [])
            if isinstance(asset_id, str) and asset_id.strip()
        ],
    )


def _build_capability_groups_for_service(
    service: BusinessService,
    db: Session,
) -> list[ProcessCapabilityGroupRow]:
    """Fetch the ServiceTemplate → SlotTemplate hierarchy merged with live SlotInstance rows."""
    svc_template: ServiceTemplate | None = None
    if service.library_item_id:
        svc_template = get_active_service_template(db, service.library_item_id)
    if svc_template is None and service.archetype:
        svc_template = get_active_service_template_by_archetype(db, service.archetype)
    if svc_template is None:
        return []

    slot_tmpls: list[SlotTemplate] = list_slot_templates_for_service(db, svc_template.id)
    if not slot_tmpls:
        return []

    slot_instances: list[SlotInstance] = (
        db.query(SlotInstance)
        .filter(
            SlotInstance.organization_id == service.organization_id,
            SlotInstance.service_id == service.id,
        )
        .all()
    )
    instance_by_slot_id = {si.slot_id: si for si in slot_instances}

    # BSP-12 — the org's frameworks can promote slots to required.
    org = db.query(Organization).filter(Organization.id == service.organization_id).first()
    slot_overrides = slot_requiredness_overrides(list(org.required_frameworks or []) if org else [])

    # Build a name lookup from the ServiceTemplate.capability_groups JSONB.
    group_name_by_key: dict[str, str] = {
        g["key"]: g["label"]
        for g in (svc_template.capability_groups or [])
        if "key" in g and "label" in g
    }
    group_order: list[str] = [
        g["key"] for g in (svc_template.capability_groups or []) if "key" in g
    ]

    groups_dict: dict[str, list[ProcessSlotRow]] = {}
    for slot_tmpl in slot_tmpls:
        gkey = slot_tmpl.capability_group_key
        instance = instance_by_slot_id.get(slot_tmpl.slot_id)
        override = slot_overrides.get(slot_tmpl.slot_id)
        row = ProcessSlotRow(
            slot_id=slot_tmpl.slot_id,
            label=slot_tmpl.label,
            purpose=slot_tmpl.purpose,
            required=bool(slot_tmpl.required) or override is not None,
            required_by_frameworks=list(override.frameworks) if override else [],
            status=instance.status if instance else "empty",
            asset_id=instance.asset_id if instance else None,
            asset_label=instance.asset_label if instance else None,
        )
        groups_dict.setdefault(gkey, []).append(row)

    # Preserve the canonical group order from the template.
    ordered_results: list[ProcessCapabilityGroupRow] = []
    seen: set[str] = set()
    for gkey in group_order:
        if gkey in groups_dict and gkey not in seen:
            ordered_results.append(
                ProcessCapabilityGroupRow(
                    group_key=gkey,
                    group_name=group_name_by_key.get(gkey, gkey.replace("_", " ").title()),
                    slots=groups_dict[gkey],
                )
            )
            seen.add(gkey)
    # Append any groups that have slots but were not in the template group list.
    for gkey, slots in groups_dict.items():
        if gkey not in seen:
            ordered_results.append(
                ProcessCapabilityGroupRow(
                    group_key=gkey,
                    group_name=gkey.replace("_", " ").title(),
                    slots=slots,
                )
            )
    return ordered_results


def _configured_core_service_keys(vs: ValueStream, db: Session) -> list[str]:
    lib_item = VALUE_STREAM_BY_KEY.get(vs.library_item_id) if vs.library_item_id else None
    if not lib_item:
        return []

    configured_keys = list(lib_item.core_service_keys)
    process_config: OrgProcessConfig | None = (
        db.query(OrgProcessConfig)
        .filter(
            OrgProcessConfig.organization_id == vs.organization_id,
            OrgProcessConfig.template_key == vs.library_item_id,
        )
        .first()
    )
    excluded_keys = set(process_config.excluded_service_keys or []) if process_config else set()
    return [service_key for service_key in configured_keys if service_key not in excluded_keys]


def _build_process_health(
    vs: ValueStream,
    member_rows: list[ProcessServiceRow],
    db: Session,
    *,
    readiness: ProcessActivationReadiness | None = None,
    owner_name: str | None = None,
    appetite_status: Literal["not_set", "pending_review", "active"] = "not_set",
) -> ProcessHealthResponse:
    scores = [r.resilience_score for r in member_rows if r.resilience_score is not None]
    min_score = min(scores) if scores else None
    total_exposure = sum(r.financial_exposure for r in member_rows) if member_rows else None
    configured = sum(1 for r in member_rows if r.bia_complete and r.bundle_complete)
    weakest = min(
        member_rows,
        key=lambda r: (r.resilience_score if r.resilience_score is not None else 999),
        default=None,
    )
    return ProcessHealthResponse(
        process_id=vs.id,
        library_item_id=vs.library_item_id,
        core_service_keys=_configured_core_service_keys(vs, db),
        name=vs.name,
        description=vs.description,
        priority=vs.priority,
        status=_process_status(min_score),
        resilience_score=min_score,
        financial_exposure=total_exposure,
        service_count=len(member_rows),
        configured_service_count=configured,
        weakest_service_name=weakest.service_name
        if weakest and weakest.resilience_score is not None
        else None,
        weakest_service_score=weakest.resilience_score if weakest else None,
        services=member_rows,
        owner_user_id=readiness.owner_user_id if readiness else None,
        owner_name=owner_name,
        ownership_accepted=readiness.ownership_accepted if readiness else False,
        bia_attested=readiness.bia_attested if readiness else False,
        appetite_status=appetite_status,
    )


def _get_process(process_id: str, organization_id: int, db: Session) -> ValueStream:
    process: ValueStream | None = (
        db.query(ValueStream)
        .filter(
            ValueStream.id == process_id,
            ValueStream.organization_id == organization_id,
        )
        .first()
    )
    if not process:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Process not found")
    return process


def _repair_process_service_linkage(vs: ValueStream, db: Session) -> list[BusinessService]:
    """Create or link BusinessService rows for a template-backed process that has none.

    Called lazily when a process detail request finds zero member services.
    This repairs data created before UC-TDM-01 added auto-creation.
    """
    lib_item = VALUE_STREAM_BY_KEY.get(vs.library_item_id) if vs.library_item_id else None
    if not lib_item:
        return []

    process_config: OrgProcessConfig | None = (
        db.query(OrgProcessConfig)
        .filter(
            OrgProcessConfig.organization_id == vs.organization_id,
            OrgProcessConfig.template_key == vs.library_item_id,
        )
        .first()
    )
    excluded_keys: set[str] = (
        set(process_config.excluded_service_keys or []) if process_config else set()
    )

    repaired: list[BusinessService] = []
    for service_key in lib_item.core_service_keys:
        if service_key in excluded_keys:
            continue

        existing: BusinessService | None = (
            db.query(BusinessService)
            .filter(
                BusinessService.organization_id == vs.organization_id,
                BusinessService.library_item_id == service_key,
            )
            .first()
        )

        if existing:
            current_ids: list[str] = list(existing.value_stream_ids or [])
            if vs.id not in current_ids:
                existing.value_stream_ids = current_ids + [vs.id]
                db.add(existing)
            repaired.append(existing)
        else:
            svc_template = get_active_service_template(db, service_key)
            new_svc = BusinessService(
                id=str(uuid.uuid4()),
                organization_id=vs.organization_id,
                name=get_service_key_name(service_key),
                library_item_id=service_key,
                archetype=get_archetype_for_service_key(service_key),
                template_key=service_key,
                template_version=svc_template.version if svc_template else None,
                value_stream_ids=[vs.id],
                tier=SERVICE_TIER_BUSINESS_CRITICAL,
                trading_impact="",
            )
            db.add(new_svc)
            repaired.append(new_svc)

    if repaired:
        db.commit()
        for svc in repaired:
            db.refresh(svc)

    return repaired


def _process_appetite_status(
    vs: ValueStream,
    db: Session,
    *,
    resolved: ResolvedProcessAppetite | None,
) -> Literal["not_set", "pending_review", "active"]:
    """What this one process decided about its Risk Appetite.

    The same three states `list_processes` reports, derived the same way: an
    effective appetite — its own override, an exception, or the organisation
    policy it inherits — is `active`; a process-scoped policy still being
    written or awaiting leadership is `pending_review`; nothing is `not_set`.
    """
    if resolved is not None:
        return "active"
    pending = (
        db.query(RiskAppetitePolicy)
        .filter(
            RiskAppetitePolicy.organization_id == vs.organization_id,
            RiskAppetitePolicy.scope == APPETITE_SCOPE_BUSINESS_PROCESS,
            RiskAppetitePolicy.process_id == vs.id,
            RiskAppetitePolicy.status.in_(
                [APPETITE_POLICY_DRAFT, APPETITE_POLICY_LEADERSHIP_REVIEW]
            ),
        )
        .first()
    )
    return "pending_review" if pending is not None else "not_set"


def _build_process_detail_response(
    vs: ValueStream,
    db: Session,
    *,
    can_edit: bool = False,
    effective_process_bia: EffectiveProcessBia | None = None,
) -> ProcessDetailResponse:
    all_services: list[BusinessService] = (
        db.query(BusinessService)
        .filter(
            BusinessService.organization_id == vs.organization_id,
            BusinessService.archived_at.is_(None),
        )
        .all()
    )
    members = [service for service in all_services if vs.id in (service.value_stream_ids or [])]

    # Lazy repair: if this is a template-backed process with no linked services,
    # create or re-link the missing BusinessService rows.
    if not members and vs.library_item_id:
        members = _repair_process_service_linkage(vs, db)

    process_appetite = resolve_process_appetite(
        db, organization_id=vs.organization_id, process_id=vs.id
    )
    appetite_status = _process_appetite_status(vs, db, resolved=process_appetite)
    # #463 — every member's BIA exceptions in this process, read once for the whole list.
    bia_exceptions = active_bia_exceptions(
        db, organization_id=vs.organization_id, process_ids=[vs.id]
    )

    rows = [
        ProcessServiceRow(
            **_build_service_row(
                svc,
                db,
                vs,
                process_appetite=process_appetite,
                effective_process_bia=effective_process_bia,
                bia_exceptions=exceptions_for(bia_exceptions, svc.id, vs.id),
            ).model_dump(exclude={"capability_groups"}),
            capability_groups=_build_capability_groups_for_service(svc, db),
        )
        for svc in members
    ]
    health = _build_process_health(vs, rows, db, appetite_status=appetite_status)
    current_assessment = get_current_process_bia_assessment(
        db,
        organization_id=vs.organization_id,
        process_id=vs.id,
    )
    # Mutation routes return the updated assessment immediately and do not
    # need to re-run the organisation-baseline resolver. The GET detail route
    # supplies the fully resolved projection; keeping this fallback local also
    # keeps lightweight route fixtures independent of optional baseline tables.
    effective = effective_process_bia or EffectiveProcessBia(
        answers=dict(vs.bia_answers) if vs.bia_answers else None,
        process_assessment_id=(
            current_assessment.id
            if current_assessment is not None
            and current_assessment.status == BIA_ASSESSMENT_ATTESTED
            else None
        ),
        organization_baseline_id=None,
        process_assessment_started=current_assessment is not None,
    )
    assessment_response = (
        ProcessBiaAssessmentResponse(
            id=current_assessment.id,
            status=current_assessment.status,
            answers=dict(current_assessment.answers),
            source=current_assessment.source,
            confidence=current_assessment.confidence,
            assumption_state=current_assessment.assumption_state,
            prepared_by_user_id=current_assessment.prepared_by_user_id,
            prepared_at=current_assessment.prepared_at,
            attested_by_user_id=current_assessment.attested_by_user_id,
            attested_at=current_assessment.attested_at,
            review_at=current_assessment.review_at,
        )
        if current_assessment is not None
        else None
    )
    effective_source = (
        "process_assessment"
        if effective.process_assessment_id
        else "organisation_baseline"
        if effective.organization_baseline_id
        else "legacy_projection"
        if effective.answers
        else None
    )

    return ProcessDetailResponse(
        process_id=health.process_id,
        library_item_id=health.library_item_id,
        core_service_keys=health.core_service_keys,
        name=health.name,
        description=health.description,
        priority=health.priority,
        status=health.status,
        resilience_score=health.resilience_score,
        financial_exposure=health.financial_exposure,
        service_count=health.service_count,
        configured_service_count=health.configured_service_count,
        weakest_service_name=health.weakest_service_name,
        weakest_service_score=health.weakest_service_score,
        services=rows,
        bpmn_definition=vs.bpmn_definition,
        bia_assessment=assessment_response,
        bia_effective_answers=dict(effective.answers) if effective.answers else None,
        bia_effective_source=effective_source,
        appetite_status=appetite_status,
        can_edit=can_edit,
    )


# ─── ROUTES ──────────────────────────────────────────────────────────────────


@router.get("", response_model=ProcessesListResponse)
def list_processes(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessesListResponse:
    """Return all value streams (processes) with derived health, plus any unassigned services."""
    priority_order = {"critical": 0, "important": 1, "standard": 2}

    streams: list[ValueStream] = (
        db.query(ValueStream).filter(ValueStream.organization_id == ctx.organization_id).all()
    )
    streams.sort(key=lambda s: (priority_order.get(s.priority, 3), s.name))

    readiness_by_process = resolve_process_activation_readiness(
        db, organization_id=ctx.organization_id, processes=streams
    )
    effective_bia_by_process = resolve_effective_process_bia_by_process(
        db,
        organization_id=ctx.organization_id,
        processes=streams,
    )
    # #463 — every service's BIA exceptions, per process, read once for the whole organisation.
    bia_exceptions = active_bia_exceptions(db, organization_id=ctx.organization_id)
    owner_ids = {
        r.owner_user_id for r in readiness_by_process.values() if r.owner_user_id is not None
    }
    owner_name_by_user_id = {
        user.id: user_display_name(user)
        for user in (
            db.query(User)
            .filter(User.organization_id == ctx.organization_id, User.id.in_(owner_ids))
            .all()
            if owner_ids
            else []
        )
    }
    # Resolved once, batched, for every process — the full exception ->
    # process-override -> organisation precedence chain, not just a direct
    # business_process-scope lookup (that used to make a process with only an
    # active *organisation* policy incorrectly report "not_set").
    resolved_appetite_by_process = resolve_appetite_for_processes(
        db, organization_id=ctx.organization_id, process_ids=[s.id for s in streams]
    )
    pending_process_appetite_policies = (
        db.query(RiskAppetitePolicy)
        .filter(
            RiskAppetitePolicy.organization_id == ctx.organization_id,
            RiskAppetitePolicy.scope == APPETITE_SCOPE_BUSINESS_PROCESS,
            RiskAppetitePolicy.process_id.in_([s.id for s in streams]),
            RiskAppetitePolicy.status.in_(
                [APPETITE_POLICY_DRAFT, APPETITE_POLICY_LEADERSHIP_REVIEW]
            ),
        )
        .all()
        if streams
        else []
    )
    pending_review_process_ids = {policy.process_id for policy in pending_process_appetite_policies}
    appetite_status_by_process: dict[str, Literal["not_set", "pending_review", "active"]] = {}
    for s in streams:
        if resolved_appetite_by_process.get(s.id) is not None:
            appetite_status_by_process[s.id] = "active"
        elif s.id in pending_review_process_ids:
            appetite_status_by_process[s.id] = "pending_review"

    all_services: list[BusinessService] = (
        db.query(BusinessService)
        .filter(
            BusinessService.organization_id == ctx.organization_id,
            BusinessService.archived_at.is_(None),
        )
        .all()
    )

    assigned_service_ids: set[str] = set()
    processes: list[ProcessHealthResponse] = []

    for vs in streams:
        members = [svc for svc in all_services if vs.id in (svc.value_stream_ids or [])]
        if not members and vs.library_item_id:
            members = _repair_process_service_linkage(vs, db)
            # Refresh the all_services list so newly created services appear
            # in later iterations (shared-service deduplication).
            all_services = (
                db.query(BusinessService)
                .filter(BusinessService.organization_id == ctx.organization_id)
                .all()
            )
        for svc in members:
            assigned_service_ids.add(svc.id)
        process_appetite = resolved_appetite_by_process.get(vs.id)
        rows = [
            _build_service_row(
                svc,
                db,
                vs,
                process_appetite=process_appetite,
                effective_process_bia=effective_bia_by_process.get(vs.id),
                bia_exceptions=exceptions_for(bia_exceptions, svc.id, vs.id),
            )
            for svc in members
        ]
        readiness = readiness_by_process.get(vs.id)
        processes.append(
            _build_process_health(
                vs,
                rows,
                db,
                readiness=readiness,
                owner_name=owner_name_by_user_id.get(readiness.owner_user_id)
                if readiness and readiness.owner_user_id
                else None,
                appetite_status=appetite_status_by_process.get(vs.id, "not_set"),
            )
        )

    unassigned = [
        _build_service_row(svc, db) for svc in all_services if svc.id not in assigned_service_ids
    ]

    return ProcessesListResponse(processes=processes, unassigned_services=unassigned)


@router.get("/{process_id}", response_model=ProcessDetailResponse)
def get_process_detail(
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessDetailResponse:
    """Return a single process with full member service detail."""
    process = _get_process(process_id, ctx.organization_id, db)
    effective_process_bia = resolve_effective_process_bia_by_process(
        db,
        organization_id=ctx.organization_id,
        processes=[process],
    )[process.id]
    return _build_process_detail_response(
        process,
        db,
        can_edit=can_process_edit(
            db,
            organization_id=ctx.organization_id,
            process_id=process.id,
            actor_user_id=ctx.user_id,
        ),
        effective_process_bia=effective_process_bia,
    )


@router.patch(
    "/{process_id}/services/{service_id}/archive",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def archive_process_service(
    process_id: str,
    service_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> Response:
    """Soft-archive a business service, removing it from all process views.

    Sets archived_at on the BusinessService row. The record is never deleted;
    restoration requires direct DB access by an administrator.
    Writes a service_archive audit entry to business_process_decision_logs.
    """
    process = _get_process(process_id, ctx.organization_id, db)
    try:
        require_process_editor(
            db,
            organization_id=ctx.organization_id,
            process_id=process.id,
            actor_user_id=ctx.user_id,
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc

    service: BusinessService | None = (
        db.query(BusinessService)
        .filter(
            BusinessService.id == service_id,
            BusinessService.organization_id == ctx.organization_id,
            BusinessService.archived_at.is_(None),
        )
        .first()
    )
    if not service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Service not found or already archived"
        )

    service.archived_at = datetime.now(timezone.utc)

    log = BusinessProcessDecisionLog(
        id=str(uuid.uuid4()),
        organization_id=ctx.organization_id,
        user_id=ctx.user_id,
        action=BusinessProcessDecisionAction.SERVICE_ARCHIVE.value,
        reason={"service_id": service_id, "service_name": service.name, "process_id": process_id},
        model_version=BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION,
    )
    db.add(log)
    db.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)


class AssignServiceOwnerRequest(BaseModel):
    owner_user_id: int | None
    owner_source: Literal["aad", "google", "platform"] | None = None


@router.patch("/{process_id}/services/{service_id}/owner", response_model=ProcessDetailResponse)
def assign_service_owner(
    process_id: str,
    service_id: str,
    payload: AssignServiceOwnerRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessDetailResponse:
    """Assign (or clear) the accountable business owner for a service."""
    vs = _get_process(process_id, ctx.organization_id, db)
    try:
        require_process_editor(
            db,
            organization_id=ctx.organization_id,
            process_id=vs.id,
            actor_user_id=ctx.user_id,
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc
    service = (
        db.query(BusinessService)
        .filter(
            BusinessService.id == service_id,
            BusinessService.organization_id == ctx.organization_id,
        )
        .first()
    )
    if service is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

    if payload.owner_user_id is not None:
        owner = (
            db.query(User)
            .filter(User.id == payload.owner_user_id, User.organization_id == ctx.organization_id)
            .first()
        )
        if owner is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Owner not found in organisation"
            )
        service.owner_user_id = owner.id
        service.owner_source = payload.owner_source or "platform"
    else:
        service.owner_user_id = None
        service.owner_source = None

    db.add(service)
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type="SERVICE_OWNER_ASSIGNED"
            if payload.owner_user_id is not None
            else "SERVICE_OWNER_CLEARED",
            metadata_json={
                "service_id": service.id,
                "process_id": vs.id,
                "owner_user_id": payload.owner_user_id,
            },
        )
    )
    db.commit()
    return _build_process_detail_response(vs, db)


class AssessProcessBiaRequest(BaseModel):
    bia_answers: BiaAnswers = Field(alias="biaAnswers")

    model_config = {"populate_by_name": True}


class PrepareProcessBiaRequest(AssessProcessBiaRequest):
    source: str
    confidence: str
    assumption_state: str = Field(alias="assumptionState")
    review_at: UtcTimestamp | None = Field(default=None, alias="reviewAt")


@router.patch("/{process_id}/bia", response_model=ProcessDetailResponse)
def assess_process_bia(
    process_id: str,
    payload: AssessProcessBiaRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessDetailResponse:
    """Record the process-level Business Impact Assessment.

    Asked once here (skill: BIA scaling rule) — every member BusinessService
    without its own override inherits these answers rather than re-asking
    the same questionnaire per service.
    """
    _get_process(process_id, ctx.organization_id, db)
    try:
        require_process_editor(
            db,
            organization_id=ctx.organization_id,
            process_id=process_id,
            actor_user_id=ctx.user_id,
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc
    assessment = get_current_process_bia_assessment(
        db,
        organization_id=ctx.organization_id,
        process_id=process_id,
    )
    try:
        if assessment is None:
            assessment = prepare_process_bia_assessment(
                db,
                organization_id=ctx.organization_id,
                process_id=process_id,
                answers=payload.bia_answers.model_dump(),
                source="manual",
                confidence="high",
                assumption_state="human_entered",
                prepared_by_user_id=ctx.user_id,
            )
            event_type = "PROCESS_BIA_PREPARED"
        else:
            update_process_bia_assessment(
                db,
                assessment,
                answers=payload.bia_answers.model_dump(),
            )
            event_type = "PROCESS_BIA_UPDATED"
    except ProcessBiaAssessmentValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=event_type,
            metadata_json={"process_id": process_id, "assessment_id": assessment.id},
        )
    )
    db.commit()
    return _build_process_detail_response(_get_process(process_id, ctx.organization_id, db), db)


@router.post("/{process_id}/bia/prepare", response_model=ProcessDetailResponse)
def prepare_process_bia(
    process_id: str,
    payload: PrepareProcessBiaRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessDetailResponse:
    """Store assumed BIA context for review without publishing it to services."""
    vs = _get_process(process_id, ctx.organization_id, db)
    try:
        require_process_editor(
            db,
            organization_id=ctx.organization_id,
            process_id=vs.id,
            actor_user_id=ctx.user_id,
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc
    try:
        assessment = prepare_process_bia_assessment(
            db,
            organization_id=ctx.organization_id,
            process_id=vs.id,
            answers=payload.bia_answers.model_dump(),
            source=payload.source,
            confidence=payload.confidence,
            assumption_state=payload.assumption_state,
            prepared_by_user_id=ctx.user_id,
            review_at=payload.review_at,
        )
    except ProcessBiaAssessmentValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type="PROCESS_BIA_PREPARED",
            metadata_json={"process_id": vs.id, "assessment_id": assessment.id},
        )
    )
    db.commit()
    return _build_process_detail_response(vs, db)


@router.post("/{process_id}/bia/attest", response_model=ProcessDetailResponse)
def attest_process_bia(
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessDetailResponse:
    """Attest a complete BIA and publish the process projection for inheritance."""
    vs = _get_process(process_id, ctx.organization_id, db)
    assessment = get_current_process_bia_assessment(
        db,
        organization_id=ctx.organization_id,
        process_id=vs.id,
    )
    if assessment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Process BIA assessment not found"
        )
    try:
        require_accepted_process_owner(
            db,
            organization_id=ctx.organization_id,
            process_id=vs.id,
            user_id=ctx.user_id,
        )
        attest_process_bia_assessment(db, assessment, attested_by_user_id=ctx.user_id)
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc
    except ProcessBiaAssessmentValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    vs.bia_answers = dict(assessment.answers)
    db.add(vs)
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type="PROCESS_BIA_ATTESTED",
            metadata_json={"process_id": vs.id, "assessment_id": assessment.id},
        )
    )
    db.commit()
    return _build_process_detail_response(vs, db)


@router.put("/{process_id}/services", response_model=ProcessDetailResponse)
def update_process_services(
    process_id: str,
    body: UpdateProcessServicesRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessDetailResponse:
    """Replace the included template-backed services for a process."""
    process = _get_process(process_id, ctx.organization_id, db)
    try:
        require_process_editor(
            db,
            organization_id=ctx.organization_id,
            process_id=process.id,
            actor_user_id=ctx.user_id,
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc
    if not process.library_item_id or process.library_item_id not in VALUE_STREAM_BY_KEY:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Only template-backed processes support process-scoped service membership updates",
        )

    template = VALUE_STREAM_BY_KEY[process.library_item_id]
    canonical_service_keys = list(template.core_service_keys)
    included_service_keys = list(dict.fromkeys(body.included_service_keys))
    if not included_service_keys:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one business service must remain included in the process",
        )

    invalid_service_keys = [
        service_key
        for service_key in included_service_keys
        if service_key not in canonical_service_keys
    ]
    if invalid_service_keys:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown service keys for process template '{process.library_item_id}': {', '.join(invalid_service_keys)}",
        )

    process_config: OrgProcessConfig | None = (
        db.query(OrgProcessConfig)
        .filter(
            OrgProcessConfig.organization_id == ctx.organization_id,
            OrgProcessConfig.template_key == process.library_item_id,
        )
        .first()
    )
    if process_config is None:
        process_config = OrgProcessConfig(
            id=str(uuid.uuid4()),
            organization_id=ctx.organization_id,
            template_key=process.library_item_id,
        )
        db.add(process_config)

    previous_excluded_service_keys = set(process_config.excluded_service_keys or [])

    excluded_service_keys = [
        service_key
        for service_key in canonical_service_keys
        if service_key not in included_service_keys
    ]
    process_config.excluded_service_keys = excluded_service_keys

    existing_services: list[BusinessService] = (
        db.query(BusinessService)
        .filter(BusinessService.organization_id == ctx.organization_id)
        .all()
    )
    service_by_library_key = {
        service.library_item_id: service for service in existing_services if service.library_item_id
    }

    for service_key in included_service_keys:
        existing_service = service_by_library_key.get(service_key)
        if existing_service is None:
            service_template = get_active_service_template(db, service_key)
            existing_service = BusinessService(
                id=str(uuid.uuid4()),
                organization_id=ctx.organization_id,
                name=get_service_key_name(service_key),
                library_item_id=service_key,
                archetype=get_archetype_for_service_key(service_key),
                template_key=service_key,
                template_version=service_template.version if service_template else None,
                value_stream_ids=[process.id],
                tier=SERVICE_TIER_BUSINESS_CRITICAL,
                trading_impact="",
            )
            db.add(existing_service)
            service_by_library_key[service_key] = existing_service
            continue

        current_stream_ids = list(existing_service.value_stream_ids or [])
        if process.id not in current_stream_ids:
            existing_service.value_stream_ids = [*current_stream_ids, process.id]
            db.add(existing_service)

    # Decided before anything is written: excluding a service that belongs to no
    # other process would orphan it, and every dependency beneath it with it
    # (#378). Refused as a whole, so the process is never left half-edited.
    detaching = [
        service
        for service in (service_by_library_key.get(key) for key in excluded_service_keys)
        if service is not None and process.id in (service.value_stream_ids or [])
    ]
    try:
        assert_removal_leaves_a_process(detaching, process_id=process.id, process_name=process.name)
    except ServiceWouldBeOrphanedError as error:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error

    for existing_service in detaching:
        existing_service.value_stream_ids = [
            stream_id
            for stream_id in (existing_service.value_stream_ids or [])
            if stream_id != process.id
        ]
        db.add(existing_service)

    new_excluded_service_keys = set(excluded_service_keys)
    newly_excluded = new_excluded_service_keys - previous_excluded_service_keys
    newly_reincluded = previous_excluded_service_keys - new_excluded_service_keys

    def _is_critical_change(service_keys: set[str]) -> bool:
        for key in service_keys:
            service = service_by_library_key.get(key)
            if service is not None and service.tier in (
                SERVICE_TIER_MISSION_CRITICAL,
                SERVICE_TIER_BUSINESS_CRITICAL,
            ):
                return True
        return False

    if newly_excluded:
        record_process_tailoring_signal(
            db,
            organization_id=ctx.organization_id,
            process_id=process.id,
            template_key=process.library_item_id,
            template_version=template.template_version,
            change_type=ProcessTailoringChangeType.SERVICE_EXCLUDED,
            affected_service_keys=sorted(newly_excluded),
            is_critical_service_change=_is_critical_change(newly_excluded),
            actor_user_id=ctx.user_id,
            rationale_code=body.rationale_code,
            evidence_state=body.evidence_state,
        )
    if newly_reincluded:
        record_process_tailoring_signal(
            db,
            organization_id=ctx.organization_id,
            process_id=process.id,
            template_key=process.library_item_id,
            template_version=template.template_version,
            change_type=ProcessTailoringChangeType.SERVICE_REINCLUDED,
            affected_service_keys=sorted(newly_reincluded),
            is_critical_service_change=_is_critical_change(newly_reincluded),
            actor_user_id=ctx.user_id,
            rationale_code=body.rationale_code,
            evidence_state=body.evidence_state,
        )

    db.commit()
    return _build_process_detail_response(process, db)


@router.put("/{process_id}/bpmn", response_model=ProcessDetailResponse)
def save_process_bpmn_definition(
    process_id: str,
    body: BpmnDefinitionWrite,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessDetailResponse:
    """Persist a reviewed tenant BPMN graph and invalidate prior activation."""
    process = _get_process(process_id, ctx.organization_id, db)
    try:
        require_process_editor(
            db,
            organization_id=ctx.organization_id,
            process_id=process.id,
            actor_user_id=ctx.user_id,
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc
    members = (
        db.query(BusinessService)
        .filter(BusinessService.organization_id == ctx.organization_id)
        .all()
    )
    try:
        validate_process_graph(body, process=process, services=members)
    except ProcessGraphValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    process.bpmn_definition = body.model_dump(mode="json", by_alias=True)
    invalidate_process_graph_activation(
        db,
        organization_id=ctx.organization_id,
        process_id=process.id,
    )
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=ProcessGraphAuditEvent.GRAPH_SAVED.value,
            metadata_json={
                "process_id": process.id,
                "node_count": len(body.nodes),
                "flow_count": len(body.flows),
                "template_key": process.library_item_id,
            },
        )
    )
    db.commit()
    return _build_process_detail_response(process, db)


@router.post("/{process_id}/services", response_model=ProcessDetailResponse)
def create_process_custom_service(
    process_id: str,
    body: CreateProcessCustomServiceRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessDetailResponse:
    """Create a tenant-owned Business Service for a tailored process."""
    process = _get_process(process_id, ctx.organization_id, db)
    try:
        require_process_editor(
            db,
            organization_id=ctx.organization_id,
            process_id=process.id,
            actor_user_id=ctx.user_id,
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc
    if body.archetype is not None and body.archetype not in VALID_ARCHETYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown archetype '{body.archetype}'",
        )
    service = BusinessService(
        id=str(uuid.uuid4()),
        organization_id=ctx.organization_id,
        name=body.name,
        tier=body.tier,
        archetype=body.archetype,
        value_stream_ids=[process.id],
        trading_impact="",
    )
    db.add(service)
    custom_service_audit_event = AuditEvent(
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        event_type=ProcessGraphAuditEvent.CUSTOM_SERVICE_CREATED.value,
        metadata_json={
            "process_id": process.id,
            "service_id": service.id,
            "template_key": process.library_item_id,
        },
    )
    db.add(custom_service_audit_event)
    record_process_tailoring_signal(
        db,
        organization_id=ctx.organization_id,
        process_id=process.id,
        template_key=process.library_item_id,
        template_version=(
            VALUE_STREAM_BY_KEY[process.library_item_id].template_version
            if process.library_item_id in VALUE_STREAM_BY_KEY
            else None
        ),
        change_type=ProcessTailoringChangeType.CUSTOM_SERVICE_ADDED,
        affected_service_keys=[],
        is_critical_service_change=(
            body.tier in (SERVICE_TIER_MISSION_CRITICAL, SERVICE_TIER_BUSINESS_CRITICAL)
        ),
        actor_user_id=ctx.user_id,
        rationale_code=body.rationale_code,
        evidence_state=body.evidence_state,
        detail={"archetype": body.archetype} if body.archetype is not None else {},
        audit_event=custom_service_audit_event,
    )
    db.commit()
    return _build_process_detail_response(process, db)
