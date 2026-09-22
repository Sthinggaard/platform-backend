"""Org-level template configuration endpoints.

Allows organisations to deviate from canonical process / service templates
by excluding capability groups or service slots, or adding custom ones.

GET  /api/v1/org-template-config/processes/{template_key}  — read org config for a process
PUT  /api/v1/org-template-config/processes/{template_key}  — save org config for a process
GET  /api/v1/org-template-config/services/{service_key}    — read org config for a service
PUT  /api/v1/org-template-config/services/{service_key}    — save org config for a service

Every endpoint is tenant-scoped: organization_id comes from JWT via TenantContext.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.schemas.timestamps import UtcTimestamp
from src.core.constants.process_tailoring_enums import (
    ProcessTailoringChangeType,
    ProcessTailoringRationaleCode,
    TailoringEvidenceState,
)
from src.core.constants.service_model import (
    SERVICE_TIER_BUSINESS_CRITICAL,
    SERVICE_TIER_MISSION_CRITICAL,
)
from src.core.constants.value_stream_library import VALUE_STREAM_BY_KEY
from src.core.database import get_db
from src.core.exceptions import AuthorizationError
from src.core.logging_config import get_logger
from src.core.models import BusinessService, OrgProcessConfig, OrgServiceConfig, ValueStream
from src.core.services.process_graph_service import record_process_tailoring_signal
from src.core.services.process_ownership_service import (
    ProcessOwnershipValidationError,
    require_process_editor,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/org-template-config", tags=["Org Template Config"])


# ─── SCHEMAS ─────────────────────────────────────────────────────────────────


class CustomServiceSlot(BaseModel):
    service_key: str
    service_name: str
    archetype: str | None = None


class OrgProcessConfigRequest(BaseModel):
    excluded_service_keys: list[str] = Field(default_factory=list)
    custom_service_slots: list[CustomServiceSlot] = Field(default_factory=list)
    note: str | None = None
    rationale_code: ProcessTailoringRationaleCode | None = None
    evidence_state: TailoringEvidenceState | None = None


class OrgProcessConfigResponse(BaseModel):
    template_key: str
    excluded_service_keys: list[str]
    custom_service_slots: list[CustomServiceSlot]
    note: str | None
    updated_at: UtcTimestamp


class CustomCapabilityGroup(BaseModel):
    key: str
    label: str
    question: str
    description: str
    required: bool = False
    expected_asset_types: list[str] = Field(default_factory=list)


class OrgServiceConfigRequest(BaseModel):
    excluded_group_keys: list[str] = Field(default_factory=list)
    custom_groups: list[CustomCapabilityGroup] = Field(default_factory=list)
    note: str | None = None


class OrgServiceConfigResponse(BaseModel):
    service_key: str
    excluded_group_keys: list[str]
    custom_groups: list[CustomCapabilityGroup]
    note: str | None
    updated_at: UtcTimestamp


# ─── ROUTES ──────────────────────────────────────────────────────────────────


@router.get("/processes/{template_key}", response_model=OrgProcessConfigResponse)
def get_process_config(
    template_key: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> OrgProcessConfigResponse:
    """Return the org's customisation for a process template, or defaults if none saved."""
    row: OrgProcessConfig | None = (
        db.query(OrgProcessConfig)
        .filter(
            OrgProcessConfig.organization_id == ctx.organization_id,
            OrgProcessConfig.template_key == template_key,
        )
        .first()
    )
    if row is None:
        return OrgProcessConfigResponse(
            template_key=template_key,
            excluded_service_keys=[],
            custom_service_slots=[],
            note=None,
            updated_at="",
        )
    return OrgProcessConfigResponse(
        template_key=row.template_key,
        excluded_service_keys=list(row.excluded_service_keys or []),
        custom_service_slots=[CustomServiceSlot(**s) for s in (row.custom_service_slots or [])],
        note=row.note,
        updated_at=row.updated_at.isoformat(),
    )


@router.put("/processes/{template_key}", response_model=OrgProcessConfigResponse)
def save_process_config(
    template_key: str,
    body: OrgProcessConfigRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> OrgProcessConfigResponse:
    """Save (upsert) the org's customisation for a process template."""
    process: ValueStream | None = (
        db.query(ValueStream)
        .filter(
            ValueStream.organization_id == ctx.organization_id,
            ValueStream.library_item_id == template_key,
        )
        .first()
    )
    try:
        require_process_editor(
            db,
            organization_id=ctx.organization_id,
            process_id=process.id if process is not None else "",
            actor_user_id=ctx.user_id,
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc

    row: OrgProcessConfig | None = (
        db.query(OrgProcessConfig)
        .filter(
            OrgProcessConfig.organization_id == ctx.organization_id,
            OrgProcessConfig.template_key == template_key,
        )
        .first()
    )
    if row is None:
        row = OrgProcessConfig(
            id=str(uuid.uuid4()),
            organization_id=ctx.organization_id,
            template_key=template_key,
        )
        db.add(row)

    previous_excluded_service_keys = set(row.excluded_service_keys or [])

    row.excluded_service_keys = list(body.excluded_service_keys)
    row.custom_service_slots = [s.model_dump() for s in body.custom_service_slots]
    row.note = body.note

    new_excluded_service_keys = set(row.excluded_service_keys)
    newly_excluded = new_excluded_service_keys - previous_excluded_service_keys
    newly_reincluded = previous_excluded_service_keys - new_excluded_service_keys

    if newly_excluded or newly_reincluded:
        service_by_library_key = {
            service.library_item_id: service
            for service in (
                db.query(BusinessService)
                .filter(BusinessService.organization_id == ctx.organization_id)
                .all()
            )
            if service.library_item_id
        }
        template = VALUE_STREAM_BY_KEY.get(template_key)

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
                process_id=process.id if process is not None else None,
                template_key=template_key,
                template_version=template.template_version if template is not None else None,
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
                process_id=process.id if process is not None else None,
                template_key=template_key,
                template_version=template.template_version if template is not None else None,
                change_type=ProcessTailoringChangeType.SERVICE_REINCLUDED,
                affected_service_keys=sorted(newly_reincluded),
                is_critical_service_change=_is_critical_change(newly_reincluded),
                actor_user_id=ctx.user_id,
                rationale_code=body.rationale_code,
                evidence_state=body.evidence_state,
            )

    db.commit()
    db.refresh(row)

    logger.info(
        "org_process_config_saved",
        org_id=ctx.organization_id,
        template_key=template_key,
        excluded=len(body.excluded_service_keys),
        custom=len(body.custom_service_slots),
    )
    return OrgProcessConfigResponse(
        template_key=row.template_key,
        excluded_service_keys=list(row.excluded_service_keys or []),
        custom_service_slots=[CustomServiceSlot(**s) for s in (row.custom_service_slots or [])],
        note=row.note,
        updated_at=row.updated_at.isoformat(),
    )


@router.get("/services/{service_key}", response_model=OrgServiceConfigResponse)
def get_service_config(
    service_key: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> OrgServiceConfigResponse:
    """Return the org's customisation for a service template, or defaults if none saved."""
    row: OrgServiceConfig | None = (
        db.query(OrgServiceConfig)
        .filter(
            OrgServiceConfig.organization_id == ctx.organization_id,
            OrgServiceConfig.service_key == service_key,
        )
        .first()
    )
    if row is None:
        return OrgServiceConfigResponse(
            service_key=service_key,
            excluded_group_keys=[],
            custom_groups=[],
            note=None,
            updated_at="",
        )
    return OrgServiceConfigResponse(
        service_key=row.service_key,
        excluded_group_keys=list(row.excluded_group_keys or []),
        custom_groups=[CustomCapabilityGroup(**g) for g in (row.custom_groups or [])],
        note=row.note,
        updated_at=row.updated_at.isoformat(),
    )


@router.put("/services/{service_key}", response_model=OrgServiceConfigResponse)
def save_service_config(
    service_key: str,
    body: OrgServiceConfigRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> OrgServiceConfigResponse:
    """Save (upsert) the org's customisation for a service template."""
    row: OrgServiceConfig | None = (
        db.query(OrgServiceConfig)
        .filter(
            OrgServiceConfig.organization_id == ctx.organization_id,
            OrgServiceConfig.service_key == service_key,
        )
        .first()
    )
    if row is None:
        row = OrgServiceConfig(
            id=str(uuid.uuid4()),
            organization_id=ctx.organization_id,
            service_key=service_key,
        )
        db.add(row)

    row.excluded_group_keys = list(body.excluded_group_keys)
    row.custom_groups = [g.model_dump() for g in body.custom_groups]
    row.note = body.note

    db.commit()
    db.refresh(row)

    logger.info(
        "org_service_config_saved",
        org_id=ctx.organization_id,
        service_key=service_key,
        excluded=len(body.excluded_group_keys),
        custom=len(body.custom_groups),
    )
    return OrgServiceConfigResponse(
        service_key=row.service_key,
        excluded_group_keys=list(row.excluded_group_keys or []),
        custom_groups=[CustomCapabilityGroup(**g) for g in (row.custom_groups or [])],
        note=row.note,
        updated_at=row.updated_at.isoformat(),
    )
