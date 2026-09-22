"""Governed, tenant-scoped Business Process template variant endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.routes.org_access import _require_org_admin
from src.api.schemas.process_template_variants import (
    ApplyProcessTemplateVariantRequest,
    ProcessTemplateVariantResponse,
    ProcessTemplateVariantsResponse,
)
from src.core.constants.process_template_variant_enums import (
    ProcessTemplateVariantAuditEvent,
    ProcessTemplateVariantErrorMessage,
)
from src.core.constants.value_stream_events import ValueStreamEvent
from src.core.constants.value_stream_library import VALUE_STREAM_BY_KEY
from src.core.database import get_db
from src.core.exceptions import ResourceNotFoundError, ValidationError
from src.core.model_defs.tenant_org import Organization
from src.core.models import AuditEvent, ValueStream, ValueStreamSignal
from src.core.repository import GlobalRepository, TenantRepository
from src.core.services.process_template_variant_service import (
    ProcessTemplateVariantValidationError,
    apply_template_variant,
    list_comparable_template_variants,
)

router = APIRouter(prefix="/api/v1/processes", tags=["Process template variants"])


def _get_process(db: Session, *, ctx: TenantContext, process_id: str) -> ValueStream:
    process = TenantRepository(db, ValueStream, ctx.organization_id).get_by_id(process_id)
    if process is None:
        raise ResourceNotFoundError(ProcessTemplateVariantErrorMessage.PROCESS_NOT_FOUND.value)
    return process


def _variant_response(variant) -> ProcessTemplateVariantResponse:
    template = variant.template
    return ProcessTemplateVariantResponse(
        template_key=template.key,
        template_version=template.template_version,
        business_outcome_key=template.business_outcome_key,
        name=template.name,
        description=template.description,
        core_service_count=len(template.core_service_keys),
        industry_fit=variant.industry_fit,
        applicability_reason=variant.applicability_reason,
    )


@router.get("/{process_id}/template-variants", response_model=ProcessTemplateVariantsResponse)
def get_process_template_variants(
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessTemplateVariantsResponse:
    process = _get_process(db, ctx=ctx, process_id=process_id)
    organisation = GlobalRepository(db, Organization).get_by_id(ctx.organization_id)
    try:
        current_template = VALUE_STREAM_BY_KEY.get(process.library_item_id or "")
        variants = list_comparable_template_variants(
            process=process,
            nace_code=organisation.nace_code if organisation else None,
        )
    except ProcessTemplateVariantValidationError as exc:
        raise ValidationError(str(exc)) from exc
    if current_template is None:
        raise ValidationError(ProcessTemplateVariantErrorMessage.PROCESS_TEMPLATE_REQUIRED.value)
    return ProcessTemplateVariantsResponse(
        process_id=process.id,
        current_template_key=current_template.key,
        business_outcome_key=current_template.business_outcome_key,
        variants=[_variant_response(variant) for variant in variants],
    )


@router.post("/{process_id}/template-variants/{template_key}/apply", response_model=ProcessTemplateVariantsResponse)
def apply_process_template_variant(
    process_id: str,
    template_key: str,
    body: ApplyProcessTemplateVariantRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessTemplateVariantsResponse:
    _require_org_admin(db, ctx)
    if not body.has_rebase_acknowledgement():
        raise ValidationError(ProcessTemplateVariantErrorMessage.REBASE_ACKNOWLEDGEMENT_REQUIRED.value)
    process = _get_process(db, ctx=ctx, process_id=process_id)
    previous_template_key = process.library_item_id
    try:
        apply_template_variant(
            db,
            organization_id=ctx.organization_id,
            process=process,
            target_template_key=template_key,
        )
    except ProcessTemplateVariantValidationError as exc:
        raise ValidationError(str(exc)) from exc

    db.add(
        ValueStreamSignal(
            organization_id=ctx.organization_id,
            user_id=ctx.user_id,
            event=ValueStreamEvent.TEMPLATE_VARIANT_APPLIED.value,
            stream_id=process.id,
            library_item_id=template_key,
            stream_key=template_key,
            payload={
                "previous_template_key": previous_template_key,
                "applied_template_key": template_key,
                "change_kind": "template_variant_rebase",
            },
        )
    )
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=ProcessTemplateVariantAuditEvent.APPLIED.value,
            metadata_json={
                "process_id": process.id,
                "previous_template_key": previous_template_key,
                "applied_template_key": template_key,
            },
        )
    )
    db.commit()
    return get_process_template_variants(process_id=process_id, ctx=ctx, db=db)
