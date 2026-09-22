"""Governed in-place rebasing of a tenant Business Process to a comparable template."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.process_template_variant_enums import (
    ProcessTemplateApplicabilityReason,
    ProcessTemplateIndustryFit,
    ProcessTemplateVariantErrorMessage,
)
from src.core.constants.service_key_archetypes import (
    get_archetype_for_service_key,
    get_service_key_name,
)
from src.core.constants.service_model import SERVICE_TIER_BUSINESS_CRITICAL
from src.core.constants.value_stream_library import (
    VALUE_STREAM_BY_KEY,
    VALUE_STREAM_LIBRARY,
    ValueStreamLibraryItem,
    is_nace_match,
)
from src.core.model_defs.value_streams import BusinessService, ValueStream
from src.core.repository import TenantRepository
from src.core.services.process_graph_service import invalidate_process_graph_activation
from src.core.services.template_library_service import get_active_service_template

import structlog

logger = structlog.get_logger(__name__)


class ProcessTemplateVariantValidationError(ValueError):
    """Raised when an alternative cannot safely rebase the current process."""


@dataclass(frozen=True)
class ComparableProcessTemplateVariant:
    template: ValueStreamLibraryItem
    industry_fit: ProcessTemplateIndustryFit
    applicability_reason: ProcessTemplateApplicabilityReason


_FIT_ORDER = {
    ProcessTemplateIndustryFit.DIRECT: 0,
    ProcessTemplateIndustryFit.COMPARABLE: 1,
    ProcessTemplateIndustryFit.UNKNOWN: 2,
}


def list_comparable_template_variants(
    *,
    process: ValueStream,
    nace_code: str | None,
) -> list[ComparableProcessTemplateVariant]:
    """Return active alternatives for the current process's immutable business outcome."""
    current_template = _require_current_template(process)
    variants = [
        _to_comparable_variant(template, nace_code)
        for template in VALUE_STREAM_LIBRARY
        if template.is_active
        and template.key != current_template.key
        and template.business_outcome_key == current_template.business_outcome_key
    ]
    return sorted(variants, key=lambda variant: (_FIT_ORDER[variant.industry_fit], variant.template.name))


def apply_template_variant(
    db: Session,
    *,
    organization_id: int,
    process: ValueStream,
    target_template_key: str,
) -> ValueStream:
    """Rebase one tenant process to a comparable canonical template in place."""
    current_template = _require_current_template(process)
    target_template = VALUE_STREAM_BY_KEY.get(target_template_key)
    if target_template is None or not target_template.is_active:
        raise ProcessTemplateVariantValidationError(
            ProcessTemplateVariantErrorMessage.TEMPLATE_VARIANT_NOT_FOUND.value
        )
    if target_template.business_outcome_key != current_template.business_outcome_key:
        raise ProcessTemplateVariantValidationError(
            ProcessTemplateVariantErrorMessage.TEMPLATE_VARIANT_OUTCOME_MISMATCH.value
        )

    services = TenantRepository(db, BusinessService, organization_id).get_all()
    _replace_default_service_membership(
        db,
        organization_id=organization_id,
        process=process,
        current_template=current_template,
        target_template=target_template,
        services=services,
    )
    TenantRepository(db, ValueStream, organization_id).update(
        process,
        library_item_id=target_template.key,
        # The new template supplies the reviewed starting point. A prior
        # tenant graph cannot truthfully describe it and must be rebuilt.
        bpmn_definition=None,
    )
    invalidate_process_graph_activation(
        db,
        organization_id=organization_id,
        process_id=process.id,
    )
    return process


def _require_current_template(process: ValueStream) -> ValueStreamLibraryItem:
    template = VALUE_STREAM_BY_KEY.get(process.library_item_id or "")
    if template is None:
        raise ProcessTemplateVariantValidationError(
            ProcessTemplateVariantErrorMessage.PROCESS_TEMPLATE_REQUIRED.value
        )
    return template


def _to_comparable_variant(
    template: ValueStreamLibraryItem,
    nace_code: str | None,
) -> ComparableProcessTemplateVariant:
    if not nace_code:
        return ComparableProcessTemplateVariant(
            template=template,
            industry_fit=ProcessTemplateIndustryFit.UNKNOWN,
            applicability_reason=ProcessTemplateApplicabilityReason.ORGANISATION_INDUSTRY_UNKNOWN,
        )
    if is_nace_match(nace_code, template.typical_industries):
        return ComparableProcessTemplateVariant(
            template=template,
            industry_fit=ProcessTemplateIndustryFit.DIRECT,
            applicability_reason=ProcessTemplateApplicabilityReason.MATCHED_REGISTERED_INDUSTRY,
        )
    return ComparableProcessTemplateVariant(
        template=template,
        industry_fit=ProcessTemplateIndustryFit.COMPARABLE,
        applicability_reason=ProcessTemplateApplicabilityReason.COMPARABLE_BUSINESS_OUTCOME,
    )


def _replace_default_service_membership(
    db: Session,
    *,
    organization_id: int,
    process: ValueStream,
    current_template: ValueStreamLibraryItem,
    target_template: ValueStreamLibraryItem,
    services: list[BusinessService],
) -> None:
    """Replace only canonical defaults; retain tenant-created services and their records."""
    current_default_keys = set(current_template.core_service_keys)
    target_default_keys = set(target_template.core_service_keys)
    service_by_template_key = {
        service.library_item_id: service
        for service in services
        if service.library_item_id
    }

    detaching = [
        service
        for service in services
        if service.library_item_id in current_default_keys
        and service.library_item_id not in target_default_keys
        and process.id in (service.value_stream_ids or [])
    ]

    # ⚠️ **This orphans a default that belongs to no other process, and #378's
    # refusal is deliberately NOT applied here.** Switching a variant is *meant*
    # to replace the old variant's canonical defaults, so refusing would block
    # the feature outright rather than protect anything — the guard on the
    # user-initiated exclusion path is a different case, where the reader is
    # choosing to remove one service and can be told why they cannot.
    #
    # What should happen to a replaced default with nowhere else to live —
    # deleted with its bundles and decisions, or kept attached — is a product
    # decision Søren has not made. Until then it is at least *visible*: this
    # used to happen in silence, which is how 57 orphans accumulated unnoticed.
    would_orphan = [
        service.name
        for service in detaching
        if len([sid for sid in (service.value_stream_ids or []) if sid != process.id]) == 0
    ]
    if would_orphan:
        logger.warning(
            "template_variant_orphaned_services",
            process_id=process.id,
            organization_id=organization_id,
            services=sorted(would_orphan),
            reason="replaced default belongs to no other process (#378)",
        )

    for service in detaching:
        service.value_stream_ids = [
            value_stream_id
            for value_stream_id in service.value_stream_ids
            if value_stream_id != process.id
        ]

    service_repository = TenantRepository(db, BusinessService, organization_id)
    for service_key in target_template.core_service_keys:
        service = service_by_template_key.get(service_key)
        if service is None:
            template = get_active_service_template(db, service_key)
            service = service_repository.create(
                id=str(uuid.uuid4()),
                name=get_service_key_name(service_key),
                library_item_id=service_key,
                archetype=get_archetype_for_service_key(service_key),
                template_key=service_key,
                template_version=template.version if template else None,
                value_stream_ids=[process.id],
                tier=SERVICE_TIER_BUSINESS_CRITICAL,
                trading_impact="",
            )
            service_by_template_key[service_key] = service
            continue
        if process.id not in (service.value_stream_ids or []):
            service.value_stream_ids = [*service.value_stream_ids, process.id]
