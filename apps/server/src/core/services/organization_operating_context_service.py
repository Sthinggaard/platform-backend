"""Prepared organisation operating-context suggestions.

Uses the canonical NACE value-stream inference as its industry input. These
records remain separate from baseline process/service assumptions: they never
create a Business Process or Business Service and require an administrator's
explicit decision.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.organization_identity_enums import (
    ORG_IDENTITY_ERROR_OPERATING_CONTEXT_SELECTION_INVALID,
    OrganizationOperatingContextSource,
    OrganizationOperatingContextSuggestionType,
    SuggestionDecision,
)
from src.core.constants.value_stream_library import infer_value_streams_from_nace
from src.core.model_defs.common import utcnow
from src.core.model_defs.organization_identity import OrganizationOperatingContextSuggestion
from src.core.model_defs.tenant_org import Organization


@dataclass(frozen=True)
class OperatingContextCatalogItem:
    key: str
    suggestion_type: OrganizationOperatingContextSuggestionType


SAAS_ARCHETYPE = OperatingContextCatalogItem(
    key="software_as_a_service",
    suggestion_type=OrganizationOperatingContextSuggestionType.INDUSTRY_ARCHETYPE,
)
SAAS_CHARACTERISTICS = (
    OperatingContextCatalogItem(
        key="subscription_services",
        suggestion_type=OrganizationOperatingContextSuggestionType.OPERATING_CHARACTERISTIC,
    ),
    OperatingContextCatalogItem(
        key="business_to_business_services",
        suggestion_type=OrganizationOperatingContextSuggestionType.OPERATING_CHARACTERISTIC,
    ),
    OperatingContextCatalogItem(
        key="cloud_based_delivery",
        suggestion_type=OrganizationOperatingContextSuggestionType.OPERATING_CHARACTERISTIC,
    ),
    OperatingContextCatalogItem(
        key="regulated_data_handling",
        suggestion_type=OrganizationOperatingContextSuggestionType.OPERATING_CHARACTERISTIC,
    ),
)

OPERATING_CONTEXT_CATALOG: dict[OrganizationOperatingContextSuggestionType, frozenset[str]] = {
    OrganizationOperatingContextSuggestionType.INDUSTRY_ARCHETYPE: frozenset({SAAS_ARCHETYPE.key}),
    OrganizationOperatingContextSuggestionType.OPERATING_CHARACTERISTIC: frozenset(
        item.key for item in SAAS_CHARACTERISTICS
    ),
}

OPERATING_CONTEXT_SELECTION_REQUIRED_ERROR = "An operating-context selection is required."
OPERATING_CONTEXT_SELECTION_INVALID_ERROR = ORG_IDENTITY_ERROR_OPERATING_CONTEXT_SELECTION_INVALID


def derive_operating_context_catalog(
    organization: Organization,
) -> list[OperatingContextCatalogItem]:
    """Derive a narrow profile from existing canonical NACE inference.

    The value-stream engine remains the single source for identifying the
    software/IT industry range. The returned items are only reviewable context
    suggestions; they do not leak into process generation.
    """
    inferred_keys = {
        item.key
        for item in infer_value_streams_from_nace(
            nace_code=organization.nace_code or "",
            company_form=(organization.settings or {}).get("company_form", ""),
            company_size=organization.company_size or "",
        )
    }
    if "software_delivery" not in inferred_keys:
        return []
    return [SAAS_ARCHETYPE, *SAAS_CHARACTERISTICS]


def prepare_operating_context_suggestions(
    db: Session, organization: Organization
) -> list[OrganizationOperatingContextSuggestion]:
    """Persist missing current suggestions idempotently for a registry handoff."""
    current = {
        (item.suggestion_type, item.suggestion_key)
        for item in db.query(OrganizationOperatingContextSuggestion)
        .filter(
            OrganizationOperatingContextSuggestion.organization_id == organization.id,
            OrganizationOperatingContextSuggestion.superseded_by_id.is_(None),
        )
        .all()
    }
    source_reference = organization.nace_code or None
    for item in derive_operating_context_catalog(organization):
        identity = (item.suggestion_type.value, item.key)
        if identity in current:
            continue
        db.add(
            OrganizationOperatingContextSuggestion(
                organization_id=organization.id,
                suggestion_type=item.suggestion_type.value,
                suggestion_key=item.key,
                source_type=OrganizationOperatingContextSource.NACE_INFERENCE.value,
                source_reference=source_reference,
                status=SuggestionDecision.SUGGESTED.value,
            )
        )
    db.flush()
    return list_current_operating_context_suggestions(db, organization.id)


def list_current_operating_context_suggestions(
    db: Session, organization_id: int
) -> list[OrganizationOperatingContextSuggestion]:
    return (
        db.query(OrganizationOperatingContextSuggestion)
        .filter(
            OrganizationOperatingContextSuggestion.organization_id == organization_id,
            OrganizationOperatingContextSuggestion.superseded_by_id.is_(None),
        )
        .order_by(OrganizationOperatingContextSuggestion.created_at.asc())
        .all()
    )


def decide_operating_context_suggestion(
    db: Session,
    suggestion: OrganizationOperatingContextSuggestion,
    *,
    status: SuggestionDecision,
    decided_by_user_id: int,
) -> OrganizationOperatingContextSuggestion:
    """Append a decision rather than overwriting a prior suggestion or decision."""
    if suggestion.status == status.value:
        return suggestion
    successor = OrganizationOperatingContextSuggestion(
        organization_id=suggestion.organization_id,
        suggestion_type=suggestion.suggestion_type,
        suggestion_key=suggestion.suggestion_key,
        source_type=suggestion.source_type,
        source_reference=suggestion.source_reference,
        status=status.value,
        decided_by_user_id=decided_by_user_id,
        decided_at=utcnow(),
    )
    db.add(successor)
    db.flush()
    suggestion.superseded_by_id = successor.id
    db.add(suggestion)
    return successor


def add_operating_context_suggestion(
    db: Session,
    *,
    organization_id: int,
    suggestion_type: OrganizationOperatingContextSuggestionType,
    suggestion_key: str,
) -> OrganizationOperatingContextSuggestion:
    if not suggestion_key.strip():
        raise ValueError(OPERATING_CONTEXT_SELECTION_REQUIRED_ERROR)
    normalized_key = suggestion_key.strip()
    if normalized_key not in OPERATING_CONTEXT_CATALOG[suggestion_type]:
        raise ValueError(OPERATING_CONTEXT_SELECTION_INVALID_ERROR)
    current = (
        db.query(OrganizationOperatingContextSuggestion)
        .filter(
            OrganizationOperatingContextSuggestion.organization_id == organization_id,
            OrganizationOperatingContextSuggestion.suggestion_type == suggestion_type.value,
            OrganizationOperatingContextSuggestion.suggestion_key == normalized_key,
            OrganizationOperatingContextSuggestion.superseded_by_id.is_(None),
            OrganizationOperatingContextSuggestion.status != SuggestionDecision.REJECTED.value,
        )
        .first()
    )
    if current is not None:
        return current
    suggestion = OrganizationOperatingContextSuggestion(
        organization_id=organization_id,
        suggestion_type=suggestion_type.value,
        suggestion_key=normalized_key,
        source_type=OrganizationOperatingContextSource.USER.value,
        status=SuggestionDecision.SUGGESTED.value,
    )
    db.add(suggestion)
    db.flush()
    return suggestion
