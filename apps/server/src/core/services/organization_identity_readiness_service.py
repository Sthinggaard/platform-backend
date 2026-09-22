"""Organisation Identity Setup — readiness evaluation + prepared read model.

Read-side companion to ``organization_identity_service`` (SRP: that module
owns writes/lifecycle transitions, this one owns deriving readiness and the
summary consumed by later onboarding stages). Readiness is always derived
from underlying records, never a status a caller can set directly — mirrors
``useOnboardingReadiness``'s existing derive-don't-store pattern on the
frontend.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from src.core.constants.organization_identity_enums import (
    OrganizationDomainType,
    OrganizationEntityStatus,
    OrganizationIdentityReadiness,
    OrganizationScopeType,
    SuggestionDecision,
)
from src.core.model_defs.organization_identity import (
    OrganizationDomain,
    OrganizationLegalEntity,
    OrganizationOperatingContextSuggestion,
    OrganizationScope,
)
from src.core.model_defs.tenant_org import Organization
from src.core.services.organization_identity_service import (
    get_active_identity_confirmation,
    get_confirmed_scope,
    get_primary_confirmed_entity,
)


@dataclass(frozen=True)
class OrganizationIdentityReadinessResult:
    ready: bool
    readiness: OrganizationIdentityReadiness
    has_organization: bool
    has_legal_name: bool
    has_registration_country: bool
    has_organization_type: bool
    has_primary_entity: bool
    has_confirmed_scope: bool
    has_confirmed_identity: bool
    missing_reasons: list[str] = field(default_factory=list)


def evaluate_identity_readiness(
    db: Session, organization_id: int
) -> OrganizationIdentityReadinessResult:
    """Deterministic readiness evaluator — every input traced back to a real record."""
    organization = db.query(Organization).filter(Organization.id == organization_id).first()
    confirmation = get_active_identity_confirmation(db, organization_id)
    primary_entity = get_primary_confirmed_entity(db, organization_id)
    confirmed_scope = get_confirmed_scope(db, organization_id)

    has_organization = organization is not None
    has_legal_name = bool(organization and organization.name)
    has_registration_country = bool(organization and organization.country)
    has_organization_type = bool(organization and organization.organization_type)
    has_primary_entity = primary_entity is not None
    has_confirmed_scope = confirmed_scope is not None
    has_confirmed_identity = confirmation is not None

    reasons: list[str] = []
    if not has_organization:
        reasons.append("organization_missing")
    if not has_legal_name:
        reasons.append("legal_name_missing")
    if not has_registration_country:
        reasons.append("registration_country_missing")
    if not has_organization_type:
        reasons.append("organisation_type_missing")
    if not has_primary_entity:
        reasons.append("primary_entity_not_confirmed")
    if not has_confirmed_scope:
        reasons.append("scope_not_confirmed")
    if not has_confirmed_identity:
        reasons.append("identity_not_confirmed")

    ready = not reasons
    if ready:
        readiness = OrganizationIdentityReadiness.READY
    elif has_organization and (has_legal_name or has_registration_country):
        readiness = OrganizationIdentityReadiness.IN_PROGRESS
    else:
        readiness = OrganizationIdentityReadiness.MISSING

    return OrganizationIdentityReadinessResult(
        ready=ready,
        readiness=readiness,
        has_organization=has_organization,
        has_legal_name=has_legal_name,
        has_registration_country=has_registration_country,
        has_organization_type=has_organization_type,
        has_primary_entity=has_primary_entity,
        has_confirmed_scope=has_confirmed_scope,
        has_confirmed_identity=has_confirmed_identity,
        missing_reasons=reasons,
    )


@dataclass(frozen=True)
class SignupIdentityContext:
    """Identity facts already captured during pretenant signup (the
    CvrEnrichmentClient result, persisted on ``Organization`` at signup
    time). This stage reviews and confirms these — it never asks the user
    to search for or re-enter an organisation Risklence has already
    identified."""

    has_data: bool
    legal_name: str | None
    registration_number: str | None
    registration_country: str | None
    industry_code: str | None
    industry_label: str | None


def get_signup_identity_context(db: Session, organization_id: int) -> SignupIdentityContext:
    organization = db.query(Organization).filter(Organization.id == organization_id).first()
    if organization is None:
        return SignupIdentityContext(False, None, None, None, None, None)
    return SignupIdentityContext(
        has_data=bool(organization.name or organization.cvr_number),
        legal_name=organization.name,
        registration_number=organization.cvr_number,
        registration_country=organization.country,
        industry_code=organization.nace_code,
        industry_label=organization.industry,
    )


@dataclass(frozen=True)
class EntityContext:
    included_entity_ids: list[str]
    known_related_entity_ids: list[str]
    excluded_entity_ids: list[str]
    included_countries: list[str]


@dataclass(frozen=True)
class IndustryContext:
    registry_industry: str | None
    confirmed_archetypes: list[str]
    confirmed_operating_characteristics: list[str]
    unresolved_suggestions: int


@dataclass(frozen=True)
class PreparedOrganisationIdentity:
    """Business-readable summary consumed by later onboarding stages
    (organisation structure setup, evidence-source configuration, Business
    Service/Process suggestion generation)."""

    organization_id: int
    primary_entity_id: str | None
    confirmed_scope_id: str | None
    legal_name: str | None
    registration_number: str | None
    registration_country: str | None
    verified_domains: list[str]
    unverified_domains: list[str]
    entity_context: EntityContext
    industry_context: IndustryContext
    readiness: OrganizationIdentityReadiness


def _build_entity_context(
    db: Session, organization_id: int, confirmed_scope: OrganizationScope | None
) -> EntityContext:
    entities = (
        db.query(OrganizationLegalEntity)
        .filter(OrganizationLegalEntity.organization_id == organization_id)
        .all()
    )
    confirmed_ids = [e.id for e in entities if e.status == OrganizationEntityStatus.CONFIRMED.value]
    excluded_ids = {e.id for e in entities if e.status == OrganizationEntityStatus.EXCLUDED.value}
    known_related_ids = [
        e.id for e in entities if e.status == OrganizationEntityStatus.SUGGESTED.value
    ]

    included_ids: list[str] = []
    included_countries: list[str] = []
    if confirmed_scope is not None:
        if confirmed_scope.scope_type == OrganizationScopeType.ENTIRE_ORGANIZATION.value:
            # "Entire organisation" scope has nothing to select — every
            # confirmed entity is in scope by definition.
            included_ids = confirmed_ids
        else:
            included_ids = list(confirmed_scope.included_entity_ids or [])
        included_countries = list(confirmed_scope.included_countries or [])
        excluded_ids |= set(confirmed_scope.excluded_entity_ids or [])

    return EntityContext(
        included_entity_ids=included_ids,
        known_related_entity_ids=known_related_ids,
        excluded_entity_ids=sorted(excluded_ids),
        included_countries=included_countries,
    )


def build_prepared_organisation_identity(
    db: Session, organization_id: int
) -> PreparedOrganisationIdentity:
    organization = db.query(Organization).filter(Organization.id == organization_id).first()
    primary_entity: OrganizationLegalEntity | None = get_primary_confirmed_entity(
        db, organization_id
    )
    confirmed_scope = get_confirmed_scope(db, organization_id)
    readiness_result = evaluate_identity_readiness(db, organization_id)

    domains = (
        db.query(OrganizationDomain)
        .filter(
            OrganizationDomain.organization_id == organization_id,
            OrganizationDomain.domain_type.in_(
                [OrganizationDomainType.PRIMARY.value, OrganizationDomainType.EMAIL.value]
            ),
        )
        .all()
    )
    verified = [d.domain for d in domains if d.verification_status == "verified"]
    unverified = [d.domain for d in domains if d.verification_status != "verified"]
    operating_context = (
        db.query(OrganizationOperatingContextSuggestion)
        .filter(
            OrganizationOperatingContextSuggestion.organization_id == organization_id,
            OrganizationOperatingContextSuggestion.superseded_by_id.is_(None),
        )
        .all()
    )
    confirmed_archetypes = [
        item.suggestion_key
        for item in operating_context
        if item.suggestion_type == "industry_archetype"
        and item.status == SuggestionDecision.CONFIRMED.value
    ]
    confirmed_characteristics = [
        item.suggestion_key
        for item in operating_context
        if item.suggestion_type == "operating_characteristic"
        and item.status == SuggestionDecision.CONFIRMED.value
    ]
    unresolved_count = sum(
        item.status == SuggestionDecision.SUGGESTED.value for item in operating_context
    )

    return PreparedOrganisationIdentity(
        organization_id=organization_id,
        primary_entity_id=primary_entity.id if primary_entity else None,
        confirmed_scope_id=confirmed_scope.id if confirmed_scope else None,
        legal_name=organization.name if organization else None,
        registration_number=primary_entity.registration_number if primary_entity else None,
        registration_country=organization.country if organization else None,
        verified_domains=verified,
        unverified_domains=unverified,
        entity_context=_build_entity_context(db, organization_id, confirmed_scope),
        industry_context=IndustryContext(
            registry_industry=organization.industry if organization else None,
            confirmed_archetypes=confirmed_archetypes,
            confirmed_operating_characteristics=confirmed_characteristics,
            unresolved_suggestions=unresolved_count,
        ),
        readiness=readiness_result.readiness,
    )
