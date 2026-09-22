"""
Seed six Organisation Identity Setup (Step 1) development scenarios.

No real customer data — every registry fact comes from
``MockRegistryProvider`` (see ``organization_registry_provider.py``), never
a live CVR lookup. Idempotent: each scenario is keyed by a fixed slug and
skipped if it already exists.

Usage:
    poetry run python scripts/seed_organization_identity.py

Scenarios:
    1. A single Danish legal entity (registry happy path).
    2. A corporate group with one entity confirmed in scope, one left
       suggested/unresolved.
    3. A registration in a country with no configured registry provider,
       falling back to manual identity entry.
    4. A non-profit organisation using manual identity entry throughout.
    5. An organisation with registry industry information captured (via
       the read model's industryContext.registryIndustry).
    6. An organisation whose identity is complete but whose optional group
       structure remains partial (unresolved subsidiary, unverified
       domain) — proves optional gaps never block readiness.
"""

from src.core.constants.organization_identity_enums import (
    OrganizationDomainType,
    OrganizationEntityStatus,
    OrganizationEntityType,
    OrganizationScopeType,
    OrganizationType,
)
from src.core.database import get_db_context
from src.core.model_defs.tenant_identity import User
from src.core.model_defs.tenant_org import Organization
from src.core.services.organization_identity_readiness_service import (
    build_prepared_organisation_identity,
    evaluate_identity_readiness,
)
from src.core.services.organization_identity_service import (
    OrganizationIdentityRegistryUnavailableError,
    add_domain,
    confirm_legal_entity,
    confirm_organization_identity,
    confirm_scope,
    create_legal_entity,
    create_scope,
    record_manual_identity_evidence,
    run_registry_lookup,
)
from src.core.services.organization_registry_provider import MockRegistryProvider


def _ensure_org(db, *, slug: str, name: str, country: str = "DK") -> tuple[Organization, bool]:
    existing = db.query(Organization).filter(Organization.slug == slug).first()
    if existing is not None:
        return existing, False
    org = Organization(name=name, slug=slug, country=country)
    db.add(org)
    db.flush()
    admin = User(
        organization_id=org.id,
        email=f"admin@{slug}.seed.local",
        role="org_admin",
        first_name="Seed",
        last_name="Admin",
    )
    db.add(admin)
    db.flush()
    return org, True


def _admin_id(db, org_id: int) -> int:
    return db.query(User).filter(User.organization_id == org_id, User.role == "org_admin").first().id


def seed_single_dk_entity(db) -> None:
    org, created = _ensure_org(db, slug="seed-org-identity-single-dk", name="Seed Single DK Entity ApS")
    if not created:
        return
    admin_id = _admin_id(db, org.id)
    evidence = run_registry_lookup(
        db,
        organization_id=org.id,
        registration_country="DK",
        registration_number="10000001",
        provider=MockRegistryProvider(),
    )
    confirm_organization_identity(
        db,
        organization_id=org.id,
        confirmed_by_user_id=admin_id,
        legal_name=evidence.raw_legal_name,
        registration_country="DK",
        organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
        evidence_id=evidence.id,
    )
    entity = create_legal_entity(
        db,
        organization_id=org.id,
        legal_name=evidence.raw_legal_name,
        registration_country="DK",
        registration_number=evidence.source_reference,
        entity_type=OrganizationEntityType.PARENT,
        is_primary=True,
        status=OrganizationEntityStatus.CONFIRMED,
        source_evidence_id=evidence.id,
    )
    confirm_legal_entity(db, entity)
    scope = create_scope(
        db, organization_id=org.id, scope_type=OrganizationScopeType.ENTIRE_ORGANIZATION, name="Entire organisation"
    )
    confirm_scope(db, scope, confirmed_by_user_id=admin_id)


def seed_corporate_group_partial_scope(db) -> None:
    org, created = _ensure_org(db, slug="seed-org-identity-corporate-group", name="Seed Corporate Group Holding ApS")
    if not created:
        return
    admin_id = _admin_id(db, org.id)
    confirm_organization_identity(
        db,
        organization_id=org.id,
        confirmed_by_user_id=admin_id,
        legal_name="Seed Corporate Group Holding ApS",
        registration_country="DK",
        organization_type=OrganizationType.CORPORATE_GROUP,
    )
    primary = create_legal_entity(
        db,
        organization_id=org.id,
        legal_name="Seed Corporate Group Holding ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.HOLDING_COMPANY,
        is_primary=True,
        status=OrganizationEntityStatus.CONFIRMED,
    )
    confirm_legal_entity(db, primary)
    # Left as a registry suggestion, deliberately unresolved — spec §3.2:
    # "Do not require a complete global group structure during initial setup."
    create_legal_entity(
        db,
        organization_id=org.id,
        legal_name="Seed Corporate Group Sweden AB",
        registration_country="SE",
        entity_type=OrganizationEntityType.SUBSIDIARY,
    )
    scope = create_scope(
        db,
        organization_id=org.id,
        scope_type=OrganizationScopeType.LEGAL_ENTITY,
        name="Danish holding company only",
        included_entity_ids=[primary.id],
    )
    confirm_scope(db, scope, confirmed_by_user_id=admin_id)


def seed_unsupported_country_manual_fallback(db) -> None:
    org, created = _ensure_org(
        db, slug="seed-org-identity-unsupported-country", name="Seed Unsupported Registry AB", country="SE"
    )
    if not created:
        return
    admin_id = _admin_id(db, org.id)
    try:
        run_registry_lookup(
            db, organization_id=org.id, registration_country="SE", registration_number="10000002"
        )
    except OrganizationIdentityRegistryUnavailableError:
        pass  # expected — no provider is configured for SE; fall back to manual entry.
    evidence = record_manual_identity_evidence(
        db, organization_id=org.id, legal_name="Seed Unsupported Registry AB", registration_country="SE"
    )
    confirm_organization_identity(
        db,
        organization_id=org.id,
        confirmed_by_user_id=admin_id,
        legal_name="Seed Unsupported Registry AB",
        registration_country="SE",
        organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
        evidence_id=evidence.id,
    )
    entity = create_legal_entity(
        db,
        organization_id=org.id,
        legal_name="Seed Unsupported Registry AB",
        registration_country="SE",
        entity_type=OrganizationEntityType.PARENT,
        is_primary=True,
        status=OrganizationEntityStatus.CONFIRMED,
        source_evidence_id=evidence.id,
    )
    confirm_legal_entity(db, entity)
    scope = create_scope(
        db, organization_id=org.id, scope_type=OrganizationScopeType.ENTIRE_ORGANIZATION, name="Entire organisation"
    )
    confirm_scope(db, scope, confirmed_by_user_id=admin_id)


def seed_non_profit_manual(db) -> None:
    org, created = _ensure_org(db, slug="seed-org-identity-non-profit", name="Seed Community Trust")
    if not created:
        return
    admin_id = _admin_id(db, org.id)
    evidence = record_manual_identity_evidence(
        db, organization_id=org.id, legal_name="Seed Community Trust", registration_country="DK"
    )
    confirm_organization_identity(
        db,
        organization_id=org.id,
        confirmed_by_user_id=admin_id,
        legal_name="Seed Community Trust",
        registration_country="DK",
        organization_type=OrganizationType.NON_PROFIT,
        evidence_id=evidence.id,
    )
    entity = create_legal_entity(
        db,
        organization_id=org.id,
        legal_name="Seed Community Trust",
        registration_country="DK",
        entity_type=OrganizationEntityType.OTHER,
        is_primary=True,
        status=OrganizationEntityStatus.CONFIRMED,
        source_evidence_id=evidence.id,
    )
    confirm_legal_entity(db, entity)
    scope = create_scope(
        db, organization_id=org.id, scope_type=OrganizationScopeType.ENTIRE_ORGANIZATION, name="Entire organisation"
    )
    confirm_scope(db, scope, confirmed_by_user_id=admin_id)


def seed_registry_industry_context(db) -> None:
    org, created = _ensure_org(db, slug="seed-org-identity-industry-context", name="Seed Retail Specialist ApS")
    if not created:
        return
    admin_id = _admin_id(db, org.id)
    evidence = run_registry_lookup(
        db,
        organization_id=org.id,
        registration_country="DK",
        registration_number="10000003",
        provider=MockRegistryProvider(),
    )
    # industryContext.registryIndustry reads Organization.industry, the
    # same field pretenant signup already populates from CvrEnrichmentClient
    # — this seed mirrors that, it does not invent a new field.
    org.industry = "Retail sale of specialist products"
    db.add(org)
    confirm_organization_identity(
        db,
        organization_id=org.id,
        confirmed_by_user_id=admin_id,
        legal_name=evidence.raw_legal_name,
        registration_country="DK",
        organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
        evidence_id=evidence.id,
    )
    entity = create_legal_entity(
        db,
        organization_id=org.id,
        legal_name=evidence.raw_legal_name,
        registration_country="DK",
        registration_number=evidence.source_reference,
        entity_type=OrganizationEntityType.PARENT,
        is_primary=True,
        status=OrganizationEntityStatus.CONFIRMED,
        source_evidence_id=evidence.id,
    )
    confirm_legal_entity(db, entity)
    scope = create_scope(
        db, organization_id=org.id, scope_type=OrganizationScopeType.ENTIRE_ORGANIZATION, name="Entire organisation"
    )
    confirm_scope(db, scope, confirmed_by_user_id=admin_id)


def seed_complete_with_partial_optional_group(db) -> None:
    org, created = _ensure_org(db, slug="seed-org-identity-partial-group", name="Seed Partial Group Holdings ApS")
    if not created:
        return
    admin_id = _admin_id(db, org.id)
    confirm_organization_identity(
        db,
        organization_id=org.id,
        confirmed_by_user_id=admin_id,
        legal_name="Seed Partial Group Holdings ApS",
        registration_country="DK",
        organization_type=OrganizationType.CORPORATE_GROUP,
    )
    primary = create_legal_entity(
        db,
        organization_id=org.id,
        legal_name="Seed Partial Group Holdings ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.HOLDING_COMPANY,
        is_primary=True,
        status=OrganizationEntityStatus.CONFIRMED,
    )
    confirm_legal_entity(db, primary)
    # Unresolved subsidiary + unverified domain: neither may block readiness.
    create_legal_entity(
        db,
        organization_id=org.id,
        legal_name="Seed Partial Group Norway AS",
        registration_country="NO",
        entity_type=OrganizationEntityType.SUBSIDIARY,
    )
    add_domain(db, organization_id=org.id, domain="seed-partial-group.example", domain_type=OrganizationDomainType.PRIMARY)
    scope = create_scope(
        db, organization_id=org.id, scope_type=OrganizationScopeType.ENTIRE_ORGANIZATION, name="Entire organisation"
    )
    confirm_scope(db, scope, confirmed_by_user_id=admin_id)


SCENARIOS = [
    seed_single_dk_entity,
    seed_corporate_group_partial_scope,
    seed_unsupported_country_manual_fallback,
    seed_non_profit_manual,
    seed_registry_industry_context,
    seed_complete_with_partial_optional_group,
]


def main() -> None:
    with get_db_context() as db:
        for scenario in SCENARIOS:
            scenario(db)
            db.commit()
        for org in db.query(Organization).filter(Organization.slug.like("seed-org-identity-%")).all():
            readiness = evaluate_identity_readiness(db, org.id)
            prepared = build_prepared_organisation_identity(db, org.id)
            print(
                f"{org.slug}: readiness={readiness.readiness.value} "
                f"entities(included={len(prepared.entity_context.included_entity_ids)}, "
                f"known_related={len(prepared.entity_context.known_related_entity_ids)}, "
                f"excluded={len(prepared.entity_context.excluded_entity_ids)}) "
                f"registry_industry={prepared.industry_context.registry_industry!r}"
            )


if __name__ == "__main__":
    main()
