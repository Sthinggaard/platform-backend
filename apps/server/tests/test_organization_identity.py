"""Organisation Identity Setup: readiness, versioned confirmation, tenant isolation."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import organization_identity as org_identity_routes
from src.core.constants.organization_identity_enums import (
    ORG_IDENTITY_AUDIT_CONFIRMED,
    ORG_IDENTITY_AUDIT_CORRECTED,
    ORG_IDENTITY_AUDIT_ENTITY_ADDED,
    ORG_IDENTITY_AUDIT_ENTITY_CONFIRMED,
    ORG_IDENTITY_AUDIT_INDUSTRY_ARCHETYPE_CONFIRMED,
    ORG_IDENTITY_AUDIT_OPERATING_CHARACTERISTIC_REJECTED,
    ORG_IDENTITY_AUDIT_SETUP_COMPLETED,
    OrganizationDomainType,
    OrganizationEntityStatus,
    OrganizationEntityType,
    OrganizationIdentityReadiness,
    OrganizationOperatingContextSuggestionType,
    OrganizationScopeType,
    OrganizationType,
    RegistryLookupStatus,
    SuggestionDecision,
)
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.organization_identity import (
    OrganizationDomain,
    OrganizationIdentityConfirmation,
    OrganizationIdentityEvidence,
    OrganizationLegalEntity,
    OrganizationOperatingContextSuggestion,
    OrganizationScope,
)
from src.core.models import AuditEvent, Organization, User
from src.core.services.organization_identity_readiness_service import (
    build_prepared_organisation_identity,
    evaluate_identity_readiness,
    get_signup_identity_context,
)
from src.core.services.organization_identity_service import (
    OrganizationIdentityRegistryLookupError,
    OrganizationIdentityRegistryUnavailableError,
    OrganizationIdentityValidationError,
    add_domain,
    confirm_organization_identity,
    confirm_scope,
    create_legal_entity,
    create_scope,
    exclude_legal_entity,
    record_manual_identity_evidence,
    run_registry_lookup,
    upsert_primary_legal_entity,
)
from src.core.services.organization_operating_context_service import (
    add_operating_context_suggestion,
    decide_operating_context_suggestion,
    prepare_operating_context_suggestions,
)
from src.core.services.organization_registry_provider import (
    CvrRegistryProvider,
    MockRegistryProvider,
    RegistryProviderNotSupportedError,
    get_registry_provider_for_country,
)
from src.pretenant.enrichment import CvrEnrichmentResult, CvrNotFoundError, CvrTimeoutError


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            User.__table__,
            OrganizationIdentityEvidence.__table__,
            OrganizationLegalEntity.__table__,
            OrganizationScope.__table__,
            OrganizationIdentityConfirmation.__table__,
            OrganizationDomain.__table__,
            OrganizationOperatingContextSuggestion.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org", country="DK"),
            Organization(id=2, name="Other Org", slug="other-org", country="DK"),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
            User(id=2, organization_id=1, email="member@example.com", role="member"),
            User(id=3, organization_id=2, email="admin2@example.com", role="org_admin"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _ctx(user_id: int, organization_id: int = 1, role: str = "org_admin") -> TenantContext:
    return TenantContext(
        user_id=user_id,
        organization_id=organization_id,
        email="x@example.com",
        roles=[role],
        permissions=[],
    )


class _FakeCvrClient:
    def __init__(self, result: CvrEnrichmentResult | None = None, error: Exception | None = None):
        self._result = result
        self._error = error

    def enrich(self, cvr: str) -> CvrEnrichmentResult:
        if self._error is not None:
            raise self._error
        return self._result


# --- Registry lookup / evidence ---------------------------------------------


def test_registry_lookup_stores_evidence_from_the_enrichment_client(db: Session):
    result = CvrEnrichmentResult(
        cvr="12345678",
        legal_name="Example Retail Denmark ApS",
        industry_code="47.19",
        country="DK",
        enriched_at=datetime.now(timezone.utc),
    )
    evidence = run_registry_lookup(
        db,
        organization_id=1,
        registration_country="DK",
        registration_number="12345678",
        provider=CvrRegistryProvider(client=_FakeCvrClient(result=result)),
    )
    assert evidence.raw_legal_name == "Example Retail Denmark ApS"
    assert evidence.source_reference == "12345678"
    assert evidence.source_type == "cvr"


def test_registry_lookup_not_found_raises_validation_error(db: Session):
    with pytest.raises(OrganizationIdentityValidationError):
        run_registry_lookup(
            db,
            organization_id=1,
            registration_country="DK",
            registration_number="00000000",
            provider=CvrRegistryProvider(
                client=_FakeCvrClient(error=CvrNotFoundError("not found"))
            ),
        )


def test_registry_lookup_timeout_raises_registry_unavailable_error(db: Session):
    with pytest.raises(OrganizationIdentityRegistryUnavailableError):
        run_registry_lookup(
            db,
            organization_id=1,
            registration_country="DK",
            registration_number="12345678",
            provider=CvrRegistryProvider(client=_FakeCvrClient(error=CvrTimeoutError("timeout"))),
        )


def test_registry_lookup_uses_country_based_provider_dispatch_by_default(db: Session):
    # No explicit provider passed — DK must resolve to the real CvrRegistryProvider
    # via get_registry_provider_for_country, proving the dispatch actually wires up.
    provider = get_registry_provider_for_country("DK")
    assert isinstance(provider, CvrRegistryProvider)


def test_registry_lookup_rejects_unsupported_country(db: Session):
    with pytest.raises(OrganizationIdentityRegistryLookupError) as error:
        run_registry_lookup(
            db, organization_id=1, registration_country="SE", registration_number="12345678"
        )
    assert error.value.status == RegistryLookupStatus.MANUAL_REQUIRED


def test_mock_registry_provider_returns_deterministic_result(db: Session):
    evidence = run_registry_lookup(
        db,
        organization_id=1,
        registration_country="DK",
        registration_number="87654321",
        provider=MockRegistryProvider(),
    )
    assert evidence.raw_legal_name == "Mock Registered Company 87654321"


def test_mock_registry_provider_not_found_sentinel(db: Session):
    with pytest.raises(OrganizationIdentityRegistryLookupError) as error:
        run_registry_lookup(
            db,
            organization_id=1,
            registration_country="DK",
            registration_number=MockRegistryProvider.NOT_FOUND_SENTINEL,
            provider=MockRegistryProvider(),
        )
    assert error.value.status == RegistryLookupStatus.NO_MATCH


@pytest.mark.parametrize(
    ("registration_number", "expected_status"),
    [
        (MockRegistryProvider.INACTIVE_SENTINEL, RegistryLookupStatus.INACTIVE),
        (MockRegistryProvider.UNAVAILABLE_SENTINEL, RegistryLookupStatus.UNAVAILABLE),
    ],
)
def test_mock_registry_provider_exposes_recoverable_exception_states(
    db: Session, registration_number: str, expected_status: RegistryLookupStatus
):
    with pytest.raises(OrganizationIdentityRegistryLookupError) as error:
        run_registry_lookup(
            db,
            organization_id=1,
            registration_country="DK",
            registration_number=registration_number,
            provider=MockRegistryProvider(),
        )
    assert error.value.status == expected_status


def test_mock_registry_provider_returns_multiple_attributable_candidates(db: Session):
    with pytest.raises(OrganizationIdentityRegistryLookupError) as error:
        run_registry_lookup(
            db,
            organization_id=1,
            registration_country="DK",
            registration_number=MockRegistryProvider.MULTIPLE_MATCHES_SENTINEL,
            provider=MockRegistryProvider(),
        )
    assert error.value.status == RegistryLookupStatus.MULTIPLE_MATCHES
    assert [candidate.raw_legal_name for candidate in error.value.candidates] == [
        "Mock Group Denmark ApS",
        "Mock Group Services ApS",
    ]
    assert {candidate.source_type for candidate in error.value.candidates} == {"cvr"}
    assert db.query(OrganizationIdentityEvidence).filter_by(organization_id=1).count() == 2


def test_registry_lookup_route_returns_multiple_candidates_and_audits_imports(
    db: Session, monkeypatch
):
    def raise_multiple(*_args, **_kwargs):
        run_registry_lookup(
            db,
            organization_id=1,
            registration_country="DK",
            registration_number=MockRegistryProvider.MULTIPLE_MATCHES_SENTINEL,
            provider=MockRegistryProvider(),
        )

    monkeypatch.setattr(org_identity_routes, "run_registry_lookup", raise_multiple)
    response = org_identity_routes.registry_lookup(
        org_identity_routes.RegistryLookupRequest(
            registration_country="DK", registration_number="99999999"
        ),
        _ctx(1),
        db,
    )
    assert response.status == RegistryLookupStatus.MULTIPLE_MATCHES
    assert len(response.candidates) == 2
    assert (
        db.query(AuditEvent).filter_by(event_type="organization.identity_evidence_imported").count()
        == 2
    )


def test_domain_mutations_require_admin_and_cannot_cross_tenant_boundaries(db: Session):
    with pytest.raises(AuthorizationError):
        org_identity_routes.add_domain_route(
            org_identity_routes.DomainRequest(
                domain="example.dk", domain_type=OrganizationDomainType.PRIMARY
            ),
            _ctx(2, role="member"),
            db,
        )

    other_domain = add_domain(
        db, organization_id=2, domain="other.example", domain_type=OrganizationDomainType.PRIMARY
    )
    db.commit()
    with pytest.raises(ResourceNotFoundError):
        org_identity_routes.verify_domain_route(other_domain.id, _ctx(1), db)


def test_domain_route_returns_manual_verification_provenance(db: Session):
    created = org_identity_routes.add_domain_route(
        org_identity_routes.DomainRequest(
            domain="example.dk", domain_type=OrganizationDomainType.PRIMARY
        ),
        _ctx(1),
        db,
    )
    verified = org_identity_routes.verify_domain_route(created.id, _ctx(1), db)
    assert verified.verification_status == "verified"
    assert verified.verification_method == "manual"
    assert verified.verified_by_user_id == 1
    assert verified.verified_at is not None


def test_get_registry_provider_for_country_raises_for_unsupported_country():
    with pytest.raises(RegistryProviderNotSupportedError):
        get_registry_provider_for_country("SE")


def test_manual_evidence_requires_legal_name(db: Session):
    with pytest.raises(OrganizationIdentityValidationError):
        record_manual_identity_evidence(
            db, organization_id=1, legal_name="   ", registration_country="DK"
        )


def test_manual_evidence_can_be_used_to_confirm_identity(db: Session):
    evidence = record_manual_identity_evidence(
        db, organization_id=1, legal_name="Community Foundation", registration_country="DK"
    )
    confirmation = confirm_organization_identity(
        db,
        organization_id=1,
        confirmed_by_user_id=1,
        legal_name="Community Foundation",
        registration_country="DK",
        organization_type=OrganizationType.NON_PROFIT,
        evidence_id=evidence.id,
    )
    assert confirmation.evidence_id == evidence.id
    assert evidence.source_type == "user"


def test_confirmation_rejects_evidence_from_another_tenant(db: Session):
    evidence = record_manual_identity_evidence(
        db, organization_id=2, legal_name="Other Org", registration_country="DK"
    )
    with pytest.raises(OrganizationIdentityValidationError):
        confirm_organization_identity(
            db,
            organization_id=1,
            confirmed_by_user_id=1,
            legal_name="Example Retail Denmark ApS",
            registration_country="DK",
            organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
            evidence_id=evidence.id,
        )


# --- Signup-carried identity data (no redundant re-search) -----------------


def test_signup_context_reports_no_data_for_a_bare_signup(db: Session):
    # Organization.name is NOT NULL, so a genuinely nameless/CVR-less org is
    # a degraded edge case rather than the everyday shape — simulate it
    # explicitly rather than assuming the fixture org qualifies.
    organization = db.query(Organization).filter(Organization.id == 1).first()
    organization.name = ""
    db.commit()

    context = get_signup_identity_context(db, 1)
    assert context.has_data is False


def test_signup_context_surfaces_data_already_captured_at_pretenant_signup(db: Session):
    organization = db.query(Organization).filter(Organization.id == 1).first()
    organization.cvr_number = "12345678"
    organization.nace_code = "47.19"
    organization.industry = "Specialist retail"
    db.commit()

    context = get_signup_identity_context(db, 1)
    assert context.has_data is True
    assert context.registration_number == "12345678"
    assert context.legal_name == "Org"
    assert context.industry_code == "47.19"


def test_confirming_identity_without_a_fresh_lookup_attaches_evidence_from_the_signup_cvr(
    db: Session,
):
    # The org arrived via a CVR-driven signup + activation link — this
    # stage must not silently confirm identity with no attributable source
    # just because the user didn't re-run a registry lookup here.
    organization = db.query(Organization).filter(Organization.id == 1).first()
    organization.cvr_number = "12345678"
    organization.nace_code = "47.19"
    db.commit()

    confirmation = confirm_organization_identity(
        db,
        organization_id=1,
        confirmed_by_user_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
    )
    assert confirmation.evidence_id is not None
    evidence = (
        db.query(OrganizationIdentityEvidence)
        .filter(OrganizationIdentityEvidence.id == confirmation.evidence_id)
        .first()
    )
    assert evidence.source_type == "cvr"
    assert evidence.source_reference == "12345678"


def test_auto_evidence_from_signup_is_reused_not_duplicated_on_a_correction(db: Session):
    organization = db.query(Organization).filter(Organization.id == 1).first()
    organization.cvr_number = "12345678"
    db.commit()

    first = confirm_organization_identity(
        db,
        organization_id=1,
        confirmed_by_user_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
    )
    second = confirm_organization_identity(
        db,
        organization_id=1,
        confirmed_by_user_id=1,
        legal_name="Example Retail Denmark A/S",
        registration_country="DK",
        organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
        correction_reason="Legal form corrected.",
    )
    assert first.evidence_id == second.evidence_id
    assert (
        db.query(OrganizationIdentityEvidence)
        .filter(OrganizationIdentityEvidence.organization_id == 1)
        .count()
        == 1
    )


# --- Operating profile context ------------------------------------------------


def test_nace_operating_context_is_suggested_with_provenance_not_confirmed(db: Session):
    organization = db.query(Organization).filter(Organization.id == 1).first()
    organization.nace_code = "62.01"
    organization.industry = "Computer programming activities"
    db.commit()

    suggestions = prepare_operating_context_suggestions(db, organization)

    assert {(item.suggestion_type, item.suggestion_key) for item in suggestions} == {
        ("industry_archetype", "software_as_a_service"),
        ("operating_characteristic", "subscription_services"),
        ("operating_characteristic", "business_to_business_services"),
        ("operating_characteristic", "cloud_based_delivery"),
        ("operating_characteristic", "regulated_data_handling"),
    }
    assert {item.source_type for item in suggestions} == {"nace_inference"}
    assert {item.source_reference for item in suggestions} == {"62.01"}
    assert {item.status for item in suggestions} == {SuggestionDecision.SUGGESTED.value}

    prepared = build_prepared_organisation_identity(db, 1)
    assert prepared.industry_context.registry_industry == "Computer programming activities"
    assert prepared.industry_context.confirmed_archetypes == []
    assert prepared.industry_context.confirmed_operating_characteristics == []
    assert prepared.industry_context.unresolved_suggestions == 5


def test_operating_context_decisions_are_append_only_and_prepared_summary_only_uses_confirmed(
    db: Session,
):
    organization = db.query(Organization).filter(Organization.id == 1).first()
    organization.nace_code = "62.01"
    suggestions = prepare_operating_context_suggestions(db, organization)
    archetype = next(
        item
        for item in suggestions
        if item.suggestion_type
        == OrganizationOperatingContextSuggestionType.INDUSTRY_ARCHETYPE.value
    )
    characteristic = next(
        item for item in suggestions if item.suggestion_key == "regulated_data_handling"
    )

    confirmed = decide_operating_context_suggestion(
        db, archetype, status=SuggestionDecision.CONFIRMED, decided_by_user_id=1
    )
    rejected = decide_operating_context_suggestion(
        db, characteristic, status=SuggestionDecision.REJECTED, decided_by_user_id=1
    )
    db.commit()

    assert archetype.superseded_by_id == confirmed.id
    assert characteristic.superseded_by_id == rejected.id
    assert confirmed.source_type == "nace_inference"
    assert confirmed.source_reference == "62.01"
    assert rejected.decided_by_user_id == 1
    assert rejected.decided_at is not None

    prepared = build_prepared_organisation_identity(db, 1)
    assert prepared.industry_context.confirmed_archetypes == ["software_as_a_service"]
    assert prepared.industry_context.confirmed_operating_characteristics == []
    assert prepared.industry_context.unresolved_suggestions == 3


def test_operating_context_addition_is_limited_to_the_structured_catalogue(db: Session):
    with pytest.raises(ValueError, match="available operating-context"):
        add_operating_context_suggestion(
            db,
            organization_id=1,
            suggestion_type=OrganizationOperatingContextSuggestionType.OPERATING_CHARACTERISTIC,
            suggestion_key="unstructured free text",
        )


def test_structured_operating_context_addition_does_not_duplicate_an_active_suggestion(
    db: Session,
):
    organization = db.query(Organization).filter(Organization.id == 1).first()
    organization.nace_code = "62.01"
    existing = prepare_operating_context_suggestions(db, organization)
    cloud_delivery = next(
        item for item in existing if item.suggestion_key == "cloud_based_delivery"
    )

    added = add_operating_context_suggestion(
        db,
        organization_id=1,
        suggestion_type=OrganizationOperatingContextSuggestionType.OPERATING_CHARACTERISTIC,
        suggestion_key="cloud_based_delivery",
    )

    assert added.id == cloud_delivery.id


def test_operating_context_routes_require_admin_are_tenant_isolated_and_audited(db: Session):
    organization = db.query(Organization).filter(Organization.id == 1).first()
    organization.nace_code = "62.01"
    db.commit()

    with pytest.raises(AuthorizationError):
        org_identity_routes.prepare_operating_context(_ctx(2, role="member"), db)

    suggestions = org_identity_routes.prepare_operating_context(_ctx(1), db)
    archetype = next(item for item in suggestions if item.suggestion_type == "industry_archetype")
    confirmed = org_identity_routes.decide_operating_context(
        archetype.id,
        org_identity_routes.OperatingContextDecisionRequest(status=SuggestionDecision.CONFIRMED),
        _ctx(1),
        db,
    )
    assert confirmed.status == SuggestionDecision.CONFIRMED.value

    repeated_confirmation = org_identity_routes.decide_operating_context(
        archetype.id,
        org_identity_routes.OperatingContextDecisionRequest(status=SuggestionDecision.CONFIRMED),
        _ctx(1),
        db,
    )
    assert repeated_confirmation.id == confirmed.id

    revised_decision = org_identity_routes.decide_operating_context(
        confirmed.id,
        org_identity_routes.OperatingContextDecisionRequest(status=SuggestionDecision.REJECTED),
        _ctx(1),
        db,
    )
    assert revised_decision.status == SuggestionDecision.REJECTED.value
    assert (
        db.query(AuditEvent)
        .filter(AuditEvent.event_type == ORG_IDENTITY_AUDIT_INDUSTRY_ARCHETYPE_CONFIRMED)
        .count()
        == 1
    )

    other = add_operating_context_suggestion(
        db,
        organization_id=2,
        suggestion_type=OrganizationOperatingContextSuggestionType.OPERATING_CHARACTERISTIC,
        suggestion_key="cloud_based_delivery",
    )
    db.commit()
    with pytest.raises(ResourceNotFoundError):
        org_identity_routes.decide_operating_context(
            other.id,
            org_identity_routes.OperatingContextDecisionRequest(status=SuggestionDecision.REJECTED),
            _ctx(1),
            db,
        )

    rejected = next(item for item in suggestions if item.suggestion_key == "cloud_based_delivery")
    org_identity_routes.decide_operating_context(
        rejected.id,
        org_identity_routes.OperatingContextDecisionRequest(status=SuggestionDecision.REJECTED),
        _ctx(1),
        db,
    )
    assert (
        db.query(AuditEvent)
        .filter(AuditEvent.event_type == ORG_IDENTITY_AUDIT_OPERATING_CHARACTERISTIC_REJECTED)
        .count()
        == 1
    )


# --- Identity confirmation lifecycle ----------------------------------------


def test_confirm_identity_requires_an_active_confirming_user(db: Session):
    with pytest.raises(OrganizationIdentityValidationError):
        confirm_organization_identity(
            db,
            organization_id=1,
            confirmed_by_user_id=999,
            legal_name="Example Retail Denmark ApS",
            registration_country="DK",
            organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
        )


def test_first_confirmation_succeeds_without_a_correction_reason(db: Session):
    confirmation = confirm_organization_identity(
        db,
        organization_id=1,
        confirmed_by_user_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
    )
    assert confirmation.version == 1
    assert confirmation.status == "confirmed"
    assert confirmation.confirmed_by_user_id == 1
    organization = db.query(Organization).filter(Organization.id == 1).first()
    assert organization.name == "Example Retail Denmark ApS"
    assert organization.organization_type == OrganizationType.SINGLE_LEGAL_ENTITY.value


def test_correcting_a_confirmed_identity_requires_a_reason(db: Session):
    confirm_organization_identity(
        db,
        organization_id=1,
        confirmed_by_user_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
    )
    with pytest.raises(OrganizationIdentityValidationError):
        confirm_organization_identity(
            db,
            organization_id=1,
            confirmed_by_user_id=1,
            legal_name="Example Retail Denmark A/S",
            registration_country="DK",
            organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
        )


def test_correction_supersedes_the_previous_confirmation_and_retains_its_history(db: Session):
    first = confirm_organization_identity(
        db,
        organization_id=1,
        confirmed_by_user_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
    )
    second = confirm_organization_identity(
        db,
        organization_id=1,
        confirmed_by_user_id=1,
        legal_name="Example Retail Denmark A/S",
        registration_country="DK",
        organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
        correction_reason="Registry corrected the legal form after re-verification.",
    )
    assert second.version == 2
    assert first.status == "superseded"
    assert first.superseded_by_id == second.id
    assert second.correction_reason.startswith("Registry corrected")
    # The prior confirmed row's data is untouched, not overwritten.
    assert first.confirmed_legal_name == "Example Retail Denmark ApS"


# --- Legal entities ----------------------------------------------------------


def test_only_one_primary_legal_entity_at_a_time(db: Session):
    first = create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.PARENT,
        is_primary=True,
    )
    second = create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Sweden AB",
        registration_country="SE",
        entity_type=OrganizationEntityType.SUBSIDIARY,
        is_primary=True,
    )
    db.refresh(first)
    assert first.is_primary is False
    assert second.is_primary is True


def test_excluded_entity_is_never_the_confirmed_primary(db: Session):
    entity = create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.PARENT,
        is_primary=True,
        status=OrganizationEntityStatus.CONFIRMED,
    )
    exclude_legal_entity(db, entity)
    db.commit()
    from src.core.services.organization_identity_service import get_primary_confirmed_entity

    assert get_primary_confirmed_entity(db, 1) is None
    assert entity.status == OrganizationEntityStatus.EXCLUDED.value
    assert entity.is_primary is False


def test_primary_entity_upsert_reuses_the_same_record_for_a_correction(db: Session):
    first, created = upsert_primary_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        registration_number="12345678",
    )
    corrected, correction_created = upsert_primary_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Denmark A/S",
        registration_country="DK",
        registration_number="12345678",
    )
    assert created is True
    assert correction_created is False
    assert corrected.id == first.id
    assert corrected.legal_name == "Example Retail Denmark A/S"
    assert corrected.status == OrganizationEntityStatus.CONFIRMED.value
    assert (
        db.query(OrganizationLegalEntity)
        .filter(OrganizationLegalEntity.organization_id == 1)
        .count()
        == 1
    )


# --- Scope --------------------------------------------------------------------


def test_scope_confirmation_records_actor_and_timestamp(db: Session):
    scope = create_scope(
        db,
        organization_id=1,
        scope_type=OrganizationScopeType.ENTIRE_ORGANIZATION,
        name="Entire organisation",
    )
    confirm_scope(db, scope, confirmed_by_user_id=1)
    db.commit()
    assert scope.status == "confirmed"
    assert scope.confirmed_by_user_id == 1
    assert scope.confirmed_at is not None


def test_scope_rejects_membership_when_entire_organisation_is_selected(db: Session):
    entity = create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.PARENT,
    )

    with pytest.raises(OrganizationIdentityValidationError, match="entire-organisation"):
        create_scope(
            db,
            organization_id=1,
            scope_type=OrganizationScopeType.ENTIRE_ORGANIZATION,
            name="Entire organisation",
            excluded_entity_ids=[entity.id],
        )


def test_scope_rejects_entities_owned_by_another_organisation(db: Session):
    other_tenant_entity = create_legal_entity(
        db,
        organization_id=2,
        legal_name="Other Org ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.PARENT,
    )

    with pytest.raises(OrganizationIdentityValidationError, match="belong to this organisation"):
        create_scope(
            db,
            organization_id=1,
            scope_type=OrganizationScopeType.LEGAL_ENTITY,
            name="Danish entity only",
            included_entity_ids=[other_tenant_entity.id],
        )


def test_scope_requires_membership_for_legal_entity_and_country_types(db: Session):
    with pytest.raises(
        OrganizationIdentityValidationError, match="Select at least one legal entity"
    ):
        create_scope(
            db,
            organization_id=1,
            scope_type=OrganizationScopeType.LEGAL_ENTITY,
            name="Danish entity only",
        )

    with pytest.raises(OrganizationIdentityValidationError, match="Select at least one country"):
        create_scope(
            db,
            organization_id=1,
            scope_type=OrganizationScopeType.COUNTRY,
            name="Danish operations",
        )


def test_prepared_identity_keeps_confirmed_country_scope_context(db: Session):
    scope = create_scope(
        db,
        organization_id=1,
        scope_type=OrganizationScopeType.COUNTRY,
        name="Danish operations",
        included_countries=["dk"],
    )
    confirm_scope(db, scope, confirmed_by_user_id=1)
    db.commit()

    prepared = build_prepared_organisation_identity(db, 1)
    assert prepared.entity_context.included_countries == ["DK"]


def test_legal_entity_parent_must_belong_to_the_same_organisation(db: Session):
    parent = create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Group ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.PARENT,
    )
    child = create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.SUBSIDIARY,
        parent_entity_id=parent.id,
    )
    assert child.parent_entity_id == parent.id

    other_tenant_parent = create_legal_entity(
        db,
        organization_id=2,
        legal_name="Other Org ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.PARENT,
    )
    with pytest.raises(OrganizationIdentityValidationError, match="parent legal entity"):
        create_legal_entity(
            db,
            organization_id=1,
            legal_name="Invalid subsidiary",
            registration_country="DK",
            entity_type=OrganizationEntityType.SUBSIDIARY,
            parent_entity_id=other_tenant_parent.id,
        )


# --- Readiness -----------------------------------------------------------------


def test_readiness_missing_when_nothing_is_recorded_yet(db: Session):
    # Organization row exists (created at signup) but no type/entity/scope/confirmation yet.
    result = evaluate_identity_readiness(db, 1)
    assert result.ready is False
    assert result.readiness in (
        OrganizationIdentityReadiness.MISSING,
        OrganizationIdentityReadiness.IN_PROGRESS,
    )
    assert "identity_not_confirmed" in result.missing_reasons
    assert "scope_not_confirmed" in result.missing_reasons
    assert "primary_entity_not_confirmed" in result.missing_reasons


def test_readiness_not_ready_without_a_confirmed_scope(db: Session):
    confirm_organization_identity(
        db,
        organization_id=1,
        confirmed_by_user_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
    )
    create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.PARENT,
        is_primary=True,
        status=OrganizationEntityStatus.CONFIRMED,
    )
    db.commit()
    result = evaluate_identity_readiness(db, 1)
    assert result.ready is False
    assert "scope_not_confirmed" in result.missing_reasons


def test_readiness_ready_once_identity_entity_and_scope_are_all_confirmed(db: Session):
    confirm_organization_identity(
        db,
        organization_id=1,
        confirmed_by_user_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
    )
    create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.PARENT,
        is_primary=True,
        status=OrganizationEntityStatus.CONFIRMED,
    )
    scope = create_scope(
        db,
        organization_id=1,
        scope_type=OrganizationScopeType.ENTIRE_ORGANIZATION,
        name="Entire organisation",
    )
    confirm_scope(db, scope, confirmed_by_user_id=1)
    db.commit()

    result = evaluate_identity_readiness(db, 1)
    assert result.ready is True
    assert result.readiness == OrganizationIdentityReadiness.READY
    assert result.missing_reasons == []


def test_optional_group_and_domain_gaps_never_block_readiness(db: Session):
    confirm_organization_identity(
        db,
        organization_id=1,
        confirmed_by_user_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        organization_type=OrganizationType.CORPORATE_GROUP,
    )
    primary = create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.PARENT,
        is_primary=True,
        status=OrganizationEntityStatus.CONFIRMED,
    )
    # A suggested-but-not-confirmed subsidiary must not block readiness.
    create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Sweden AB",
        registration_country="SE",
        entity_type=OrganizationEntityType.SUBSIDIARY,
    )
    scope = create_scope(
        db,
        organization_id=1,
        scope_type=OrganizationScopeType.LEGAL_ENTITY,
        name="Danish entity only",
        included_entity_ids=[primary.id],
    )
    confirm_scope(db, scope, confirmed_by_user_id=1)
    db.commit()

    result = evaluate_identity_readiness(db, 1)
    assert result.ready is True


def test_prepared_organisation_identity_read_model(db: Session):
    confirm_organization_identity(
        db,
        organization_id=1,
        confirmed_by_user_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
    )
    entity = create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        registration_number="12345678",
        entity_type=OrganizationEntityType.PARENT,
        is_primary=True,
        status=OrganizationEntityStatus.CONFIRMED,
    )
    scope = create_scope(
        db,
        organization_id=1,
        scope_type=OrganizationScopeType.ENTIRE_ORGANIZATION,
        name="Entire organisation",
    )
    confirm_scope(db, scope, confirmed_by_user_id=1)
    domain = add_domain(
        db, organization_id=1, domain="example.dk", domain_type=OrganizationDomainType.PRIMARY
    )
    db.commit()

    prepared = build_prepared_organisation_identity(db, 1)
    assert prepared.primary_entity_id == entity.id
    assert prepared.confirmed_scope_id == scope.id
    assert prepared.legal_name == "Example Retail Denmark ApS"
    assert prepared.registration_number == "12345678"
    assert prepared.readiness == OrganizationIdentityReadiness.READY
    assert domain.domain in prepared.unverified_domains
    assert prepared.verified_domains == []
    # "Entire organisation" scope has nothing to select, so every confirmed
    # entity is included by definition.
    assert prepared.entity_context.included_entity_ids == [entity.id]
    assert prepared.entity_context.known_related_entity_ids == []
    assert prepared.entity_context.excluded_entity_ids == []
    # No archetype/operating-characteristic model exists at this stage —
    # these must be honest empty placeholders, never fabricated.
    assert prepared.industry_context.confirmed_archetypes == []
    assert prepared.industry_context.confirmed_operating_characteristics == []
    assert prepared.industry_context.unresolved_suggestions == 0


def test_prepared_entity_context_reflects_scope_selection_and_exclusion(db: Session):
    confirm_organization_identity(
        db,
        organization_id=1,
        confirmed_by_user_id=1,
        legal_name="Example Retail Group",
        registration_country="DK",
        organization_type=OrganizationType.CORPORATE_GROUP,
    )
    primary = create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.PARENT,
        is_primary=True,
        status=OrganizationEntityStatus.CONFIRMED,
    )
    suggested = create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Sweden AB",
        registration_country="SE",
        entity_type=OrganizationEntityType.SUBSIDIARY,
    )
    excluded = create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Norway AS",
        registration_country="NO",
        entity_type=OrganizationEntityType.SUBSIDIARY,
    )
    exclude_legal_entity(db, excluded)
    scope = create_scope(
        db,
        organization_id=1,
        scope_type=OrganizationScopeType.LEGAL_ENTITY,
        name="Danish entity only",
        included_entity_ids=[primary.id],
    )
    confirm_scope(db, scope, confirmed_by_user_id=1)
    db.commit()

    prepared = build_prepared_organisation_identity(db, 1)
    assert prepared.entity_context.included_entity_ids == [primary.id]
    assert prepared.entity_context.known_related_entity_ids == [suggested.id]
    assert prepared.entity_context.excluded_entity_ids == [excluded.id]


# --- Route-level authorisation and tenant isolation --------------------------


def test_only_org_admin_can_add_a_legal_entity(db: Session):
    with pytest.raises(AuthorizationError):
        org_identity_routes.add_entity(
            org_identity_routes.LegalEntityRequest(
                legal_name="Example Retail Denmark ApS",
                registration_country="DK",
                entity_type=OrganizationEntityType.PARENT,
            ),
            ctx=_ctx(2, role="member"),
            db=db,
        )


def test_primary_entity_route_is_idempotent_and_audited(db: Session):
    body = org_identity_routes.PrimaryLegalEntityRequest(
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        registration_number="12345678",
    )
    first = org_identity_routes.upsert_primary_entity(body, ctx=_ctx(1), db=db)
    second = org_identity_routes.upsert_primary_entity(
        org_identity_routes.PrimaryLegalEntityRequest(
            legal_name="Example Retail Denmark A/S",
            registration_country="DK",
            registration_number="12345678",
        ),
        ctx=_ctx(1),
        db=db,
    )
    assert first.id == second.id
    assert second.legal_name == "Example Retail Denmark A/S"
    events = db.query(AuditEvent).filter(AuditEvent.organization_id == 1).all()
    event_types = [event.event_type for event in events]
    assert event_types.count(ORG_IDENTITY_AUDIT_ENTITY_ADDED) == 1
    assert event_types.count(ORG_IDENTITY_AUDIT_ENTITY_CONFIRMED) == 2


def test_confirm_entity_writes_an_audit_event(db: Session):
    entity = org_identity_routes.add_entity(
        org_identity_routes.LegalEntityRequest(
            legal_name="Example Retail Denmark ApS",
            registration_country="DK",
            entity_type=OrganizationEntityType.PARENT,
        ),
        ctx=_ctx(1),
        db=db,
    )

    org_identity_routes.confirm_entity(entity.id, ctx=_ctx(1), db=db)

    events = db.query(AuditEvent).filter(AuditEvent.organization_id == 1).all()
    assert any(event.event_type == ORG_IDENTITY_AUDIT_ENTITY_CONFIRMED for event in events)


def test_scope_route_rejects_entire_organisation_exclusions(db: Session):
    entity = create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.PARENT,
    )
    db.commit()

    with pytest.raises(ValidationError, match="entire-organisation"):
        org_identity_routes.add_scope(
            org_identity_routes.ScopeRequest(
                scope_type=OrganizationScopeType.ENTIRE_ORGANIZATION,
                name="Entire organisation",
                excluded_entity_ids=[entity.id],
            ),
            ctx=_ctx(1),
            db=db,
        )


def test_only_org_admin_can_confirm_identity(db: Session):
    with pytest.raises(AuthorizationError):
        org_identity_routes.confirm_identity(
            org_identity_routes.ConfirmIdentityRequest(
                legal_name="Example Retail Denmark ApS",
                registration_country="DK",
                organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
            ),
            ctx=_ctx(2, role="member"),
            db=db,
        )


def test_complete_identity_setup_rejects_when_not_ready(db: Session):
    with pytest.raises(ValidationError):
        org_identity_routes.complete_identity_setup(ctx=_ctx(1), db=db)


def test_complete_identity_setup_succeeds_once_ready_and_writes_an_audit_event(db: Session):
    confirm_organization_identity(
        db,
        organization_id=1,
        confirmed_by_user_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
    )
    create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.PARENT,
        is_primary=True,
        status=OrganizationEntityStatus.CONFIRMED,
    )
    scope = create_scope(
        db,
        organization_id=1,
        scope_type=OrganizationScopeType.ENTIRE_ORGANIZATION,
        name="Entire organisation",
    )
    confirm_scope(db, scope, confirmed_by_user_id=1)
    db.commit()

    result = org_identity_routes.complete_identity_setup(ctx=_ctx(1), db=db)
    assert result.ready is True
    events = db.query(AuditEvent).filter(AuditEvent.organization_id == 1).all()
    assert any(e.event_type == ORG_IDENTITY_AUDIT_SETUP_COMPLETED for e in events)


def test_entity_lookup_is_tenant_isolated(db: Session):
    entity = create_legal_entity(
        db,
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        entity_type=OrganizationEntityType.PARENT,
    )
    db.commit()

    with pytest.raises(ResourceNotFoundError):
        org_identity_routes.confirm_entity(entity.id, ctx=_ctx(3, organization_id=2), db=db)


def test_confirming_identity_writes_confirmed_then_corrected_audit_events(db: Session):
    org_identity_routes.confirm_identity(
        org_identity_routes.ConfirmIdentityRequest(
            legal_name="Example Retail Denmark ApS",
            registration_country="DK",
            organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
        ),
        ctx=_ctx(1),
        db=db,
    )
    org_identity_routes.confirm_identity(
        org_identity_routes.ConfirmIdentityRequest(
            legal_name="Example Retail Denmark A/S",
            registration_country="DK",
            organization_type=OrganizationType.SINGLE_LEGAL_ENTITY,
            correction_reason="Legal form corrected after re-verification.",
        ),
        ctx=_ctx(1),
        db=db,
    )
    events = db.query(AuditEvent).filter(AuditEvent.organization_id == 1).all()
    event_types = [e.event_type for e in events]
    assert ORG_IDENTITY_AUDIT_CONFIRMED in event_types
    assert ORG_IDENTITY_AUDIT_CORRECTED in event_types
