"""Organisation Structure: hierarchy, pairwise merge, readiness, tenant isolation."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import organization_structure as org_structure_routes
from src.core.constants.organization_structure_enums import (
    MAJOR_ORGANIZATION_UNIT_TYPES,
    ORG_STRUCTURE_AUDIT_COMPLETED,
    OrganizationLocationType,
    OrganizationUnitMembershipRole,
    OrganizationUnitRelationshipType,
    OrganizationUnitScopeStatus,
    OrganizationUnitSource,
    OrganizationUnitStatus,
    OrganizationUnitType,
)
from src.core.constants.organization_unit_archetype_library import (
    OrganisationIndustryFamily,
    OrganisationSizeBand,
    suggest_units_for_archetype,
)
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.org_access import OrgMandateRoleAssignment
from src.core.model_defs.organization_identity import OrganizationLegalEntity, OrganizationScope
from src.core.model_defs.organization_structure import (
    OrganizationLocation,
    OrganizationUnit,
    OrganizationUnitMatchSuggestion,
    OrganizationUnitMembership,
    OrganizationUnitRelationship,
)
from src.core.models import AuditEvent, Organization, User
from src.core.repository import TenantRepository
from src.core.services.organization_structure_readiness_service import (
    build_prepared_organisation_structure,
    evaluate_structure_readiness,
)
from src.core.services.organization_structure_service import (
    OrganizationStructureValidationError,
    assign_technical_setup_owner,
    confirm_location,
    confirm_membership,
    confirm_relationship,
    confirm_unit,
    create_location,
    create_match_suggestion,
    create_membership,
    create_relationship,
    create_unit,
    exclude_unit,
    generate_duplicate_unit_suggestions,
    keep_units_separate,
    merge_units,
    move_unit,
    reject_match_suggestion,
    rename_unit,
    restore_unit,
    seed_units_from_organization_identity,
    suggest_units_from_archetype,
)


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
            OrganizationLegalEntity.__table__,
            OrganizationScope.__table__,
            OrganizationUnit.__table__,
            OrganizationUnitRelationship.__table__,
            OrganizationLocation.__table__,
            OrganizationUnitMembership.__table__,
            OrganizationUnitMatchSuggestion.__table__,
            OrgMandateRoleAssignment.__table__,
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
        user_id=user_id, organization_id=organization_id, email="x@example.com", roles=[role], permissions=[]
    )


# --- Units / hierarchy ---------------------------------------------------------


def test_unit_creation_requires_a_name(db: Session):
    with pytest.raises(OrganizationStructureValidationError):
        create_unit(db, organization_id=1, name="   ", unit_type=OrganizationUnitType.BUSINESS_UNIT)


def test_confirm_unit_records_actor_and_timestamp(db: Session):
    unit = create_unit(db, organization_id=1, name="Retail", unit_type=OrganizationUnitType.BUSINESS_UNIT)
    confirm_unit(db, unit, confirmed_by_user_id=1)
    db.commit()
    assert unit.status == "confirmed"
    assert unit.confirmed_by_user_id == 1
    assert unit.confirmed_at is not None


def test_exclude_unit_sets_status(db: Session):
    unit = create_unit(db, organization_id=1, name="Retail", unit_type=OrganizationUnitType.BUSINESS_UNIT)
    exclude_unit(db, unit)
    db.commit()
    assert unit.status == "excluded"


def test_rename_unit_preserves_previous_name_as_alias(db: Session):
    unit = create_unit(db, organization_id=1, name="IT", unit_type=OrganizationUnitType.DEPARTMENT)
    rename_unit(db, unit, name="Technology")
    db.commit()
    assert unit.name == "Technology"
    assert "IT" in unit.aliases


def test_move_unit_rejects_self_as_parent(db: Session):
    unit = create_unit(db, organization_id=1, name="Retail", unit_type=OrganizationUnitType.BUSINESS_UNIT)
    db.commit()
    with pytest.raises(OrganizationStructureValidationError):
        move_unit(db, unit, parent_unit_id=unit.id)


def test_restore_unit_undoes_an_exclude_back_to_suggested(db: Session):
    # impeccable critique P0: exclude previously had no recovery path.
    unit = create_unit(db, organization_id=1, name="Retail", unit_type=OrganizationUnitType.BUSINESS_UNIT)
    exclude_unit(db, unit)
    db.commit()
    assert unit.status == "excluded"

    restore_unit(db, unit)
    db.commit()
    assert unit.status == "suggested"


def test_hierarchy_supports_arbitrary_depth_no_fixed_levels(db: Session):
    root = create_unit(db, organization_id=1, name="Example Group", unit_type=OrganizationUnitType.LEGAL_ENTITY)
    country = create_unit(
        db, organization_id=1, name="Denmark", unit_type=OrganizationUnitType.COUNTRY, parent_unit_id=root.id
    )
    unit = create_unit(
        db,
        organization_id=1,
        name="Retail",
        unit_type=OrganizationUnitType.BUSINESS_UNIT,
        parent_unit_id=country.id,
    )
    department = create_unit(
        db,
        organization_id=1,
        name="Store Technology",
        unit_type=OrganizationUnitType.DEPARTMENT,
        parent_unit_id=unit.id,
    )
    db.commit()
    assert department.parent_unit_id == unit.id
    assert unit.parent_unit_id == country.id
    assert country.parent_unit_id == root.id
    assert root.parent_unit_id is None


# --- Relationships ---------------------------------------------------------------


def test_relationship_rejects_self_relationship(db: Session):
    unit = create_unit(db, organization_id=1, name="Retail", unit_type=OrganizationUnitType.BUSINESS_UNIT)
    db.commit()
    with pytest.raises(OrganizationStructureValidationError):
        create_relationship(
            db,
            organization_id=1,
            source_unit_id=unit.id,
            target_unit_id=unit.id,
            relationship_type=OrganizationUnitRelationshipType.PART_OF,
        )


def test_relationship_confirm_lifecycle(db: Session):
    a = create_unit(db, organization_id=1, name="Store 104", unit_type=OrganizationUnitType.LOCATION)
    b = create_unit(db, organization_id=1, name="Nordic Infrastructure", unit_type=OrganizationUnitType.SHARED_SERVICE)
    relationship = create_relationship(
        db,
        organization_id=1,
        source_unit_id=a.id,
        target_unit_id=b.id,
        relationship_type=OrganizationUnitRelationshipType.SUPPORTED_BY,
    )
    confirm_relationship(db, relationship, confirmed_by_user_id=1)
    db.commit()
    assert relationship.status == "confirmed"
    assert relationship.confirmed_by_user_id == 1


# --- Locations ---------------------------------------------------------------------


def test_location_confirm(db: Session):
    unit = create_unit(db, organization_id=1, name="Retail", unit_type=OrganizationUnitType.BUSINESS_UNIT)
    location = create_location(
        db,
        organization_id=1,
        name="Store 001",
        location_type=OrganizationLocationType.STORE,
        organization_unit_id=unit.id,
    )
    confirm_location(db, location)
    db.commit()
    assert location.status == "confirmed"


# --- Membership never grants mandate -------------------------------------------


def test_membership_never_creates_a_mandate_role_assignment(db: Session):
    unit = create_unit(db, organization_id=1, name="Retail Technology", unit_type=OrganizationUnitType.DEPARTMENT)
    membership = create_membership(
        db,
        organization_id=1,
        organization_unit_id=unit.id,
        user_id=2,
        membership_role=OrganizationUnitMembershipRole.TECHNICAL_CONTACT,
    )
    confirm_membership(db, membership)
    db.commit()

    assert membership.status == "confirmed"
    assert db.query(OrgMandateRoleAssignment).count() == 0


# --- Pairwise duplicate detection + merge --------------------------------------


def test_match_suggestion_rejects_self_match(db: Session):
    unit = create_unit(db, organization_id=1, name="IT", unit_type=OrganizationUnitType.DEPARTMENT)
    db.commit()
    with pytest.raises(OrganizationStructureValidationError):
        create_match_suggestion(
            db, organization_id=1, unit_a_id=unit.id, unit_b_id=unit.id, match_confidence=0.9, matching_reasons=[]
        )


def test_merge_requires_survivor_to_be_one_of_the_pair(db: Session):
    a = create_unit(db, organization_id=1, name="IT", unit_type=OrganizationUnitType.DEPARTMENT)
    b = create_unit(db, organization_id=1, name="Technology", unit_type=OrganizationUnitType.DEPARTMENT)
    other = create_unit(db, organization_id=1, name="Finance", unit_type=OrganizationUnitType.DEPARTMENT)
    suggestion = create_match_suggestion(
        db,
        organization_id=1,
        unit_a_id=a.id,
        unit_b_id=b.id,
        match_confidence=0.8,
        matching_reasons=["Similar name"],
    )
    db.commit()
    with pytest.raises(OrganizationStructureValidationError):
        merge_units(db, suggestion, survivor_unit_id=other.id, decided_by_user_id=1)


def test_merge_repoints_children_memberships_locations_relationships_and_preserves_alias(db: Session):
    survivor = create_unit(db, organization_id=1, name="Technology", unit_type=OrganizationUnitType.DEPARTMENT)
    merged = create_unit(db, organization_id=1, name="IT", unit_type=OrganizationUnitType.DEPARTMENT)
    child = create_unit(
        db, organization_id=1, name="Store Tech", unit_type=OrganizationUnitType.FUNCTION, parent_unit_id=merged.id
    )
    membership = create_membership(
        db,
        organization_id=1,
        organization_unit_id=merged.id,
        user_id=2,
        membership_role=OrganizationUnitMembershipRole.MEMBER,
    )
    location = create_location(
        db, organization_id=1, name="HQ", location_type=OrganizationLocationType.OFFICE, organization_unit_id=merged.id
    )
    other_unit = create_unit(db, organization_id=1, name="Security", unit_type=OrganizationUnitType.FUNCTION)
    relationship = create_relationship(
        db,
        organization_id=1,
        source_unit_id=merged.id,
        target_unit_id=other_unit.id,
        relationship_type=OrganizationUnitRelationshipType.SUPPORTED_BY,
    )
    suggestion = create_match_suggestion(
        db,
        organization_id=1,
        unit_a_id=survivor.id,
        unit_b_id=merged.id,
        match_confidence=0.85,
        matching_reasons=["IT and Technology likely the same department"],
    )
    db.commit()

    result = merge_units(db, suggestion, survivor_unit_id=survivor.id, decided_by_user_id=1)
    db.commit()

    assert result.id == survivor.id
    assert "IT" in survivor.aliases
    assert merged.status == "archived"
    assert merged.merged_into_unit_id == survivor.id
    db.refresh(child)
    db.refresh(membership)
    db.refresh(location)
    db.refresh(relationship)
    assert child.parent_unit_id == survivor.id
    assert membership.organization_unit_id == survivor.id
    assert location.organization_unit_id == survivor.id
    assert relationship.source_unit_id == survivor.id
    assert suggestion.status == "merged"


def test_merge_rejects_an_already_archived_unit(db: Session):
    a = create_unit(db, organization_id=1, name="IT", unit_type=OrganizationUnitType.DEPARTMENT)
    b = create_unit(db, organization_id=1, name="Technology", unit_type=OrganizationUnitType.DEPARTMENT)
    c = create_unit(db, organization_id=1, name="Digital", unit_type=OrganizationUnitType.DEPARTMENT)
    first = create_match_suggestion(
        db, organization_id=1, unit_a_id=a.id, unit_b_id=b.id, match_confidence=0.8, matching_reasons=[]
    )
    db.commit()
    merge_units(db, first, survivor_unit_id=a.id, decided_by_user_id=1)
    db.commit()

    second = create_match_suggestion(
        db, organization_id=1, unit_a_id=c.id, unit_b_id=b.id, match_confidence=0.7, matching_reasons=[]
    )
    db.commit()
    with pytest.raises(OrganizationStructureValidationError):
        merge_units(db, second, survivor_unit_id=c.id, decided_by_user_id=1)


def test_keep_units_separate_lifecycle(db: Session):
    a = create_unit(db, organization_id=1, name="IT", unit_type=OrganizationUnitType.DEPARTMENT)
    b = create_unit(db, organization_id=1, name="Technology", unit_type=OrganizationUnitType.DEPARTMENT)
    suggestion = create_match_suggestion(
        db, organization_id=1, unit_a_id=a.id, unit_b_id=b.id, match_confidence=0.6, matching_reasons=[]
    )
    keep_units_separate(db, suggestion, decided_by_user_id=1)
    db.commit()
    assert suggestion.status == "kept_separate"
    assert suggestion.decided_by_user_id == 1


def test_reject_match_suggestion_lifecycle(db: Session):
    a = create_unit(db, organization_id=1, name="Finance", unit_type=OrganizationUnitType.DEPARTMENT)
    b = create_unit(db, organization_id=1, name="Financial Operations", unit_type=OrganizationUnitType.DEPARTMENT)
    suggestion = create_match_suggestion(
        db, organization_id=1, unit_a_id=a.id, unit_b_id=b.id, match_confidence=0.5, matching_reasons=[]
    )
    reject_match_suggestion(db, suggestion, decided_by_user_id=1)
    db.commit()
    assert suggestion.status == "rejected"


# --- Duplicate-unit auto-detection ------------------------------------------------


def test_generate_duplicate_suggestions_flags_a_known_synonym_pair(db: Session):
    a = create_unit(db, organization_id=1, name="IT", unit_type=OrganizationUnitType.DEPARTMENT)
    b = create_unit(db, organization_id=1, name="Global Information Technology", unit_type=OrganizationUnitType.DEPARTMENT)
    db.commit()

    created = generate_duplicate_unit_suggestions(db, 1)
    assert len(created) == 1
    assert {created[0].unit_a_id, created[0].unit_b_id} == {a.id, b.id}
    assert created[0].match_confidence == 0.9


def test_generate_duplicate_suggestions_flags_close_name_similarity(db: Session):
    create_unit(db, organization_id=1, name="Customer Service Nordics", unit_type=OrganizationUnitType.DEPARTMENT)
    create_unit(db, organization_id=1, name="Customer Service Nordic", unit_type=OrganizationUnitType.DEPARTMENT)
    db.commit()

    created = generate_duplicate_unit_suggestions(db, 1)
    assert len(created) == 1


def test_generate_duplicate_suggestions_ignores_unrelated_names(db: Session):
    create_unit(db, organization_id=1, name="Finance", unit_type=OrganizationUnitType.DEPARTMENT)
    create_unit(db, organization_id=1, name="Retail Operations", unit_type=OrganizationUnitType.DEPARTMENT)
    db.commit()

    created = generate_duplicate_unit_suggestions(db, 1)
    assert created == []


def test_generate_duplicate_suggestions_never_crosses_unit_types(db: Session):
    create_unit(db, organization_id=1, name="Technology", unit_type=OrganizationUnitType.DEPARTMENT)
    create_unit(db, organization_id=1, name="Technology", unit_type=OrganizationUnitType.LOCATION)
    db.commit()

    created = generate_duplicate_unit_suggestions(db, 1)
    assert created == []


def test_generate_duplicate_suggestions_skips_archived_and_excluded_units(db: Session):
    a = create_unit(db, organization_id=1, name="IT", unit_type=OrganizationUnitType.DEPARTMENT)
    b = create_unit(db, organization_id=1, name="Technology", unit_type=OrganizationUnitType.DEPARTMENT)
    exclude_unit(db, b)
    db.commit()

    created = generate_duplicate_unit_suggestions(db, 1)
    assert created == []


def test_generate_duplicate_suggestions_is_idempotent(db: Session):
    create_unit(db, organization_id=1, name="IT", unit_type=OrganizationUnitType.DEPARTMENT)
    create_unit(db, organization_id=1, name="Technology", unit_type=OrganizationUnitType.DEPARTMENT)
    db.commit()

    first = generate_duplicate_unit_suggestions(db, 1)
    db.commit()
    second = generate_duplicate_unit_suggestions(db, 1)
    assert len(first) == 1
    assert second == []


def test_generate_duplicate_suggestions_does_not_reflag_a_decided_pair(db: Session):
    a = create_unit(db, organization_id=1, name="IT", unit_type=OrganizationUnitType.DEPARTMENT)
    b = create_unit(db, organization_id=1, name="Technology", unit_type=OrganizationUnitType.DEPARTMENT)
    suggestion = create_match_suggestion(
        db, organization_id=1, unit_a_id=a.id, unit_b_id=b.id, match_confidence=0.9, matching_reasons=["manual"]
    )
    keep_units_separate(db, suggestion, decided_by_user_id=1)
    db.commit()

    created = generate_duplicate_unit_suggestions(db, 1)
    assert created == []


def test_generate_duplicate_suggestions_route_requires_org_admin(db: Session):
    with pytest.raises(AuthorizationError):
        org_structure_routes.generate_match_suggestions_route(ctx=_ctx(2, role="member"), db=db)


def test_generate_duplicate_suggestions_route_writes_audit_events(db: Session):
    create_unit(db, organization_id=1, name="IT", unit_type=OrganizationUnitType.DEPARTMENT)
    create_unit(db, organization_id=1, name="Technology", unit_type=OrganizationUnitType.DEPARTMENT)
    db.commit()

    result = org_structure_routes.generate_match_suggestions_route(ctx=_ctx(1), db=db)
    assert len(result) == 1
    events = db.query(AuditEvent).filter(AuditEvent.organization_id == 1).all()
    assert any(e.event_type == "organization_unit.match_suggestions_generated" for e in events)


# --- Technical Setup Owner -------------------------------------------------------


def test_assign_technical_setup_owner_requires_an_active_user(db: Session):
    with pytest.raises(OrganizationStructureValidationError):
        assign_technical_setup_owner(db, organization_id=1, user_id=999)


def test_assign_technical_setup_owner_succeeds(db: Session):
    organization = assign_technical_setup_owner(db, organization_id=1, user_id=1)
    db.commit()
    assert organization.technical_setup_owner_user_id == 1


# --- Seeding from organisation identity -----------------------------------------


def test_seed_creates_legal_entity_and_scope_country_units(db: Session):
    entity = OrganizationLegalEntity(
        id="entity-1",
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        entity_type="parent",
        status="confirmed",
        is_primary=True,
    )
    scope = OrganizationScope(
        id="scope-1",
        organization_id=1,
        scope_type="entire_organisation",
        name="Entire organisation",
        status="confirmed",
        included_countries=["DK", "SE"],
    )
    db.add_all([entity, scope])
    db.commit()

    created = seed_units_from_organization_identity(db, 1)
    db.commit()

    names = {u.name for u in created}
    assert "Example Retail Denmark ApS" in names
    assert "DK" in names and "SE" in names
    assert all(u.status == "suggested" for u in created)


def test_seed_is_idempotent_on_second_call(db: Session):
    entity = OrganizationLegalEntity(
        id="entity-1",
        organization_id=1,
        legal_name="Example Retail Denmark ApS",
        registration_country="DK",
        entity_type="parent",
        status="confirmed",
        is_primary=True,
    )
    db.add(entity)
    db.commit()

    first = seed_units_from_organization_identity(db, 1)
    db.commit()
    second = seed_units_from_organization_identity(db, 1)
    db.commit()

    assert len(first) == 1
    assert len(second) == 0


# --- Archetype-based unit suggestion (industry family + size band) -----------


def test_archetype_suggestion_scales_with_size_band():
    small = suggest_units_for_archetype(OrganisationIndustryFamily.MANUFACTURING, OrganisationSizeBand.SMALL)
    medium = suggest_units_for_archetype(OrganisationIndustryFamily.MANUFACTURING, OrganisationSizeBand.MEDIUM)
    large = suggest_units_for_archetype(OrganisationIndustryFamily.MANUFACTURING, OrganisationSizeBand.LARGE)

    small_names = {u.name for u in small}
    medium_names = {u.name for u in medium}
    large_names = {u.name for u in large}

    assert small_names <= medium_names <= large_names
    assert "Production" in small_names
    # Finance/Technology are universal even at small size.
    assert "Finance" in small_names
    # People & Culture only appears once the org is big enough to have one.
    assert "People & Culture" not in small_names
    assert "People & Culture" in medium_names
    assert len(large_names) > len(small_names)


def test_archetype_suggestion_never_duplicates_a_universal_and_industry_unit():
    for industry in OrganisationIndustryFamily:
        suggestions = suggest_units_for_archetype(industry, OrganisationSizeBand.LARGE)
        names = [u.name for u in suggestions]
        assert len(names) == len(set(names))


def test_suggest_units_from_archetype_creates_suggested_units(db: Session):
    result = suggest_units_from_archetype(
        db, 1, industry_family=OrganisationIndustryFamily.TECHNOLOGY, size_band=OrganisationSizeBand.SMALL
    )
    db.commit()

    names = {u.name for u in result.created}
    assert "Engineering" in names
    assert "Product" in names
    assert all(u.status == "suggested" for u in result.created)
    assert all(u.source == "risklence_suggestion" for u in result.created)


def test_suggest_units_from_archetype_is_idempotent_on_second_call(db: Session):
    first = suggest_units_from_archetype(
        db, 1, industry_family=OrganisationIndustryFamily.RETAIL, size_band=OrganisationSizeBand.MEDIUM
    )
    db.commit()
    second = suggest_units_from_archetype(
        db, 1, industry_family=OrganisationIndustryFamily.RETAIL, size_band=OrganisationSizeBand.MEDIUM
    )
    db.commit()

    # Idempotent in what it writes...
    assert len(first.created) > 0
    assert len(second.created) == 0
    # ...and never empty in what it says. A second click used to return [],
    # which a caller renders exactly like "this archetype suggests nothing",
    # while the units sat in the database the whole time (#372).
    assert [u.id for u in second.units] == [u.id for u in first.units]


def test_a_second_click_never_looks_like_no_suggestions(db: Session):
    """Søren, walking the onboarding journey 2026-08-31: click twice, see nothing."""
    first = suggest_units_from_archetype(
        db, 1, industry_family=OrganisationIndustryFamily.PROFESSIONAL_SERVICES,
        size_band=OrganisationSizeBand.MEDIUM,
    )
    db.commit()
    second = suggest_units_from_archetype(
        db, 1, industry_family=OrganisationIndustryFamily.PROFESSIONAL_SERVICES,
        size_band=OrganisationSizeBand.MEDIUM,
    )
    db.commit()

    assert len(second.units) == len(first.units) > 0
    assert {u.name for u in second.units} == {u.name for u in first.units}


def test_a_unit_the_reader_has_excluded_is_not_offered_again(db: Session):
    """An exclusion is a decision. Re-suggesting it would undo one silently."""
    first = suggest_units_from_archetype(
        db, 1, industry_family=OrganisationIndustryFamily.TECHNOLOGY, size_band=OrganisationSizeBand.SMALL
    )
    db.commit()
    excluded = first.units[0]
    excluded.status = OrganizationUnitStatus.EXCLUDED.value
    db.commit()

    second = suggest_units_from_archetype(
        db, 1, industry_family=OrganisationIndustryFamily.TECHNOLOGY, size_band=OrganisationSizeBand.SMALL
    )
    db.commit()

    assert excluded.id not in {u.id for u in second.units}
    assert len(second.units) == len(first.units) - 1
    # And it is still not re-created — idempotency is unchanged.
    assert second.created == []


# --- Readiness -----------------------------------------------------------------


def test_readiness_missing_without_major_units_or_technical_setup_owner(db: Session):
    result = evaluate_structure_readiness(db, 1)
    assert result.ready is False
    assert "no_major_operational_units" in result.missing_reasons
    assert "technical_setup_owner_missing" in result.missing_reasons


def test_readiness_blocks_on_unresolved_scope_for_a_confirmed_major_unit(db: Session):
    unit = create_unit(db, organization_id=1, name="Retail", unit_type=OrganizationUnitType.BUSINESS_UNIT)
    confirm_unit(db, unit, confirmed_by_user_id=1)
    assign_technical_setup_owner(db, organization_id=1, user_id=1)
    db.commit()

    result = evaluate_structure_readiness(db, 1)
    assert result.ready is False
    assert "major_unit_scope_unresolved" in result.missing_reasons


def test_readiness_ready_once_major_unit_is_scoped_and_tso_assigned(db: Session):
    unit = create_unit(db, organization_id=1, name="Retail", unit_type=OrganizationUnitType.BUSINESS_UNIT)
    confirm_unit(db, unit, confirmed_by_user_id=1)
    unit.scope_status = OrganizationUnitScopeStatus.IN_SCOPE.value
    db.add(unit)
    assign_technical_setup_owner(db, organization_id=1, user_id=1)
    db.commit()

    result = evaluate_structure_readiness(db, 1)
    assert result.ready is True
    assert result.readiness.value == "ready"


def test_readiness_ignores_minor_suggested_units_with_unresolved_scope(db: Session):
    major = create_unit(db, organization_id=1, name="Retail", unit_type=OrganizationUnitType.BUSINESS_UNIT)
    confirm_unit(db, major, confirmed_by_user_id=1)
    major.scope_status = OrganizationUnitScopeStatus.IN_SCOPE.value
    db.add(major)
    # A minor, still-suggested subdepartment with unresolved scope must never block.
    create_unit(db, organization_id=1, name="Some Subteam", unit_type=OrganizationUnitType.OTHER)
    assign_technical_setup_owner(db, organization_id=1, user_id=1)
    db.commit()

    result = evaluate_structure_readiness(db, 1)
    assert result.ready is True
    assert result.unresolved_optional_issues >= 1


def test_prepared_organisation_structure_read_model(db: Session):
    unit = create_unit(db, organization_id=1, name="Retail", unit_type=OrganizationUnitType.BUSINESS_UNIT)
    confirm_unit(db, unit, confirmed_by_user_id=1)
    unit.scope_status = OrganizationUnitScopeStatus.IN_SCOPE.value
    db.add(unit)
    shared = create_unit(db, organization_id=1, name="Nordic IT", unit_type=OrganizationUnitType.SHARED_SERVICE)
    confirm_unit(db, shared, confirmed_by_user_id=1)
    shared.scope_status = OrganizationUnitScopeStatus.SHARED_DEPENDENCY.value
    db.add(shared)
    # A still-suggested unit must appear in `units` (with its own honest
    # status) and surface as a non-blocking issue, never silently dropped.
    subteam = create_unit(db, organization_id=1, name="Some Subteam", unit_type=OrganizationUnitType.OTHER)
    location = create_location(
        db,
        organization_id=1,
        name="Copenhagen Store",
        location_type=OrganizationLocationType.STORE,
        organization_unit_id=unit.id,
    )
    confirm_location(db, location)
    membership = create_membership(
        db,
        organization_id=1,
        organization_unit_id=unit.id,
        user_id=2,
        membership_role=OrganizationUnitMembershipRole.TECHNICAL_CONTACT,
    )
    confirm_membership(db, membership)
    assign_technical_setup_owner(db, organization_id=1, user_id=1)
    db.commit()

    prepared = build_prepared_organisation_structure(db, 1)
    assert prepared.confirmed_unit_count == 2
    assert shared.id in prepared.shared_service_unit_ids
    assert prepared.technical_setup_owner_id == 1
    assert prepared.readiness.value == "ready"
    assert {u.id for u in prepared.units} == {unit.id, shared.id, subteam.id}
    assert len(prepared.locations) == 1
    assert prepared.locations[0].id == location.id
    assert prepared.setup_ownership.technical_setup_owner_id == 1
    assert 1 in prepared.setup_ownership.organisation_administrator_ids
    assert 2 in prepared.setup_ownership.technical_contact_ids
    assert any(i.issue_type == "unit_suggestion_unresolved" and not i.blocking for i in prepared.unresolved_structure_issues)


# --- Route-level authorisation and tenant isolation --------------------------


def test_only_org_admin_can_create_a_unit(db: Session):
    with pytest.raises(AuthorizationError):
        org_structure_routes.create_unit_route(
            org_structure_routes.UnitRequest(name="Retail", unit_type=OrganizationUnitType.BUSINESS_UNIT),
            ctx=_ctx(2, role="member"),
            db=db,
        )


def test_only_org_admin_can_suggest_units_from_archetype(db: Session):
    with pytest.raises(AuthorizationError):
        org_structure_routes.suggest_units_from_archetype_route(
            org_structure_routes.SuggestFromArchetypeRequest(
                industry_family=OrganisationIndustryFamily.OTHER, size_band=OrganisationSizeBand.SMALL
            ),
            ctx=_ctx(2, role="member"),
            db=db,
        )


def test_suggest_units_from_archetype_route_writes_audit_event(db: Session):
    result = org_structure_routes.suggest_units_from_archetype_route(
        org_structure_routes.SuggestFromArchetypeRequest(
            industry_family=OrganisationIndustryFamily.OTHER, size_band=OrganisationSizeBand.SMALL
        ),
        ctx=_ctx(1),
        db=db,
    )
    assert len(result) > 0
    events = db.query(AuditEvent).filter(AuditEvent.organization_id == 1).all()
    assert any(e.event_type == "organization_unit.suggested_from_archetype" for e in events)


def test_only_org_admin_can_assign_technical_setup_owner(db: Session):
    with pytest.raises(AuthorizationError):
        org_structure_routes.patch_setup_ownership_route(
            org_structure_routes.SetupOwnershipRequest(technical_setup_owner_user_id=1),
            ctx=_ctx(2, role="member"),
            db=db,
        )


def test_complete_structure_setup_rejects_when_not_ready(db: Session):
    with pytest.raises(ValidationError):
        org_structure_routes.complete_structure_setup_route(ctx=_ctx(1), db=db)


def test_complete_structure_setup_succeeds_once_ready_and_writes_audit_event(db: Session):
    unit = create_unit(db, organization_id=1, name="Retail", unit_type=OrganizationUnitType.BUSINESS_UNIT)
    confirm_unit(db, unit, confirmed_by_user_id=1)
    unit.scope_status = OrganizationUnitScopeStatus.IN_SCOPE.value
    db.add(unit)
    assign_technical_setup_owner(db, organization_id=1, user_id=1)
    db.commit()

    result = org_structure_routes.complete_structure_setup_route(ctx=_ctx(1), db=db)
    assert result.ready is True
    events = db.query(AuditEvent).filter(AuditEvent.organization_id == 1).all()
    assert any(e.event_type == ORG_STRUCTURE_AUDIT_COMPLETED for e in events)


def test_unit_lookup_is_tenant_isolated(db: Session):
    unit = create_unit(db, organization_id=1, name="Retail", unit_type=OrganizationUnitType.BUSINESS_UNIT)
    db.commit()
    with pytest.raises(ResourceNotFoundError):
        org_structure_routes.confirm_unit_route(unit.id, ctx=_ctx(3, organization_id=2), db=db)
