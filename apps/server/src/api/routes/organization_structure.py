"""Organisation Structure routes — sufficient operational structure (post-ORG-ID stage).

Sits between Organisation Identity Setup and Leadership Authorisation in
the onboarding readiness sequence. Mutations require the platform
``org_admin``/``admin`` role, following the same ``_require_org_admin``
pattern as ``organization_identity.py`` and ``leadership_authorization.py``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.organization_structure_enums import (
    ORG_STRUCTURE_AUDIT_COMPLETED,
    ORG_STRUCTURE_AUDIT_LOCATION_CONFIRMED,
    ORG_STRUCTURE_AUDIT_LOCATION_IMPORTED,
    ORG_STRUCTURE_AUDIT_MEMBERSHIP_CONFIRMED,
    ORG_STRUCTURE_AUDIT_MEMBERSHIP_SUGGESTED,
    ORG_STRUCTURE_AUDIT_RELATIONSHIP_CONFIRMED,
    ORG_STRUCTURE_AUDIT_RELATIONSHIP_REJECTED,
    ORG_STRUCTURE_AUDIT_RELATIONSHIP_SUGGESTED,
    ORG_STRUCTURE_AUDIT_TSO_ASSIGNED,
    ORG_STRUCTURE_AUDIT_UNIT_CONFIRMED,
    ORG_STRUCTURE_AUDIT_UNIT_CREATED,
    ORG_STRUCTURE_AUDIT_UNIT_EXCLUDED,
    ORG_STRUCTURE_AUDIT_UNIT_MERGED,
    ORG_STRUCTURE_AUDIT_UNIT_MOVED,
    ORG_STRUCTURE_AUDIT_UNIT_RENAMED,
    ORG_STRUCTURE_AUDIT_UNIT_RESTORED,
    ORG_STRUCTURE_AUDIT_MATCH_SUGGESTIONS_GENERATED,
    ORG_STRUCTURE_AUDIT_UNITS_SUGGESTED_FROM_ARCHETYPE,
    ORG_STRUCTURE_ERROR_ADMIN_REQUIRED,
    ORG_STRUCTURE_ERROR_LOCATION_NOT_FOUND,
    ORG_STRUCTURE_ERROR_MATCH_SUGGESTION_NOT_FOUND,
    ORG_STRUCTURE_ERROR_MEMBERSHIP_NOT_FOUND,
    ORG_STRUCTURE_ERROR_RELATIONSHIP_NOT_FOUND,
    ORG_STRUCTURE_ERROR_UNIT_NOT_FOUND,
    OrganizationLocationType,
    OrganizationUnitMembershipRole,
    OrganizationUnitMembershipSource,
    OrganizationUnitRelationshipType,
    OrganizationUnitSource,
    OrganizationUnitType,
)
from src.core.constants.organization_unit_archetype_library import (
    OrganisationIndustryFamily,
    OrganisationSizeBand,
)
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.organization_structure import (
    OrganizationLocation,
    OrganizationUnit,
    OrganizationUnitMatchSuggestion,
    OrganizationUnitMembership,
    OrganizationUnitRelationship,
)
from src.core.models import AuditEvent, User
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES
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
    create_membership,
    create_relationship,
    create_unit,
    exclude_unit,
    generate_duplicate_unit_suggestions,
    keep_units_separate,
    merge_units,
    move_unit,
    reject_match_suggestion,
    reject_relationship,
    rename_unit,
    restore_unit,
    seed_units_from_organization_identity,
    set_unit_scope_status,
    suggest_units_from_archetype,
)

router = APIRouter(prefix="/api/v1/organization-structure", tags=["Organisation structure"])


class UnitRequest(BaseModel):
    name: str
    unit_type: OrganizationUnitType
    parent_unit_id: str | None = None
    legal_entity_id: str | None = None
    country_code: str | None = None
    code: str | None = None
    description: str | None = None


class UnitPatchRequest(BaseModel):
    name: str | None = None
    parent_unit_id: str | None = None
    scope_status: str | None = None


class UnitResponse(BaseModel):
    id: str
    name: str
    unit_type: str
    parent_unit_id: str | None
    legal_entity_id: str | None
    country_code: str | None
    status: str
    scope_status: str
    source: str
    confidence: float | None
    aliases: list[str]
    merged_into_unit_id: str | None


class RelationshipRequest(BaseModel):
    source_unit_id: str
    target_unit_id: str
    relationship_type: OrganizationUnitRelationshipType


class RelationshipResponse(BaseModel):
    id: str
    source_unit_id: str
    target_unit_id: str
    relationship_type: str
    status: str


class LocationRequest(BaseModel):
    name: str
    location_type: OrganizationLocationType
    organization_unit_id: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None


class LocationResponse(BaseModel):
    id: str
    name: str
    location_type: str
    organization_unit_id: str | None
    status: str


class MembershipRequest(BaseModel):
    organization_unit_id: str
    user_id: int
    membership_role: OrganizationUnitMembershipRole


class MembershipResponse(BaseModel):
    id: str
    organization_unit_id: str
    user_id: int
    membership_role: str
    status: str


class MatchSuggestionResponse(BaseModel):
    id: str
    unit_a_id: str
    unit_b_id: str
    match_confidence: float
    matching_reasons: list[str]
    status: str


class MergeRequest(BaseModel):
    survivor_unit_id: str


class SetupOwnershipRequest(BaseModel):
    technical_setup_owner_user_id: int


class SetupOwnershipResponse(BaseModel):
    technical_setup_owner_user_id: int | None


class ReadinessResponse(BaseModel):
    ready: bool
    readiness: str
    missing_reasons: list[str]
    unresolved_optional_issues: int


class PreparedUnitResponse(BaseModel):
    id: str
    name: str
    unit_type: str
    parent_unit_id: str | None
    legal_entity_id: str | None
    scope_status: str
    status: str


class PreparedLocationResponse(BaseModel):
    id: str
    name: str
    location_type: str
    organization_unit_id: str | None
    country_code: str | None


class PreparedSetupOwnershipResponse(BaseModel):
    """Setup ownership as it appears *inside* the prepared-structure response.

    Renamed 2026-08-31. It was also called ``SetupOwnershipResponse``, the same
    name as the standalone `/setup-ownership` endpoint's model 30 lines above —
    so this definition silently shadowed that one. Both `/setup-ownership`
    routes then built ``{technical_setup_owner_user_id}`` while FastAPI
    validated the result against *these* three fields, failed, and the
    middleware's catch-all turned the ValidationError into a 500.

    It broke the Organisation Structure step of onboarding, and the error a user
    saw said the authentication token could not be processed.
    """

    organisation_administrator_ids: list[int]
    technical_setup_owner_id: int | None
    technical_contact_ids: list[int]


class StructureIssueResponse(BaseModel):
    id: str
    issue_type: str
    blocking: bool


class PreparedStructureResponse(BaseModel):
    organization_id: int
    scope_id: str | None
    root_unit_id: str | None
    unit_count: int
    confirmed_unit_count: int
    units: list[PreparedUnitResponse]
    locations: list[PreparedLocationResponse]
    shared_service_unit_ids: list[str]
    technical_setup_owner_id: int | None
    setup_ownership: PreparedSetupOwnershipResponse
    unresolved_blocking_issues: int
    unresolved_optional_issues: int
    unresolved_structure_issues: list[StructureIssueResponse]
    readiness: str


def _require_org_admin(db: Session, ctx: TenantContext) -> None:
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or user.role not in ADMIN_ROLES:
        raise AuthorizationError(ORG_STRUCTURE_ERROR_ADMIN_REQUIRED)


def _write_audit(db: Session, *, ctx: TenantContext, event_type: str, metadata: dict) -> None:
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=event_type,
            metadata_json=metadata,
        )
    )


def _unit_response(unit: OrganizationUnit) -> UnitResponse:
    return UnitResponse(
        id=unit.id,
        name=unit.name,
        unit_type=unit.unit_type,
        parent_unit_id=unit.parent_unit_id,
        legal_entity_id=unit.legal_entity_id,
        country_code=unit.country_code,
        status=unit.status,
        scope_status=unit.scope_status,
        source=unit.source,
        confidence=unit.confidence,
        aliases=unit.aliases or [],
        merged_into_unit_id=unit.merged_into_unit_id,
    )


def _relationship_response(relationship: OrganizationUnitRelationship) -> RelationshipResponse:
    return RelationshipResponse(
        id=relationship.id,
        source_unit_id=relationship.source_unit_id,
        target_unit_id=relationship.target_unit_id,
        relationship_type=relationship.relationship_type,
        status=relationship.status,
    )


def _location_response(location: OrganizationLocation) -> LocationResponse:
    return LocationResponse(
        id=location.id,
        name=location.name,
        location_type=location.location_type,
        organization_unit_id=location.organization_unit_id,
        status=location.status,
    )


def _membership_response(membership: OrganizationUnitMembership) -> MembershipResponse:
    return MembershipResponse(
        id=membership.id,
        organization_unit_id=membership.organization_unit_id,
        user_id=membership.user_id,
        membership_role=membership.membership_role,
        status=membership.status,
    )


def _match_response(suggestion: OrganizationUnitMatchSuggestion) -> MatchSuggestionResponse:
    return MatchSuggestionResponse(
        id=suggestion.id,
        unit_a_id=suggestion.unit_a_id,
        unit_b_id=suggestion.unit_b_id,
        match_confidence=suggestion.match_confidence,
        matching_reasons=suggestion.matching_reasons or [],
        status=suggestion.status,
    )


@router.get("/units", response_model=list[UnitResponse])
def list_units_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[UnitResponse]:
    units = (
        db.query(OrganizationUnit)
        .filter(OrganizationUnit.organization_id == ctx.organization_id)
        .order_by(OrganizationUnit.created_at.asc())
        .all()
    )
    return [_unit_response(u) for u in units]


@router.post("/units", response_model=UnitResponse)
def create_unit_route(
    body: UnitRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> UnitResponse:
    _require_org_admin(db, ctx)
    try:
        unit = create_unit(
            db,
            organization_id=ctx.organization_id,
            name=body.name,
            unit_type=body.unit_type,
            parent_unit_id=body.parent_unit_id,
            legal_entity_id=body.legal_entity_id,
            country_code=body.country_code,
            code=body.code,
            description=body.description,
            source=OrganizationUnitSource.USER,
        )
    except OrganizationStructureValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_UNIT_CREATED, metadata={"unit_id": unit.id})
    db.commit()
    db.refresh(unit)
    return _unit_response(unit)


@router.post("/units/seed-from-identity", response_model=list[UnitResponse])
def seed_units_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[UnitResponse]:
    _require_org_admin(db, ctx)
    created = seed_units_from_organization_identity(db, ctx.organization_id)
    for unit in created:
        _write_audit(db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_UNIT_CREATED, metadata={"unit_id": unit.id, "seeded": True})
    db.commit()
    return [_unit_response(u) for u in result.units]


class SuggestFromArchetypeRequest(BaseModel):
    industry_family: OrganisationIndustryFamily
    size_band: OrganisationSizeBand


@router.post("/units/suggest-from-archetype", response_model=list[UnitResponse])
def suggest_units_from_archetype_route(
    body: SuggestFromArchetypeRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[UnitResponse]:
    _require_org_admin(db, ctx)
    # ⚠️ The response is what the organisation now has, not only what this call
    # created. Skipping already-seeded units is right for idempotency and wrong
    # as an answer: a second click used to return `[]`, which a caller renders
    # identically to "this archetype suggests nothing" (#372).
    result = suggest_units_from_archetype(
        db, ctx.organization_id, industry_family=body.industry_family, size_band=body.size_band
    )
    # Audit only the new ones. The rest were audited when they were created, and
    # re-auditing them would record a suggestion that did not happen.
    for unit in result.created:
        _write_audit(
            db,
            ctx=ctx,
            event_type=ORG_STRUCTURE_AUDIT_UNITS_SUGGESTED_FROM_ARCHETYPE,
            metadata={
                "unit_id": unit.id,
                "industry_family": body.industry_family.value,
                "size_band": body.size_band.value,
            },
        )
    db.commit()
    return [_unit_response(u) for u in result.units]


def _require_unit(db: Session, *, ctx: TenantContext, unit_id: str) -> OrganizationUnit:
    unit = TenantRepository(db, OrganizationUnit, ctx.organization_id).get_by_id(unit_id)
    if unit is None:
        raise ResourceNotFoundError(ORG_STRUCTURE_ERROR_UNIT_NOT_FOUND)
    return unit


@router.post("/units/{unit_id}/confirm", response_model=UnitResponse)
def confirm_unit_route(
    unit_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> UnitResponse:
    _require_org_admin(db, ctx)
    unit = _require_unit(db, ctx=ctx, unit_id=unit_id)
    confirm_unit(db, unit, confirmed_by_user_id=ctx.user_id)
    _write_audit(db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_UNIT_CONFIRMED, metadata={"unit_id": unit.id})
    db.commit()
    db.refresh(unit)
    return _unit_response(unit)


@router.post("/units/{unit_id}/exclude", response_model=UnitResponse)
def exclude_unit_route(
    unit_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> UnitResponse:
    _require_org_admin(db, ctx)
    unit = _require_unit(db, ctx=ctx, unit_id=unit_id)
    exclude_unit(db, unit)
    _write_audit(db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_UNIT_EXCLUDED, metadata={"unit_id": unit.id})
    db.commit()
    db.refresh(unit)
    return _unit_response(unit)


@router.post("/units/{unit_id}/restore", response_model=UnitResponse)
def restore_unit_route(
    unit_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> UnitResponse:
    _require_org_admin(db, ctx)
    unit = _require_unit(db, ctx=ctx, unit_id=unit_id)
    restore_unit(db, unit)
    _write_audit(db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_UNIT_RESTORED, metadata={"unit_id": unit.id})
    db.commit()
    db.refresh(unit)
    return _unit_response(unit)


@router.patch("/units/{unit_id}", response_model=UnitResponse)
def patch_unit_route(
    unit_id: str,
    body: UnitPatchRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> UnitResponse:
    _require_org_admin(db, ctx)
    unit = _require_unit(db, ctx=ctx, unit_id=unit_id)
    try:
        if body.name is not None:
            rename_unit(db, unit, name=body.name)
            _write_audit(db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_UNIT_RENAMED, metadata={"unit_id": unit.id})
        if "parent_unit_id" in body.model_fields_set:
            move_unit(db, unit, parent_unit_id=body.parent_unit_id)
            _write_audit(db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_UNIT_MOVED, metadata={"unit_id": unit.id})
        if body.scope_status is not None:
            set_unit_scope_status(db, unit, scope_status=body.scope_status)
    except OrganizationStructureValidationError as exc:
        raise ValidationError(str(exc)) from exc
    db.commit()
    db.refresh(unit)
    return _unit_response(unit)


@router.get("/relationships", response_model=list[RelationshipResponse])
def list_relationships_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[RelationshipResponse]:
    relationships = (
        db.query(OrganizationUnitRelationship)
        .filter(OrganizationUnitRelationship.organization_id == ctx.organization_id)
        .all()
    )
    return [_relationship_response(r) for r in relationships]


@router.post("/relationships", response_model=RelationshipResponse)
def create_relationship_route(
    body: RelationshipRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> RelationshipResponse:
    _require_org_admin(db, ctx)
    try:
        relationship = create_relationship(
            db,
            organization_id=ctx.organization_id,
            source_unit_id=body.source_unit_id,
            target_unit_id=body.target_unit_id,
            relationship_type=body.relationship_type,
            source=OrganizationUnitSource.USER,
        )
    except OrganizationStructureValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_RELATIONSHIP_SUGGESTED, metadata={"relationship_id": relationship.id}
    )
    db.commit()
    db.refresh(relationship)
    return _relationship_response(relationship)


def _require_relationship(db: Session, *, ctx: TenantContext, relationship_id: str) -> OrganizationUnitRelationship:
    relationship = TenantRepository(db, OrganizationUnitRelationship, ctx.organization_id).get_by_id(relationship_id)
    if relationship is None:
        raise ResourceNotFoundError(ORG_STRUCTURE_ERROR_RELATIONSHIP_NOT_FOUND)
    return relationship


@router.post("/relationships/{relationship_id}/confirm", response_model=RelationshipResponse)
def confirm_relationship_route(
    relationship_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> RelationshipResponse:
    _require_org_admin(db, ctx)
    relationship = _require_relationship(db, ctx=ctx, relationship_id=relationship_id)
    confirm_relationship(db, relationship, confirmed_by_user_id=ctx.user_id)
    _write_audit(
        db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_RELATIONSHIP_CONFIRMED, metadata={"relationship_id": relationship.id}
    )
    db.commit()
    db.refresh(relationship)
    return _relationship_response(relationship)


@router.post("/relationships/{relationship_id}/reject", response_model=RelationshipResponse)
def reject_relationship_route(
    relationship_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> RelationshipResponse:
    _require_org_admin(db, ctx)
    relationship = _require_relationship(db, ctx=ctx, relationship_id=relationship_id)
    reject_relationship(db, relationship)
    _write_audit(
        db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_RELATIONSHIP_REJECTED, metadata={"relationship_id": relationship.id}
    )
    db.commit()
    db.refresh(relationship)
    return _relationship_response(relationship)


@router.get("/locations", response_model=list[LocationResponse])
def list_locations_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[LocationResponse]:
    locations = (
        db.query(OrganizationLocation).filter(OrganizationLocation.organization_id == ctx.organization_id).all()
    )
    return [_location_response(l) for l in locations]


@router.post("/locations", response_model=LocationResponse)
def create_location_route(
    body: LocationRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LocationResponse:
    _require_org_admin(db, ctx)
    try:
        location = create_location(
            db,
            organization_id=ctx.organization_id,
            name=body.name,
            location_type=body.location_type,
            organization_unit_id=body.organization_unit_id,
            country_code=body.country_code,
            region=body.region,
            city=body.city,
        )
    except OrganizationStructureValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_LOCATION_IMPORTED, metadata={"location_id": location.id})
    db.commit()
    db.refresh(location)
    return _location_response(location)


@router.post("/locations/{location_id}/confirm", response_model=LocationResponse)
def confirm_location_route(
    location_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> LocationResponse:
    _require_org_admin(db, ctx)
    location = TenantRepository(db, OrganizationLocation, ctx.organization_id).get_by_id(location_id)
    if location is None:
        raise ResourceNotFoundError(ORG_STRUCTURE_ERROR_LOCATION_NOT_FOUND)
    confirm_location(db, location)
    _write_audit(db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_LOCATION_CONFIRMED, metadata={"location_id": location.id})
    db.commit()
    db.refresh(location)
    return _location_response(location)


@router.get("/memberships", response_model=list[MembershipResponse])
def list_memberships_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[MembershipResponse]:
    memberships = (
        db.query(OrganizationUnitMembership)
        .filter(OrganizationUnitMembership.organization_id == ctx.organization_id)
        .all()
    )
    return [_membership_response(m) for m in memberships]


@router.post("/memberships", response_model=MembershipResponse)
def create_membership_route(
    body: MembershipRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> MembershipResponse:
    _require_org_admin(db, ctx)
    membership = create_membership(
        db,
        organization_id=ctx.organization_id,
        organization_unit_id=body.organization_unit_id,
        user_id=body.user_id,
        membership_role=body.membership_role,
        source=OrganizationUnitMembershipSource.MANUAL,
    )
    _write_audit(
        db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_MEMBERSHIP_SUGGESTED, metadata={"membership_id": membership.id}
    )
    db.commit()
    db.refresh(membership)
    return _membership_response(membership)


@router.post("/memberships/{membership_id}/confirm", response_model=MembershipResponse)
def confirm_membership_route(
    membership_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> MembershipResponse:
    _require_org_admin(db, ctx)
    membership = TenantRepository(db, OrganizationUnitMembership, ctx.organization_id).get_by_id(membership_id)
    if membership is None:
        raise ResourceNotFoundError(ORG_STRUCTURE_ERROR_MEMBERSHIP_NOT_FOUND)
    confirm_membership(db, membership)
    _write_audit(
        db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_MEMBERSHIP_CONFIRMED, metadata={"membership_id": membership.id}
    )
    db.commit()
    db.refresh(membership)
    return _membership_response(membership)


@router.post("/match-suggestions/generate", response_model=list[MatchSuggestionResponse])
def generate_match_suggestions_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[MatchSuggestionResponse]:
    _require_org_admin(db, ctx)
    created = generate_duplicate_unit_suggestions(db, ctx.organization_id)
    for suggestion in created:
        _write_audit(
            db,
            ctx=ctx,
            event_type=ORG_STRUCTURE_AUDIT_MATCH_SUGGESTIONS_GENERATED,
            metadata={
                "suggestion_id": suggestion.id,
                "unit_a_id": suggestion.unit_a_id,
                "unit_b_id": suggestion.unit_b_id,
                "match_confidence": suggestion.match_confidence,
            },
        )
    db.commit()
    return [_match_response(s) for s in created]


@router.get("/match-suggestions", response_model=list[MatchSuggestionResponse])
def list_match_suggestions_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[MatchSuggestionResponse]:
    suggestions = (
        db.query(OrganizationUnitMatchSuggestion)
        .filter(OrganizationUnitMatchSuggestion.organization_id == ctx.organization_id)
        .all()
    )
    return [_match_response(s) for s in suggestions]


def _require_match_suggestion(
    db: Session, *, ctx: TenantContext, suggestion_id: str
) -> OrganizationUnitMatchSuggestion:
    suggestion = TenantRepository(db, OrganizationUnitMatchSuggestion, ctx.organization_id).get_by_id(suggestion_id)
    if suggestion is None:
        raise ResourceNotFoundError(ORG_STRUCTURE_ERROR_MATCH_SUGGESTION_NOT_FOUND)
    return suggestion


@router.post("/match-suggestions/{suggestion_id}/merge", response_model=UnitResponse)
def merge_units_route(
    suggestion_id: str,
    body: MergeRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> UnitResponse:
    _require_org_admin(db, ctx)
    suggestion = _require_match_suggestion(db, ctx=ctx, suggestion_id=suggestion_id)
    try:
        survivor = merge_units(
            db, suggestion, survivor_unit_id=body.survivor_unit_id, decided_by_user_id=ctx.user_id
        )
    except OrganizationStructureValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=ORG_STRUCTURE_AUDIT_UNIT_MERGED,
        metadata={"suggestion_id": suggestion.id, "survivor_unit_id": survivor.id},
    )
    db.commit()
    db.refresh(survivor)
    return _unit_response(survivor)


@router.post("/match-suggestions/{suggestion_id}/keep-separate", response_model=MatchSuggestionResponse)
def keep_separate_route(
    suggestion_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> MatchSuggestionResponse:
    _require_org_admin(db, ctx)
    suggestion = _require_match_suggestion(db, ctx=ctx, suggestion_id=suggestion_id)
    keep_units_separate(db, suggestion, decided_by_user_id=ctx.user_id)
    db.commit()
    db.refresh(suggestion)
    return _match_response(suggestion)


@router.post("/match-suggestions/{suggestion_id}/reject", response_model=MatchSuggestionResponse)
def reject_match_suggestion_route(
    suggestion_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> MatchSuggestionResponse:
    _require_org_admin(db, ctx)
    suggestion = _require_match_suggestion(db, ctx=ctx, suggestion_id=suggestion_id)
    reject_match_suggestion(db, suggestion, decided_by_user_id=ctx.user_id)
    db.commit()
    db.refresh(suggestion)
    return _match_response(suggestion)


@router.get("/setup-ownership", response_model=SetupOwnershipResponse)
def get_setup_ownership_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> SetupOwnershipResponse:
    from src.core.model_defs.tenant_org import Organization

    organization = db.query(Organization).filter(Organization.id == ctx.organization_id).first()
    return SetupOwnershipResponse(
        technical_setup_owner_user_id=organization.technical_setup_owner_user_id if organization else None
    )


@router.patch("/setup-ownership", response_model=SetupOwnershipResponse)
def patch_setup_ownership_route(
    body: SetupOwnershipRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> SetupOwnershipResponse:
    _require_org_admin(db, ctx)
    try:
        organization = assign_technical_setup_owner(
            db, organization_id=ctx.organization_id, user_id=body.technical_setup_owner_user_id
        )
    except OrganizationStructureValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=ORG_STRUCTURE_AUDIT_TSO_ASSIGNED,
        metadata={"technical_setup_owner_user_id": body.technical_setup_owner_user_id},
    )
    db.commit()
    db.refresh(organization)
    return SetupOwnershipResponse(technical_setup_owner_user_id=organization.technical_setup_owner_user_id)


@router.get("/readiness", response_model=ReadinessResponse)
def get_readiness_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ReadinessResponse:
    result = evaluate_structure_readiness(db, ctx.organization_id)
    return ReadinessResponse(
        ready=result.ready,
        readiness=result.readiness.value,
        missing_reasons=result.missing_reasons,
        unresolved_optional_issues=result.unresolved_optional_issues,
    )


@router.get("/prepared", response_model=PreparedStructureResponse)
def get_prepared_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> PreparedStructureResponse:
    prepared = build_prepared_organisation_structure(db, ctx.organization_id)
    return PreparedStructureResponse(
        organization_id=prepared.organization_id,
        scope_id=prepared.scope_id,
        root_unit_id=prepared.root_unit_id,
        unit_count=prepared.unit_count,
        confirmed_unit_count=prepared.confirmed_unit_count,
        units=[
            PreparedUnitResponse(
                id=u.id,
                name=u.name,
                unit_type=u.unit_type,
                parent_unit_id=u.parent_unit_id,
                legal_entity_id=u.legal_entity_id,
                scope_status=u.scope_status,
                status=u.status,
            )
            for u in prepared.units
        ],
        locations=[
            PreparedLocationResponse(
                id=loc.id,
                name=loc.name,
                location_type=loc.location_type,
                organization_unit_id=loc.organization_unit_id,
                country_code=loc.country_code,
            )
            for loc in prepared.locations
        ],
        shared_service_unit_ids=prepared.shared_service_unit_ids,
        technical_setup_owner_id=prepared.technical_setup_owner_id,
        setup_ownership=PreparedSetupOwnershipResponse(
            organisation_administrator_ids=prepared.setup_ownership.organisation_administrator_ids,
            technical_setup_owner_id=prepared.setup_ownership.technical_setup_owner_id,
            technical_contact_ids=prepared.setup_ownership.technical_contact_ids,
        ),
        unresolved_blocking_issues=prepared.unresolved_blocking_issues,
        unresolved_optional_issues=prepared.unresolved_optional_issues,
        unresolved_structure_issues=[
            StructureIssueResponse(id=i.id, issue_type=i.issue_type, blocking=i.blocking)
            for i in prepared.unresolved_structure_issues
        ],
        readiness=prepared.readiness.value,
    )


@router.post("/complete", response_model=ReadinessResponse)
def complete_structure_setup_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ReadinessResponse:
    _require_org_admin(db, ctx)
    result = evaluate_structure_readiness(db, ctx.organization_id)
    if not result.ready:
        raise ValidationError(
            "Organisation structure is not yet sufficient to complete: " + ", ".join(result.missing_reasons)
        )
    _write_audit(
        db, ctx=ctx, event_type=ORG_STRUCTURE_AUDIT_COMPLETED, metadata={"organization_id": ctx.organization_id}
    )
    db.commit()
    return ReadinessResponse(
        ready=result.ready,
        readiness=result.readiness.value,
        missing_reasons=[],
        unresolved_optional_issues=result.unresolved_optional_issues,
    )
