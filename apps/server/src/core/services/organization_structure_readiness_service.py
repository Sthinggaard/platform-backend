"""Organisation Structure — readiness evaluation + prepared read model.

Read-side companion to ``organization_structure_service`` (SRP, mirrors
``organization_identity_readiness_service``). Readiness is always derived
from underlying records, never a status a caller can set directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from src.core.constants.organization_structure_enums import (
    MAJOR_ORGANIZATION_UNIT_TYPES,
    OrganizationLocationStatus,
    OrganizationStructureReadiness,
    OrganizationUnitMembershipRole,
    OrganizationUnitMembershipStatus,
    OrganizationUnitScopeStatus,
    OrganizationUnitStatus,
)
from src.core.model_defs.organization_structure import (
    OrganizationLocation,
    OrganizationUnit,
    OrganizationUnitMembership,
)
from src.core.model_defs.tenant_identity import User
from src.core.model_defs.tenant_org import Organization
from src.core.roles import ADMIN_ROLES
from src.core.services.organization_identity_service import get_confirmed_scope
from src.core.services.organization_structure_service import get_confirmed_major_units


@dataclass(frozen=True)
class OrganizationStructureReadinessResult:
    ready: bool
    readiness: OrganizationStructureReadiness
    organisation_root_ready: bool
    major_units_ready: bool
    scope_mappings_ready: bool
    technical_setup_owner_assigned: bool
    unresolved_blocking_issues: int
    unresolved_optional_issues: int
    missing_reasons: list[str] = field(default_factory=list)


def evaluate_structure_readiness(db: Session, organization_id: int) -> OrganizationStructureReadinessResult:
    """Deterministic readiness evaluator.

    A unit's scope status only counts as blocking once it's a *confirmed
    major* unit — minor/suggested units never hold up readiness (spec:
    "missing minor departments... incomplete out-of-scope organisational
    areas" must never block).
    """
    organization = db.query(Organization).filter(Organization.id == organization_id).first()
    organisation_root_ready = organization is not None

    major_units = get_confirmed_major_units(db, organization_id, MAJOR_ORGANIZATION_UNIT_TYPES)
    major_units_ready = len(major_units) > 0

    unresolved_major = [u for u in major_units if u.scope_status == OrganizationUnitScopeStatus.UNRESOLVED.value]
    scope_mappings_ready = major_units_ready and not unresolved_major

    technical_setup_owner_assigned = bool(organization and organization.technical_setup_owner_user_id)

    reasons: list[str] = []
    if not organisation_root_ready:
        reasons.append("organization_missing")
    if not major_units_ready:
        reasons.append("no_major_operational_units")
    if major_units_ready and unresolved_major:
        reasons.append("major_unit_scope_unresolved")
    if not technical_setup_owner_assigned:
        reasons.append("technical_setup_owner_missing")

    # Non-blocking: suggested units still awaiting review, and any
    # non-major unit sitting at "unresolved" scope — visible, never gating.
    optional_issues = (
        db.query(OrganizationUnit)
        .filter(
            OrganizationUnit.organization_id == organization_id,
            OrganizationUnit.status == OrganizationUnitStatus.SUGGESTED.value,
        )
        .count()
    )
    optional_issues += (
        db.query(OrganizationLocation)
        .filter(
            OrganizationLocation.organization_id == organization_id,
            OrganizationLocation.status == "suggested",
        )
        .count()
    )

    ready = not reasons
    if ready:
        readiness = OrganizationStructureReadiness.READY
    elif organisation_root_ready and major_units_ready:
        readiness = OrganizationStructureReadiness.REVIEW_REQUIRED
    elif organisation_root_ready:
        readiness = OrganizationStructureReadiness.IN_PROGRESS
    else:
        readiness = OrganizationStructureReadiness.MISSING

    return OrganizationStructureReadinessResult(
        ready=ready,
        readiness=readiness,
        organisation_root_ready=organisation_root_ready,
        major_units_ready=major_units_ready,
        scope_mappings_ready=scope_mappings_ready,
        technical_setup_owner_assigned=technical_setup_owner_assigned,
        unresolved_blocking_issues=len(reasons),
        unresolved_optional_issues=optional_issues,
        missing_reasons=reasons,
    )


@dataclass(frozen=True)
class PreparedUnit:
    id: str
    name: str
    unit_type: str
    parent_unit_id: str | None
    legal_entity_id: str | None
    scope_status: str
    status: str


@dataclass(frozen=True)
class PreparedLocation:
    id: str
    name: str
    location_type: str
    organization_unit_id: str | None
    country_code: str | None


@dataclass(frozen=True)
class SetupOwnership:
    organisation_administrator_ids: list[int]
    technical_setup_owner_id: int | None
    technical_contact_ids: list[int]


@dataclass(frozen=True)
class StructureIssue:
    id: str
    issue_type: str
    blocking: bool


@dataclass(frozen=True)
class PreparedOrganisationStructure:
    """Business-readable summary consumed by later onboarding stages
    (evidence-source scoping, Business Service/Process suggestion
    generation) — deliberately does not include criticality, BIA, or
    ownership conclusions."""

    organization_id: int
    scope_id: str | None
    root_unit_id: str | None
    unit_count: int
    confirmed_unit_count: int
    units: list[PreparedUnit]
    locations: list[PreparedLocation]
    shared_service_unit_ids: list[str]
    technical_setup_owner_id: int | None
    setup_ownership: SetupOwnership
    unresolved_blocking_issues: int
    unresolved_optional_issues: int
    unresolved_structure_issues: list[StructureIssue]
    readiness: OrganizationStructureReadiness


def _build_setup_ownership(db: Session, organization_id: int, organization: Organization | None) -> SetupOwnership:
    admin_ids = [
        u.id
        for u in db.query(User)
        .filter(User.organization_id == organization_id, User.role.in_(ADMIN_ROLES), User.is_active.is_(True))
        .all()
    ]
    technical_contact_ids = [
        m.user_id
        for m in db.query(OrganizationUnitMembership)
        .filter(
            OrganizationUnitMembership.organization_id == organization_id,
            OrganizationUnitMembership.membership_role == OrganizationUnitMembershipRole.TECHNICAL_CONTACT.value,
            OrganizationUnitMembership.status == OrganizationUnitMembershipStatus.CONFIRMED.value,
        )
        .all()
    ]
    return SetupOwnership(
        organisation_administrator_ids=admin_ids,
        technical_setup_owner_id=organization.technical_setup_owner_user_id if organization else None,
        technical_contact_ids=technical_contact_ids,
    )


def _build_structure_issues(
    db: Session, organization_id: int, major_units: list[OrganizationUnit]
) -> list[StructureIssue]:
    issues: list[StructureIssue] = [
        StructureIssue(id=u.id, issue_type="major_unit_scope_unresolved", blocking=True)
        for u in major_units
        if u.scope_status == OrganizationUnitScopeStatus.UNRESOLVED.value
    ]
    if not major_units:
        issues.append(StructureIssue(id="major_units", issue_type="no_major_operational_units", blocking=True))

    suggested_units = (
        db.query(OrganizationUnit)
        .filter(
            OrganizationUnit.organization_id == organization_id,
            OrganizationUnit.status == OrganizationUnitStatus.SUGGESTED.value,
        )
        .all()
    )
    issues += [
        StructureIssue(id=u.id, issue_type="unit_suggestion_unresolved", blocking=False) for u in suggested_units
    ]

    suggested_locations = (
        db.query(OrganizationLocation)
        .filter(
            OrganizationLocation.organization_id == organization_id,
            OrganizationLocation.status == OrganizationLocationStatus.SUGGESTED.value,
        )
        .all()
    )
    issues += [
        StructureIssue(id=loc.id, issue_type="location_suggestion_unresolved", blocking=False)
        for loc in suggested_locations
    ]
    return issues


def build_prepared_organisation_structure(db: Session, organization_id: int) -> PreparedOrganisationStructure:
    organization = db.query(Organization).filter(Organization.id == organization_id).first()
    units = (
        db.query(OrganizationUnit)
        .filter(
            OrganizationUnit.organization_id == organization_id,
            OrganizationUnit.status != OrganizationUnitStatus.ARCHIVED.value,
        )
        .all()
    )
    confirmed_units = [u for u in units if u.status == OrganizationUnitStatus.CONFIRMED.value]
    root = next((u for u in confirmed_units if u.parent_unit_id is None), None)
    shared_service_ids = [u.id for u in confirmed_units if u.unit_type == "shared_service"]

    confirmed_locations = (
        db.query(OrganizationLocation)
        .filter(
            OrganizationLocation.organization_id == organization_id,
            OrganizationLocation.status == OrganizationLocationStatus.CONFIRMED.value,
        )
        .all()
    )

    confirmed_scope = get_confirmed_scope(db, organization_id)
    readiness_result = evaluate_structure_readiness(db, organization_id)
    major_units = get_confirmed_major_units(db, organization_id, MAJOR_ORGANIZATION_UNIT_TYPES)

    return PreparedOrganisationStructure(
        organization_id=organization_id,
        scope_id=confirmed_scope.id if confirmed_scope else None,
        root_unit_id=root.id if root else None,
        unit_count=len(units),
        confirmed_unit_count=len(confirmed_units),
        units=[
            PreparedUnit(
                id=u.id,
                name=u.name,
                unit_type=u.unit_type,
                parent_unit_id=u.parent_unit_id,
                legal_entity_id=u.legal_entity_id,
                scope_status=u.scope_status,
                status=u.status,
            )
            for u in units
        ],
        locations=[
            PreparedLocation(
                id=loc.id,
                name=loc.name,
                location_type=loc.location_type,
                organization_unit_id=loc.organization_unit_id,
                country_code=loc.country_code,
            )
            for loc in confirmed_locations
        ],
        shared_service_unit_ids=shared_service_ids,
        technical_setup_owner_id=organization.technical_setup_owner_user_id if organization else None,
        setup_ownership=_build_setup_ownership(db, organization_id, organization),
        unresolved_blocking_issues=readiness_result.unresolved_blocking_issues,
        unresolved_optional_issues=readiness_result.unresolved_optional_issues,
        unresolved_structure_issues=_build_structure_issues(db, organization_id, major_units),
        readiness=readiness_result.readiness,
    )
