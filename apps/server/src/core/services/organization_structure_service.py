"""Organisation Structure — units, relationships, locations, membership,
pairwise duplicate detection (post-ORG-ID onboarding stage).

Establishes places and possible owners, not business-impact conclusions —
this module must never determine criticality, BIA, risk appetite, or
process/service ownership. ``OrganizationUnitMembership`` is placement
only: no function here ever creates or touches ``OrgMandateRoleAssignment``
— a manager/member relationship never grants the process or service
owner's operational mandate (see docs/tasks/active/
onboarding-domain-org-skill-alignment.md).
"""

from __future__ import annotations

from dataclasses import dataclass

import difflib

from sqlalchemy.orm import Session

from src.core.constants.organization_structure_enums import (
    ORG_UNIT_NAME_SYNONYM_GROUPS,
    OrganizationLocationStatus,
    OrganizationUnitMatchStatus,
    OrganizationUnitMembershipSource,
    OrganizationUnitMembershipStatus,
    OrganizationUnitRelationshipStatus,
    OrganizationUnitSource,
    OrganizationUnitStatus,
    OrganizationUnitType,
)
from src.core.constants.organization_unit_archetype_library import (
    OrganisationIndustryFamily,
    OrganisationSizeBand,
    suggest_units_for_archetype,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.organization_identity import OrganizationLegalEntity, OrganizationScope
from src.core.model_defs.organization_structure import (
    OrganizationLocation,
    OrganizationUnit,
    OrganizationUnitMatchSuggestion,
    OrganizationUnitMembership,
    OrganizationUnitRelationship,
)
from src.core.model_defs.tenant_identity import User
from src.core.model_defs.tenant_org import Organization


class OrganizationStructureValidationError(ValueError):
    """Raised when an organisation-structure operation is invalid."""


def assign_technical_setup_owner(db: Session, *, organization_id: int, user_id: int) -> Organization:
    """A real, active user of this organisation — same accountable-actor
    shape as every other actor field in this codebase, never free text."""
    user = db.query(User).filter(User.id == user_id, User.organization_id == organization_id).first()
    if user is None or not user.is_active:
        raise OrganizationStructureValidationError(
            "The Technical Setup Owner must be an active user of this organisation."
        )
    organization = db.query(Organization).filter(Organization.id == organization_id).first()
    if organization is None:
        raise OrganizationStructureValidationError("Organisation not found.")
    organization.technical_setup_owner_user_id = user_id
    db.add(organization)
    return organization


# --- Units -------------------------------------------------------------------


def create_unit(
    db: Session,
    *,
    organization_id: int,
    name: str,
    unit_type: OrganizationUnitType,
    parent_unit_id: str | None = None,
    legal_entity_id: str | None = None,
    country_code: str | None = None,
    code: str | None = None,
    description: str | None = None,
    status: OrganizationUnitStatus = OrganizationUnitStatus.SUGGESTED,
    source: OrganizationUnitSource = OrganizationUnitSource.USER,
    source_reference: str | None = None,
    confidence: float | None = None,
) -> OrganizationUnit:
    if not name.strip():
        raise OrganizationStructureValidationError("A unit name is required.")
    unit = OrganizationUnit(
        organization_id=organization_id,
        name=name.strip(),
        code=code,
        description=description,
        unit_type=unit_type.value,
        parent_unit_id=parent_unit_id,
        legal_entity_id=legal_entity_id,
        country_code=country_code,
        status=status.value,
        source=source.value,
        source_reference=source_reference,
        confidence=confidence,
    )
    db.add(unit)
    db.flush()
    return unit


def confirm_unit(db: Session, unit: OrganizationUnit, *, confirmed_by_user_id: int) -> OrganizationUnit:
    unit.status = OrganizationUnitStatus.CONFIRMED.value
    unit.confirmed_by_user_id = confirmed_by_user_id
    unit.confirmed_at = utcnow()
    db.add(unit)
    return unit


def exclude_unit(db: Session, unit: OrganizationUnit) -> OrganizationUnit:
    unit.status = OrganizationUnitStatus.EXCLUDED.value
    db.add(unit)
    return unit


def restore_unit(db: Session, unit: OrganizationUnit) -> OrganizationUnit:
    """Undoes an exclude — returns the unit to "suggested" so it re-enters
    the confirm/exclude decision rather than being silently auto-confirmed
    (impeccable critique P0: exclude had no recovery path)."""
    unit.status = OrganizationUnitStatus.SUGGESTED.value
    db.add(unit)
    return unit


def rename_unit(db: Session, unit: OrganizationUnit, *, name: str) -> OrganizationUnit:
    if not name.strip():
        raise OrganizationStructureValidationError("A unit name is required.")
    aliases = list(unit.aliases or [])
    if unit.name and unit.name != name.strip():
        aliases.append(unit.name)
    unit.name = name.strip()
    unit.aliases = aliases
    db.add(unit)
    return unit


def move_unit(db: Session, unit: OrganizationUnit, *, parent_unit_id: str | None) -> OrganizationUnit:
    if parent_unit_id == unit.id:
        raise OrganizationStructureValidationError("A unit cannot be its own parent.")
    unit.parent_unit_id = parent_unit_id
    db.add(unit)
    return unit


def set_unit_scope_status(db: Session, unit: OrganizationUnit, *, scope_status: str) -> OrganizationUnit:
    unit.scope_status = scope_status
    db.add(unit)
    return unit


def list_units(db: Session, organization_id: int) -> list[OrganizationUnit]:
    return (
        db.query(OrganizationUnit)
        .filter(OrganizationUnit.organization_id == organization_id)
        .order_by(OrganizationUnit.created_at.asc())
        .all()
    )


def get_confirmed_major_units(db: Session, organization_id: int, major_types: frozenset[str]) -> list[OrganizationUnit]:
    return (
        db.query(OrganizationUnit)
        .filter(
            OrganizationUnit.organization_id == organization_id,
            OrganizationUnit.status == OrganizationUnitStatus.CONFIRMED.value,
            OrganizationUnit.unit_type.in_(major_types),
        )
        .all()
    )


# --- Relationships -------------------------------------------------------------


def create_relationship(
    db: Session,
    *,
    organization_id: int,
    source_unit_id: str,
    target_unit_id: str,
    relationship_type,
    source: OrganizationUnitSource = OrganizationUnitSource.USER,
    confidence: float | None = None,
    status: OrganizationUnitRelationshipStatus = OrganizationUnitRelationshipStatus.SUGGESTED,
) -> OrganizationUnitRelationship:
    if source_unit_id == target_unit_id:
        raise OrganizationStructureValidationError("A unit cannot have a relationship to itself.")
    relationship = OrganizationUnitRelationship(
        organization_id=organization_id,
        source_unit_id=source_unit_id,
        target_unit_id=target_unit_id,
        relationship_type=relationship_type.value,
        status=status.value,
        source=source.value,
        confidence=confidence,
    )
    db.add(relationship)
    db.flush()
    return relationship


def confirm_relationship(
    db: Session, relationship: OrganizationUnitRelationship, *, confirmed_by_user_id: int
) -> OrganizationUnitRelationship:
    relationship.status = OrganizationUnitRelationshipStatus.CONFIRMED.value
    relationship.confirmed_by_user_id = confirmed_by_user_id
    relationship.confirmed_at = utcnow()
    db.add(relationship)
    return relationship


def reject_relationship(db: Session, relationship: OrganizationUnitRelationship) -> OrganizationUnitRelationship:
    relationship.status = OrganizationUnitRelationshipStatus.REJECTED.value
    db.add(relationship)
    return relationship


# --- Locations -----------------------------------------------------------------


def create_location(
    db: Session,
    *,
    organization_id: int,
    name: str,
    location_type,
    organization_unit_id: str | None = None,
    country_code: str | None = None,
    region: str | None = None,
    city: str | None = None,
    address_reference: str | None = None,
    status: OrganizationLocationStatus = OrganizationLocationStatus.SUGGESTED,
) -> OrganizationLocation:
    if not name.strip():
        raise OrganizationStructureValidationError("A location name is required.")
    location = OrganizationLocation(
        organization_id=organization_id,
        organization_unit_id=organization_unit_id,
        name=name.strip(),
        location_type=location_type.value,
        country_code=country_code,
        region=region,
        city=city,
        address_reference=address_reference,
        status=status.value,
    )
    db.add(location)
    db.flush()
    return location


def confirm_location(db: Session, location: OrganizationLocation) -> OrganizationLocation:
    location.status = OrganizationLocationStatus.CONFIRMED.value
    db.add(location)
    return location


# --- Membership (placement only — never grants mandate) ------------------------


def create_membership(
    db: Session,
    *,
    organization_id: int,
    organization_unit_id: str,
    user_id: int,
    membership_role,
    source: OrganizationUnitMembershipSource = OrganizationUnitMembershipSource.MANUAL,
    status: OrganizationUnitMembershipStatus = OrganizationUnitMembershipStatus.SUGGESTED,
) -> OrganizationUnitMembership:
    resolved_source = source
    membership = OrganizationUnitMembership(
        organization_id=organization_id,
        organization_unit_id=organization_unit_id,
        user_id=user_id,
        membership_role=membership_role.value,
        source=resolved_source.value,
        status=status.value,
    )
    db.add(membership)
    db.flush()
    return membership


def confirm_membership(db: Session, membership: OrganizationUnitMembership) -> OrganizationUnitMembership:
    membership.status = OrganizationUnitMembershipStatus.CONFIRMED.value
    db.add(membership)
    return membership


# --- Pairwise duplicate-unit detection + merge ---------------------------------


def create_match_suggestion(
    db: Session,
    *,
    organization_id: int,
    unit_a_id: str,
    unit_b_id: str,
    match_confidence: float,
    matching_reasons: list[str],
) -> OrganizationUnitMatchSuggestion:
    if unit_a_id == unit_b_id:
        raise OrganizationStructureValidationError("A unit cannot be a duplicate of itself.")
    suggestion = OrganizationUnitMatchSuggestion(
        organization_id=organization_id,
        unit_a_id=unit_a_id,
        unit_b_id=unit_b_id,
        match_confidence=match_confidence,
        matching_reasons=matching_reasons,
        status=OrganizationUnitMatchStatus.PENDING.value,
    )
    db.add(suggestion)
    db.flush()
    return suggestion


# Below this ratio, two unit names are treated as unrelated — deliberately
# high so this never fabricates a duplicate from a coincidental overlap.
_DUPLICATE_NAME_SIMILARITY_THRESHOLD = 0.82


def _normalize_unit_name(name: str) -> str:
    return " ".join(name.strip().lower().split())


def _synonym_group_containing(normalized_name: str) -> frozenset[str] | None:
    for group in ORG_UNIT_NAME_SYNONYM_GROUPS:
        if normalized_name in group:
            return group
    return None


def generate_duplicate_unit_suggestions(
    db: Session, organization_id: int
) -> list[OrganizationUnitMatchSuggestion]:
    """Propose likely-duplicate unit pairs from name similarity (spec §11:
    "IT / Information Technology / Technology / Global IT may refer to the
    same organisational unit and require normalisation"). Deliberately
    simple — stdlib ``difflib.SequenceMatcher`` plus a small, conservative
    synonym list (``ORG_UNIT_NAME_SYNONYM_GROUPS``, same narrow-by-design
    principle as evidence_source's ``EVIDENCE_FIELD_SYNONYMS``) — this only
    ever *flags* a candidate pair for a human to decide via
    ``merge_units``/``keep_units_separate``/``reject_match_suggestion``; it
    never merges anything itself. Only compares units of the same type
    (a department and a location sharing a name is not the kind of
    duplicate this spec example describes), skips archived/excluded units,
    and never re-proposes a pair that already has a suggestion — pending,
    decided, or previously rejected.
    """
    units = (
        db.query(OrganizationUnit)
        .filter(
            OrganizationUnit.organization_id == organization_id,
            OrganizationUnit.status.notin_(
                [OrganizationUnitStatus.ARCHIVED.value, OrganizationUnitStatus.EXCLUDED.value]
            ),
        )
        .order_by(OrganizationUnit.created_at.asc())
        .all()
    )
    existing_pairs = {
        frozenset((s.unit_a_id, s.unit_b_id))
        for s in db.query(OrganizationUnitMatchSuggestion)
        .filter(OrganizationUnitMatchSuggestion.organization_id == organization_id)
        .all()
    }

    created: list[OrganizationUnitMatchSuggestion] = []
    for index, unit_a in enumerate(units):
        name_a = _normalize_unit_name(unit_a.name)
        synonym_group = _synonym_group_containing(name_a)
        for unit_b in units[index + 1 :]:
            if unit_a.unit_type != unit_b.unit_type:
                continue
            pair_key = frozenset((unit_a.id, unit_b.id))
            if pair_key in existing_pairs:
                continue

            name_b = _normalize_unit_name(unit_b.name)
            if synonym_group is not None and name_b in synonym_group:
                confidence = 0.9
                reasons = [f"known synonym pair: {unit_a.name!r} / {unit_b.name!r}"]
            else:
                ratio = difflib.SequenceMatcher(None, name_a, name_b).ratio()
                if ratio < _DUPLICATE_NAME_SIMILARITY_THRESHOLD:
                    continue
                confidence = ratio
                reasons = [f"name similarity {ratio:.2f}: {unit_a.name!r} / {unit_b.name!r}"]

            suggestion = create_match_suggestion(
                db,
                organization_id=organization_id,
                unit_a_id=unit_a.id,
                unit_b_id=unit_b.id,
                match_confidence=round(confidence, 2),
                matching_reasons=reasons,
            )
            created.append(suggestion)
            existing_pairs.add(pair_key)

    return created


def reject_match_suggestion(
    db: Session, suggestion: OrganizationUnitMatchSuggestion, *, decided_by_user_id: int
) -> OrganizationUnitMatchSuggestion:
    suggestion.status = OrganizationUnitMatchStatus.REJECTED.value
    suggestion.decided_by_user_id = decided_by_user_id
    suggestion.decided_at = utcnow()
    db.add(suggestion)
    return suggestion


def keep_units_separate(
    db: Session, suggestion: OrganizationUnitMatchSuggestion, *, decided_by_user_id: int
) -> OrganizationUnitMatchSuggestion:
    suggestion.status = OrganizationUnitMatchStatus.KEPT_SEPARATE.value
    suggestion.decided_by_user_id = decided_by_user_id
    suggestion.decided_at = utcnow()
    db.add(suggestion)
    return suggestion


def merge_units(
    db: Session,
    suggestion: OrganizationUnitMatchSuggestion,
    *,
    survivor_unit_id: str,
    decided_by_user_id: int,
) -> OrganizationUnit:
    """Merge two duplicate units into one survivor, in one transaction.

    Nothing is ever deleted (spec: "must be reversible where practical").
    The merged-away unit is archived and redirects (``merged_into_unit_id``)
    to the survivor; its name becomes an alias on the survivor; every
    relationship, membership, location, and child unit that referenced the
    merged-away unit is re-pointed to the survivor rather than orphaned or
    dropped.
    """
    if survivor_unit_id not in (suggestion.unit_a_id, suggestion.unit_b_id):
        raise OrganizationStructureValidationError(
            "The survivor must be one of the two units in the suggestion."
        )
    merged_id = suggestion.unit_b_id if survivor_unit_id == suggestion.unit_a_id else suggestion.unit_a_id

    survivor = db.query(OrganizationUnit).filter(OrganizationUnit.id == survivor_unit_id).first()
    merged = db.query(OrganizationUnit).filter(OrganizationUnit.id == merged_id).first()
    if survivor is None or merged is None:
        raise OrganizationStructureValidationError("Both units in the suggestion must exist.")
    if merged.status == OrganizationUnitStatus.ARCHIVED.value:
        raise OrganizationStructureValidationError("This unit has already been merged into another unit.")

    aliases = list(survivor.aliases or [])
    if merged.name and merged.name not in aliases:
        aliases.append(merged.name)
    survivor.aliases = aliases
    db.add(survivor)

    merged.status = OrganizationUnitStatus.ARCHIVED.value
    merged.merged_into_unit_id = survivor.id
    db.add(merged)

    db.query(OrganizationUnit).filter(OrganizationUnit.parent_unit_id == merged.id).update(
        {"parent_unit_id": survivor.id}, synchronize_session=False
    )
    db.query(OrganizationUnitMembership).filter(
        OrganizationUnitMembership.organization_unit_id == merged.id
    ).update({"organization_unit_id": survivor.id}, synchronize_session=False)
    db.query(OrganizationLocation).filter(OrganizationLocation.organization_unit_id == merged.id).update(
        {"organization_unit_id": survivor.id}, synchronize_session=False
    )
    db.query(OrganizationUnitRelationship).filter(
        OrganizationUnitRelationship.source_unit_id == merged.id
    ).update({"source_unit_id": survivor.id}, synchronize_session=False)
    db.query(OrganizationUnitRelationship).filter(
        OrganizationUnitRelationship.target_unit_id == merged.id
    ).update({"target_unit_id": survivor.id}, synchronize_session=False)

    suggestion.status = OrganizationUnitMatchStatus.MERGED.value
    suggestion.decided_by_user_id = decided_by_user_id
    suggestion.decided_at = utcnow()
    db.add(suggestion)
    db.flush()
    return survivor


# --- v1 suggestion seeding (from organisation identity only) -------------------


def seed_units_from_organization_identity(db: Session, organization_id: int) -> list[OrganizationUnit]:
    """Seeds suggested units from what ORG-ID already established: one
    ``legal_entity``-type unit per confirmed legal entity, and one
    ``country``-type unit per country in the confirmed implementation
    scope. Identity-provider/CMDB/HR-import suggestion sources are a named
    follow-up (no such integrations exist in this codebase yet) — this is
    deliberately the only v1 seeding source.
    """
    created: list[OrganizationUnit] = []

    existing_source_refs = {
        u.source_reference
        for u in db.query(OrganizationUnit).filter(OrganizationUnit.organization_id == organization_id).all()
        if u.source_reference
    }

    entities = (
        db.query(OrganizationLegalEntity)
        .filter(
            OrganizationLegalEntity.organization_id == organization_id,
            OrganizationLegalEntity.status == "confirmed",
        )
        .all()
    )
    for entity in entities:
        if entity.id in existing_source_refs:
            continue
        unit = create_unit(
            db,
            organization_id=organization_id,
            name=entity.legal_name,
            unit_type=OrganizationUnitType.LEGAL_ENTITY,
            legal_entity_id=entity.id,
            country_code=entity.registration_country,
            status=OrganizationUnitStatus.SUGGESTED,
            source=OrganizationUnitSource.REGISTRY,
            source_reference=entity.id,
            confidence=0.9,
        )
        created.append(unit)

    scope = (
        db.query(OrganizationScope)
        .filter(OrganizationScope.organization_id == organization_id, OrganizationScope.status == "confirmed")
        .order_by(OrganizationScope.confirmed_at.desc())
        .first()
    )
    if scope is not None:
        for country_code in scope.included_countries or []:
            source_ref = f"scope-country-{country_code}"
            if source_ref in existing_source_refs:
                continue
            unit = create_unit(
                db,
                organization_id=organization_id,
                name=country_code,
                unit_type=OrganizationUnitType.COUNTRY,
                country_code=country_code,
                status=OrganizationUnitStatus.SUGGESTED,
                source=OrganizationUnitSource.RISKLENCE_SUGGESTION,
                source_reference=source_ref,
                confidence=0.7,
            )
            created.append(unit)

    return created


#: A unit the reader has ruled out, or one merged away. Never re-offered: a
#: suggestion that comes back after a person has excluded it undoes their
#: decision, which this product never does silently.
_WITHDRAWN_UNIT_STATUSES = frozenset({OrganizationUnitStatus.EXCLUDED, OrganizationUnitStatus.ARCHIVED})


@dataclass(frozen=True)
class ArchetypeSuggestionResult:
    """What the call created, and what the organisation now has.

    ⚠️ **These are not the same list, and returning only the first was a bug.**
    The function skips any unit whose ``source_reference`` already exists —
    right for idempotency, wrong as an answer. A second click therefore returned
    `[]`, indistinguishable from "this archetype suggests nothing", while the
    seven units sat in the database the whole time (#372, found by Søren walking
    the onboarding journey on 2026-08-31).
    """

    #: Newly created this call. Audit these — the others were audited already.
    created: list[OrganizationUnit]
    #: Every unit this archetype stands for that the organisation now holds,
    #: in catalogue order, minus the ones a person has withdrawn.
    units: list[OrganizationUnit]


def suggest_units_from_archetype(
    db: Session,
    organization_id: int,
    *,
    industry_family: OrganisationIndustryFamily,
    size_band: OrganisationSizeBand,
) -> ArchetypeSuggestionResult:
    """Seeds suggested units from a user-selected industry family + size
    band (2026-07-17, Søren: "is it possible to have suggestions based on
    the size of the org and the org type?"). A simpler sibling to
    ``seed_units_from_organization_identity`` — same idempotency shape via
    ``source_reference``, same ``RISKLENCE_SUGGESTION`` source, but derived
    from a quick user-supplied classification rather than confirmed
    registry facts, so it always carries a flat, honest confidence rather
    than the registry-derived seeding's higher one.

    Returns both what it created and what the organisation now has — see
    :class:`ArchetypeSuggestionResult`.
    """
    created: list[OrganizationUnit] = []
    units: list[OrganizationUnit] = []

    existing_by_source_ref = {
        u.source_reference: u
        for u in db.query(OrganizationUnit).filter(OrganizationUnit.organization_id == organization_id).all()
        if u.source_reference
    }

    for suggestion in suggest_units_for_archetype(industry_family, size_band):
        source_ref = f"archetype-{industry_family.value}-{suggestion.name}"
        existing = existing_by_source_ref.get(source_ref)
        if existing is not None:
            # Already offered once. Carried through so a second click shows the
            # same seven units, unless the reader has since ruled it out.
            if OrganizationUnitStatus(existing.status) not in _WITHDRAWN_UNIT_STATUSES:
                units.append(existing)
            continue
        unit = create_unit(
            db,
            organization_id=organization_id,
            name=suggestion.name,
            unit_type=OrganizationUnitType(suggestion.unit_type),
            status=OrganizationUnitStatus.SUGGESTED,
            source=OrganizationUnitSource.RISKLENCE_SUGGESTION,
            source_reference=source_ref,
            confidence=0.6,
        )
        created.append(unit)
        units.append(unit)

    return ArchetypeSuggestionResult(created=created, units=units)
