"""Organisation Structure — sufficient operational structure (post-ORG-ID stage).

Establishes units, non-hierarchical unit relationships, locations, unit
membership, and pairwise duplicate-unit detection — enough to place
technical evidence, ownership, Business Services, and future Business
Processes. Deliberately not a complete HR chart, and not a business-impact
or criticality determination (see organization_structure_service.py).
"""

from enum import StrEnum


class OrganizationUnitType(StrEnum):
    LEGAL_ENTITY = "legal_entity"
    COUNTRY = "country"
    REGION = "region"
    BUSINESS_UNIT = "business_unit"
    DIVISION = "division"
    DEPARTMENT = "department"
    FUNCTION = "function"
    BRAND = "brand"
    LOCATION = "location"
    SHARED_SERVICE = "shared_service"
    PROGRAMME = "programme"
    OTHER = "other"


# Unit types material enough to gate readiness on — a "major operational
# unit" per the contract. Minor/suggested subdepartments never block.
MAJOR_ORGANIZATION_UNIT_TYPES: frozenset[str] = frozenset(
    {
        OrganizationUnitType.BUSINESS_UNIT.value,
        OrganizationUnitType.DIVISION.value,
        OrganizationUnitType.DEPARTMENT.value,
        OrganizationUnitType.SHARED_SERVICE.value,
    }
)


class OrganizationUnitStatus(StrEnum):
    SUGGESTED = "suggested"
    CONFIRMED = "confirmed"
    EXCLUDED = "excluded"
    INACTIVE = "inactive"
    # Terminal state after a merge (see OrganizationUnitMatchSuggestion) —
    # never deleted, redirected via merged_into_unit_id.
    ARCHIVED = "archived"


class OrganizationUnitReviewDecision(StrEnum):
    CONFIRM = "confirm"
    EXCLUDE = "exclude"
    RESTORE = "restore"


class OrganizationUnitSource(StrEnum):
    REGISTRY = "registry"
    IDENTITY_PROVIDER = "identity_provider"
    CMDB = "cmdb"
    HR_SYSTEM = "hr_system"
    COLLECTOR = "collector"
    USER = "user"
    RISKLENCE_SUGGESTION = "risklence_suggestion"
    INTEGRATION = "integration"


class OrganizationUnitScopeStatus(StrEnum):
    IN_SCOPE = "in_scope"
    PARTIALLY_IN_SCOPE = "partially_in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    SHARED_DEPENDENCY = "shared_dependency"
    UNRESOLVED = "unresolved"


class OrganizationUnitRelationshipType(StrEnum):
    SUPPORTED_BY = "supported_by"
    GOVERNED_BY = "governed_by"
    OPERATED_BY = "operated_by"
    SHARED_WITH = "shared_with"
    REPORTS_TO = "reports_to"
    PROVIDES_SERVICE_TO = "provides_service_to"
    PART_OF = "part_of"
    OTHER = "other"


class OrganizationUnitRelationshipStatus(StrEnum):
    SUGGESTED = "suggested"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class OrganizationLocationType(StrEnum):
    OFFICE = "office"
    STORE = "store"
    WAREHOUSE = "warehouse"
    FACTORY = "factory"
    CLINIC = "clinic"
    DATA_CENTRE = "data_centre"
    BRANCH = "branch"
    REMOTE = "remote"
    OTHER = "other"


class OrganizationLocationStatus(StrEnum):
    SUGGESTED = "suggested"
    CONFIRMED = "confirmed"
    INACTIVE = "inactive"


class OrganizationUnitMembershipRole(StrEnum):
    MEMBER = "member"
    UNIT_ADMIN = "unit_admin"
    UNIT_OWNER = "unit_owner"
    TECHNICAL_CONTACT = "technical_contact"
    BUSINESS_CONTACT = "business_contact"
    VIEWER = "viewer"


class OrganizationUnitMembershipSource(StrEnum):
    MANUAL = "manual"
    IDENTITY_PROVIDER = "identity_provider"
    HR_SYSTEM = "hr_system"
    INTEGRATION = "integration"


class OrganizationUnitMembershipStatus(StrEnum):
    SUGGESTED = "suggested"
    CONFIRMED = "confirmed"
    INACTIVE = "inactive"


# Pairwise duplicate-unit detection (confirmed with Søren 2026-07-16: not
# n-way candidate groups — a 3+-way duplicate is just multiple pairwise
# suggestions).
class OrganizationUnitMatchStatus(StrEnum):
    PENDING = "pending"
    MERGED = "merged"
    KEPT_SEPARATE = "kept_separate"
    REJECTED = "rejected"


class OrganizationStructureReadiness(StrEnum):
    MISSING = "missing"
    IN_PROGRESS = "in_progress"
    REVIEW_REQUIRED = "review_required"
    READY = "ready"
    BLOCKED = "blocked"


# Conservative synonym groups for duplicate-unit detection (spec §11's own
# example: "IT / Information Technology / Technology / Global IT may refer
# to the same organisational unit"). Same deliberately-narrow principle as
# evidence_source_enums.EVIDENCE_FIELD_SYNONYMS — only genuinely unambiguous
# groups, never a loose word-overlap heuristic that would fabricate a false
# duplicate.
ORG_UNIT_NAME_SYNONYM_GROUPS: tuple[frozenset[str], ...] = (
    frozenset({"it", "information technology", "technology", "global it", "global information technology"}),
    frozenset({"hr", "human resources", "people", "people and culture", "people & culture"}),
    frozenset({"finance", "financial"}),
    frozenset({"security", "information security", "infosec", "cyber security", "cybersecurity"}),
    frozenset({"legal", "legal affairs", "legal and compliance"}),
    frozenset({"procurement", "purchasing", "sourcing"}),
    frozenset({"customer service", "customer support", "customer care"}),
    frozenset({"marketing", "marketing and communications", "marcomms"}),
)

ORG_STRUCTURE_AUDIT_UNIT_SUGGESTED = "organization_unit.suggested"
ORG_STRUCTURE_AUDIT_UNIT_CREATED = "organization_unit.created"
ORG_STRUCTURE_AUDIT_UNITS_SUGGESTED_FROM_ARCHETYPE = "organization_unit.suggested_from_archetype"
ORG_STRUCTURE_AUDIT_UNIT_CONFIRMED = "organization_unit.confirmed"
ORG_STRUCTURE_AUDIT_UNIT_RENAMED = "organization_unit.renamed"
ORG_STRUCTURE_AUDIT_UNIT_MOVED = "organization_unit.moved"
ORG_STRUCTURE_AUDIT_UNIT_EXCLUDED = "organization_unit.excluded"
ORG_STRUCTURE_AUDIT_UNIT_RESTORED = "organization_unit.restored"
ORG_STRUCTURE_AUDIT_UNIT_MERGED = "organization_unit.merged"
ORG_STRUCTURE_AUDIT_MATCH_SUGGESTIONS_GENERATED = "organization_unit.match_suggestions_generated"
ORG_STRUCTURE_AUDIT_RELATIONSHIP_SUGGESTED = "organization_unit.relationship_suggested"
ORG_STRUCTURE_AUDIT_RELATIONSHIP_CONFIRMED = "organization_unit.relationship_confirmed"
ORG_STRUCTURE_AUDIT_RELATIONSHIP_REJECTED = "organization_unit.relationship_rejected"
ORG_STRUCTURE_AUDIT_SCOPE_CHANGED = "organization_unit.scope_changed"
ORG_STRUCTURE_AUDIT_LOCATION_IMPORTED = "organization_location.imported"
ORG_STRUCTURE_AUDIT_LOCATION_CONFIRMED = "organization_location.confirmed"
ORG_STRUCTURE_AUDIT_MEMBERSHIP_SUGGESTED = "organization_membership.suggested"
ORG_STRUCTURE_AUDIT_MEMBERSHIP_CONFIRMED = "organization_membership.confirmed"
ORG_STRUCTURE_AUDIT_TSO_ASSIGNED = "technical_setup_owner.assigned"
ORG_STRUCTURE_AUDIT_TSO_REASSIGNED = "technical_setup_owner.reassigned"
ORG_STRUCTURE_AUDIT_COMPLETED = "organization_structure.completed"

ORG_STRUCTURE_ERROR_ADMIN_REQUIRED = (
    "Organisation administrator access is required to manage organisation structure"
)
ORG_STRUCTURE_ERROR_UNIT_NOT_FOUND = "Organisation unit not found"
ORG_STRUCTURE_ERROR_UNIT_NAME_REQUIRED = "A unit name is required"
ORG_STRUCTURE_ERROR_RELATIONSHIP_NOT_FOUND = "Organisation unit relationship not found"
ORG_STRUCTURE_ERROR_LOCATION_NOT_FOUND = "Organisation location not found"
ORG_STRUCTURE_ERROR_MEMBERSHIP_NOT_FOUND = "Organisation unit membership not found"
ORG_STRUCTURE_ERROR_MATCH_SUGGESTION_NOT_FOUND = "Organisation unit match suggestion not found"
ORG_STRUCTURE_ERROR_SELF_RELATIONSHIP = "A unit cannot have a relationship to itself"
ORG_STRUCTURE_ERROR_SELF_MATCH = "A unit cannot be a duplicate of itself"
ORG_STRUCTURE_ERROR_ALREADY_ARCHIVED = "This unit has already been merged into another unit"
