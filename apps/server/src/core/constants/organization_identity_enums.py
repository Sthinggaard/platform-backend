"""Organisation Identity Setup — lifecycle and classification values.

Post-signup stage (onboarding governance): establishes a trustworthy
organisational root and enough context for later organisation structure,
technical discovery, and Business Service/Process suggestions. Deliberately
narrow — it does not determine criticality, business impact, resilience, or
compliance status. It owns only reviewable operating context used as input
to later suggestions; it never creates downstream records.
"""

from enum import StrEnum


class OrganizationType(StrEnum):
    SINGLE_LEGAL_ENTITY = "single_legal_entity"
    CORPORATE_GROUP = "corporate_group"
    PUBLIC_BODY = "public_body"
    NON_PROFIT = "non_profit"
    OTHER = "other"


class OrganizationEntityType(StrEnum):
    PARENT = "parent"
    SUBSIDIARY = "subsidiary"
    OPERATING_COMPANY = "operating_company"
    HOLDING_COMPANY = "holding_company"
    BRANCH = "branch"
    OTHER = "other"


class OrganizationEntityStatus(StrEnum):
    SUGGESTED = "suggested"
    CONFIRMED = "confirmed"
    EXCLUDED = "excluded"


class OrganizationScopeType(StrEnum):
    ENTIRE_ORGANIZATION = "entire_organisation"
    LEGAL_ENTITY = "legal_entity"
    BUSINESS_UNIT = "business_unit"
    COUNTRY = "country"
    REGION = "region"
    PROGRAMME = "programme"
    CUSTOM = "custom"


class OrganizationScopeStatus(StrEnum):
    DRAFT = "draft"
    SUGGESTED = "suggested"
    CONFIRMED = "confirmed"


# Mirrors LeadershipAuthorizationStatus's append-only draft/review/confirmed
# shape (organization_identity.py's OrganizationIdentityConfirmation). No
# "active" state here — a confirmation is either the latest confirmed
# version or it has been superseded by a correction.
class OrganizationIdentityConfirmationStatus(StrEnum):
    DRAFT = "draft"
    SUGGESTED = "suggested"
    REVIEW_REQUIRED = "review_required"
    CONFIRMED = "confirmed"
    SUPERSEDED = "superseded"


class OrganizationIdentityEvidenceSource(StrEnum):
    CVR = "cvr"
    COMPANY_REGISTRY = "company_registry"
    USER = "user"
    CONTRACT = "contract"
    INTEGRATION = "integration"


class RegistryLookupStatus(StrEnum):
    MATCH = "match"
    NO_MATCH = "no_match"
    MULTIPLE_MATCHES = "multiple_matches"
    INACTIVE = "inactive"
    UNAVAILABLE = "unavailable"
    MANUAL_REQUIRED = "manual_required"


class OrganizationOperatingContextSuggestionType(StrEnum):
    INDUSTRY_ARCHETYPE = "industry_archetype"
    OPERATING_CHARACTERISTIC = "operating_characteristic"


class SuggestionDecision(StrEnum):
    SUGGESTED = "suggested"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class OrganizationOperatingContextSource(StrEnum):
    REGISTRY_INDUSTRY = "registry_industry"
    NACE_INFERENCE = "nace_inference"
    USER = "user"


class OrganizationDomainType(StrEnum):
    PRIMARY = "primary"
    EMAIL = "email"
    APPLICATION = "application"
    BRAND = "brand"
    SUBSIDIARY = "subsidiary"


class DomainVerificationStatus(StrEnum):
    UNVERIFIED = "unverified"
    VERIFICATION_PENDING = "verification_pending"
    VERIFIED = "verified"
    REJECTED = "rejected"


# Simplified readiness value exposed to the wider platform — see
# organization_identity_service.evaluate_identity_readiness. Prefer deriving
# this from underlying records rather than letting it be set directly.
class OrganizationIdentityReadiness(StrEnum):
    MISSING = "missing"
    IN_PROGRESS = "in_progress"
    REVIEW_REQUIRED = "review_required"
    READY = "ready"
    BLOCKED = "blocked"


ORG_IDENTITY_AUDIT_REGISTRY_LOOKUP_REQUESTED = "organization.identity_registry_lookup_requested"
ORG_IDENTITY_AUDIT_EVIDENCE_IMPORTED = "organization.identity_evidence_imported"
ORG_IDENTITY_AUDIT_CONFIRMED = "organization.identity_confirmed"
ORG_IDENTITY_AUDIT_CORRECTED = "organization.identity_corrected"
ORG_IDENTITY_AUDIT_SCOPE_CREATED = "organization.scope_created"
ORG_IDENTITY_AUDIT_SCOPE_CONFIRMED = "organization.scope_confirmed"
ORG_IDENTITY_AUDIT_ENTITY_ADDED = "organization.entity_added"
ORG_IDENTITY_AUDIT_ENTITY_CONFIRMED = "organization.entity_confirmed"
ORG_IDENTITY_AUDIT_ENTITY_EXCLUDED = "organization.entity_excluded"
ORG_IDENTITY_AUDIT_DOMAIN_ADDED = "organization.domain_added"
ORG_IDENTITY_AUDIT_DOMAIN_VERIFIED = "organization.domain_verified"
ORG_IDENTITY_AUDIT_INDUSTRY_ARCHETYPE_CONFIRMED = "organization.industry_archetype_confirmed"
ORG_IDENTITY_AUDIT_INDUSTRY_ARCHETYPE_REJECTED = "organization.industry_archetype_rejected"
ORG_IDENTITY_AUDIT_OPERATING_CHARACTERISTIC_CONFIRMED = (
    "organization.operating_characteristic_confirmed"
)
ORG_IDENTITY_AUDIT_OPERATING_CHARACTERISTIC_REJECTED = (
    "organization.operating_characteristic_rejected"
)
ORG_IDENTITY_AUDIT_SETUP_COMPLETED = "organization.identity_setup_completed"

OPERATING_CONTEXT_AUDIT_EVENTS: dict[
    tuple[OrganizationOperatingContextSuggestionType, SuggestionDecision], str
] = {
    (
        OrganizationOperatingContextSuggestionType.INDUSTRY_ARCHETYPE,
        SuggestionDecision.CONFIRMED,
    ): ORG_IDENTITY_AUDIT_INDUSTRY_ARCHETYPE_CONFIRMED,
    (
        OrganizationOperatingContextSuggestionType.INDUSTRY_ARCHETYPE,
        SuggestionDecision.REJECTED,
    ): ORG_IDENTITY_AUDIT_INDUSTRY_ARCHETYPE_REJECTED,
    (
        OrganizationOperatingContextSuggestionType.OPERATING_CHARACTERISTIC,
        SuggestionDecision.CONFIRMED,
    ): ORG_IDENTITY_AUDIT_OPERATING_CHARACTERISTIC_CONFIRMED,
    (
        OrganizationOperatingContextSuggestionType.OPERATING_CHARACTERISTIC,
        SuggestionDecision.REJECTED,
    ): ORG_IDENTITY_AUDIT_OPERATING_CHARACTERISTIC_REJECTED,
}

ORG_IDENTITY_ERROR_ADMIN_REQUIRED = (
    "Organisation administrator access is required to manage organisation identity"
)
ORG_IDENTITY_ERROR_NOT_FOUND = "Organisation identity record not found"
ORG_IDENTITY_ERROR_LEGAL_NAME_REQUIRED = "A legal name is required to confirm organisation identity"
ORG_IDENTITY_ERROR_NO_PRIMARY_ENTITY = "A confirmed primary legal entity is required"
ORG_IDENTITY_ERROR_SCOPE_NOT_FOUND = "Organisation scope not found"
ORG_IDENTITY_ERROR_CORRECTION_REASON_REQUIRED = (
    "A reason is required to correct a confirmed organisation identity"
)
ORG_IDENTITY_ERROR_ENTITY_NOT_FOUND = "Legal entity not found"
ORG_IDENTITY_ERROR_DOMAIN_NOT_FOUND = "Organisation domain not found"
ORG_IDENTITY_ERROR_OPERATING_CONTEXT_NOT_FOUND = (
    "Organisation operating-context suggestion not found"
)
ORG_IDENTITY_ERROR_OPERATING_CONTEXT_DECISION_REQUIRED = (
    "Select confirm or reject for an operating-context suggestion"
)
ORG_IDENTITY_ERROR_OPERATING_CONTEXT_SELECTION_INVALID = (
    "Select an available operating-context option."
)
