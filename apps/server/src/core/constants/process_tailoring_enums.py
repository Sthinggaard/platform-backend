"""Canonical vocabulary for structured, privacy-safe process-tailoring signals."""

from enum import StrEnum


class ProcessTailoringChangeType(StrEnum):
    SERVICE_EXCLUDED = "service_excluded"
    SERVICE_REINCLUDED = "service_reincluded"
    CUSTOM_SERVICE_ADDED = "custom_service_added"


class ProcessTailoringRationaleCode(StrEnum):
    NOT_USED_BY_THIS_ORGANISATION = "not_used_by_this_organisation"
    HANDLED_OUTSIDE_THIS_PROCESS = "handled_outside_this_process"
    DUPLICATE_OF_EXISTING_SERVICE = "duplicate_of_existing_service"
    ORGANISATION_SPECIFIC_CAPABILITY = "organisation_specific_capability"
    RESTORED_PREVIOUSLY_EXCLUDED_SERVICE = "restored_previously_excluded_service"
    OTHER = "other"
    UNSPECIFIED = "unspecified"


class TailoringEvidenceState(StrEnum):
    """Same controlled vocabulary as the shared UI-state model (owner-approved through
    needs-review) — one vocabulary platform-wide, not a parallel one for this record type.
    """

    OWNER_APPROVED = "owner_approved"
    SCANNER = "scanner"
    ARCHETYPE = "archetype"
    PROFILE = "profile"
    INHERITED = "inherited"
    REJECTED = "rejected"
    NEEDS_REVIEW = "needs_review"


class ProcessTailoringAuditEvent(StrEnum):
    SERVICE_EXCLUDED = "business_process_service_excluded"
    SERVICE_REINCLUDED = "business_process_service_reincluded"
