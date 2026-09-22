"""Lifecycle values for accountable Business Process ownership."""

from enum import StrEnum


class ProcessOwnershipStatus(StrEnum):
    INVITATION_SENT = "invitation_sent"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class ProcessOwnerProposalStatus(StrEnum):
    ASSIGNED = "assigned"
    CANDIDATES_AVAILABLE = "candidates_available"
    NEEDS_ADMIN_ASSIGNMENT = "needs_admin_assignment"


class ProcessOwnerProposalSource(StrEnum):
    EXISTING_PROCESS_BINDING = "existing_process_binding"
    SERVICE_OWNER = "service_owner"
    ORG_BPO_MANDATE = "org_bpo_mandate"


class ProcessOwnershipRejectionReason(StrEnum):
    WRONG_ORGANISATIONAL_RESPONSIBILITY = "wrong_organisational_responsibility"
    OTHER_BUSINESS_UNIT = "other_business_unit"
    TEMPORARY_VACANCY = "temporary_vacancy"
    EXECUTIVE_CLARIFICATION = "executive_clarification"
    DUPLICATE_OR_INCORRECTLY_MODELLED = "duplicate_or_incorrectly_modelled"


class ProcessOwnershipAuditEvent(StrEnum):
    INVITATION_SENT = "process_owner_invitation_sent"
    ACCEPTED = "process_owner_accepted"
    REJECTED = "process_owner_rejected"


class ProcessOwnershipErrorMessage(StrEnum):
    PROCESS_OWNER_BINDING_NOT_FOUND = "A scoped Business Process Owner mandate is required"
    OWNER_ACCEPTANCE_REQUIRES_USER = "Business Process Owner acceptance requires a user-bound mandate"
    OWNER_USER_INACTIVE = "The assigned Business Process Owner is not active"
    OWNER_INVITATION_NOT_FOUND = "Business Process Owner invitation not found"
    OWNER_INVITATION_NOT_PENDING = "Business Process Owner invitation is not pending"
    OWNER_ALREADY_ACCEPTED = "The current Business Process Owner has already accepted ownership"
    OWNER_ACTOR_MISMATCH = "Only the assigned Business Process Owner may respond to this invitation"
    OWNER_ACCEPTANCE_REQUIRED = "Accepted Business Process Owner ownership is required"
    PROCESS_EDITOR_ACCESS_REQUIRED = "Organisation administrator or assigned Business Process Owner access is required"
