"""Canonical organisation access values.

These values deliberately describe Risklence mandates and visibility policy,
not a customer's job titles or the platform's global administration roles.
"""

from enum import StrEnum


class CanonicalMandateRole(StrEnum):
    BUSINESS_PROCESS_OWNER = "business_process_owner"
    BUSINESS_SERVICE_OWNER = "business_service_owner"
    APPROVER_ESCALATION_CONTACT = "approver_escalation_contact"
    ORG_WIDE_VISIBILITY = "org_wide_visibility"


class MandateAssignmentSubjectType(StrEnum):
    USER = "user"
    IDENTITY_GROUP = "identity_group"


class MandateScopeType(StrEnum):
    BUSINESS_PROCESS = "business_process"
    BUSINESS_SERVICE = "business_service"


class IdentityProvider(StrEnum):
    AZURE_AD = "azure_ad"
    GOOGLE_WORKSPACE = "google_workspace"


class OrgAccessAuditEvent(StrEnum):
    MANDATE_ROLE_ASSIGNED = "org_mandate_role_assigned"
    MANDATE_ROLE_UNASSIGNED = "org_mandate_role_unassigned"
    VISIBILITY_POLICY_UPDATED = "org_visibility_policy_updated"
    REPORTING_LINE_EXCEPTION_SET = "reporting_line_exception_set"
    REPORTING_LINE_EXCEPTION_CLEARED = "reporting_line_exception_cleared"
    MANDATE_SCOPE_BOUND = "org_mandate_scope_bound"
    MANDATE_SCOPE_UNBOUND = "org_mandate_scope_unbound"


class OrgAccessErrorMessage(StrEnum):
    ADMIN_REQUIRED = "Organisation administrator access is required"
    USER_NOT_FOUND = "User not found in this organisation"
    ROLE_ASSIGNMENT_NOT_FOUND = "Mandate role assignment not found"
    DUPLICATE_ROLE_ASSIGNMENT = "This mandate role is already assigned to this subject"
    ROLE_ASSIGNMENT_HAS_SCOPE_BINDINGS = "Remove scoped mandate bindings before removing this mandate role assignment"
    INVALID_ASSIGNMENT_SUBJECT = "Mandate assignments must target exactly one valid subject"
    REPORTING_LINE_EXCEPTION_NOT_FOUND = "Reporting-line exception not found"
    INVALID_REPORTING_LINE_EXCEPTION = "A reporting-line exception cannot assign a user as their own manager"
    MANDATE_SCOPE_NOT_FOUND = "Business Process or Business Service not found in this organisation"
    MANDATE_SCOPE_BINDING_NOT_FOUND = "Scoped mandate binding not found"
    INVALID_MANDATE_SCOPE_ROLE = "This canonical mandate role cannot be bound to the selected scope"
    MANDATE_ASSIGNMENT_ROLE_MISMATCH = "The selected mandate assignment does not match the canonical role"
