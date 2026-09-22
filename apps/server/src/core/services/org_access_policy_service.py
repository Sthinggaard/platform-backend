"""Validation and normalization for the organisation access configuration."""

from __future__ import annotations

from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    IdentityProvider,
    MandateAssignmentSubjectType,
    MandateScopeType,
    OrgAccessErrorMessage,
)

MANDATE_SCOPE_ALLOWED_ROLES: dict[MandateScopeType, frozenset[CanonicalMandateRole]] = {
    MandateScopeType.BUSINESS_PROCESS: frozenset(
        {
            CanonicalMandateRole.BUSINESS_PROCESS_OWNER,
            CanonicalMandateRole.APPROVER_ESCALATION_CONTACT,
        }
    ),
    MandateScopeType.BUSINESS_SERVICE: frozenset(
        {
            CanonicalMandateRole.BUSINESS_SERVICE_OWNER,
            CanonicalMandateRole.APPROVER_ESCALATION_CONTACT,
        }
    ),
}


class OrgAccessPolicyValidationError(ValueError):
    """Raised when a mandate mapping or visibility policy is invalid."""


def validate_assignment_subject(
    *,
    subject_type: MandateAssignmentSubjectType,
    user_id: int | None,
    identity_group_id: str | None,
    identity_provider: IdentityProvider | None,
) -> None:
    """Ensure mandate assignments do not mix a person and an identity group."""
    if subject_type is MandateAssignmentSubjectType.USER:
        if user_id is None or identity_group_id is not None or identity_provider is not None:
            raise OrgAccessPolicyValidationError(
                "A user mandate assignment requires only a user identifier"
            )
        return

    if subject_type is MandateAssignmentSubjectType.IDENTITY_GROUP:
        if user_id is not None or not identity_group_id or identity_provider is None:
            raise OrgAccessPolicyValidationError(
                "An identity group mandate assignment requires a provider and group identifier"
            )
        return

    raise OrgAccessPolicyValidationError("Unsupported mandate assignment subject")


def normalize_policy_roles(roles: list[CanonicalMandateRole]) -> list[str]:
    """Return a stable deduplicated canonical-role list for persistence."""
    return list(dict.fromkeys(role.value for role in roles))


def validate_scope_role(
    *,
    scope_type: MandateScopeType,
    canonical_role: CanonicalMandateRole,
) -> None:
    """Ensure canonical mandate roles are bound only to meaningful scopes."""
    if canonical_role not in MANDATE_SCOPE_ALLOWED_ROLES[scope_type]:
        raise OrgAccessPolicyValidationError(OrgAccessErrorMessage.INVALID_MANDATE_SCOPE_ROLE.value)
