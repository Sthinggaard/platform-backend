"""Contracts for organisation mandate mappings and visibility policies."""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    IdentityProvider,
    MandateAssignmentSubjectType,
    MandateScopeType,
)


class MandateRoleAssignmentWriteRequest(BaseModel):
    canonical_role: CanonicalMandateRole
    subject_type: MandateAssignmentSubjectType
    user_id: int | None = Field(default=None, ge=1)
    identity_group_id: str | None = Field(default=None, min_length=1, max_length=255)
    identity_provider: IdentityProvider | None = None

    @model_validator(mode="after")
    def validate_subject(self) -> "MandateRoleAssignmentWriteRequest":
        if self.subject_type is MandateAssignmentSubjectType.USER:
            if (
                self.user_id is None
                or self.identity_group_id is not None
                or self.identity_provider is not None
            ):
                raise ValueError("User assignments require only user_id")
        elif (
            self.user_id is not None or not self.identity_group_id or self.identity_provider is None
        ):
            raise ValueError("Identity-group assignments require provider and identity_group_id")
        return self


class MandateRoleAssignmentResponse(BaseModel):
    id: str
    canonical_role: CanonicalMandateRole
    subject_type: MandateAssignmentSubjectType
    user_id: int | None = None
    identity_group_id: str | None = None
    identity_provider: IdentityProvider | None = None


class MandateScopeBindingWriteRequest(BaseModel):
    scope_type: MandateScopeType
    scope_id: str = Field(min_length=1, max_length=36)
    canonical_role: CanonicalMandateRole
    role_assignment_id: str = Field(min_length=1, max_length=36)


class MandateScopeBindingResponse(BaseModel):
    id: str
    scope_type: MandateScopeType
    value_stream_id: str | None = None
    business_service_id: str | None = None
    canonical_role: CanonicalMandateRole
    role_assignment_id: str


class VisibilityPolicyWriteRequest(BaseModel):
    overview_role_keys: list[CanonicalMandateRole] = Field(default_factory=list)
    full_detail_role_keys: list[CanonicalMandateRole] = Field(default_factory=list)


class VisibilityPolicyResponse(BaseModel):
    overview_role_keys: list[CanonicalMandateRole]
    full_detail_role_keys: list[CanonicalMandateRole]


class ReportingLineExceptionWriteRequest(BaseModel):
    manager_user_id: int = Field(ge=1)
    exception_reason: str = Field(min_length=3, max_length=500)


class ReportingLineExceptionResponse(BaseModel):
    id: str
    employee_user_id: int
    manager_user_id: int
    exception_reason: str


class OrgAccessConfigurationResponse(BaseModel):
    role_assignments: list[MandateRoleAssignmentResponse]
    scope_bindings: list[MandateScopeBindingResponse]
    visibility_policy: VisibilityPolicyResponse
