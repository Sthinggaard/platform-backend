"""HTTP contracts for atomic onboarding page submissions."""

from pydantic import BaseModel, Field

from src.core.constants.organization_identity_enums import SuggestionDecision
from src.core.constants.organization_structure_enums import (
    OrganizationUnitReviewDecision,
    OrganizationUnitScopeStatus,
    OrganizationUnitType,
)


class OperatingContextDecisionRequest(BaseModel):
    suggestion_id: str
    status: SuggestionDecision


class OperatingContextPageSubmissionRequest(BaseModel):
    decisions: list[OperatingContextDecisionRequest] = Field(default_factory=list)
    added_characteristic_keys: list[str] = Field(default_factory=list)


class OrganizationUnitDecisionRequest(BaseModel):
    unit_id: str
    decision: OrganizationUnitReviewDecision


class OrganizationUnitAdditionRequest(BaseModel):
    name: str
    unit_type: OrganizationUnitType


class OrganizationUnitsPageSubmissionRequest(BaseModel):
    decisions: list[OrganizationUnitDecisionRequest]
    additions: list[OrganizationUnitAdditionRequest] = Field(default_factory=list)


class OrganizationUnitScopeRequest(BaseModel):
    unit_id: str
    scope_status: OrganizationUnitScopeStatus


class OrganizationUnitScopePageSubmissionRequest(BaseModel):
    scope: list[OrganizationUnitScopeRequest]


class OnboardingPageSubmissionResponse(BaseModel):
    submitted_count: int
