from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from src.core.constants.decision_runtime import (
    ALTERNATIVE_RESOLUTION_CATEGORY_ADDED_FALLBACK,
    ALTERNATIVE_RESOLUTION_CATEGORY_CHANGED_ARCHITECTURE,
    ALTERNATIVE_RESOLUTION_CATEGORY_OTHER,
    ALTERNATIVE_RESOLUTION_CATEGORY_PROCESS_CHANGE,
    ALTERNATIVE_RESOLUTION_CATEGORY_REPLACED_PROVIDER,
)
from src.api.schemas.timestamps import UtcTimestamp

DecisionAction = Literal["jira", "servicenow", "accepted", "escalated"]
OutcomeQuality = Literal["fully-resolved", "partially-resolved", "recurred", "escalated-later"]
ResolutionType = Literal[
    "followed-recommendation",
    "solved-differently",
    "accepted-risk",
    "not-resolved",
]
AlternativeResolutionCategory = Literal[
    ALTERNATIVE_RESOLUTION_CATEGORY_ADDED_FALLBACK,
    ALTERNATIVE_RESOLUTION_CATEGORY_REPLACED_PROVIDER,
    ALTERNATIVE_RESOLUTION_CATEGORY_CHANGED_ARCHITECTURE,
    ALTERNATIVE_RESOLUTION_CATEGORY_PROCESS_CHANGE,
    ALTERNATIVE_RESOLUTION_CATEGORY_OTHER,
]
ResolutionStatus = Literal["captured"]
VerificationStatus = Literal[
    "pending",
    "verified_successful",
    "verified_alternative",
    "verified_insufficient",
    "not_verified",
]


class DecisionSummaryRecord(BaseModel):
    action: DecisionAction
    by: str
    role: str
    rationale: str
    ref: Optional[str] = None
    integrationProvider: Optional[str] = None
    externalUrl: Optional[str] = None
    timestamp: str
    reviewDate: Optional[UtcTimestamp] = None
    outcome: Optional[str] = None
    outcomeQuality: Optional[OutcomeQuality] = None
    outcomeReasonKey: Optional[str] = None
    recommendationId: Optional[str] = None
    stale: bool = False
    forecastSnapshot: Optional[dict] = None

    model_config = ConfigDict(extra="ignore")


class ResolutionSummaryRecord(BaseModel):
    resolutionId: str
    recommendationId: str
    decisionId: Optional[str] = None
    threatId: Optional[str] = None
    recoveryActionId: Optional[int] = None
    resolutionType: ResolutionType
    selectedActionOption: DecisionAction
    alternativeCategory: Optional[AlternativeResolutionCategory] = None
    resolutionSummary: Optional[str] = None
    resolvedBy: str
    resolvedRole: Optional[str] = None
    resolvedAt: UtcTimestamp
    status: ResolutionStatus
    verificationStatus: VerificationStatus

    model_config = ConfigDict(extra="ignore")


class VerificationObservedChange(BaseModel):
    type: str
    description: str
    before: Optional[str] = None
    after: Optional[str] = None

    model_config = ConfigDict(extra="ignore")


class ResolutionVerificationRecord(BaseModel):
    resolutionId: str
    verificationStatus: VerificationStatus
    verificationTimestamp: Optional[UtcTimestamp] = None
    observedChanges: list[VerificationObservedChange] = Field(default_factory=list)
    confidence: int = 0
    notes: Optional[str] = None

    model_config = ConfigDict(extra="ignore")


class RecommendationContextResponse(BaseModel):
    type: str = Field(..., description="Context type such as asset, dependency, or service.")
    id: str = Field(..., description="Stable or best-known context identifier.")
    label: Optional[str] = Field(default=None, description="Business-facing label for the linked context.")
