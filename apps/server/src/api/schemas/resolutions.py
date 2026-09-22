from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from src.api.schemas.decision_common import (
    AlternativeResolutionCategory,
    DecisionAction,
    ResolutionStatus,
    ResolutionType,
    ResolutionVerificationRecord,
    VerificationStatus,
)
from src.api.schemas.timestamps import UtcTimestamp


class CreateResolutionRequest(BaseModel):
    recommendationId: str = Field(..., description="Recommendation the resolution belongs to.")
    resolutionType: ResolutionType = Field(..., description="Structured human resolution outcome.")
    selectedActionOption: DecisionAction = Field(..., description="Decision route that was actually taken.")
    alternativeCategory: Optional[AlternativeResolutionCategory] = Field(
        default=None,
        description="Required structured category when resolutionType is solved-differently.",
    )
    resolutionSummary: Optional[str] = Field(
        default=None,
        max_length=300,
        description="Optional short human summary of what happened.",
    )
    resolvedBy: str = Field(..., min_length=1, description="Display name or email for the human capturing the resolution.")
    recoveryActionId: Optional[int] = Field(default=None, description="Optional linked recovery action identifier.")


class ResolutionRecordResponse(BaseModel):
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
    resolvedRole: str
    resolvedAt: UtcTimestamp
    status: ResolutionStatus
    verificationStatus: VerificationStatus

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "resolutionId": "res-123",
                "recommendationId": "rec-123",
                "decisionId": "dec-123",
                "threatId": "threat-1",
                "recoveryActionId": 77,
                "resolutionType": "followed-recommendation",
                "selectedActionOption": "jira",
                "alternativeCategory": None,
                "resolutionSummary": "Engineering closed the change and restored clean traffic.",
                "resolvedBy": "ciso@risklence.test",
                "resolvedRole": "ciso",
                "resolvedAt": "2026-04-20T08:45:00+00:00",
                "status": "captured",
                "verificationStatus": "pending",
            }
        }
    )

    @classmethod
    def from_summary(cls, summary: dict) -> "ResolutionRecordResponse":
        payload = {**summary}
        payload["resolvedRole"] = payload.get("resolvedRole") or "user"
        return cls(**payload)


class ResolutionVerificationResponse(ResolutionVerificationRecord):
    pass
