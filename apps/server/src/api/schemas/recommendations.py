from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from src.api.schemas.decision_common import (
    DecisionAction,
    DecisionSummaryRecord,
    RecommendationContextResponse,
    ResolutionSummaryRecord,
)
from src.api.schemas.timestamps import UtcTimestamp


class RecommendationResponse(BaseModel):
    recommendationId: str = Field(..., description="Stable recommendation identifier.")
    threatId: Optional[str] = Field(default=None, description="Threat currently linked to the recommendation.")
    problem: str = Field(..., description="Business-language problem statement.")
    whyItMatters: str = Field(..., description="Business impact explanation.")
    suggestedAction: DecisionAction = Field(..., description="System-recommended action.")
    linkedContext: RecommendationContextResponse = Field(..., description="Context the recommendation is linked to.")
    generatedAt: UtcTimestamp = Field(..., description="When the recommendation snapshot was generated.")
    isStale: bool = Field(..., description="Whether the context changed after recommendation generation.")
    confidenceScore: int = Field(..., description="Confidence score exposed to the UI.")
    intelligence: dict[str, Any] = Field(
        default_factory=dict,
        description="Reasoning and evidence snapshot shown in the recommendation UI.",
    )
    decision: Optional[DecisionSummaryRecord] = Field(
        default=None,
        description="Latest recorded decision against this recommendation, if present.",
    )
    resolution: Optional[ResolutionSummaryRecord] = Field(
        default=None,
        description="Latest append-only resolution record linked to this recommendation, if present.",
    )
    decisionCount: int = Field(default=0, description="Number of append-only decision records for this recommendation.")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "recommendationId": "rec-123",
                "threatId": "threat-1",
                "problem": "Packet loss rising across the payment network.",
                "whyItMatters": "Payment transactions will fail if the degradation continues.",
                "suggestedAction": "jira",
                "linkedContext": {
                    "type": "asset",
                    "id": "asset-123",
                    "label": "Payment Gateway",
                },
                "generatedAt": "2026-04-16T08:30:00+00:00",
                "isStale": False,
                "confidenceScore": 91,
                "intelligence": {
                    "recommendedAction": "jira",
                    "confidence": 91,
                    "basis": "Peer evidence",
                    "reasoning": "Operational engineering path is fastest.",
                },
                "decision": None,
                "resolution": None,
                "decisionCount": 0,
            }
        }
    )


class CreateDecisionRequest(BaseModel):
    recommendationId: str = Field(..., description="Recommendation being acted on.")
    selectedAction: DecisionAction = Field(..., description="Human-selected route.")
    decisionType: Optional[str] = Field(
        default=None,
        description="Optional client-side classification of recommended vs alternative route.",
    )
    rationale: str = Field(
        default="",
        description="Reason required for non-recommended routes; optional for recommended route.",
    )
    decidedBy: Optional[str] = Field(
        default=None,
        description="Display name captured by the client. Server auth context remains authoritative.",
    )
    reviewDate: Optional[str] = Field(default=None, description="Required when the selected route is accept risk.")
    ref: Optional[str] = Field(default=None, description="Optional client-provided external reference.")
    forecastSnapshot: Optional[dict] = Field(
        default=None,
        description="Forecast visible to the user at decision time. Stored for audit traceability.",
    )


class DecisionRecordResponse(BaseModel):
    decisionId: str = Field(..., description="Append-only decision record identifier.")
    recommendationId: str = Field(..., description="Recommendation the record belongs to.")
    threatId: Optional[str] = Field(default=None, description="Threat linked to the recommendation, if any.")
    status: str = Field(..., description="Updated threat lifecycle state after the decision.")
    recoveryActionId: Optional[int] = Field(default=None, description="Recovery action created for actionable routes.")
    decision: DecisionSummaryRecord = Field(..., description="Decision summary shown to the UI.")


class RecommendationGenerationResponse(BaseModel):
    organizationId: int = Field(..., description="Tenant scope the generation run applied to.")
    totalThreats: int = Field(..., description="Threats considered for recommendation generation.")
    createdCount: int = Field(..., description="New recommendation rows created.")
    refreshedCount: int = Field(..., description="Older recommendation rows superseded and marked stale.")
    unchangedCount: int = Field(..., description="Threats whose latest recommendation snapshot stayed unchanged.")
    generatedAt: UtcTimestamp = Field(..., description="Timestamp for the generation run completion.")
