from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field
from src.api.schemas.timestamps import UtcTimestamp


class ThreatTraceContext(BaseModel):
    """Minimal, identifying context only — the live ``threat.decision`` view is
    deliberately not exposed here, since it is a weaker, unversioned
    convenience field; the trace's own snapshot fields are authoritative."""

    id: str = Field(..., description="Threat identifier.")
    asset: str = Field(..., description="Affected asset.")
    severity: str = Field(..., description="Threat severity at reference time.")
    status: str = Field(..., description="Current threat status.")
    tier: str = Field(..., description="Business tier of the affected service.")


class RecoveryActionTraceSummary(BaseModel):
    id: int = Field(..., description="Recovery action identifier.")
    title: str = Field(..., description="Recovery action title.")
    status: str = Field(..., description="Current recovery action status.")
    progress: int = Field(..., description="Completion progress, 0-100.")
    ref: Optional[str] = Field(default=None, description="External integration reference, if any.")


class DecisionTraceResponse(BaseModel):
    decisionRecordId: str = Field(..., description="Decision record identifier.")
    recommendationId: str = Field(..., description="Recommendation this decision was made against.")
    selectedAction: str = Field(..., description="Action the human selected.")
    decisionType: str = Field(..., description="Whether the selected action matched the recommendation or diverged.")
    rationale: str = Field(..., description="Human-provided reasoning for the decision.")
    decidedBy: str = Field(..., description="Display name/identifier of the deciding human.")
    decidedRole: str = Field(..., description="Role/authority of the deciding human.")
    reviewDate: Optional[UtcTimestamp] = Field(default=None, description="Scheduled review date, if the decision requires one.")
    stale: bool = Field(..., description="Whether the underlying context changed after this decision was recorded.")
    decidedAt: UtcTimestamp = Field(..., description="When the decision was recorded.")

    recommendationSnapshot: dict[str, Any] = Field(
        ..., description="Frozen recommendation exactly as shown to the human at decision time."
    )
    reasoningSnapshot: dict[str, Any] = Field(
        ..., description="Frozen reasoning/intelligence exactly as shown to the human at decision time."
    )
    forecastSnapshot: Optional[dict[str, Any]] = Field(
        default=None, description="Frozen forecast impact shown at decision time, if supplied."
    )

    integrationProvider: Optional[str] = Field(default=None, description="Integration the decision was routed to, if any.")
    integrationRef: Optional[str] = Field(default=None, description="External integration reference, if any.")
    externalUrl: Optional[str] = Field(default=None, description="Link to the external integration item, if any.")

    threat: Optional[ThreatTraceContext] = Field(default=None, description="Threat context, when the decision is threat-linked.")
    recoveryAction: Optional[RecoveryActionTraceSummary] = Field(
        default=None, description="Recovery action spawned by this decision, when one exists."
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "decisionRecordId": "dr-123",
                "recommendationId": "rec-456",
                "selectedAction": "jira",
                "decisionType": "followed-recommendation",
                "rationale": "Fastest path to remediation, minimal customer impact.",
                "decidedBy": "Anna Jensen",
                "decidedRole": "org_admin",
                "reviewDate": None,
                "stale": False,
                "decidedAt": "2026-07-20T10:04:00+00:00",
                "recommendationSnapshot": {},
                "reasoningSnapshot": {},
                "forecastSnapshot": None,
                "integrationProvider": "jira",
                "integrationRef": "RISK-4821",
                "externalUrl": None,
                "threat": None,
                "recoveryAction": None,
            }
        }
    )


class DecisionTraceSummary(BaseModel):
    """One row in a threat's decision history — the list view, not the full trace."""

    decisionRecordId: str = Field(..., description="Decision record identifier.")
    selectedAction: str = Field(..., description="Action the human selected.")
    decisionType: str = Field(..., description="Whether the selected action matched the recommendation or diverged.")
    decidedBy: str = Field(..., description="Display name/identifier of the deciding human.")
    decidedAt: UtcTimestamp = Field(..., description="When the decision was recorded.")


class DecisionTraceListResponse(BaseModel):
    entries: list[DecisionTraceSummary] = Field(default_factory=list, description="Newest-first decision history for a threat.")
    nextCursor: Optional[str] = Field(default=None, description="Opaque cursor to fetch the next page, if hasMore.")
    hasMore: bool = Field(default=False, description="Whether more entries exist beyond this page.")
