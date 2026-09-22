from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from src.api.schemas.decision_common import DecisionAction, DecisionSummaryRecord, OutcomeQuality, ResolutionSummaryRecord
from src.core.models import Threat
from src.api.schemas.timestamps import UtcTimestamp


class ThreatResponse(BaseModel):
    """Threat representation returned to tenant decision surfaces."""

    id: str = Field(..., description="Stable threat identifier.")
    status: str = Field(..., description="Current threat lifecycle status.")
    severity: str = Field(..., description="Business-facing severity classification.")
    source: str = Field(..., description="Signal source that raised the threat.")
    asset: str = Field(..., description="Primary affected asset label.")
    tier: str = Field(..., description="Business service tier label.")
    signal: str = Field(..., description="Observed signal text presented to the user.")
    whatItMeans: str = Field(..., description="Human-readable business impact explanation.")
    recommendation: str = Field(..., description="Recommended next action.")
    intelligence: dict[str, Any] = Field(
        ...,
        description="Supporting recommendation payload used by the decision UI.",
    )
    dailyCost: int = Field(..., description="Estimated daily exposure in business terms.")
    frameworks: list[str] = Field(default_factory=list, description="Applicable frameworks or control sources.")
    requiresEscalation: bool = Field(..., description="Whether the threat is pre-classified as requiring escalation.")
    recommendationId: Optional[str] = Field(default=None, description="Current recommendation identifier for the threat.")
    recommendationGeneratedAt: Optional[UtcTimestamp] = Field(
        default=None,
        description="When the current recommendation snapshot was generated.",
    )
    recommendationIsStale: bool = Field(
        default=False,
        description="Whether the recommendation context changed after recommendation generation.",
    )
    decisionCount: int = Field(default=0, description="Append-only decision records linked to the current recommendation.")
    decision: Optional[DecisionSummaryRecord | dict[str, Any]] = Field(
        default=None,
        description="Recorded human decision, if present.",
    )
    resolution: Optional[ResolutionSummaryRecord] = Field(
        default=None,
        description="Latest structured resolution record for the current recommendation, if present.",
    )
    savedPerHour: Optional[int] = Field(default=None, description="Protected value per hour once resolved.")
    # ``Threat.resolved_on`` is a legacy display-date column (for example,
    # ``22 May 2026``), not a persisted instant. Keep this boundary aligned
    # with the model until a canonical timestamp column is introduced.
    resolvedOn: Optional[str] = Field(default=None, description="Resolution date shown in the kept-safe view.")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "threat-1",
                "status": "in-progress",
                "severity": "critical",
                "source": "GLIC",
                "asset": "Payment Gateway",
                "tier": "Mission Critical",
                "signal": "Packet loss rising 0.2%→8.4%",
                "whatItMeans": "Payment traffic will fail if left unresolved.",
                "recommendation": "Replace the failing edge device.",
                "intelligence": {
                    "recommendedAction": "jira",
                    "confidence": 91,
                    "basis": "Peer evidence",
                    "reasoning": "Operational engineering path is fastest.",
                    "frameworkGuidance": "Operational maintenance route.",
                    "alternativeNote": None,
                },
                "dailyCost": 8400,
                "frameworks": ["DORA"],
                "requiresEscalation": False,
                "decision": {
                    "action": "jira",
                    "by": "ciso@risklence.test",
                    "role": "ciso",
                    "rationale": "Engineering owns this fix.",
                    "ref": "JIRA-123",
                    "integrationProvider": "jira",
                    "externalUrl": "https://jira.example/browse/JIRA-123",
                    "timestamp": "2026-03-29 10:15",
                    "reviewDate": None,
                },
                "resolution": None,
                "savedPerHour": None,
                "resolvedOn": None,
            }
        },
    )

    @classmethod
    def from_model(
        cls,
        t: Threat,
        *,
        recommendation_id: str | None = None,
        recommendation_generated_at: str | None = None,
        recommendation_is_stale: bool = False,
        decision_count: int = 0,
        decision: dict[str, Any] | None = None,
        resolution: ResolutionSummaryRecord | None = None,
    ) -> "ThreatResponse":
        return cls(
            id=t.id,
            status=t.status,
            severity=t.severity,
            source=t.source,
            asset=t.asset,
            tier=t.tier,
            signal=t.signal,
            whatItMeans=t.what_it_means,
            recommendation=t.recommendation,
            intelligence=t.intelligence,
            dailyCost=t.daily_cost,
            frameworks=t.frameworks or [],
            requiresEscalation=t.requires_escalation,
            recommendationId=recommendation_id,
            recommendationGeneratedAt=recommendation_generated_at,
            recommendationIsStale=recommendation_is_stale,
            decisionCount=decision_count,
            decision=decision if decision is not None else t.decision,
            resolution=resolution,
            savedPerHour=t.saved_per_hour,
            resolvedOn=t.resolved_on,
        )


class RecordDecisionRequest(BaseModel):
    action: DecisionAction = Field(..., description="Decision route chosen by the human operator.")
    rationale: str = Field(..., min_length=3, description="Human rationale captured for the decision record.")
    ref: Optional[str] = Field(default=None, description="Optional external reference provided by the client.")
    review_date: Optional[str] = Field(default=None, description="Optional review date for accepted risks.")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "jira",
                "rationale": "Engineering owns this fix.",
                "ref": "JIRA-123",
                "review_date": None,
            }
        }
    )


class RecordOutcomeRequest(BaseModel):
    outcome: str = Field(..., min_length=3, description="Human-readable outcome summary.")
    outcome_quality: OutcomeQuality = Field(..., description="Outcome classification used by the decision UI.")
    outcome_reason_key: Optional[str] = Field(default=None, description="Optional structured reason key.")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "outcome": "Remediation verified in staging and production.",
                "outcome_quality": "fully-resolved",
                "outcome_reason_key": "verified_fix",
            }
        }
    )
