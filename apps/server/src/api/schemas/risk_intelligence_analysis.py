from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field
from src.api.schemas.timestamps import UtcTimestamp


class AnalysisFindingResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    findingId: int = Field(..., description="Normalized finding identifier.")
    assetId: int = Field(..., description="Asset linked to the normalized finding.")
    assetName: str = Field(..., description="Display name of the matched asset.")
    severity: str = Field(..., description="Normalized severity value.")
    threatId: str | None = Field(default=None, description="Threat created or refreshed for the finding.")
    recommendationId: str | None = Field(
        default=None, description="Recommendation snapshot produced for the threat, if any."
    )
    businessConsequence: str = Field(..., description="Business-language consequence derived from the finding.")
    suggestedAction: str = Field(..., description="Human-review recommendation generated from the finding.")
    evidenceRefs: list[str] = Field(
        default_factory=list,
        description="Evidence chain tying the analysis result back to the raw ingestion batch.",
    )


class AnalysisBatchResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    ingestionBatchId: int = Field(..., description="Risk ingestion batch identifier.")
    organizationId: int = Field(..., description="Tenant scope the analysis applied to.")
    batchStatus: str = Field(..., description="Stored batch state after analysis.")
    analyzedAt: UtcTimestamp = Field(..., description="Timestamp when the analysis completed.")
    technicalSummary: str = Field(..., description="Short machine-readable summary of the analysis run.")
    humanDecisionRequired: bool = Field(
        ..., description="Whether the resulting recommendations require a human decision."
    )
    findingCount: int = Field(..., description="Total normalized findings considered for analysis.")
    highSeverityFindingCount: int = Field(
        ..., description="Number of high or critical findings turned into threats."
    )
    threatCount: int = Field(..., description="Number of threat rows created or refreshed.")
    recommendationCount: int = Field(..., description="Number of recommendation snapshots available.")
    findings: list[AnalysisFindingResponse] = Field(
        default_factory=list,
        description="Per-finding analysis results for review and traceability.",
    )

