from __future__ import annotations

from pydantic import BaseModel, ConfigDict
from src.api.schemas.timestamps import UtcTimestamp


class NormalizedBusinessContextResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    assetId: int
    assetName: str
    matchedBy: str
    created: bool
    linkedServiceNames: list[str]
    linkedProcessNames: list[str]
    crownJewelCandidate: bool
    blastRadiusServiceCount: int
    blastRadiusMissionCriticalCount: int
    hasFinancialExposure: bool


class NormalizedFindingResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    findingId: int
    assetId: int
    severity: str
    title: str
    status: str
    evidenceRefs: list[str]
    riskScore: float | None = None


class NormalizedBatchResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    ingestionBatchId: int
    organizationId: int
    batchStatus: str
    normalizedAt: UtcTimestamp
    technicalSummary: str
    humanDecisionRequired: bool
    signalCount: int
    findingCount: int
    matchedAssetIds: list[int]
    createdAssetIds: list[int]
    businessContexts: list[NormalizedBusinessContextResponse]
    findings: list[NormalizedFindingResponse]

