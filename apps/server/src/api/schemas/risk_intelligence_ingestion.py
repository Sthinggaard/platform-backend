from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from src.api.schemas.timestamps import UtcTimestamp


class IngestionBatchCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sourceName: str = Field(..., min_length=1, max_length=150)
    collectorProfile: str = Field(..., min_length=1, max_length=150)
    fileName: str | None = Field(default=None, max_length=255)
    contentType: str | None = Field(default="application/json", max_length=100)
    rawPayload: dict[str, Any] | list[Any]

    @field_validator("sourceName", "collectorProfile", "fileName", "contentType")
    @classmethod
    def _strip_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        trimmed = value.strip()
        return trimmed or None


class IngestionBatchSummaryResponse(BaseModel):
    ingestionBatchId: int
    organizationId: int
    sourceName: str
    collectorProfile: str
    fileName: str | None = None
    contentType: str | None = None
    payloadChecksum: str
    rawPayloadSizeBytes: int
    status: str
    receivedAt: UtcTimestamp
    updatedAt: UtcTimestamp
    errorMessage: str | None = None
    decisionEvidence: dict[str, Any] | None = None


class IngestionBatchDetailResponse(IngestionBatchSummaryResponse):
    rawPayload: dict[str, Any] | list[Any]
