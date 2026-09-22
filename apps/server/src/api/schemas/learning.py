from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel
from src.api.schemas.timestamps import UtcTimestamp


class TriggerLearningLoopRequest(BaseModel):
    since: UtcTimestamp | None = None


class LearningLoopRunResponse(BaseModel):
    id: str
    status: str
    triggered_by: str
    since: str | None
    signals_ingested: int
    candidates_generated: int
    candidates_auto_staged: int
    summary: dict
    error: str | None
    started_at: UtcTimestamp
    finished_at: UtcTimestamp | None


class TrainingSignalCountResponse(BaseModel):
    signalType: str
    count: int


class LearningCandidateResponse(BaseModel):
    id: str
    runId: str
    candidateType: str
    targetType: str
    targetKey: str
    governanceClass: str
    status: str
    sampleSize: int
    confidenceScore: int
    summary: dict
    proposedChanges: list[dict]
    reviewedBy: str | None
    reviewNote: str | None
    createdAt: UtcTimestamp
    updatedAt: UtcTimestamp


class LearningSignalSummaryResponse(BaseModel):
    since: str | None
    generatedAt: UtcTimestamp
    signalCounts: list[TrainingSignalCountResponse]
    candidates: list[LearningCandidateResponse]
