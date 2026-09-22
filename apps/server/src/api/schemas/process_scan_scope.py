"""CA-10 (#50) — request/response schemas for ProcessScanScope."""

from __future__ import annotations

from pydantic import BaseModel

from src.api.schemas.timestamps import UtcTimestamp


class CreateProcessScanScopeRequest(BaseModel):
    bundle_version_ids: list[str] = []
    artefacts: list[str] = []
    connectors: list[str] = []
    checks: list[str] = []
    profile_versions: dict = {}
    rationale: dict = {}


class SubmitProcessScanScopeRequest(BaseModel):
    decision_note: str | None = None


class ApproveProcessScanScopeRequest(BaseModel):
    decision_note: str | None = None


class MarkProcessScanScopeOutdatedRequest(BaseModel):
    reason: str


class ProcessScanScopeResponse(BaseModel):
    id: str
    organization_id: int
    business_process_id: str
    revision: int
    status: str
    bundle_version_ids: list[str]
    artefacts: list[str]
    connectors: list[str]
    checks: list[str]
    profile_versions: dict
    rationale: dict
    derived_at: UtcTimestamp
    submitted_by_user_id: int | None
    submitted_at: UtcTimestamp | None
    approved_by_user_id: int | None
    approved_at: UtcTimestamp | None
    decision_note: str | None
    outdated_at: UtcTimestamp | None
    outdated_reason: str | None
    revoked_by_user_id: int | None
    revoked_at: UtcTimestamp | None
    superseded_by_scope_id: str | None
    created_at: UtcTimestamp
    updated_at: UtcTimestamp
