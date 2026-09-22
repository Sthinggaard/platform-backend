from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from src.pretenant.store import PRETENANT_STORE, DraftOrganisation, DraftStatus
from src.pretenant.workspace_contracts import (
    OnboardingWorkspace,
    OnboardingWorkspacePatch,
    WorkspaceSynthesisResponse,
)
from src.pretenant.workspace_service import load_workspace, merge_workspace, synthesize_workspace

router = APIRouter(prefix="/public/onboarding", tags=["Public Onboarding Workspace"])


def _resolve_draft(session_id: str, *, require_draft: bool) -> DraftOrganisation:
    status_value = PRETENANT_STORE.get_session_status(session_id)
    if status_value == "expired":
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={"error_type": "session_expired", "message": "Onboarding session expired"},
        )
    if status_value == "missing":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_type": "session_not_found", "message": "Onboarding session not found"},
        )

    draft_org = PRETENANT_STORE.get_draft_org(session_id)
    if not draft_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_type": "session_not_found", "message": "Onboarding session not found"},
        )

    if require_draft and draft_org.status != DraftStatus.DRAFT:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_type": "draft_locked", "message": "Draft is locked"},
        )
    return draft_org


@router.get("/sessions/{session_id}/workspace", response_model=OnboardingWorkspace)
def get_public_onboarding_workspace(session_id: str) -> OnboardingWorkspace:
    draft_org = _resolve_draft(session_id, require_draft=False)
    workspace = load_workspace(session_id, draft_org)
    if draft_org.workspace_snapshot is None:
        updated = PRETENANT_STORE.update_draft_org(
            session_id,
            workspace_snapshot=workspace.model_dump(mode="json", by_alias=True),
        )
        if updated is not None:
            draft_org = updated
            workspace = load_workspace(session_id, draft_org)
    return workspace


@router.put("/sessions/{session_id}/workspace", response_model=OnboardingWorkspace)
def update_public_onboarding_workspace(session_id: str, payload: OnboardingWorkspacePatch) -> OnboardingWorkspace:
    draft_org = _resolve_draft(session_id, require_draft=True)
    current = load_workspace(session_id, draft_org)
    updated_workspace = merge_workspace(current, payload)
    updated_draft = PRETENANT_STORE.update_draft_org(
        session_id,
        workspace_snapshot=updated_workspace.model_dump(mode="json", by_alias=True),
    )
    if updated_draft is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_type": "session_not_found", "message": "Onboarding session not found"},
        )
    return load_workspace(session_id, updated_draft)


@router.post("/sessions/{session_id}/workspace/synthesis", response_model=WorkspaceSynthesisResponse)
def synthesize_public_onboarding_workspace(session_id: str) -> WorkspaceSynthesisResponse:
    draft_org = _resolve_draft(session_id, require_draft=True)
    current = load_workspace(session_id, draft_org)
    synthesized = synthesize_workspace(current)
    updated_draft = PRETENANT_STORE.update_draft_org(
        session_id,
        workspace_snapshot=synthesized.model_dump(mode="json", by_alias=True),
    )
    if updated_draft is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_type": "session_not_found", "message": "Onboarding session not found"},
        )
    return WorkspaceSynthesisResponse(workspace=load_workspace(session_id, updated_draft), generated=True)
