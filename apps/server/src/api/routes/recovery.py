"""Decision Layer — Recovery Action endpoints.

GET   /api/v1/recovery              — list all recovery actions for the org
PATCH /api/v1/recovery/{id}         — update progress, status, or steps

Recovery actions are auto-created by the threats endpoint when a decision
action of 'jira', 'servicenow', or 'escalated' is recorded.
Every endpoint is tenant-scoped via TenantContext.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.routes.decision_runtime_helpers import (
    get_latest_decision_for_recovery_action,
    get_latest_resolution_for_recovery_action,
    serialize_resolution_record,
)
from src.api.schemas.decision_common import ResolutionSummaryRecord
from src.core.database import get_db
from src.core.logging_config import get_logger
from src.core.models import RecoveryAction
from src.api.schemas.timestamps import UtcTimestamp

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/recovery", tags=["Decision Layer"])


# ─── SCHEMAS ──────────────────────────────────────────────────────────────────

class RecoveryStep(BaseModel):
    label: str
    status: str  # "done" | "active" | "pending"


class RecoveryActionResponse(BaseModel):
    id: int
    threatId: Optional[str]
    title: str
    issue: str
    action: str
    affectedServices: list[str]
    exposureReduction: Optional[str]
    priority: str
    status: str
    assignedTo: Optional[str]
    dueDate: Optional[UtcTimestamp]
    ref: Optional[str]
    progress: int
    steps: list[dict[str, Any]]
    createdAt: UtcTimestamp
    recommendationId: Optional[str] = None
    selectedActionOption: Optional[str] = None
    resolution: Optional[ResolutionSummaryRecord] = None
    requiresResolutionCapture: bool = False

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(
        cls,
        r: RecoveryAction,
        *,
        recommendation_id: str | None = None,
        selected_action_option: str | None = None,
        resolution: ResolutionSummaryRecord | None = None,
    ) -> "RecoveryActionResponse":
        return cls(
            id=r.id,
            threatId=r.threat_id,
            title=r.title,
            issue=r.issue,
            action=r.action,
            affectedServices=r.affected_services or [],
            exposureReduction=r.exposure_reduction,
            priority=r.priority,
            status=r.status,
            assignedTo=r.assigned_to,
            dueDate=r.due_date.strftime("%Y-%m-%d") if r.due_date else None,
            ref=r.ref,
            progress=r.progress,
            steps=r.steps or [],
            createdAt=r.created_at.strftime("%Y-%m-%d %H:%M"),
            recommendationId=recommendation_id,
            selectedActionOption=selected_action_option,
            resolution=resolution,
            requiresResolutionCapture=r.progress >= 100 and resolution is None,
        )


class UpdateRecoveryRequest(BaseModel):
    status: Optional[str] = Field(
        None, pattern="^(open|in-progress|completed|cancelled)$"
    )
    progress: Optional[int] = Field(None, ge=0, le=100)
    steps: Optional[list[RecoveryStep]] = None
    assigned_to: Optional[str] = Field(None, max_length=255)
    ref: Optional[str] = Field(None, max_length=200)


# ─── ROUTES ───────────────────────────────────────────────────────────────────

@router.get("", response_model=list[RecoveryActionResponse])
def list_recovery_actions(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[RecoveryActionResponse]:
    """Return all recovery actions for the authenticated organisation, newest first."""
    actions = (
        db.query(RecoveryAction)
        .filter(RecoveryAction.organization_id == ctx.organization_id)
        .order_by(RecoveryAction.created_at.desc())
        .all()
    )
    logger.info("recovery_actions_listed", org_id=ctx.organization_id, count=len(actions))
    return [_build_recovery_action_response(action=a, org_id=ctx.organization_id, db=db) for a in actions]


@router.patch("/{action_id}", response_model=RecoveryActionResponse)
def update_recovery_action(
    action_id: int,
    body: UpdateRecoveryRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> RecoveryActionResponse:
    """Update progress, status, steps, assignee, or ref of a recovery action."""
    action = _get_action(action_id, ctx.organization_id, db)

    if body.status is not None:
        action.status = body.status
    if body.progress is not None:
        action.progress = body.progress
    if body.steps is not None:
        action.steps = [s.model_dump() for s in body.steps]
    if body.assigned_to is not None:
        action.assigned_to = body.assigned_to
    if body.ref is not None:
        action.ref = body.ref

    action.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(action)

    logger.info(
        "recovery_action_updated",
        org_id=ctx.organization_id,
        action_id=action_id,
    )
    return _build_recovery_action_response(action=action, org_id=ctx.organization_id, db=db)


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _get_action(action_id: int, org_id: int, db: Session) -> RecoveryAction:
    action = (
        db.query(RecoveryAction)
        .filter(
            RecoveryAction.id == action_id,
            RecoveryAction.organization_id == org_id,
        )
        .first()
    )
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recovery action '{action_id}' not found.",
        )
    return action


def _build_recovery_action_response(
    action: RecoveryAction,
    org_id: int,
    db: Session,
) -> RecoveryActionResponse:
    latest_decision = get_latest_decision_for_recovery_action(action.id, org_id, db)
    latest_resolution = get_latest_resolution_for_recovery_action(action.id, org_id, db)
    return RecoveryActionResponse.from_model(
        action,
        recommendation_id=latest_decision.recommendation_id if latest_decision else None,
        selected_action_option=latest_decision.selected_action if latest_decision else None,
        resolution=serialize_resolution_record(latest_resolution, org_id=org_id, db=db),
    )
