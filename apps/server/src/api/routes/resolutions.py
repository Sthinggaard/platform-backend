from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.routes.decision_runtime_helpers import get_latest_decision_for_recommendation, serialize_resolution_record
from src.api.schemas.resolutions import (
    CreateResolutionRequest,
    ResolutionRecordResponse,
    ResolutionVerificationResponse,
)
from src.core.constants.decision_runtime import (
    ALTERNATIVE_RESOLUTION_CATEGORIES,
    RESOLUTION_STATUS_CAPTURED,
    RESOLUTION_TYPE_FOLLOWED_RECOMMENDATION,
    RESOLUTION_TYPE_SOLVED_DIFFERENTLY,
    VERIFICATION_STATUS_PENDING,
)
from src.core.database import get_db
from src.core.logging_config import get_logger
from src.core.models import DecisionRecord, Recommendation, RecoveryAction, ResolutionRecord
from src.core.services.resolution_verification_service import (
    build_pending_verification_payload,
    get_latest_verification_for_resolution,
    serialize_verification_record,
    verify_resolution_status,
)

logger = get_logger(__name__)
router = APIRouter(tags=["Recommendations"])


@router.post(
    "/api/v1/resolutions",
    response_model=ResolutionRecordResponse,
    summary="Create an append-only resolution record",
    response_description="Created resolution record awaiting verification.",
    responses={
        404: {"description": "Recommendation or recovery action not found for the authenticated tenant."},
        422: {"description": "Resolution payload failed a business rule validation."},
    },
)
def create_resolution(
    body: CreateResolutionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ResolutionRecordResponse:
    recommendation = _get_recommendation(body.recommendationId, ctx.organization_id, db)
    latest_decision = get_latest_decision_for_recommendation(recommendation.id, ctx.organization_id, db)
    recovery_action = _resolve_recovery_action(body.recoveryActionId, latest_decision, ctx.organization_id, db)
    _validate_resolution_payload(body, recommendation, latest_decision)

    resolution = ResolutionRecord(
        organization_id=ctx.organization_id,
        recommendation_id=recommendation.id,
        decision_record_id=latest_decision.id if latest_decision else None,
        threat_id=recommendation.threat_id,
        recovery_action_id=recovery_action.id if recovery_action else None,
        resolution_type=body.resolutionType,
        selected_action_option=body.selectedActionOption,
        alternative_category=body.alternativeCategory,
        resolution_summary=(body.resolutionSummary or "").strip() or None,
        resolved_by=ctx.email,
        resolved_role=ctx.roles[0] if ctx.roles else "user",
        status=RESOLUTION_STATUS_CAPTURED,
        verification_status=VERIFICATION_STATUS_PENDING,
        created_at=datetime.now(timezone.utc),
    )
    db.add(resolution)
    db.commit()
    db.refresh(resolution)

    logger.info(
        "resolution_record_created",
        org_id=ctx.organization_id,
        recommendation_id=recommendation.id,
        resolution_id=resolution.id,
        resolution_type=resolution.resolution_type,
    )
    summary = serialize_resolution_record(resolution, org_id=ctx.organization_id, db=db)
    assert summary is not None
    return ResolutionRecordResponse.from_summary(summary)


@router.get(
    "/api/v1/resolutions/{resolution_id}/verification",
    response_model=ResolutionVerificationResponse,
    summary="Load verification state for a captured resolution",
    response_description="Latest scanner-backed verification state for the authenticated tenant.",
    responses={404: {"description": "Resolution not found for the authenticated tenant."}},
)
def get_resolution_verification(
    resolution_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ResolutionVerificationResponse:
    resolution = _get_resolution(resolution_id, ctx.organization_id, db)
    latest_verification = get_latest_verification_for_resolution(resolution.id, ctx.organization_id, db)
    if latest_verification is None or latest_verification.verification_status == VERIFICATION_STATUS_PENDING:
        latest_verification = verify_resolution_status(db, resolution, org_id=ctx.organization_id)
        if latest_verification is not None:
            db.commit()
            db.refresh(latest_verification)

    payload = (
        serialize_verification_record(latest_verification)
        if latest_verification is not None
        else build_pending_verification_payload(resolution.id)
    )
    return ResolutionVerificationResponse(**payload)


def _get_recommendation(recommendation_id: str, org_id: int, db: Session) -> Recommendation:
    recommendation = (
        db.query(Recommendation)
        .filter(
            Recommendation.id == recommendation_id,
            Recommendation.organization_id == org_id,
        )
        .first()
    )
    if recommendation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recommendation not found for the authenticated tenant.",
        )
    return recommendation


def _get_resolution(resolution_id: str, org_id: int, db: Session) -> ResolutionRecord:
    resolution = (
        db.query(ResolutionRecord)
        .filter(
            ResolutionRecord.id == resolution_id,
            ResolutionRecord.organization_id == org_id,
        )
        .first()
    )
    if resolution is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resolution not found for the authenticated tenant.",
        )
    return resolution


def _resolve_recovery_action(
    recovery_action_id: int | None,
    latest_decision: DecisionRecord | None,
    org_id: int,
    db: Session,
) -> RecoveryAction | None:
    resolved_id = recovery_action_id or (latest_decision.recovery_action_id if latest_decision else None)
    if resolved_id is None:
        return None
    action = (
        db.query(RecoveryAction)
        .filter(
            RecoveryAction.id == resolved_id,
            RecoveryAction.organization_id == org_id,
        )
        .first()
    )
    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recovery action '{resolved_id}' not found.",
        )
    return action


def _validate_resolution_payload(
    body: CreateResolutionRequest,
    recommendation: Recommendation,
    latest_decision: DecisionRecord | None,
) -> None:
    if latest_decision and body.selectedActionOption != latest_decision.selected_action:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Resolution selectedActionOption must match the latest recorded decision.",
        )
    if (
        body.resolutionType == RESOLUTION_TYPE_FOLLOWED_RECOMMENDATION
        and body.selectedActionOption != recommendation.suggested_action
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="followed-recommendation can only be used when the selected action matches the recommendation.",
        )
    if body.resolutionType == RESOLUTION_TYPE_SOLVED_DIFFERENTLY:
        if body.alternativeCategory not in ALTERNATIVE_RESOLUTION_CATEGORIES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="alternativeCategory is required when resolutionType is solved-differently.",
            )
    elif body.alternativeCategory is not None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="alternativeCategory can only be used when resolutionType is solved-differently.",
        )
