"""Decision Layer — Threat endpoints.

GET  /api/v1/threats              — list all threats for the authenticated org
POST /api/v1/threats/{id}/decision — record a decision on a threat
POST /api/v1/threats/{id}/outcome  — record an outcome on a decided threat

Every endpoint is tenant-scoped: organization_id is taken from the JWT via
TenantContext and never accepted from the caller.
"""

from __future__ import annotations

from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.routes import recommendations as recommendation_routes
from src.api.routes.decision_runtime_helpers import (
    get_latest_decision_for_recommendation,
    get_latest_resolution_for_recommendation,
    serialize_resolution_record,
)
from src.api.schemas.recommendations import CreateDecisionRequest
from src.api.schemas.threats import (
    RecordDecisionRequest,
    RecordOutcomeRequest,
    ThreatResponse,
)
from src.core.database import get_db
from src.core.logging_config import get_logger
from src.core.models import DecisionRecord, Recommendation, Threat
from src.core.services.recommendation_generation_service import (
    generate_live_recommendations_for_org,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/threats", tags=["Decision Layer"])


# ─── ROUTES ───────────────────────────────────────────────────────────────────


@router.get(
    "",
    response_model=list[ThreatResponse],
    summary="List decision-layer threats",
    response_description="Threats for the authenticated tenant, newest first.",
)
def list_threats(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[ThreatResponse]:
    """Return all threats for the authenticated organisation, newest first."""
    generate_live_recommendations_for_org(db, ctx.organization_id)
    threats = (
        db.query(Threat)
        .filter(Threat.organization_id == ctx.organization_id)
        .order_by(Threat.created_at.desc())
        .all()
    )
    logger.info(
        "threats_listed",
        org_id=ctx.organization_id,
        count=len(threats),
    )
    return [_build_threat_response(threat=t, org_id=ctx.organization_id, db=db) for t in threats]


@router.post(
    "/{threat_id}/decision",
    response_model=ThreatResponse,
    summary="Record a threat decision",
    response_description="Updated threat with the latest immutable decision record.",
    responses={
        404: {"description": "Threat not found for the authenticated tenant."},
        409: {"description": "A recommendation is required before recording a decision."},
        502: {"description": "External integration adapter failed to dispatch the decision."},
    },
)
def record_decision(
    threat_id: str,
    body: RecordDecisionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ThreatResponse:
    """Compatibility adapter for the append-only recommendation decision flow.

    The former implementation wrote mutable ``Threat.decision`` JSON directly.
    The canonical ``/api/v1/decisions`` route owns decision authorisation,
    snapshots, audit provenance, and immutable ``DecisionRecord`` history.
    Keep this route only as a backwards-compatible entry point for callers that
    still address a threat directly.
    """
    threat = _get_threat(threat_id, ctx.organization_id, db)

    generate_live_recommendations_for_org(db, ctx.organization_id)
    recommendation = _get_latest_recommendation_for_threat(
        threat.id,
        ctx.organization_id,
        db,
    )
    if not recommendation:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A recommendation is required before recording a threat decision.",
        )

    recommendation_routes.create_decision(
        body=CreateDecisionRequest(
            recommendationId=recommendation.id,
            selectedAction=body.action,
            rationale=body.rationale,
            reviewDate=body.review_date,
            ref=body.ref,
        ),
        ctx=ctx,
        db=db,
    )

    logger.info(
        "threat_decision_recorded",
        org_id=ctx.organization_id,
        threat_id=threat_id,
        action=body.action,
    )
    return _build_threat_response(threat=threat, org_id=ctx.organization_id, db=db)


@router.post(
    "/{threat_id}/outcome",
    response_model=None,
    summary="Retired legacy threat outcome endpoint",
    response_description="The legacy endpoint is retired; use the canonical resolution endpoint.",
    responses={
        404: {"description": "Threat not found for the authenticated tenant."},
        410: {"description": "The legacy outcome endpoint is retired."},
    },
)
def record_outcome(
    threat_id: str,
    body: RecordOutcomeRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> None:
    """Reject the legacy mutable outcome contract after tenant validation.

    Outcomes are structured ``ResolutionRecord`` entries. The tenant runtime
    already uses ``POST /api/v1/resolutions``; keeping this compatibility route
    would allow callers to bypass that append-only contract.
    """
    _get_threat(threat_id, ctx.organization_id, db)
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail={
            "error_code": "LEGACY_OUTCOME_ENDPOINT_RETIRED",
            "message": "Record outcomes through the canonical resolution endpoint.",
            "canonical_endpoint": "/api/v1/resolutions",
        },
    )


# ─── HELPERS ──────────────────────────────────────────────────────────────────


def _get_threat(threat_id: str, org_id: int, db: Session) -> Threat:
    """Fetch a threat, enforcing tenant isolation."""
    threat = (
        db.query(Threat).filter(Threat.id == threat_id, Threat.organization_id == org_id).first()
    )
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat '{threat_id}' not found.",
        )
    return threat


def _build_threat_response(threat: Threat, org_id: int, db: Session) -> ThreatResponse:
    if not hasattr(db, "query"):
        return ThreatResponse.from_model(threat)

    recommendation = _get_latest_recommendation_for_threat(threat.id, org_id, db)
    latest_decision: DecisionRecord | None = None
    decision_count = 0
    if recommendation:
        latest_decision = get_latest_decision_for_recommendation(recommendation.id, org_id, db)
        latest_resolution = get_latest_resolution_for_recommendation(recommendation.id, org_id, db)
        decision_count = (
            db.query(DecisionRecord)
            .filter(
                DecisionRecord.recommendation_id == recommendation.id,
                DecisionRecord.organization_id == org_id,
            )
            .count()
        )
    return ThreatResponse.from_model(
        threat,
        recommendation_id=recommendation.id if recommendation else None,
        recommendation_generated_at=recommendation.generated_at.isoformat()
        if recommendation
        else None,
        recommendation_is_stale=recommendation.is_stale if recommendation else False,
        decision_count=decision_count,
        decision=_serialize_decision_record(latest_decision)
        if latest_decision
        else threat.decision,
        resolution=serialize_resolution_record(latest_resolution, org_id=org_id, db=db)
        if recommendation
        else None,
    )


def _get_latest_recommendation_for_threat(
    threat_id: str,
    org_id: int,
    db: Session,
) -> Recommendation | None:
    return (
        db.query(Recommendation)
        .filter(
            Recommendation.threat_id == threat_id,
            Recommendation.organization_id == org_id,
        )
        .order_by(Recommendation.generated_at.desc())
        .first()
    )


def _serialize_decision_record(decision_record: DecisionRecord) -> dict:
    return {
        "action": decision_record.selected_action,
        "by": decision_record.decided_by,
        "role": decision_record.decided_role,
        "rationale": decision_record.rationale,
        "ref": decision_record.integration_ref,
        "integrationProvider": decision_record.integration_provider,
        "externalUrl": decision_record.external_url,
        "timestamp": decision_record.created_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M"),
        "reviewDate": decision_record.review_date,
        "recommendationId": decision_record.recommendation_id,
        "stale": decision_record.stale,
    }
