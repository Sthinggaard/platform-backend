from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.routes.decision_runtime_helpers import (
    get_latest_decision_for_recommendation,
    get_latest_resolution_for_recommendation,
    serialize_resolution_record,
)
from src.api.schemas.decision_common import DecisionSummaryRecord, RecommendationContextResponse
from src.api.schemas.recommendations import (
    CreateDecisionRequest,
    DecisionRecordResponse,
    RecommendationGenerationResponse,
    RecommendationResponse,
)
from src.core.constants.decision_runtime import (
    ACTIONABLE_DECISION_ACTIONS,
    DECISION_ACTION_ACCEPTED,
    DECISION_ACTION_ESCALATED,
    DECISION_TYPE_ALTERNATIVE,
    DECISION_TYPE_RECOMMENDED,
    RECOMMENDATION_STATUS_DECIDED,
    THREAT_STATUS_ACCEPTED,
    THREAT_STATUS_IN_PROGRESS,
)
from src.core.database import get_db
from src.core.models import BusinessService
from src.core.services.service_change_notice_service import notify_service_decision
from src.core.services.threat_decision_authority_service import (
    ThreatDecisionRefusal,
    resolve_threat_decision_authority,
)
from src.core.constants.service_model import SERVICE_TIER_BUSINESS_CRITICAL
from src.core.error_codes import E
from src.core.logging_config import get_logger
from src.core.models import DecisionRecord, Recommendation, RecoveryAction, Threat
from src.core.roles import UserRole
from src.core.services.decision_taxonomy_service import build_business_decision_taxonomy
from src.core.services.risk_intelligence_ingestion_service import close_ingestion_batch_after_decision
from src.core.services.recommendation_generation_service import (
    generate_live_recommendations_for_org,
)
from src.integrations.decision_adapters import (
    DecisionIntegrationRequest,
    IntegrationDispatchError,
    IntegrationDispatchResult,
    get_decision_integration_adapter,
)

logger = get_logger(__name__)
router = APIRouter(tags=["Recommendations"])

ACTIONABLE_DECISIONS = set(ACTIONABLE_DECISION_ACTIONS)


def _require_admin(ctx: TenantContext) -> None:
    if not ctx.is_admin():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required.")


def _require_non_consultant(ctx: TenantContext) -> None:
    """Epic A4 slice 2 — the narrow, time-boxed, external-facing Consultant
    role (DISC-44, capped at 90 days access) may view and prepare, but must
    not record a binding business decision (accept risk, escalate, dispatch
    to Jira/ServiceNow) on the org's behalf. Every other active role may."""
    if UserRole.CONSULTANT.value in ctx.roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Consultants cannot record decisions.")


#: Why a refusal happened, in the reader's terms. A lookup rather than an
#: if-chain, so a refusal and its explanation cannot drift apart (me.md).
_DECISION_REFUSAL_DETAIL: dict[ThreatDecisionRefusal, str] = {
    ThreatDecisionRefusal.ASSET_NOT_FOUND:
        "This threat's artefact is not in your inventory, so nobody is accountable for it yet.",
    ThreatDecisionRefusal.NO_SERVICE_REACHED:
        "This threat's artefact is not carried by any business service, so it has no owner to decide.",
    ThreatDecisionRefusal.ACCOUNTABILITY_UNRESOLVED:
        "Nobody is accountable for the service this threat concerns. Assign an owner before deciding.",
    ThreatDecisionRefusal.NOT_THE_HOLDER:
        "Only the owner of the service this threat concerns may record this decision.",
}


def _tell_the_other_owners(
    db: Session,
    *,
    ctx: TenantContext,
    threat,
    decision_record,
    selected_action: str,
    rationale: str,
) -> None:
    """Write a notice to every process owner whose process leans on this service.

    Søren, 2026-08-31: *"the ones affected by this decision is informed... via a
    message saying person made this decision, please click there to read more."*

    ⚠️ **Informing never blocks the decision.** It happens after the record is
    written, in the same transaction, and a failure to find anybody to tell is
    not a failure to decide.

    ⚠️ The rationale is carried across **verbatim**, as the decider's own words.
    Summarising it here would make the platform the author of somebody else's
    reasoning.
    """
    authority = resolve_threat_decision_authority(
        db,
        organization_id=ctx.organization_id,
        threat_asset_name=getattr(threat, "asset", "") or "",
        actor_user_id=ctx.user_id,
    )
    if not authority.affected_service_ids or ctx.user_id is None:
        return

    services = (
        db.query(BusinessService)
        .filter(
            BusinessService.organization_id == ctx.organization_id,
            BusinessService.id.in_(authority.affected_service_ids),
        )
        .all()
    )
    asset = getattr(threat, "asset", None) or "a dependency"
    for service in services:
        notify_service_decision(
            db,
            organization_id=ctx.organization_id,
            service=service,
            decided_by_user_id=ctx.user_id,
            title=f"Decision recorded on {asset}",
            description=(
                f"{_DECISION_SENTENCE.get(selected_action, 'A decision was recorded')} "
                f"on {asset}, which this process depends on."
            ),
            owner_comment=rationale or None,
            decision_record_id=decision_record.id,
        )


#: What each action means, in the reader's words rather than the enum's. A
#: lookup, so an action and the sentence describing it cannot drift apart.
_DECISION_SENTENCE: dict[str, str] = {
    "accepted": "The risk was accepted",
    "escalated": "The risk was escalated",
    "jira": "Remediation was raised in Jira",
    "servicenow": "Remediation was raised in ServiceNow",
}


def _require_decision_authority(ctx: TenantContext, threat, db: Session) -> None:
    """Authority follows ownership of the thing decided (#374).

    🚨 Until 2026-09-04 the only guard here was ``_require_non_consultant``, so
    any active non-consultant could accept risk, escalate or dispatch to Jira on
    ANY threat in the organisation — a view-only member included.

    ⚠️ Fails closed. Where nobody is accountable, nobody may decide; the repair
    is to state an owner (#376), never to widen who may act.
    """
    authority = resolve_threat_decision_authority(
        db,
        organization_id=ctx.organization_id,
        threat_asset_name=getattr(threat, "asset", "") or "",
        actor_user_id=ctx.user_id,
    )
    if authority.may_decide:
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=_DECISION_REFUSAL_DETAIL[authority.refusal],
    )


@router.post(
    "/api/v1/recommendations/generate",
    response_model=RecommendationGenerationResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Generate live recommendation snapshots for the tenant",
)
def generate_recommendations(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> RecommendationGenerationResponse:
    _require_admin(ctx)
    result = generate_live_recommendations_for_org(db, ctx.organization_id)
    return RecommendationGenerationResponse(
        organizationId=result.organization_id,
        totalThreats=result.total_threats,
        createdCount=result.created_count,
        refreshedCount=result.refreshed_count,
        unchangedCount=result.unchanged_count,
        generatedAt=result.generated_at.isoformat(),
    )


@router.get(
    "/api/v1/recommendations/{recommendation_id}",
    response_model=RecommendationResponse,
    summary="Load recommendation detail",
    response_description="Recommendation detail with latest decision state for the authenticated tenant.",
    responses={404: {"description": "Recommendation not found for the authenticated tenant."}},
)
def get_recommendation(
    recommendation_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> RecommendationResponse:
    recommendation = _get_recommendation(recommendation_id, ctx.organization_id, db)
    latest_decision = get_latest_decision_for_recommendation(
        recommendation.id, ctx.organization_id, db
    )
    latest_resolution = get_latest_resolution_for_recommendation(
        recommendation.id, ctx.organization_id, db
    )
    decision_count = _count_decision_records(recommendation.id, ctx.organization_id, db)

    logger.info(
        "recommendation_loaded",
        org_id=ctx.organization_id,
        recommendation_id=recommendation.id,
        decision_count=decision_count,
    )
    return _build_recommendation_response(
        recommendation,
        latest_decision,
        latest_resolution,
        decision_count,
        db=db,
    )


@router.post(
    "/api/v1/decisions",
    response_model=DecisionRecordResponse,
    summary="Create an append-only decision record",
    response_description="Created decision record plus the updated threat lifecycle state.",
    responses={
        404: {"description": "Recommendation not found for the authenticated tenant."},
        422: {"description": "Decision payload failed a business rule validation."},
        502: {"description": "External integration adapter failed to dispatch the decision."},
    },
)
def create_decision(
    body: CreateDecisionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DecisionRecordResponse:
    _require_non_consultant(ctx)
    recommendation = _get_recommendation(body.recommendationId, ctx.organization_id, db)
    threat = _get_recommendation_threat(recommendation, ctx.organization_id, db)
    _require_decision_authority(ctx, threat, db)
    rationale = body.rationale.strip()
    decision_type = (
        DECISION_TYPE_RECOMMENDED
        if body.selectedAction == recommendation.suggested_action
        else DECISION_TYPE_ALTERNATIVE
    )

    if decision_type == DECISION_TYPE_ALTERNATIVE and len(rationale) < 3:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A rationale is required when the human chooses a non-recommended route.",
        )
    if body.selectedAction == DECISION_ACTION_ACCEPTED and not (body.reviewDate or "").strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A review date is required when the human accepts risk.",
        )

    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%d %H:%M")
    actor_role = ctx.roles[0] if ctx.roles else "user"
    effective_rationale = rationale if decision_type == DECISION_TYPE_ALTERNATIVE else rationale

    integration_result: IntegrationDispatchResult | None = None
    if body.selectedAction in ACTIONABLE_DECISIONS:
        integration_result = _dispatch_integration(
            recommendation=recommendation,
            threat=threat,
            ctx=ctx,
            action=body.selectedAction,
            rationale=effective_rationale,
            provided_ref=body.ref or None,
            review_date=body.reviewDate or None,
            timestamp=timestamp,
        )

    decision_record = DecisionRecord(
        organization_id=ctx.organization_id,
        recommendation_id=recommendation.id,
        threat_id=threat.id if threat else recommendation.threat_id,
        selected_action=body.selectedAction,
        decision_type=decision_type,
        rationale=effective_rationale,
        decided_by=ctx.email,
        decided_role=actor_role,
        review_date=body.reviewDate or None,
        stale=recommendation.is_stale,
        recommendation_snapshot=_recommendation_snapshot(recommendation),
        reasoning_snapshot=_reasoning_snapshot(
            recommendation,
            decision_type,
            selected_action=body.selectedAction,
        ),
        forecast_snapshot=body.forecastSnapshot or None,
        integration_ref=integration_result.ref if integration_result else body.ref or None,
        integration_provider=integration_result.provider if integration_result else None,
        external_url=integration_result.external_url if integration_result else None,
    )
    db.add(decision_record)

    decision_summary = _decision_summary(decision_record, timestamp)
    if threat:
        _apply_decision_to_threat(threat, decision_summary, now)
    recommendation.status = RECOMMENDATION_STATUS_DECIDED
    recommendation.updated_at = now

    db.flush()

    recovery_action_id: int | None = None
    if body.selectedAction in ACTIONABLE_DECISIONS:
        recovery_action_id = _ensure_recovery_action(
            recommendation=recommendation,
            threat=threat,
            organization_id=ctx.organization_id,
            ref=decision_record.integration_ref,
            db=db,
        )
        decision_record.recovery_action_id = recovery_action_id

    close_ingestion_batch_after_decision(
        db,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        recommendation=recommendation,
        threat=threat,
        decision_record=decision_record,
    )

    _tell_the_other_owners(
        db,
        ctx=ctx,
        threat=threat,
        decision_record=decision_record,
        selected_action=body.selectedAction,
        rationale=rationale,
    )

    db.commit()
    db.refresh(decision_record)
    if threat:
        db.refresh(threat)

    logger.info(
        "decision_record_created",
        org_id=ctx.organization_id,
        recommendation_id=recommendation.id,
        decision_id=decision_record.id,
        action=body.selectedAction,
        decision_type=decision_type,
        stale=recommendation.is_stale,
    )
    return DecisionRecordResponse(
        decisionId=decision_record.id,
        recommendationId=recommendation.id,
        threatId=decision_record.threat_id,
        status=threat.status
        if threat
        else (
            THREAT_STATUS_ACCEPTED
            if body.selectedAction == DECISION_ACTION_ACCEPTED
            else THREAT_STATUS_IN_PROGRESS
        ),
        recoveryActionId=recovery_action_id,
        decision=_decision_summary(decision_record, timestamp),
    )


def _build_recommendation_response(
    recommendation: Recommendation,
    latest_decision: DecisionRecord | None,
    latest_resolution,
    decision_count: int,
    *,
    db: Session,
) -> RecommendationResponse:
    return RecommendationResponse(
        recommendationId=recommendation.id,
        threatId=recommendation.threat_id,
        problem=recommendation.problem,
        whyItMatters=recommendation.why_it_matters,
        suggestedAction=recommendation.suggested_action,
        linkedContext=RecommendationContextResponse(
            type=recommendation.linked_context_type,
            id=recommendation.linked_context_id,
            label=recommendation.linked_context_label,
        ),
        generatedAt=recommendation.generated_at.isoformat(),
        isStale=recommendation.is_stale,
        confidenceScore=recommendation.confidence_score,
        intelligence=recommendation.intelligence_snapshot or {},
        decision=_decision_summary(latest_decision) if latest_decision else None,
        resolution=serialize_resolution_record(
            latest_resolution, org_id=recommendation.organization_id, db=db
        ),
        decisionCount=decision_count,
    )


def _get_recommendation(recommendation_id: str, org_id: int, db: Session) -> Recommendation:
    recommendation = (
        db.query(Recommendation)
        .filter(
            Recommendation.id == recommendation_id,
            Recommendation.organization_id == org_id,
        )
        .first()
    )
    if not recommendation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recommendation not found for the authenticated tenant.",
        )
    return recommendation


def _get_recommendation_threat(
    recommendation: Recommendation,
    org_id: int,
    db: Session,
) -> Threat | None:
    if not recommendation.threat_id:
        return None
    return (
        db.query(Threat)
        .filter(Threat.id == recommendation.threat_id, Threat.organization_id == org_id)
        .first()
    )


def _count_decision_records(
    recommendation_id: str,
    org_id: int,
    db: Session,
) -> int:
    return (
        db.query(DecisionRecord)
        .filter(
            DecisionRecord.recommendation_id == recommendation_id,
            DecisionRecord.organization_id == org_id,
        )
        .count()
    )


def _decision_summary(
    decision_record: DecisionRecord | None,
    timestamp_override: str | None = None,
) -> DecisionSummaryRecord | None:
    if decision_record is None:
        return None
    return DecisionSummaryRecord(
        action=decision_record.selected_action,
        by=decision_record.decided_by,
        role=decision_record.decided_role,
        rationale=decision_record.rationale,
        ref=decision_record.integration_ref,
        integrationProvider=decision_record.integration_provider,
        externalUrl=decision_record.external_url,
        timestamp=timestamp_override
        or decision_record.created_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M"),
        reviewDate=decision_record.review_date,
        recommendationId=decision_record.recommendation_id,
        stale=decision_record.stale,
        forecastSnapshot=decision_record.forecast_snapshot or None,
    )


def _apply_decision_to_threat(
    threat: Threat,
    decision_summary: DecisionSummaryRecord,
    now: datetime,
) -> None:
    threat.decision = decision_summary.model_dump(mode="json")
    threat.status = (
        THREAT_STATUS_ACCEPTED
        if decision_summary.action == DECISION_ACTION_ACCEPTED
        else THREAT_STATUS_IN_PROGRESS
    )
    threat.updated_at = now


def _dispatch_integration(
    *,
    recommendation: Recommendation,
    threat: Threat | None,
    ctx: TenantContext,
    action: str,
    rationale: str,
    provided_ref: str | None,
    review_date: str | None,
    timestamp: str,
) -> IntegrationDispatchResult:
    adapter = get_decision_integration_adapter(action)
    integration_threat = threat or _build_integration_threat(recommendation, ctx.organization_id)
    try:
        return adapter.send(
            integration_threat,
            DecisionIntegrationRequest(
                organization_id=ctx.organization_id,
                submitted_by=ctx.email,
                submitted_role=ctx.roles[0] if ctx.roles else "user",
                action=action,
                rationale=rationale,
                provided_ref=provided_ref,
                review_date=review_date,
                timestamp=timestamp,
            ),
        )
    except IntegrationDispatchError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error_type": E.PROVIDER_ERROR,
                "message": str(exc),
            },
        ) from exc


def _build_integration_threat(recommendation: Recommendation, org_id: int) -> Threat:
    return Threat(
        id=recommendation.threat_id or recommendation.id,
        organization_id=org_id,
        status="detected",
        severity="high",
        source="cross-org",
        asset=recommendation.linked_context_label or recommendation.linked_context_id,
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        signal=recommendation.problem,
        what_it_means=recommendation.why_it_matters,
        recommendation=recommendation.intelligence_snapshot.get("suggestedActionText")
        or recommendation.problem,
        intelligence=recommendation.intelligence_snapshot or {},
        daily_cost=0,
        frameworks=[],
        requires_escalation=recommendation.suggested_action == DECISION_ACTION_ESCALATED,
    )


def _ensure_recovery_action(
    *,
    recommendation: Recommendation,
    threat: Threat | None,
    organization_id: int,
    ref: Optional[str],
    db: Session,
) -> int:
    if threat and threat.id:
        existing = (
            db.query(RecoveryAction)
            .filter(
                RecoveryAction.threat_id == threat.id,
                RecoveryAction.organization_id == organization_id,
            )
            .first()
        )
    else:
        existing = (
            db.query(RecoveryAction)
            .filter(
                RecoveryAction.organization_id == organization_id,
                RecoveryAction.title
                == f"Address: {recommendation.linked_context_label or recommendation.linked_context_id}",
            )
            .first()
        )
    if existing:
        if ref and not existing.ref:
            existing.ref = ref
            existing.updated_at = datetime.now(timezone.utc)
            db.flush()
        return existing.id

    action = RecoveryAction(
        organization_id=organization_id,
        threat_id=threat.id if threat else recommendation.threat_id,
        title=f"Address: {recommendation.linked_context_label or recommendation.linked_context_id}",
        issue=recommendation.why_it_matters,
        action=recommendation.problem,
        affected_services=[recommendation.linked_context_label]
        if recommendation.linked_context_label
        else [],
        priority="high" if (threat and threat.severity in {"critical", "high"}) else "medium",
        status="open",
        ref=ref,
        progress=0,
        steps=[
            {"label": "Review recommendation context and confirm scope", "status": "pending"},
            {"label": "Assign responsible team and due date", "status": "pending"},
            {"label": "Implement the selected action", "status": "pending"},
            {"label": "Validate outcome and capture evidence", "status": "pending"},
        ],
    )
    db.add(action)
    db.flush()
    return action.id


def _recommendation_snapshot(recommendation: Recommendation) -> dict:
    return {
        "recommendationId": recommendation.id,
        "problem": recommendation.problem,
        "whyItMatters": recommendation.why_it_matters,
        "suggestedAction": recommendation.suggested_action,
        "linkedContext": {
            "type": recommendation.linked_context_type,
            "id": recommendation.linked_context_id,
            "label": recommendation.linked_context_label,
        },
        "generatedAt": recommendation.generated_at.isoformat(),
        "isStale": recommendation.is_stale,
        "confidenceScore": recommendation.confidence_score,
        "businessDecisionTaxonomy": build_business_decision_taxonomy(
            recommended_action=recommendation.suggested_action,
        ),
    }


def _reasoning_snapshot(
    recommendation: Recommendation,
    decision_type: str,
    *,
    selected_action: str,
) -> dict:
    return {
        "decisionType": decision_type,
        "recommendedAction": recommendation.suggested_action,
        "businessDecisionTaxonomy": build_business_decision_taxonomy(
            recommended_action=recommendation.suggested_action,
            selected_action=selected_action,
            decision_type=decision_type,
        ),
        "intelligence": recommendation.intelligence_snapshot or {},
    }
