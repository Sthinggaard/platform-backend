from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from src.core.constants.decision_runtime import (
    ACTIONABLE_DECISION_ACTIONS,
    DECISION_ACTION_ACCEPTED,
    DECISION_ACTION_ESCALATED,
    DECISION_ACTION_JIRA,
    DECISION_ACTION_SERVICENOW,
    RECOMMENDATION_GENERATOR_VERSION,
    RECOMMENDATION_STATUS_OPEN,
    RECOMMENDATION_TYPE_CRITICAL_ASSET,
    RECOMMENDATION_TYPE_RUNTIME_THREAT,
    THREAT_STATUS_KEPT_SAFE,
)
from src.core.models import Recommendation, Threat
from src.core.services.asset_context_service import (
    build_asset_business_context,
    resolve_asset_by_label,
)
from src.core.services.decision_taxonomy_service import build_business_decision_taxonomy

ALLOWED_ACTIONS = {DECISION_ACTION_ACCEPTED, *ACTIONABLE_DECISION_ACTIONS}


@dataclass(frozen=True)
class RecommendationGenerationResult:
    organization_id: int
    total_threats: int
    created_count: int
    refreshed_count: int
    unchanged_count: int
    generated_at: datetime


def generate_live_recommendations_for_org(
    db: Session, organization_id: int
) -> RecommendationGenerationResult:
    threats = (
        db.query(Threat)
        .filter(Threat.organization_id == organization_id, Threat.status != THREAT_STATUS_KEPT_SAFE)
        .order_by(Threat.created_at.desc())
        .all()
    )

    latest_by_threat: dict[str, Recommendation] = {}
    recommendations = (
        db.query(Recommendation)
        .filter(
            Recommendation.organization_id == organization_id,
            Recommendation.threat_id.isnot(None),
        )
        .order_by(Recommendation.generated_at.desc())
        .all()
    )
    for recommendation in recommendations:
        if recommendation.threat_id and recommendation.threat_id not in latest_by_threat:
            latest_by_threat[recommendation.threat_id] = recommendation

    created_count = 0
    refreshed_count = 0
    unchanged_count = 0
    now = datetime.now(timezone.utc)

    for threat in threats:
        candidate = _build_candidate(threat, organization_id=organization_id, db=db)
        latest = latest_by_threat.get(threat.id)

        if latest and _matches_candidate(latest, candidate):
            unchanged_count += 1
            continue

        if latest:
            latest.is_stale = True
            latest.updated_at = now
            refreshed_count += 1
        else:
            created_count += 1

        recommendation = Recommendation(
            organization_id=organization_id,
            threat_id=threat.id,
            status=RECOMMENDATION_STATUS_OPEN,
            linked_context_type=candidate["linked_context_type"],
            linked_context_id=candidate["linked_context_id"],
            linked_context_label=candidate["linked_context_label"],
            problem=candidate["problem"],
            why_it_matters=candidate["why_it_matters"],
            suggested_action=candidate["suggested_action"],
            confidence_score=candidate["confidence_score"],
            is_stale=False,
            intelligence_snapshot=candidate["intelligence_snapshot"],
            generated_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(recommendation)

    db.commit()
    return RecommendationGenerationResult(
        organization_id=organization_id,
        total_threats=len(threats),
        created_count=created_count,
        refreshed_count=refreshed_count,
        unchanged_count=unchanged_count,
        generated_at=now,
    )


def _build_candidate(threat: Threat, *, organization_id: int, db: Session) -> dict:
    intelligence = dict(threat.intelligence or {})
    asset = resolve_asset_by_label(threat.asset, organization_id, db)
    asset_context = build_asset_business_context(asset, organization_id, db) if asset else None

    uncertainty_factors: list[str] = []
    if asset is None:
        uncertainty_factors.append("asset_context_unmatched")
    if asset_context and not asset_context.linked_services:
        uncertainty_factors.append("service_mapping_incomplete")
    if asset_context and not asset_context.linked_processes:
        uncertainty_factors.append("process_mapping_incomplete")
    if asset and asset.confidence < 0.6:
        uncertainty_factors.append("asset_observation_confidence_low")

    structural_rationale: list[str] = []
    if asset_context and asset_context.crown_jewel_candidate:
        structural_rationale.append("derived_crown_jewel_candidate")
    if asset_context and asset_context.blast_radius.mission_critical_count >= 2:
        structural_rationale.append("supports_multiple_mission_critical_services")
    if asset and asset.is_spof:
        structural_rationale.append("single_point_of_failure")
    if asset_context and asset_context.blast_radius.has_financial_exposure:
        structural_rationale.append("linked_financial_exposure")
    if asset and asset.findings_count > 0:
        structural_rationale.append("active_asset_findings")

    suggested_action = _select_suggested_action(threat, intelligence)
    recommendation_type = (
        RECOMMENDATION_TYPE_CRITICAL_ASSET
        if asset_context and asset_context.crown_jewel_candidate
        else RECOMMENDATION_TYPE_RUNTIME_THREAT
    )
    confidence_score = _build_confidence_score(threat, intelligence, uncertainty_factors)

    why_it_matters_parts = [threat.what_it_means.strip()]
    structural_summary = _build_structural_summary(asset_context)
    if structural_summary:
        why_it_matters_parts.append(structural_summary)
    why_it_matters = " ".join(part for part in why_it_matters_parts if part).strip()

    linked_context_type = "asset" if asset else "asset"
    linked_context_id = f"asset-{asset.id}" if asset else threat.asset
    linked_context_label = asset.display_name if asset else threat.asset

    intelligence_snapshot = {
        **intelligence,
        "generatorVersion": RECOMMENDATION_GENERATOR_VERSION,
        "recommendationType": recommendation_type,
        "businessDecisionTaxonomy": build_business_decision_taxonomy(
            recommended_action=suggested_action,
        ),
        "suggestedActionText": threat.recommendation,
        "uncertaintyFactors": uncertainty_factors,
        "structuralRationale": structural_rationale,
        "scenario": {
            "threatId": threat.id,
            "severity": threat.severity,
            "source": threat.source,
            "signal": threat.signal,
            "businessConsequence": threat.what_it_means,
            "dailyCost": threat.daily_cost,
            "frameworks": threat.frameworks or [],
        },
        "assetContext": (
            {
                "assetId": asset_context.asset_id,
                "displayName": asset_context.display_name,
                "riskScore": asset_context.risk_score,
                "findingsCount": asset_context.findings_count,
                "isSpof": asset_context.is_spof,
                "crownJewelCandidate": asset_context.crown_jewel_candidate,
                "blastRadius": {
                    "serviceCount": asset_context.blast_radius.service_count,
                    "missionCriticalCount": asset_context.blast_radius.mission_critical_count,
                    "hasFinancialExposure": asset_context.blast_radius.has_financial_exposure,
                },
                "linkedServices": [
                    {
                        "serviceId": service.service_id,
                        "serviceName": service.service_name,
                        "tier": service.service_tier,
                        "financialExposure": service.financial_exposure,
                        "role": service.role,
                    }
                    for service in asset_context.linked_services
                ],
                "linkedProcesses": [
                    {
                        "processId": process.process_id,
                        "processName": process.process_name,
                    }
                    for process in asset_context.linked_processes
                ],
            }
            if asset_context
            else None
        ),
    }

    return {
        "problem": threat.signal.strip(),
        "why_it_matters": why_it_matters,
        "suggested_action": suggested_action,
        "confidence_score": confidence_score,
        "linked_context_type": linked_context_type,
        "linked_context_id": linked_context_id,
        "linked_context_label": linked_context_label,
        "intelligence_snapshot": intelligence_snapshot,
    }


def _build_structural_summary(asset_context) -> str:
    if asset_context is None:
        return ""

    statements: list[str] = []
    if asset_context.crown_jewel_candidate:
        statements.append("The asset is structurally a crown-jewel candidate.")
    if asset_context.blast_radius.mission_critical_count >= 2:
        statements.append(
            f"It currently supports {asset_context.blast_radius.mission_critical_count} mission-critical services."
        )
    if asset_context.is_spof:
        statements.append("It is currently classified as a single point of failure.")
    if asset_context.blast_radius.has_financial_exposure:
        statements.append("Business exposure is already linked to this dependency path.")
    return " ".join(statements)


def _build_confidence_score(
    threat: Threat, intelligence: dict, uncertainty_factors: list[str]
) -> int:
    base = int(intelligence.get("confidence") or 0)
    if base <= 0:
        base = {
            "critical": 90,
            "high": 78,
            "medium": 64,
            "low": 52,
        }.get(threat.severity, 60)
    adjusted = max(0, min(100, base - (len(uncertainty_factors) * 8)))
    return adjusted


def _select_suggested_action(threat: Threat, intelligence: dict) -> str:
    recommended_action = str(intelligence.get("recommendedAction") or "").strip()
    if recommended_action in ALLOWED_ACTIONS:
        return recommended_action
    if threat.requires_escalation:
        return DECISION_ACTION_ESCALATED
    if threat.severity in {"critical", "high"}:
        return DECISION_ACTION_JIRA
    return DECISION_ACTION_SERVICENOW


def _matches_candidate(recommendation: Recommendation, candidate: dict) -> bool:
    return (
        recommendation.problem == candidate["problem"]
        and recommendation.why_it_matters == candidate["why_it_matters"]
        and recommendation.suggested_action == candidate["suggested_action"]
        and recommendation.linked_context_type == candidate["linked_context_type"]
        and recommendation.linked_context_id == candidate["linked_context_id"]
        and recommendation.linked_context_label == candidate["linked_context_label"]
        and recommendation.confidence_score == candidate["confidence_score"]
        and (recommendation.intelligence_snapshot or {}) == candidate["intelligence_snapshot"]
        and recommendation.is_stale is False
    )
