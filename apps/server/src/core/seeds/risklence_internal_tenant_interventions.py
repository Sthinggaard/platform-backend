from __future__ import annotations

from typing import Any
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy.orm import Session

from src.core.constants.decision_runtime import (
    DECISION_ACTION_ACCEPTED,
    DECISION_ACTION_ESCALATED,
    RECOMMENDATION_STATUS_DECIDED,
)
from src.core.constants import SERVICE_TIER_BUSINESS_CRITICAL, SERVICE_TIER_MISSION_CRITICAL
from src.core.model_defs.assets_runtime import AssetStatus
from src.core.models import DecisionRecord, Recommendation, Threat
from src.core.services.recommendation_generation_service import generate_live_recommendations_for_org
from src.core.seeds.risklence_internal_tenant_risks import DECISION_BLUEPRINTS, WEAKNESS_BLUEPRINTS
from src.core.seeds.risklence_internal_tenant_structure import FIXTURE_TIMESTAMP_LATER, ORGANIZATION_NAME


def _stable_id(*parts: str) -> str:
    return str(uuid5(NAMESPACE_URL, "risklence::" + "::".join(parts)))


def _seed_threats(db: Session, org_id: int) -> list[Threat]:
    threats: list[Threat] = []
    for item in WEAKNESS_BLUEPRINTS:
        threat = Threat(
            id=_stable_id("threat", item["key"]),
            organization_id=org_id,
            status="detected",
            severity=item["severity"],
            source="cmdb",
            asset=item["asset"],
            tier=(
                SERVICE_TIER_MISSION_CRITICAL
                if item["severity"] == "critical"
                else SERVICE_TIER_BUSINESS_CRITICAL
            ),
            signal=f"{item['title']} — {item['business_impact']}",
            what_it_means=item["business_impact"],
            recommendation=item["recommendation"],
            intelligence={
                "recommendedAction": item["recommended_action"],
                "confidence": 90 if item["severity"] == "critical" else 82 if item["severity"] == "high" else 72,
                "basis": f"Internal architecture review: {item['key']}",
                "reasoning": item["business_impact"],
                "peerData": "Observed in internal SaaS resilience baselines.",
                "frameworkGuidance": "Human review required before remediation changes are accepted.",
                "alternativeNote": None,
            },
            daily_cost=18000 if item["severity"] == "critical" else 8000 if item["severity"] == "high" else 3500,
            frameworks=["NIS2", "GDPR"],
            requires_escalation=item["recommended_action"] == DECISION_ACTION_ESCALATED,
        )
        db.add(threat)
        threats.append(threat)
    db.flush()
    return threats


def _seed_decisions(db: Session, org_id: int, threats: list[Threat]) -> None:
    recommendations = {
        recommendation.threat_id: recommendation
        for recommendation in db.query(Recommendation)
        .filter(Recommendation.organization_id == org_id)
        .all()
    }

    for item in DECISION_BLUEPRINTS:
        threat = next(threat for threat in threats if threat.id == _stable_id("threat", item["intervention_key"]))
        recommendation = recommendations.get(threat.id)
        if recommendation is None:
            continue

        decision = DecisionRecord(
            organization_id=org_id,
            recommendation_id=recommendation.id,
            threat_id=threat.id,
            selected_action=item["selected_action"],
            decision_type=item["decision_type"],
            rationale=item["rationale"],
            decided_by=item["decided_by"],
            decided_role=item["decided_role"],
            review_date=item["review_date"],
            stale=False,
            recommendation_snapshot={
                "recommendation_id": recommendation.id,
                "problem": recommendation.problem,
                "why_it_matters": recommendation.why_it_matters,
                "suggested_action": recommendation.suggested_action,
            },
            reasoning_snapshot={
                "selected_action": item["selected_action"],
                "timestamp": item["timestamp"],
                "review_date": item["review_date"],
                "ref": item["ref"],
            },
            integration_ref=item["ref"],
            integration_provider=item["integration_provider"],
            external_url=None,
        )
        db.add(decision)
        recommendation.status = RECOMMENDATION_STATUS_DECIDED

        threat.status = "accepted" if item["selected_action"] == DECISION_ACTION_ACCEPTED else "in-progress"
        threat.decision = {
            "action": item["selected_action"],
            "by": item["decided_by"],
            "role": item["decided_role"],
            "rationale": item["rationale"],
            "ref": item["ref"],
            "integrationProvider": item["integration_provider"],
            "timestamp": item["timestamp"],
            "reviewDate": item["review_date"],
            "recommendationId": recommendation.id,
            "stale": False,
        }
        threat.updated_at = FIXTURE_TIMESTAMP_LATER

    db.flush()


def seed_risklence_internal_tenant_interventions(db: Session, org_id: int) -> None:
    threats = _seed_threats(db, org_id)
    generate_live_recommendations_for_org(db, org_id)
    _seed_decisions(db, org_id, threats)
