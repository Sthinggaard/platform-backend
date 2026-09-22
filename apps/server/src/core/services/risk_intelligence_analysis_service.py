from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from src.core.constants.decision_runtime import RECOMMENDATION_STATUS_OPEN
from src.core.constants.risk_intelligence_ingestion import (
    FINDING_DOMAIN_RISK_INTELLIGENCE,
    INGESTION_BATCH_ANALYZED_EVENT,
)
from src.core.logging_config import get_logger
from src.core.model_defs.common import SeverityLevel, utcnow
from src.core.models import AssetFinding, AuditEvent, Recommendation, RiskIngestionBatch, RiskIngestionBatchStatus, Threat
from src.core.services.asset_context_service import build_asset_business_context
from src.core.services.risk_intelligence_ingestion_service import get_ingestion_batch
from src.core.services.recommendation_generation_service import generate_live_recommendations_for_org

logger = get_logger(__name__)

_FINDING_DOMAIN = FINDING_DOMAIN_RISK_INTELLIGENCE
_ANALYSIS_VERSION = "risk-intelligence-analysis-v1"
_HIGH_SEVERITY_LEVELS = {SeverityLevel.CRITICAL.value, SeverityLevel.HIGH.value}
_DAILY_COST_BY_SEVERITY = {
    SeverityLevel.CRITICAL.value: 18000,
    SeverityLevel.HIGH.value: 8000,
    SeverityLevel.MEDIUM.value: 3500,
    SeverityLevel.LOW.value: 1200,
    SeverityLevel.INFO.value: 0,
}


@dataclass(frozen=True)
class AnalysisFindingSummary:
    finding_id: int
    asset_id: int
    asset_name: str
    severity: str
    threat_id: str | None
    recommendation_id: str | None
    business_consequence: str
    suggested_action: str
    evidence_refs: list[str]


@dataclass(frozen=True)
class AnalysisResult:
    ingestion_batch_id: int
    organization_id: int
    batch_status: RiskIngestionBatchStatus
    analyzed_at: datetime
    technical_summary: str
    human_decision_required: bool
    finding_count: int
    high_severity_finding_count: int
    threat_count: int
    recommendation_count: int
    findings: list[AnalysisFindingSummary]


def analyze_normalized_ingestion_batch(
    db: Session,
    *,
    organization_id: int,
    actor_user_id: int | None,
    batch_id: int,
) -> AnalysisResult:
    batch = get_ingestion_batch(db, organization_id=organization_id, batch_id=batch_id)
    normalized_findings = _load_normalized_findings(db, organization_id=organization_id, batch_id=batch.id)
    elevated_findings = [
        finding
        for finding in normalized_findings
        if _severity_value(finding.severity) in _HIGH_SEVERITY_LEVELS
    ]

    now = utcnow()
    analysis_findings: list[AnalysisFindingSummary] = []
    threats: list[Threat] = []

    for finding in elevated_findings:
        asset = finding.asset
        if asset is None:
            continue

        asset_context = build_asset_business_context(asset, organization_id, db)
        business_consequence = _build_business_consequence(
            asset_name=asset_context.display_name,
            finding_title=finding.title,
            finding_description=finding.description,
            severity=_severity_value(finding.severity),
            asset_context=asset_context,
        )
        suggested_action = _build_suggested_action(
            asset_context=asset_context,
            severity=_severity_value(finding.severity),
        )
        threat = _upsert_threat(
            db,
            batch=batch,
            finding=finding,
            asset_context=asset_context,
            business_consequence=business_consequence,
            suggested_action=suggested_action,
            observed_at=now,
        )
        threats.append(threat)
        analysis_findings.append(
            AnalysisFindingSummary(
                finding_id=finding.id,
                asset_id=asset_context.asset_id,
                asset_name=asset_context.display_name,
                severity=_severity_value(finding.severity),
                threat_id=threat.id,
                recommendation_id=None,
                business_consequence=business_consequence,
                suggested_action=suggested_action,
                evidence_refs=[ref for ref in (finding.evidence_refs or []) if isinstance(ref, str)],
            )
        )

    if threats:
        db.flush()
        generate_live_recommendations_for_org(db, organization_id)

    recommendations_by_threat = _latest_recommendations_by_threat(db, organization_id=organization_id, threats=threats)
    analysis_findings = [
        AnalysisFindingSummary(
            finding_id=item.finding_id,
            asset_id=item.asset_id,
            asset_name=item.asset_name,
            severity=item.severity,
            threat_id=item.threat_id,
            recommendation_id=recommendations_by_threat.get(item.threat_id or ""),
            business_consequence=item.business_consequence,
            suggested_action=item.suggested_action,
            evidence_refs=item.evidence_refs,
        )
        for item in analysis_findings
    ]

    batch.status = RiskIngestionBatchStatus.ANALYZED
    batch.updated_at = now
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            event_type=INGESTION_BATCH_ANALYZED_EVENT,
            metadata_json={
                "ingestionBatchId": batch.id,
                "findingCount": len(normalized_findings),
                "highSeverityFindingCount": len(elevated_findings),
                "threatCount": len(threats),
                "recommendationCount": len(recommendations_by_threat),
                "threatIds": [threat.id for threat in threats],
                "recommendationIds": list(recommendations_by_threat.values()),
                "status": batch.status.value,
            },
        )
    )
    db.commit()
    db.refresh(batch)

    logger.info(
        "risk_intelligence_ingestion_batch_analyzed",
        organization_id=organization_id,
        ingestion_batch_id=batch.id,
        finding_count=len(normalized_findings),
        high_severity_finding_count=len(elevated_findings),
        threat_count=len(threats),
        recommendation_count=len(recommendations_by_threat),
    )

    technical_summary = _build_analysis_summary(
        batch=batch,
        finding_count=len(normalized_findings),
        elevated_count=len(elevated_findings),
        threat_count=len(threats),
        recommendation_count=len(recommendations_by_threat),
    )
    return AnalysisResult(
        ingestion_batch_id=batch.id,
        organization_id=organization_id,
        batch_status=batch.status,
        analyzed_at=now,
        technical_summary=technical_summary,
        human_decision_required=bool(threats),
        finding_count=len(normalized_findings),
        high_severity_finding_count=len(elevated_findings),
        threat_count=len(threats),
        recommendation_count=len(recommendations_by_threat),
        findings=analysis_findings,
    )


def serialize_analysis_result(result: AnalysisResult) -> dict[str, Any]:
    return {
        "ingestionBatchId": result.ingestion_batch_id,
        "organizationId": result.organization_id,
        "batchStatus": result.batch_status.value,
        "analyzedAt": result.analyzed_at.isoformat(),
        "technicalSummary": result.technical_summary,
        "humanDecisionRequired": result.human_decision_required,
        "findingCount": result.finding_count,
        "highSeverityFindingCount": result.high_severity_finding_count,
        "threatCount": result.threat_count,
        "recommendationCount": result.recommendation_count,
        "findings": [
            {
                "findingId": finding.finding_id,
                "assetId": finding.asset_id,
                "assetName": finding.asset_name,
                "severity": finding.severity,
                "threatId": finding.threat_id,
                "recommendationId": finding.recommendation_id,
                "businessConsequence": finding.business_consequence,
                "suggestedAction": finding.suggested_action,
                "evidenceRefs": finding.evidence_refs,
            }
            for finding in result.findings
        ],
    }


def _load_normalized_findings(db: Session, *, organization_id: int, batch_id: int) -> list[AssetFinding]:
    findings = (
        db.query(AssetFinding)
        .filter(
            AssetFinding.organization_id == organization_id,
            AssetFinding.domain == _FINDING_DOMAIN,
        )
        .order_by(AssetFinding.last_seen_at.desc())
        .all()
    )
    batch_ref = f"ingestion-batch:{batch_id}"
    return [
        finding
        for finding in findings
        if any(isinstance(ref, str) and ref == batch_ref for ref in (finding.evidence_refs or []))
    ]


def _upsert_threat(
    db: Session,
    *,
    batch: RiskIngestionBatch,
    finding: AssetFinding,
    asset_context,
    business_consequence: str,
    suggested_action: str,
    observed_at: datetime,
) -> Threat:
    existing = _find_existing_threat(db, organization_id=batch.organization_id, batch_id=batch.id, finding_id=finding.id)
    intelligence = _build_intelligence_payload(
        batch=batch,
        finding=finding,
        asset_context=asset_context,
        business_consequence=business_consequence,
        suggested_action=suggested_action,
    )
    severity_value = _severity_value(finding.severity)
    daily_cost = _daily_cost_for_severity(severity_value)
    tier = _tier_for_context(asset_context)
    signal = finding.title.strip()

    if existing is not None:
        existing.status = "detected"
        existing.severity = severity_value
        existing.source = batch.collector_profile
        existing.asset = asset_context.display_name
        existing.tier = tier
        existing.signal = signal
        existing.what_it_means = business_consequence
        existing.recommendation = suggested_action
        existing.intelligence = intelligence
        existing.daily_cost = daily_cost
        existing.frameworks = []
        existing.requires_escalation = False
        existing.updated_at = observed_at
        return existing

    threat = Threat(
        id=str(uuid4()),
        organization_id=batch.organization_id,
        status="detected",
        severity=severity_value,
        source=batch.collector_profile,
        asset=asset_context.display_name,
        tier=tier,
        signal=signal,
        what_it_means=business_consequence,
        recommendation=suggested_action,
        intelligence=intelligence,
        daily_cost=daily_cost,
        frameworks=[],
        requires_escalation=False,
        created_at=observed_at,
        updated_at=observed_at,
    )
    db.add(threat)
    return threat


def _find_existing_threat(
    db: Session,
    *,
    organization_id: int,
    batch_id: int,
    finding_id: int,
) -> Threat | None:
    for threat in db.query(Threat).filter(Threat.organization_id == organization_id).all():
        intelligence = threat.intelligence or {}
        if (
            intelligence.get("ingestionBatchId") == batch_id
            and intelligence.get("normalizedFindingId") == finding_id
        ):
            return threat
    return None


def _latest_recommendations_by_threat(
    db: Session,
    *,
    organization_id: int,
    threats: list[Threat],
) -> dict[str, str]:
    threat_ids = {threat.id for threat in threats}
    if not threat_ids:
        return {}

    recommendations = (
        db.query(Recommendation)
        .filter(
            Recommendation.organization_id == organization_id,
            Recommendation.threat_id.in_(threat_ids),
            Recommendation.status == RECOMMENDATION_STATUS_OPEN,
        )
        .order_by(Recommendation.generated_at.desc())
        .all()
    )
    latest_by_threat: dict[str, str] = {}
    for recommendation in recommendations:
        if recommendation.threat_id and recommendation.threat_id not in latest_by_threat:
            latest_by_threat[recommendation.threat_id] = recommendation.id
    return latest_by_threat


def _build_intelligence_payload(
    *,
    batch: RiskIngestionBatch,
    finding: AssetFinding,
    asset_context,
    business_consequence: str,
    suggested_action: str,
) -> dict[str, Any]:
    normalized_finding = {
        "findingId": finding.id,
        "title": finding.title,
        "description": finding.description,
        "severity": _severity_value(finding.severity),
        "status": finding.status.value if hasattr(finding.status, "value") else str(finding.status),
        "riskScore": finding.risk_score,
        "evidenceRefs": [ref for ref in (finding.evidence_refs or []) if isinstance(ref, str)],
    }
    asset_context_payload = {
        "assetId": asset_context.asset_id,
        "displayName": asset_context.display_name,
        "assetType": asset_context.asset_type,
        "isSpof": asset_context.is_spof,
        "riskScore": asset_context.risk_score,
        "findingsCount": asset_context.findings_count,
        "crownJewelCandidate": asset_context.crown_jewel_candidate,
        "linkedServices": [
            {
                "serviceId": service.service_id,
                "serviceName": service.service_name,
                "serviceTier": service.service_tier,
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
    return {
        "analysisVersion": _ANALYSIS_VERSION,
        "ingestionBatchId": batch.id,
        "sourceName": batch.source_name,
        "collectorProfile": batch.collector_profile,
        "normalizedFindingId": finding.id,
        "businessConsequence": business_consequence,
        "recommendedAction": suggested_action,
        "businessDecisionTaxonomy": {
            "version": "business-decision-taxonomy-v1",
            "recommendedRoute": suggested_action,
        },
        "assetContext": asset_context_payload,
        "normalizedFinding": normalized_finding,
        "evidenceRefs": normalized_finding["evidenceRefs"],
    }


def _build_business_consequence(
    *,
    asset_name: str,
    finding_title: str,
    finding_description: str | None,
    severity: str,
    asset_context,
) -> str:
    if severity == SeverityLevel.CRITICAL.value:
        prefix = f"If {asset_name} remains exposed, the impact is immediate and severe"
    elif severity == SeverityLevel.HIGH.value:
        prefix = f"If {asset_name} remains exposed, business operations are significantly disrupted"
    else:
        prefix = f"If {asset_name} remains exposed, business capability is reduced"

    detail_source = finding_description or finding_title
    detail = detail_source.split(".")[0].strip() if detail_source else ""
    consequence_parts = [prefix]
    if detail:
        consequence_parts.append(f"because {detail.lower().rstrip('.')}")
    if asset_context.crown_jewel_candidate:
        consequence_parts.append("The asset is already treated as a crown-jewel dependency path.")
    elif asset_context.blast_radius.mission_critical_count > 0:
        consequence_parts.append(
            f"It supports {asset_context.blast_radius.mission_critical_count} mission-critical service(s)."
        )
    return " ".join(consequence_parts).strip() + "."


def _build_suggested_action(*, asset_context, severity: str) -> str:
    if severity == SeverityLevel.CRITICAL.value:
        if asset_context.crown_jewel_candidate:
            return "Stabilise the exposed asset, patch the issue, and verify the fix before any acceptance decision."
        return "Patch the exposed asset immediately and validate the fix with the original scan profile."
    if severity == SeverityLevel.HIGH.value:
        return "Patch the exposed asset, rescan to confirm, and route the issue to the business owner for review."
    return "Review the finding with the asset owner and plan remediation before the next operating cycle."


def _tier_for_context(asset_context) -> str:
    if asset_context.crown_jewel_candidate:
        return "Mission Critical"
    if asset_context.blast_radius.mission_critical_count > 0:
        return "Business Critical"
    return "Operational"


def _daily_cost_for_severity(severity: str) -> int:
    return _DAILY_COST_BY_SEVERITY.get(severity, 0)


def _severity_value(severity: Any) -> str:
    if hasattr(severity, "value"):
        return str(getattr(severity, "value"))
    return str(severity).strip().lower()


def _build_analysis_summary(
    *,
    batch: RiskIngestionBatch,
    finding_count: int,
    elevated_count: int,
    threat_count: int,
    recommendation_count: int,
) -> str:
    if finding_count == 0:
        return f"No normalized findings were available for batch {batch.source_name}."
    if elevated_count == 0:
        return (
            f"Analyzed {finding_count} normalized findings from {batch.source_name} and found no "
            "high-severity items requiring human review."
        )
    return (
        f"Analyzed {finding_count} normalized findings from {batch.source_name} and promoted "
        f"{threat_count} high-severity finding(s) into {recommendation_count} recommendation snapshot(s)."
    )
