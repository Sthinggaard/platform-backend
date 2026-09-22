from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.models import DecisionRecord, ResolutionRecord
from src.core.services.resolution_verification_service import get_latest_verification_for_resolution


def get_latest_decision_for_recommendation(
    recommendation_id: str,
    org_id: int,
    db: Session,
) -> DecisionRecord | None:
    return (
        db.query(DecisionRecord)
        .filter(
            DecisionRecord.recommendation_id == recommendation_id,
            DecisionRecord.organization_id == org_id,
        )
        .order_by(DecisionRecord.created_at.desc())
        .first()
    )


def get_latest_resolution_for_recommendation(
    recommendation_id: str,
    org_id: int,
    db: Session,
) -> ResolutionRecord | None:
    return (
        db.query(ResolutionRecord)
        .filter(
            ResolutionRecord.recommendation_id == recommendation_id,
            ResolutionRecord.organization_id == org_id,
        )
        .order_by(ResolutionRecord.created_at.desc())
        .first()
    )


def get_latest_decision_for_recovery_action(
    recovery_action_id: int,
    org_id: int,
    db: Session,
) -> DecisionRecord | None:
    return (
        db.query(DecisionRecord)
        .filter(
            DecisionRecord.recovery_action_id == recovery_action_id,
            DecisionRecord.organization_id == org_id,
        )
        .order_by(DecisionRecord.created_at.desc())
        .first()
    )


def get_latest_resolution_for_recovery_action(
    recovery_action_id: int,
    org_id: int,
    db: Session,
) -> ResolutionRecord | None:
    return (
        db.query(ResolutionRecord)
        .filter(
            ResolutionRecord.recovery_action_id == recovery_action_id,
            ResolutionRecord.organization_id == org_id,
        )
        .order_by(ResolutionRecord.created_at.desc())
        .first()
    )


def serialize_resolution_record(
    record: ResolutionRecord | None,
    *,
    org_id: int | None = None,
    db: Session | None = None,
) -> dict | None:
    if record is None:
        return None
    verification_status = record.verification_status
    if org_id is not None and db is not None and hasattr(db, "query"):
        latest_verification = get_latest_verification_for_resolution(record.id, org_id, db)
        if latest_verification is not None:
            verification_status = latest_verification.verification_status
    return {
        "resolutionId": record.id,
        "recommendationId": record.recommendation_id,
        "decisionId": record.decision_record_id,
        "threatId": record.threat_id,
        "recoveryActionId": record.recovery_action_id,
        "resolutionType": record.resolution_type,
        "selectedActionOption": record.selected_action_option,
        "alternativeCategory": record.alternative_category,
        "resolutionSummary": record.resolution_summary,
        "resolvedBy": record.resolved_by,
        "resolvedRole": record.resolved_role,
        "resolvedAt": record.created_at.isoformat(),
        "status": record.status,
        "verificationStatus": verification_status,
    }
