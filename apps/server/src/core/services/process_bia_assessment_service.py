"""Lifecycle rules for the authoritative Business Process BIA assessment."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from src.core.model_defs.common import utcnow
from src.core.model_defs.process_bia_assessment import (
    BIA_ASSESSMENT_ATTESTED,
    BIA_ASSESSMENT_IN_PROGRESS,
    BIA_ASSESSMENT_PREPARED,
    BIA_ASSESSMENT_SUPERSEDED,
    ProcessBiaAssessment,
)
from src.core.services.bia_inheritance_service import bia_is_complete


class ProcessBiaAssessmentValidationError(ValueError):
    """Raised for invalid process BIA lifecycle transitions."""


def get_current_process_bia_assessment(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
) -> ProcessBiaAssessment | None:
    return (
        db.query(ProcessBiaAssessment)
        .filter(
            ProcessBiaAssessment.organization_id == organization_id,
            ProcessBiaAssessment.process_id == process_id,
            ProcessBiaAssessment.status != BIA_ASSESSMENT_SUPERSEDED,
        )
        .order_by(ProcessBiaAssessment.created_at.desc())
        .first()
    )


def prepare_process_bia_assessment(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
    answers: dict,
    source: str,
    confidence: str,
    assumption_state: str,
    prepared_by_user_id: int,
    review_at: datetime | None = None,
) -> ProcessBiaAssessment:
    """Create a reviewable process BIA without publishing it to services."""
    if not answers:
        raise ProcessBiaAssessmentValidationError("Business Impact Assessment answers are required.")
    if not source.strip() or not confidence.strip() or not assumption_state.strip():
        raise ProcessBiaAssessmentValidationError(
            "Business Impact Assessment source, confidence, and assumption state are required."
        )

    predecessor = get_current_process_bia_assessment(
        db,
        organization_id=organization_id,
        process_id=process_id,
    )
    assessment = ProcessBiaAssessment(
        organization_id=organization_id,
        process_id=process_id,
        status=BIA_ASSESSMENT_PREPARED,
        answers=dict(answers),
        source=source.strip(),
        confidence=confidence.strip(),
        assumption_state=assumption_state.strip(),
        prepared_by_user_id=prepared_by_user_id,
        review_at=review_at,
    )
    db.add(assessment)
    db.flush()
    if predecessor is not None:
        predecessor.status = BIA_ASSESSMENT_SUPERSEDED
        predecessor.superseded_by_id = assessment.id
        db.add(predecessor)
    return assessment


def update_process_bia_assessment(
    db: Session,
    assessment: ProcessBiaAssessment,
    *,
    answers: dict,
) -> ProcessBiaAssessment:
    """Update prepared BIA answers before human attestation."""
    if assessment.status not in (BIA_ASSESSMENT_PREPARED, BIA_ASSESSMENT_IN_PROGRESS):
        raise ProcessBiaAssessmentValidationError("Only a prepared Business Impact Assessment can be updated.")
    if not answers:
        raise ProcessBiaAssessmentValidationError("Business Impact Assessment answers are required.")
    assessment.answers = dict(answers)
    assessment.status = BIA_ASSESSMENT_IN_PROGRESS
    db.add(assessment)
    return assessment


def attest_process_bia_assessment(
    db: Session,
    assessment: ProcessBiaAssessment,
    *,
    attested_by_user_id: int,
) -> ProcessBiaAssessment:
    """Make a complete BIA authoritative for the process and inheriting services."""
    if assessment.status not in (BIA_ASSESSMENT_PREPARED, BIA_ASSESSMENT_IN_PROGRESS):
        raise ProcessBiaAssessmentValidationError("Only a prepared Business Impact Assessment can be attested.")
    if not bia_is_complete(assessment.answers):
        raise ProcessBiaAssessmentValidationError(
            "A complete Business Impact Assessment is required before attestation."
        )
    assessment.status = BIA_ASSESSMENT_ATTESTED
    assessment.attested_by_user_id = attested_by_user_id
    assessment.attested_at = utcnow()
    db.add(assessment)
    return assessment
