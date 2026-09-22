"""Service Owner requests, Process Owner approves: appetite reassessment lifecycle (ONB-GOV-11).

Append-only per (business_service_id, category): requesting a new
reassessment for a category that already has a pending or approved row
supersedes it, never mutates it. Mirrors the append-only supersede pattern
already proven by `risk_appetite_resolution_service.py`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from src.core.constants.appetite_reassessment_enums import AppetiteReassessmentStatus
from src.core.model_defs.common import utcnow
from src.core.model_defs.service_appetite_reassessment import ServiceAppetiteReassessment
from src.core.services.appetite_inheritance_service import (
    APPETITE_DIMENSION_KEYS,
    appetite_category_provenance,
    effective_service_appetite,
    service_appetite_status,
)


class AppetiteReassessmentValidationError(ValueError):
    """Raised when a reassessment lifecycle transition is invalid."""


@dataclass
class EffectiveServiceAppetiteResolution:
    """The appetite actually in force for one service: process appetite plus
    this service's own approved/pending reassessments overlaid on top."""

    status: str
    answers: dict | None
    provenance: dict[str, str]
    pending: list[ServiceAppetiteReassessment]


def _naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    from datetime import timezone

    return value.astimezone(timezone.utc).replace(tzinfo=None)


def get_active_reassessments(
    db: Session, *, organization_id: int, business_service_id: str
) -> dict[str, ServiceAppetiteReassessment]:
    """The current in-force reassessment per category: approved wins, else a pending one."""
    rows = (
        db.query(ServiceAppetiteReassessment)
        .filter(
            ServiceAppetiteReassessment.organization_id == organization_id,
            ServiceAppetiteReassessment.business_service_id == business_service_id,
            ServiceAppetiteReassessment.status.in_(
                [AppetiteReassessmentStatus.APPROVED.value, AppetiteReassessmentStatus.PENDING.value]
            ),
        )
        .order_by(ServiceAppetiteReassessment.version.desc())
        .all()
    )
    by_category: dict[str, ServiceAppetiteReassessment] = {}
    for row in rows:
        existing = by_category.get(row.category)
        if existing is None:
            by_category[row.category] = row
        elif existing.status == AppetiteReassessmentStatus.PENDING.value and row.status == AppetiteReassessmentStatus.APPROVED.value:
            by_category[row.category] = row
    return by_category


def list_approved_reassessment_reviews(
    db: Session, *, organization_id: int
) -> list[ServiceAppetiteReassessment]:
    """Every approved reassessment with a review date, org-wide (mirrors the
    Process Risk Appetite half in ``risk_appetite_resolution_service``)."""
    return (
        db.query(ServiceAppetiteReassessment)
        .filter(
            ServiceAppetiteReassessment.organization_id == organization_id,
            ServiceAppetiteReassessment.status == AppetiteReassessmentStatus.APPROVED.value,
            ServiceAppetiteReassessment.review_at.isnot(None),
        )
        .all()
    )


def list_pending_reassessments(db: Session, *, organization_id: int) -> list[ServiceAppetiteReassessment]:
    """Every pending reassessment across the whole organisation, newest first.

    Portfolio-wide, for the executive governance dashboard (ONB-GOV-10) —
    unlike ``get_active_reassessments``, this is not scoped to one service.
    """
    return (
        db.query(ServiceAppetiteReassessment)
        .filter(
            ServiceAppetiteReassessment.organization_id == organization_id,
            ServiceAppetiteReassessment.status == AppetiteReassessmentStatus.PENDING.value,
        )
        .order_by(ServiceAppetiteReassessment.created_at.desc())
        .all()
    )


def approved_answers(
    db: Session, *, organization_id: int, business_service_id: str
) -> dict[str, int]:
    """Category -> approved level, for categories with an approved reassessment."""
    active = get_active_reassessments(db, organization_id=organization_id, business_service_id=business_service_id)
    return {
        category: row.requested_level
        for category, row in active.items()
        if row.status == AppetiteReassessmentStatus.APPROVED.value
    }


def resolve_effective_service_appetite(
    db: Session,
    *,
    organization_id: int,
    business_service_id: str,
    process_answers: dict | None,
) -> EffectiveServiceAppetiteResolution:
    """Overlay one service's own reassessments onto its process's already-
    resolved appetite. Cheap — call `resolve_process_appetite` once per
    process (it queries every policy scope, exception included) and this
    once per service, rather than re-resolving the process policy per
    service."""
    reassessed = approved_answers(db, organization_id=organization_id, business_service_id=business_service_id)
    active = get_active_reassessments(db, organization_id=organization_id, business_service_id=business_service_id)
    pending = [row for row in active.values() if row.status == AppetiteReassessmentStatus.PENDING.value]

    return EffectiveServiceAppetiteResolution(
        status=service_appetite_status(reassessed, has_pending_reassessment=bool(pending)),
        answers=effective_service_appetite(reassessed, process_answers),
        provenance=appetite_category_provenance(reassessed),
        pending=pending,
    )


def request_reassessment(
    db: Session,
    *,
    organization_id: int,
    business_service_id: str,
    process_id: str,
    category: str,
    requested_level: int,
    reason: str,
    requested_by: str,
    evidence: str | None = None,
) -> ServiceAppetiteReassessment:
    if category not in APPETITE_DIMENSION_KEYS:
        raise AppetiteReassessmentValidationError(f"Unknown appetite category '{category}'.")
    if not 0 <= requested_level <= 4:
        raise AppetiteReassessmentValidationError("Appetite level must be between 0 and 4.")
    if not reason.strip():
        raise AppetiteReassessmentValidationError("A structured reason is required.")

    predecessor: ServiceAppetiteReassessment | None = (
        db.query(ServiceAppetiteReassessment)
        .filter(
            ServiceAppetiteReassessment.organization_id == organization_id,
            ServiceAppetiteReassessment.business_service_id == business_service_id,
            ServiceAppetiteReassessment.category == category,
            ServiceAppetiteReassessment.status.in_(
                [AppetiteReassessmentStatus.APPROVED.value, AppetiteReassessmentStatus.PENDING.value]
            ),
        )
        .order_by(ServiceAppetiteReassessment.version.desc())
        .first()
    )
    reassessment = ServiceAppetiteReassessment(
        organization_id=organization_id,
        business_service_id=business_service_id,
        process_id=process_id,
        category=category,
        requested_level=requested_level,
        reason=reason.strip(),
        evidence=evidence,
        requested_by=requested_by,
        status=AppetiteReassessmentStatus.PENDING.value,
        version=(predecessor.version + 1) if predecessor else 1,
    )
    db.add(reassessment)
    db.flush()
    if predecessor is not None:
        predecessor.status = AppetiteReassessmentStatus.SUPERSEDED.value
        predecessor.superseded_by_id = reassessment.id
        db.add(predecessor)
    return reassessment


def approve_reassessment(
    db: Session,
    reassessment: ServiceAppetiteReassessment,
    *,
    reviewed_by: str,
    review_at: datetime,
    effective_from: datetime | None = None,
) -> ServiceAppetiteReassessment:
    if reassessment.status != AppetiteReassessmentStatus.PENDING.value:
        raise AppetiteReassessmentValidationError("Only a pending reassessment can be approved.")
    reassessment.status = AppetiteReassessmentStatus.APPROVED.value
    reassessment.reviewed_by = reviewed_by
    reassessment.reviewed_at = utcnow()
    reassessment.effective_from = _naive_utc(effective_from or utcnow())
    reassessment.review_at = _naive_utc(review_at)
    db.add(reassessment)
    return reassessment


def reject_reassessment(
    db: Session,
    reassessment: ServiceAppetiteReassessment,
    *,
    reviewed_by: str,
    rejection_reason: str,
) -> ServiceAppetiteReassessment:
    if reassessment.status != AppetiteReassessmentStatus.PENDING.value:
        raise AppetiteReassessmentValidationError("Only a pending reassessment can be rejected.")
    if not rejection_reason.strip():
        raise AppetiteReassessmentValidationError("A rejection reason is required.")
    reassessment.status = AppetiteReassessmentStatus.REJECTED.value
    reassessment.reviewed_by = reviewed_by
    reassessment.reviewed_at = utcnow()
    reassessment.rejection_reason = rejection_reason.strip()
    db.add(reassessment)
    return reassessment
