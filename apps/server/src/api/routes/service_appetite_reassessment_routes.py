"""Business Service Risk Appetite inheritance + reassessment routes (ONB-GOV-11).

The service inherits its process's approved Risk Appetite by default
(GET .../appetite/effective). A Service Owner requests a reassessment of one
category at a time; the Process Owner of the process this service belongs to
approves or rejects it. Never a blank re-ask of the full questionnaire.
"""

from __future__ import annotations

from datetime import datetime

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.appetite_reassessment_enums import (
    APPETITE_REASSESSMENT_AUDIT_APPROVED,
    APPETITE_REASSESSMENT_AUDIT_REJECTED,
    APPETITE_REASSESSMENT_AUDIT_REQUESTED,
    APPETITE_REASSESSMENT_ERROR_NOT_FOUND,
    APPETITE_REASSESSMENT_ERROR_OWNER_REQUIRED,
)
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.service_appetite_reassessment import ServiceAppetiteReassessment
from src.core.models import AuditEvent, BusinessService, ValueStream
from src.core.repository import TenantRepository
from src.core.services.process_ownership_service import (
    ProcessOwnershipValidationError,
    require_accepted_process_owner,
)
from src.core.services.risk_appetite_resolution_service import resolve_process_appetite
from src.core.services.service_appetite_reassessment_service import (
    AppetiteReassessmentValidationError,
    approve_reassessment,
    list_pending_reassessments,
    reject_reassessment,
    request_reassessment,
    resolve_effective_service_appetite,
)
from src.api.schemas.timestamps import UtcTimestamp

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/business-services", tags=["Business Service Appetite Reassessment"])


class ReassessmentRequest(BaseModel):
    process_id: str
    category: str
    requested_level: int
    reason: str
    evidence: str | None = None


class ReassessmentApprovalRequest(BaseModel):
    review_at: UtcTimestamp
    effective_from: UtcTimestamp | None = None


class ReassessmentRejectionRequest(BaseModel):
    rejection_reason: str


class ReassessmentResponse(BaseModel):
    id: str
    business_service_id: str
    process_id: str
    category: str
    requested_level: int
    reason: str
    evidence: str | None = None
    requested_by: str
    status: str
    version: int
    reviewed_by: str | None = None
    reviewed_at: UtcTimestamp | None = None
    rejection_reason: str | None = None
    effective_from: UtcTimestamp | None = None
    review_at: UtcTimestamp | None = None
    created_at: UtcTimestamp


class EffectiveServiceAppetiteResponse(BaseModel):
    status: str
    answers: dict | None = None
    provenance: dict[str, str]
    pending: list[ReassessmentResponse]


class PendingReassessmentSummary(BaseModel):
    reassessment: ReassessmentResponse
    business_service_name: str
    process_name: str | None = None


def _reassessment_response(row: ServiceAppetiteReassessment) -> ReassessmentResponse:
    return ReassessmentResponse(
        id=row.id,
        business_service_id=row.business_service_id,
        process_id=row.process_id,
        category=row.category,
        requested_level=row.requested_level,
        reason=row.reason,
        evidence=row.evidence,
        requested_by=row.requested_by,
        status=row.status,
        version=row.version,
        reviewed_by=row.reviewed_by,
        reviewed_at=row.reviewed_at.isoformat() if row.reviewed_at else None,
        rejection_reason=row.rejection_reason,
        effective_from=row.effective_from.isoformat() if row.effective_from else None,
        review_at=row.review_at.isoformat() if row.review_at else None,
        created_at=row.created_at.isoformat(),
    )


def _require_service(db: Session, organization_id: int, business_service_id: str) -> BusinessService:
    service = TenantRepository(db, BusinessService, organization_id).get_by_id(business_service_id)
    if service is None:
        raise ResourceNotFoundError("Business service not found")
    return service


def _require_service_owner(service: BusinessService, ctx: TenantContext) -> None:
    if service.owner_user_id != ctx.user_id:
        raise AuthorizationError(APPETITE_REASSESSMENT_ERROR_OWNER_REQUIRED)


def _require_reassessment(
    db: Session, *, organization_id: int, business_service_id: str, reassessment_id: str
) -> ServiceAppetiteReassessment:
    reassessment = TenantRepository(db, ServiceAppetiteReassessment, organization_id).get_by_id(reassessment_id)
    if reassessment is None or reassessment.business_service_id != business_service_id:
        raise ResourceNotFoundError(APPETITE_REASSESSMENT_ERROR_NOT_FOUND)
    return reassessment


def _write_audit(db: Session, *, ctx: TenantContext, event_type: str, reassessment: ServiceAppetiteReassessment) -> None:
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=event_type,
            metadata_json={
                "reassessment_id": reassessment.id,
                "business_service_id": reassessment.business_service_id,
                "process_id": reassessment.process_id,
                "category": reassessment.category,
                "status": reassessment.status,
            },
        )
    )


@router.get("/appetite/reassessments/pending", response_model=list[PendingReassessmentSummary])
def list_pending_service_reassessments(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[PendingReassessmentSummary]:
    """Every reassessment awaiting Process Owner approval, org-wide (ONB-GOV-10)."""
    pending = list_pending_reassessments(db, organization_id=ctx.organization_id)
    service_name_by_id = {
        row.id: row.name
        for row in db.query(BusinessService).filter(BusinessService.organization_id == ctx.organization_id).all()
    }
    process_name_by_id = {
        row.id: row.name
        for row in db.query(ValueStream).filter(ValueStream.organization_id == ctx.organization_id).all()
    }
    return [
        PendingReassessmentSummary(
            reassessment=_reassessment_response(row),
            business_service_name=service_name_by_id.get(row.business_service_id, row.business_service_id),
            process_name=process_name_by_id.get(row.process_id),
        )
        for row in pending
    ]


@router.get("/{business_service_id}/appetite/effective", response_model=EffectiveServiceAppetiteResponse)
def get_effective_service_appetite(
    business_service_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> EffectiveServiceAppetiteResponse:
    """The appetite actually in force for this service: inherited + any approved reassessments."""
    service = _require_service(db, ctx.organization_id, business_service_id)
    process_id = service.value_stream_ids[0] if service.value_stream_ids else None
    process_answers = None
    if process_id:
        resolved = resolve_process_appetite(db, organization_id=ctx.organization_id, process_id=process_id)
        process_answers = resolved.answers if resolved else None

    resolution = resolve_effective_service_appetite(
        db,
        organization_id=ctx.organization_id,
        business_service_id=business_service_id,
        process_answers=process_answers,
    )

    return EffectiveServiceAppetiteResponse(
        status=resolution.status,
        answers=resolution.answers,
        provenance=resolution.provenance,
        pending=[_reassessment_response(row) for row in resolution.pending],
    )


@router.post("/{business_service_id}/appetite/reassessments", response_model=ReassessmentResponse)
def create_reassessment(
    business_service_id: str,
    body: ReassessmentRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ReassessmentResponse:
    """The Service Owner requests a reassessment of one category."""
    service = _require_service(db, ctx.organization_id, business_service_id)
    _require_service_owner(service, ctx)
    try:
        reassessment = request_reassessment(
            db,
            organization_id=ctx.organization_id,
            business_service_id=business_service_id,
            process_id=body.process_id,
            category=body.category,
            requested_level=body.requested_level,
            reason=body.reason,
            requested_by=str(ctx.user_id),
            evidence=body.evidence,
        )
    except AppetiteReassessmentValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=APPETITE_REASSESSMENT_AUDIT_REQUESTED, reassessment=reassessment)
    db.commit()
    db.refresh(reassessment)
    return _reassessment_response(reassessment)


@router.post(
    "/{business_service_id}/appetite/reassessments/{reassessment_id}/approve",
    response_model=ReassessmentResponse,
)
def approve_service_reassessment(
    business_service_id: str,
    reassessment_id: str,
    body: ReassessmentApprovalRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ReassessmentResponse:
    """The Process Owner of the reassessment's named process approves it."""
    reassessment = _require_reassessment(
        db, organization_id=ctx.organization_id, business_service_id=business_service_id, reassessment_id=reassessment_id
    )
    try:
        require_accepted_process_owner(
            db, organization_id=ctx.organization_id, process_id=reassessment.process_id, user_id=ctx.user_id
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc
    try:
        approve_reassessment(
            db, reassessment, reviewed_by=str(ctx.user_id), review_at=body.review_at, effective_from=body.effective_from
        )
    except AppetiteReassessmentValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=APPETITE_REASSESSMENT_AUDIT_APPROVED, reassessment=reassessment)
    db.commit()
    db.refresh(reassessment)
    return _reassessment_response(reassessment)


@router.post(
    "/{business_service_id}/appetite/reassessments/{reassessment_id}/reject",
    response_model=ReassessmentResponse,
)
def reject_service_reassessment(
    business_service_id: str,
    reassessment_id: str,
    body: ReassessmentRejectionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ReassessmentResponse:
    reassessment = _require_reassessment(
        db, organization_id=ctx.organization_id, business_service_id=business_service_id, reassessment_id=reassessment_id
    )
    try:
        require_accepted_process_owner(
            db, organization_id=ctx.organization_id, process_id=reassessment.process_id, user_id=ctx.user_id
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc
    try:
        reject_reassessment(db, reassessment, reviewed_by=str(ctx.user_id), rejection_reason=body.rejection_reason)
    except AppetiteReassessmentValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=APPETITE_REASSESSMENT_AUDIT_REJECTED, reassessment=reassessment)
    db.commit()
    db.refresh(reassessment)
    return _reassessment_response(reassessment)
