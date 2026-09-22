"""Business Process Owner invitation and acceptance endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.routes.org_access import _require_org_admin
from src.api.schemas.process_ownership import (
    PendingOwnerInvitationResponse,
    PendingOwnerInvitationsResponse,
    ProcessOwnerCandidateResponse,
    ProcessOwnerProposalResponse,
    ProcessOwnershipInvitationRequest,
    ProcessOwnershipRejectionRequest,
    ProcessOwnershipResponse,
)
from src.core.constants.process_ownership_enums import ProcessOwnershipAuditEvent
from src.core.database import get_db
from src.core.exceptions import ResourceNotFoundError, ValidationError
from src.core.model_defs.process_ownership import ProcessOwnerAcceptance
from src.core.models import AuditEvent, ValueStream
from src.core.repository import TenantRepository
from src.core.services.process_owner_proposal_service import propose_process_owner
from src.core.services.process_ownership_service import (
    ProcessOwnershipValidationError,
    accept_process_ownership,
    list_pending_owner_invitations,
    invite_process_owner,
    reject_process_ownership,
)

router = APIRouter(prefix="/api/v1/process-ownership", tags=["Process ownership"])


@router.get("/processes/{process_id}/proposal", response_model=ProcessOwnerProposalResponse)
def get_process_owner_proposal(
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessOwnerProposalResponse:
    """Return a tenant-scoped owner recommendation without mutating mandates.

    Administrator-only: the response carries the name, email and job title of
    every mandate holder and service owner it proposes, and only an
    Organisation Administrator can act on it by assigning ownership.
    """
    _require_org_admin(db, ctx)
    process = TenantRepository(db, ValueStream, ctx.organization_id).get_by_id(process_id)
    if process is None:
        raise ResourceNotFoundError("Business Process not found in this organisation")
    proposal = propose_process_owner(
        db,
        organization_id=ctx.organization_id,
        process_id=process_id,
    )
    return ProcessOwnerProposalResponse(
        process_id=process_id,
        status=proposal.status,
        recommended_user_id=proposal.recommended_user_id,
        current_owner_user_id=proposal.current_owner_user_id,
        acceptance_status=proposal.acceptance_status,
        candidates=[
            ProcessOwnerCandidateResponse(
                user_id=candidate.user_id,
                name=candidate.name,
                email=candidate.email,
                title=candidate.title,
                source=candidate.source,
            )
            for candidate in proposal.candidates
        ],
    )


@router.get("/invitations/mine", response_model=PendingOwnerInvitationsResponse)
def list_my_owner_invitations(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> PendingOwnerInvitationsResponse:
    """The caller's own unanswered ownership invitations.

    Deliberately not addressable by user id: an invitation belongs to the person
    named on it, so this returns the caller's and nobody else's. An
    administrator sees their own here, not everyone's.

    Without it an invitation cannot be found. Accept and reject are addressed by
    process id, so answering one meant already knowing the id of a process
    nobody had told you about — which is why every acceptance in the dev
    organisation was made by calling the API directly.
    """
    pending = list_pending_owner_invitations(
        db,
        organization_id=ctx.organization_id,
        user_id=ctx.user_id,
    )
    return PendingOwnerInvitationsResponse(
        invitations=[
            PendingOwnerInvitationResponse(
                process_id=item.process_id,
                process_name=item.process_name,
                outcome_statement=item.outcome_statement,
                service_count=item.service_count,
                invited_at=item.invited_at,
                invited_by_user_id=item.invited_by_user_id,
            )
            for item in pending
        ]
    )


def _response(acceptance: ProcessOwnerAcceptance) -> ProcessOwnershipResponse:
    return ProcessOwnershipResponse(
        id=acceptance.id,
        process_id=acceptance.process_id,
        scope_binding_id=acceptance.scope_binding_id,
        owner_user_id=acceptance.owner_user_id,
        status=acceptance.status,
        rejection_reason=acceptance.rejection_reason,
    )


def _write_audit(db: Session, *, ctx: TenantContext, event_type: ProcessOwnershipAuditEvent, acceptance: ProcessOwnerAcceptance) -> None:
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=event_type.value,
            metadata_json={
                "process_id": acceptance.process_id,
                "scope_binding_id": acceptance.scope_binding_id,
                "owner_user_id": acceptance.owner_user_id,
                "status": acceptance.status,
                "rejection_reason": acceptance.rejection_reason,
            },
        )
    )


@router.post("/invitations", response_model=ProcessOwnershipResponse)
def create_process_ownership_invitation(
    body: ProcessOwnershipInvitationRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessOwnershipResponse:
    _require_org_admin(db, ctx)
    try:
        acceptance = invite_process_owner(
            db,
            organization_id=ctx.organization_id,
            scope_binding_id=body.scope_binding_id,
            invited_by_user_id=ctx.user_id,
        )
    except ProcessOwnershipValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=ProcessOwnershipAuditEvent.INVITATION_SENT, acceptance=acceptance)
    db.commit()
    db.refresh(acceptance)
    return _response(acceptance)


@router.post("/processes/{process_id}/accept", response_model=ProcessOwnershipResponse)
def accept_process_owner_invitation(
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessOwnershipResponse:
    try:
        acceptance = accept_process_ownership(
            db,
            organization_id=ctx.organization_id,
            process_id=process_id,
            actor_user_id=ctx.user_id,
        )
    except ProcessOwnershipValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=ProcessOwnershipAuditEvent.ACCEPTED, acceptance=acceptance)
    db.commit()
    db.refresh(acceptance)
    return _response(acceptance)


@router.post("/processes/{process_id}/reject", response_model=ProcessOwnershipResponse)
def reject_process_owner_invitation(
    process_id: str,
    body: ProcessOwnershipRejectionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessOwnershipResponse:
    try:
        acceptance = reject_process_ownership(
            db,
            organization_id=ctx.organization_id,
            process_id=process_id,
            actor_user_id=ctx.user_id,
            reason=body.reason,
        )
    except ProcessOwnershipValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=ProcessOwnershipAuditEvent.REJECTED, acceptance=acceptance)
    db.commit()
    db.refresh(acceptance)
    return _response(acceptance)
