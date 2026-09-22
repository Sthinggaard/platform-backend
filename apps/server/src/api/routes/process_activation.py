"""Human-confirmed Business Process activation endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.routes.org_access import _require_org_admin
from src.api.schemas.process_activation import (
    ProcessActivationReadinessResponse,
    ProcessNonConfirmationRequest,
)
from src.core.constants.process_activation_enums import (
    PROCESS_CONFIRMATION_REASON_BY_OUTCOME,
    TERMINAL_PROCESS_CONFIRMATION_OUTCOMES,
    ProcessActivationAuditEvent,
    ProcessActivationErrorMessage,
    ProcessConfirmationOutcome,
)
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.models import AuditEvent, ValueStream
from src.core.repository import TenantRepository
from src.core.services.process_activation_service import (
    ProcessActivationReadiness,
    ProcessActivationValidationError,
    activate_business_process,
    confirm_business_process,
    record_non_confirmation,
    resolve_process_activation_readiness,
)
from src.core.services.process_ownership_service import (
    ProcessOwnershipValidationError,
    require_accepted_process_owner,
)

router = APIRouter(prefix="/api/v1/process-activation", tags=["Process activation"])


def _get_process(db: Session, *, ctx: TenantContext, process_id: str) -> ValueStream:
    process = TenantRepository(db, ValueStream, ctx.organization_id).get_by_id(process_id)
    if process is None:
        raise ResourceNotFoundError(ProcessActivationErrorMessage.PROCESS_NOT_FOUND.value)
    return process


def _response(readiness: ProcessActivationReadiness) -> ProcessActivationReadinessResponse:
    return ProcessActivationReadinessResponse(**readiness.__dict__)


def _readiness_after_mutation(
    db: Session,
    *,
    ctx: TenantContext,
    process: ValueStream,
) -> ProcessActivationReadiness:
    """Resolve readiness so it reflects the change just made.

    The session is created with ``autoflush=False``, so a freshly *created*
    BusinessProcessActivation is still pending when the readiness query runs and
    the query does not see it. The first confirmation of a process therefore
    answered ``process_confirmed: false`` and ``activation_id: null`` even though
    it had just been recorded and was about to commit — the owner clicked
    Confirm, the server stored it, and the response told them nothing had
    happened. Flushing first makes the pending row visible to the query without
    committing anything, so the response describes the state the caller is
    about to get.
    """
    db.flush()
    return resolve_process_activation_readiness(
        db,
        organization_id=ctx.organization_id,
        processes=[process],
    )[process.id]


def _audit(
    db: Session,
    *,
    ctx: TenantContext,
    event_type: ProcessActivationAuditEvent,
    readiness: ProcessActivationReadiness,
    confirmation_metadata: dict[str, str | None] | None = None,
) -> None:
    metadata = {
        "process_id": readiness.process_id,
        "activation_id": readiness.activation_id,
        "state": readiness.state.value,
        "next_action": readiness.next_action.value,
        "confirmation_outcome": readiness.confirmation_outcome.value,
    }
    if confirmation_metadata:
        metadata.update(confirmation_metadata)
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=event_type.value,
            metadata_json=metadata,
        )
    )


@router.get("/processes/{process_id}", response_model=ProcessActivationReadinessResponse)
def get_process_activation_readiness(
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessActivationReadinessResponse:
    process = _get_process(db, ctx=ctx, process_id=process_id)
    readiness = resolve_process_activation_readiness(
        db,
        organization_id=ctx.organization_id,
        processes=[process],
    )[process.id]
    return _response(readiness)


@router.post("/processes/{process_id}/confirm", response_model=ProcessActivationReadinessResponse)
def confirm_process_for_activation(
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessActivationReadinessResponse:
    # Ownership precedes approval: the accepted owner is the only one who may
    # confirm a process. The administrator's authority is curation — retiring
    # a bad suggestion via /not-confirmed, which stays admin-authorised below.
    process = _get_process(db, ctx=ctx, process_id=process_id)
    try:
        require_accepted_process_owner(
            db,
            organization_id=ctx.organization_id,
            process_id=process.id,
            user_id=ctx.user_id,
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc
    confirm_business_process(
        db,
        organization_id=ctx.organization_id,
        process_id=process.id,
        confirmed_by_user_id=ctx.user_id,
    )
    readiness = _readiness_after_mutation(db, ctx=ctx, process=process)
    _audit(db, ctx=ctx, event_type=ProcessActivationAuditEvent.PROCESS_CONFIRMED, readiness=readiness)
    db.commit()
    return _response(readiness)


@router.post("/processes/{process_id}/not-confirmed", response_model=ProcessActivationReadinessResponse)
def record_process_non_confirmation(
    process_id: str,
    body: ProcessNonConfirmationRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessActivationReadinessResponse:
    _require_org_admin(db, ctx)
    process = _get_process(db, ctx=ctx, process_id=process_id)
    if body.outcome not in TERMINAL_PROCESS_CONFIRMATION_OUTCOMES:
        raise ValidationError(ProcessActivationErrorMessage.INVALID_CONFIRMATION_OUTCOME.value)
    if PROCESS_CONFIRMATION_REASON_BY_OUTCOME[body.outcome] is not body.reason_code:
        raise ValidationError(ProcessActivationErrorMessage.INVALID_CONFIRMATION_REASON.value)
    successor_id = body.successor_process_id
    if body.outcome is ProcessConfirmationOutcome.DUPLICATE and successor_id is None:
        raise ValidationError(ProcessActivationErrorMessage.DUPLICATE_REQUIRES_SUCCESSOR.value)
    if successor_id is not None:
        if successor_id == process.id:
            raise ValidationError(ProcessActivationErrorMessage.PROCESS_CANNOT_BE_OWN_SUCCESSOR.value)
        _get_process(db, ctx=ctx, process_id=successor_id)
    record_non_confirmation(
        db,
        organization_id=ctx.organization_id,
        process_id=process.id,
        outcome=body.outcome,
        reason_code=body.reason_code,
        reason_detail=body.reason_detail,
        successor_process_id=successor_id,
    )
    readiness = _readiness_after_mutation(db, ctx=ctx, process=process)
    _audit(
        db,
        ctx=ctx,
        event_type=ProcessActivationAuditEvent.PROCESS_NOT_CONFIRMED,
        readiness=readiness,
        confirmation_metadata={
            "reason_code": body.reason_code.value,
            "successor_process_id": successor_id,
        },
    )
    db.commit()
    return _response(readiness)


@router.post("/processes/{process_id}/activate", response_model=ProcessActivationReadinessResponse)
def activate_process_impact_model(
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessActivationReadinessResponse:
    process = _get_process(db, ctx=ctx, process_id=process_id)
    try:
        require_accepted_process_owner(
            db,
            organization_id=ctx.organization_id,
            process_id=process.id,
            user_id=ctx.user_id,
        )
        activate_business_process(
            db,
            organization_id=ctx.organization_id,
            process=process,
            activated_by_user_id=ctx.user_id,
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc
    except ProcessActivationValidationError as exc:
        raise ValidationError(str(exc)) from exc
    readiness = _readiness_after_mutation(db, ctx=ctx, process=process)
    _audit(
        db,
        ctx=ctx,
        event_type=ProcessActivationAuditEvent.IMPACT_MODEL_ACTIVATED,
        readiness=readiness,
    )
    db.commit()
    return _response(readiness)
