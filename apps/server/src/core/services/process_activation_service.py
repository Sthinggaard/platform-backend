"""Write operations for governed Business Process activation."""

from sqlalchemy.orm import Session

from src.core.constants.org_access_enums import CanonicalMandateRole, MandateScopeType
from src.core.constants.process_activation_enums import (
    TERMINAL_PROCESS_CONFIRMATION_OUTCOMES,
    ProcessActivationState,
    ProcessConfirmationOutcome,
    ProcessConfirmationReasonCode,
)
from src.core.constants.process_ownership_enums import ProcessOwnershipStatus
from src.core.model_defs.common import utcnow
from src.core.model_defs.org_access import OrgMandateScopeBinding
from src.core.model_defs.process_activation import BusinessProcessActivation
from src.core.model_defs.process_ownership import ProcessOwnerAcceptance
from src.core.model_defs.value_streams import ValueStream
from src.core.repository import TenantRepository
from src.core.services.bia_inheritance_service import bia_is_complete
from src.core.services.effective_process_bia_service import resolve_effective_process_bia_by_process
from src.core.services.process_activation_readiness_service import (
    ProcessActivationReadiness,
    resolve_process_activation_readiness,
)
from src.core.services.risk_appetite_resolution_service import resolve_organisation_appetite


class ProcessActivationValidationError(ValueError):
    """Raised when a human requests activation before the current gates are ready."""


def confirm_business_process(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
    confirmed_by_user_id: int,
) -> BusinessProcessActivation:
    """Record the administrator's explicit confirmation of a Business Process."""
    activations = TenantRepository(db, BusinessProcessActivation, organization_id)
    activation = next(iter(activations.filter_by(process_id=process_id)), None)
    if activation is None:
        return activations.create(
            process_id=process_id,
            confirmed_by_user_id=confirmed_by_user_id,
            confirmed_at=utcnow(),
            confirmation_outcome=ProcessConfirmationOutcome.CONFIRMED.value,
        )
    activations.update(
        activation,
        confirmed_by_user_id=confirmed_by_user_id,
        confirmed_at=utcnow(),
        confirmation_outcome=ProcessConfirmationOutcome.CONFIRMED.value,
        confirmation_reason_code=None,
        confirmation_reason_detail=None,
        successor_process_id=None,
    )
    return activation


def record_non_confirmation(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
    outcome: ProcessConfirmationOutcome,
    reason_code: ProcessConfirmationReasonCode,
    reason_detail: str | None,
    successor_process_id: str | None,
) -> BusinessProcessActivation:
    """Record a terminal human decision and invalidate any prior activation."""
    if outcome not in TERMINAL_PROCESS_CONFIRMATION_OUTCOMES:
        raise ProcessActivationValidationError(outcome.value)
    activations = TenantRepository(db, BusinessProcessActivation, organization_id)
    activation = next(iter(activations.filter_by(process_id=process_id)), None)
    values = {
        "confirmed_by_user_id": None,
        "confirmed_at": None,
        "confirmation_outcome": outcome.value,
        "confirmation_reason_code": reason_code.value,
        "confirmation_reason_detail": reason_detail,
        "successor_process_id": successor_process_id,
        "activated_by_user_id": None,
        "activated_at": None,
        "activated_bia_assessment_id": None,
        "activated_organization_bia_baseline_id": None,
        "activated_owner_acceptance_id": None,
        "activated_appetite_policy_id": None,
        "activated_confirmation_at": None,
    }
    if activation is None:
        return activations.create(process_id=process_id, **values)
    activations.update(activation, **values)
    return activation


def activate_business_process(
    db: Session,
    *,
    organization_id: int,
    process: ValueStream,
    activated_by_user_id: int,
) -> tuple[BusinessProcessActivation, ProcessActivationReadiness]:
    """Snapshot current governed inputs after a human requests activation."""
    readiness = resolve_process_activation_readiness(
        db,
        organization_id=organization_id,
        processes=[process],
    )[process.id]
    if readiness.state != ProcessActivationState.READY_FOR_ACTIVATION:
        raise ProcessActivationValidationError(readiness.state.value)

    activation = TenantRepository(db, BusinessProcessActivation, organization_id).get_by_id(
        readiness.activation_id
    )
    binding = _owner_binding(db, organization_id=organization_id, process_id=process.id)
    acceptance = _accepted_owner_response(db, organization_id=organization_id, binding=binding)
    effective_bia = resolve_effective_process_bia_by_process(
        db,
        organization_id=organization_id,
        processes=[process],
    )[process.id]
    appetite = resolve_organisation_appetite(db, organization_id=organization_id)
    if (
        activation is None
        or acceptance is None
        or not bia_is_complete(effective_bia.answers)
        or appetite is None
    ):
        raise ProcessActivationValidationError(ProcessActivationState.READY_FOR_ACTIVATION.value)
    TenantRepository(db, BusinessProcessActivation, organization_id).update(
        activation,
        activated_by_user_id=activated_by_user_id,
        activated_at=utcnow(),
        activated_bia_assessment_id=effective_bia.process_assessment_id,
        activated_organization_bia_baseline_id=effective_bia.organization_baseline_id,
        activated_owner_acceptance_id=acceptance.id,
        activated_appetite_policy_id=appetite.policy_id,
        activated_confirmation_at=activation.confirmed_at,
    )
    return activation, readiness


def _owner_binding(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
) -> OrgMandateScopeBinding | None:
    return next(
        iter(
            TenantRepository(db, OrgMandateScopeBinding, organization_id).filter_by(
                scope_type=MandateScopeType.BUSINESS_PROCESS.value,
                value_stream_id=process_id,
                canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
            )
        ),
        None,
    )


def _accepted_owner_response(
    db: Session,
    *,
    organization_id: int,
    binding: OrgMandateScopeBinding | None,
) -> ProcessOwnerAcceptance | None:
    if binding is None:
        return None
    return next(
        iter(
            TenantRepository(db, ProcessOwnerAcceptance, organization_id).filter_by(
                scope_binding_id=binding.id,
                status=ProcessOwnershipStatus.ACCEPTED.value,
            )
        ),
        None,
    )
