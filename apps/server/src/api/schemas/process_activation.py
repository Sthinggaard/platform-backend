"""Contracts for Business Process confirmation and impact-model activation."""

from pydantic import BaseModel

from src.api.schemas.timestamps import UtcTimestamp
from src.core.constants.process_ownership_enums import (
    ProcessOwnershipRejectionReason,
    ProcessOwnershipStatus,
)
from src.core.constants.process_activation_enums import (
    ProcessActivationState,
    ProcessConfirmationOutcome,
    ProcessConfirmationReasonCode,
)


class ProcessActivationReadinessResponse(BaseModel):
    process_id: str
    activation_id: str | None = None
    state: ProcessActivationState
    next_action: ProcessActivationState
    confirmation_outcome: ProcessConfirmationOutcome
    process_confirmed: bool
    owner_assigned: bool
    owner_user_id: int | None = None
    ownership_accepted: bool
    # The invitation behind the assignment, so the process can say how long it
    # has waited and why a candidate refused.
    owner_acceptance_status: ProcessOwnershipStatus | None = None
    owner_invited_at: UtcTimestamp | None = None
    owner_rejection_reason: ProcessOwnershipRejectionReason | None = None
    bia_attested: bool
    organisation_appetite_effective: bool
    impact_model_active: bool


class ProcessNonConfirmationRequest(BaseModel):
    outcome: ProcessConfirmationOutcome
    reason_code: ProcessConfirmationReasonCode
    reason_detail: str | None = None
    successor_process_id: str | None = None
