"""Canonical lifecycle values for Business Process confirmation and activation."""

from enum import StrEnum


class ProcessConfirmationOutcome(StrEnum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    NOT_APPLICABLE = "not_applicable"
    DUPLICATE = "duplicate"
    WRONG_SCOPE = "wrong_scope"
    REDESIGN_REQUIRED = "redesign_required"


class ProcessConfirmationReasonCode(StrEnum):
    NOT_A_BUSINESS_PROCESS = "not_a_business_process"
    DUPLICATE_PROCESS = "duplicate_process"
    BELONGS_TO_ANOTHER_BUSINESS_UNIT = "belongs_to_another_business_unit"
    PROCESS_BOUNDARY_INCORRECT = "process_boundary_incorrect"


class ProcessActivationState(StrEnum):
    CONFIRMATION_REQUIRED = "confirmation_required"
    OWNERSHIP_REQUIRED = "ownership_required"
    OWNER_ACCEPTANCE_REQUIRED = "owner_acceptance_required"
    BIA_REQUIRED = "bia_required"
    BIA_IN_PROGRESS = "bia_in_progress"
    LEADERSHIP_APPETITE_REQUIRED = "leadership_appetite_required"
    READY_FOR_ACTIVATION = "ready_for_activation"
    IMPACT_UNDERSTOOD = "impact_understood"
    NOT_APPLICABLE = "not_applicable"
    DUPLICATE = "duplicate"
    WRONG_SCOPE = "wrong_scope"
    REDESIGN_REQUIRED = "redesign_required"


TERMINAL_PROCESS_CONFIRMATION_OUTCOMES = frozenset(
    {
        ProcessConfirmationOutcome.NOT_APPLICABLE,
        ProcessConfirmationOutcome.DUPLICATE,
        ProcessConfirmationOutcome.WRONG_SCOPE,
        ProcessConfirmationOutcome.REDESIGN_REQUIRED,
    }
)

TERMINAL_PROCESS_ACTIVATION_STATES = frozenset(
    {
        ProcessActivationState.NOT_APPLICABLE,
        ProcessActivationState.DUPLICATE,
        ProcessActivationState.WRONG_SCOPE,
        ProcessActivationState.REDESIGN_REQUIRED,
    }
)

PROCESS_CONFIRMATION_OUTCOME_TO_ACTIVATION_STATE = {
    ProcessConfirmationOutcome.NOT_APPLICABLE: ProcessActivationState.NOT_APPLICABLE,
    ProcessConfirmationOutcome.DUPLICATE: ProcessActivationState.DUPLICATE,
    ProcessConfirmationOutcome.WRONG_SCOPE: ProcessActivationState.WRONG_SCOPE,
    ProcessConfirmationOutcome.REDESIGN_REQUIRED: ProcessActivationState.REDESIGN_REQUIRED,
}

PROCESS_CONFIRMATION_REASON_BY_OUTCOME = {
    ProcessConfirmationOutcome.NOT_APPLICABLE: ProcessConfirmationReasonCode.NOT_A_BUSINESS_PROCESS,
    ProcessConfirmationOutcome.DUPLICATE: ProcessConfirmationReasonCode.DUPLICATE_PROCESS,
    ProcessConfirmationOutcome.WRONG_SCOPE: ProcessConfirmationReasonCode.BELONGS_TO_ANOTHER_BUSINESS_UNIT,
    ProcessConfirmationOutcome.REDESIGN_REQUIRED: ProcessConfirmationReasonCode.PROCESS_BOUNDARY_INCORRECT,
}


class ProcessActivationAuditEvent(StrEnum):
    PROCESS_CONFIRMED = "business_process_confirmed"
    PROCESS_NOT_CONFIRMED = "business_process_not_confirmed"
    IMPACT_MODEL_ACTIVATED = "business_process_impact_model_activated"


class ProcessActivationErrorMessage(StrEnum):
    PROCESS_NOT_FOUND = "Business Process not found in this organisation"
    PROCESS_NOT_CONFIRMED = "A Business Process must be confirmed before activation"
    ACTIVATION_NOT_READY = "This Business Process cannot activate until its setup gates are complete"
    INVALID_CONFIRMATION_OUTCOME = "A terminal confirmation outcome is required"
    INVALID_CONFIRMATION_REASON = "The reason code does not match the confirmation outcome"
    DUPLICATE_REQUIRES_SUCCESSOR = "A duplicate process requires a successor process"
    PROCESS_CANNOT_BE_OWN_SUCCESSOR = "A process cannot be its own successor"
    DEPENDENCY_PUBLICATION_REQUIRES_ACTIVATION = (
        "Dependency publication requires an active Business Process impact model"
    )
