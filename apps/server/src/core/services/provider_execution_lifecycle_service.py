"""Guarded transitions for the domain-owned ProviderExecution lifecycle."""

from src.core.constants.discovery_execution_enums import ALLOWED_PROVIDER_EXECUTION_TRANSITIONS
from src.core.constants.lifecycle_enums import LifecycleDenialReason
from src.core.model_defs.discovery_execution import ProviderExecution


class ProviderExecutionTransitionError(ValueError):
    def __init__(self, reason: LifecycleDenialReason, current_state: str, target_state: str):
        self.reason = reason
        self.current_state = current_state
        self.target_state = target_state
        super().__init__(
            f"Provider execution cannot transition from '{current_state}' to '{target_state}'."
        )


def transition_provider_execution(job: ProviderExecution, target_state: str) -> None:
    if target_state not in ALLOWED_PROVIDER_EXECUTION_TRANSITIONS:
        raise ProviderExecutionTransitionError(
            LifecycleDenialReason.INVALID_TARGET_STATE, job.status, target_state
        )
    if target_state not in ALLOWED_PROVIDER_EXECUTION_TRANSITIONS.get(job.status, frozenset()):
        reason = (
            LifecycleDenialReason.TERMINAL_STATE
            if not ALLOWED_PROVIDER_EXECUTION_TRANSITIONS.get(job.status)
            else LifecycleDenialReason.INVALID_SOURCE_STATE
        )
        raise ProviderExecutionTransitionError(reason, job.status, target_state)
    job.status = target_state
