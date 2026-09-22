"""Guarded transitions for the domain-owned DiscoveryExecutionPlan lifecycle."""

from src.core.constants.discovery_execution_enums import ALLOWED_EXECUTION_PLAN_TRANSITIONS
from src.core.constants.lifecycle_enums import LifecycleDenialReason
from src.core.model_defs.discovery_execution import DiscoveryExecutionPlan


class DiscoveryExecutionPlanTransitionError(ValueError):
    def __init__(self, reason: LifecycleDenialReason, current_state: str, target_state: str):
        self.reason = reason
        self.current_state = current_state
        self.target_state = target_state
        super().__init__(
            f"Discovery execution plan cannot transition from '{current_state}' to '{target_state}'."
        )


def transition_discovery_execution_plan(plan: DiscoveryExecutionPlan, target_state: str) -> None:
    if target_state not in ALLOWED_EXECUTION_PLAN_TRANSITIONS:
        raise DiscoveryExecutionPlanTransitionError(
            LifecycleDenialReason.INVALID_TARGET_STATE, plan.status, target_state
        )
    if target_state not in ALLOWED_EXECUTION_PLAN_TRANSITIONS.get(plan.status, frozenset()):
        reason = (
            LifecycleDenialReason.TERMINAL_STATE
            if not ALLOWED_EXECUTION_PLAN_TRANSITIONS.get(plan.status)
            else LifecycleDenialReason.INVALID_SOURCE_STATE
        )
        raise DiscoveryExecutionPlanTransitionError(reason, plan.status, target_state)
    plan.status = target_state
