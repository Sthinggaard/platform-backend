import pytest

from src.core.constants.discovery_execution_enums import ExecutionPlanStatus
from src.core.constants.lifecycle_enums import LifecycleDenialReason
from src.core.model_defs.discovery_execution import DiscoveryExecutionPlan
from src.core.services.discovery_execution_plan_lifecycle_service import (
    DiscoveryExecutionPlanTransitionError,
    transition_discovery_execution_plan,
)


def _plan(status: str) -> DiscoveryExecutionPlan:
    return DiscoveryExecutionPlan(
        organization_id=1,
        discovery_run_id="run-1",
        plan_definition={},
        status=status,
    )


def test_execution_plan_allows_completion_from_execution():
    plan = _plan(ExecutionPlanStatus.EXECUTING.value)

    transition_discovery_execution_plan(plan, ExecutionPlanStatus.COMPLETED.value)

    assert plan.status == ExecutionPlanStatus.COMPLETED.value


def test_execution_plan_rejects_transition_from_terminal_state():
    with pytest.raises(DiscoveryExecutionPlanTransitionError) as error:
        transition_discovery_execution_plan(
            _plan(ExecutionPlanStatus.CANCELLED.value), ExecutionPlanStatus.EXECUTING.value
        )

    assert error.value.reason == LifecycleDenialReason.TERMINAL_STATE
