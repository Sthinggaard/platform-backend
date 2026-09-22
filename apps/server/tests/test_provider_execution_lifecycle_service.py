import pytest

from src.core.constants.discovery_execution_enums import ProviderExecutionStatus
from src.core.constants.lifecycle_enums import LifecycleDenialReason
from src.core.model_defs.discovery_execution import ProviderExecution
from src.core.services.provider_execution_lifecycle_service import (
    ProviderExecutionTransitionError,
    transition_provider_execution,
)


def _job(status: str) -> ProviderExecution:
    return ProviderExecution(execution_stage_id="stage-1", provider_id="nmap", status=status)


def test_provider_execution_allows_technical_progression():
    job = _job(ProviderExecutionStatus.PENDING.value)

    transition_provider_execution(job, ProviderExecutionStatus.LEASED.value)
    transition_provider_execution(job, ProviderExecutionStatus.RUNNING.value)
    transition_provider_execution(job, ProviderExecutionStatus.COMPLETED.value)

    assert job.status == ProviderExecutionStatus.COMPLETED.value


def test_provider_execution_rejects_reopening_a_terminal_attempt():
    with pytest.raises(ProviderExecutionTransitionError) as error:
        transition_provider_execution(
            _job(ProviderExecutionStatus.FAILED.value), ProviderExecutionStatus.RUNNING.value
        )

    assert error.value.reason == LifecycleDenialReason.TERMINAL_STATE
