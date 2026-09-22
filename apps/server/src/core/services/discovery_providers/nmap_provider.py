"""Step 4.2 Part 2 — Nmap as a DELEGATED provider.

Nmap must run on the customer's own scanner agent (apps/scanner) — never
directly from Risklence's backend, which cannot reach a customer's network
and must never attempt to (a genuine security/correctness boundary, see
discovery_execution_enums.ExecutionMode's own docstring). `execute()`
therefore does not run anything itself: it creates a signed ScannerCommand
tied to this one ProviderExecution and returns immediately. The job stays
open until the scanner reports a real result via
discovery_execution_command_service.record_provider_execution_result.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.discovery_execution_enums import ExecutionMode
from src.core.constants.discovery_run_enums import DISCOVERY_COMMAND_EXPIRY_SECONDS, DiscoveryStage
from src.core.model_defs.discovery_execution import ProviderExecution
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.services.discovery_providers.base import (
    ProviderCapabilities,
    ProviderExecutionOutcome,
)


class NmapProvider:
    provider_id = "nmap"

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id=self.provider_id,
            execution_mode=ExecutionMode.DELEGATED.value,
            supported_discovery_stages=frozenset(
                {
                    DiscoveryStage.EXTERNAL_DISCOVERY.value,
                    DiscoveryStage.INTERNAL_DISCOVERY.value,
                    DiscoveryStage.SERVICE_FINGERPRINTING.value,
                }
            ),
            dependency_requirements={"requiresTool": "nmap"},
            timeout_recommendation_seconds=DISCOVERY_COMMAND_EXPIRY_SECONDS,
            retry_recommendation={"maxAttempts": 3, "backoffSeconds": 60},
            estimated_execution_characteristics={"typicalDurationSeconds": 120},
        )

    def execute(
        self, db: Session, *, run: DiscoveryRun, provider_execution: ProviderExecution
    ) -> ProviderExecutionOutcome:
        # Local import: discovery_execution_command_service now imports
        # discovery_execution_scheduler_service (to cascade stage/plan
        # completion), which imports the discovery_providers registry (to
        # resolve a provider by id) — a module-level import here would
        # cycle back through that registry into this exact module. Both
        # sides are fully loaded by the time execute() is actually called.
        from src.core.services.discovery_execution_command_service import create_command_for_provider_execution

        command = create_command_for_provider_execution(db, run, provider_execution)
        return ProviderExecutionOutcome(mode=ExecutionMode.DELEGATED.value, delegated_command_id=command.id)
