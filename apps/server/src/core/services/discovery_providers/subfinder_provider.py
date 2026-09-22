"""Step 4.2 Part 2 — CA-04.3: Subfinder as a DELEGATED provider.

Mirrors NmapProvider exactly (same reason: Subfinder must run on the
customer's own scanner agent — Risklence's backend cannot resolve a
customer's private DNS/subdomain surface directly, and must never attempt
to). Subfinder is passive subdomain enumeration only — external discovery,
never internal or fingerprinting; it never opens a connection to a
discovered host itself.
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


class SubfinderProvider:
    provider_id = "subfinder"

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id=self.provider_id,
            execution_mode=ExecutionMode.DELEGATED.value,
            supported_discovery_stages=frozenset({DiscoveryStage.EXTERNAL_DISCOVERY.value}),
            dependency_requirements={"requiresTool": "subfinder"},
            timeout_recommendation_seconds=DISCOVERY_COMMAND_EXPIRY_SECONDS,
            retry_recommendation={"maxAttempts": 3, "backoffSeconds": 60},
            estimated_execution_characteristics={"typicalDurationSeconds": 60},
        )

    def execute(
        self, db: Session, *, run: DiscoveryRun, provider_execution: ProviderExecution
    ) -> ProviderExecutionOutcome:
        # Local import — same circular-import reason as NmapProvider.execute().
        from src.core.services.discovery_execution_command_service import create_command_for_provider_execution

        command = create_command_for_provider_execution(db, run, provider_execution)
        return ProviderExecutionOutcome(mode=ExecutionMode.DELEGATED.value, delegated_command_id=command.id)
