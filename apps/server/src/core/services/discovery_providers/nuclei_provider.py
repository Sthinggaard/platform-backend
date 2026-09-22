"""Step 4.2 Part 2 — CA-04.4: Nuclei as a DELEGATED provider.

Mirrors NmapProvider/SubfinderProvider exactly (same reason: Nuclei must
run on the customer's own scanner agent). Nuclei runs templated
vulnerability checks against already-discovered/fingerprinted targets —
``DiscoveryStage.VULNERABILITY_DISCOVERY`` only, never external/internal
discovery or fingerprinting themselves.

``dependency_requirements`` names only ``requiresTool: nuclei`` — matching
the other two providers' single-key shape — but Nuclei's Collector-side
readiness gate (``evidence_scanner_readiness_service._CAPABILITY_REQUIRED_TOOLS``)
already requires both the ``nuclei`` binary and the ``nuclei_templates``
directory before ``vulnerabilityScanningEnabled`` is set, so a run can
never reach this provider without both being present.

⚠️ **The scope boundary this docstring used to disclose is closed
(2026-09-06).** It read: the Collector genuinely executes Nuclei and reports
a real completed/failed result, *but no evidence is attached yet*. That gap
is why the platform held 69 evidence packages and **zero findings**, while
CA-09V — vulnerability intelligence — had no input at all.
``discovery_execution_evidence_adapter.py`` now registers a
``(json, nuclei)`` parser and the Collector attaches its raw JSONL.
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


class NucleiProvider:
    provider_id = "nuclei"

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id=self.provider_id,
            execution_mode=ExecutionMode.DELEGATED.value,
            supported_discovery_stages=frozenset({DiscoveryStage.VULNERABILITY_DISCOVERY.value}),
            # CA-02.3 slice 3 — both, not just the binary. Nuclei without its
            # template pack is an engine with nothing to run, and naming only
            # the binary let a Collector missing the pack still be planned for
            # vulnerability work. `requiresTool` (singular) stays supported for
            # the other providers' single-key shape.
            dependency_requirements={"requiresTools": ["nuclei", "nuclei_templates"]},
            timeout_recommendation_seconds=DISCOVERY_COMMAND_EXPIRY_SECONDS,
            retry_recommendation={"maxAttempts": 3, "backoffSeconds": 60},
            estimated_execution_characteristics={"typicalDurationSeconds": 180},
            # CA-09V — Nuclei scans what discovery found, not the approved
            # range itself. Handed `192.168.50.0/24` it expanded that to 256
            # addresses, exhausted its timeout on the 243 that hold nothing,
            # and was killed mid-scan on every run since 2026-08-27 — reporting
            # a clean, empty scan each time. VULNERABILITY_DISCOVERY already
            # depends on SERVICE_FINGERPRINTING in the stage DAG; this makes
            # the command actually carry what that dependency produced.
            targets_discovered_hosts=True,
        )

    def execute(
        self, db: Session, *, run: DiscoveryRun, provider_execution: ProviderExecution
    ) -> ProviderExecutionOutcome:
        # Local import — same circular-import reason as NmapProvider.execute().
        from src.core.services.discovery_execution_command_service import create_command_for_provider_execution

        command = create_command_for_provider_execution(db, run, provider_execution)
        return ProviderExecutionOutcome(mode=ExecutionMode.DELEGATED.value, delegated_command_id=command.id)
