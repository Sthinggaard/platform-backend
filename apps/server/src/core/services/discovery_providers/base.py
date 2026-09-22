"""Step 4.2 Part 2 — shared provider-abstraction types.

Split out from ``discovery_providers/__init__.py`` purely to avoid a
circular import: the registry (``__init__.py``) needs to import each
concrete provider module (e.g. ``nmap_provider.py``), and each concrete
provider module needs these shared types — putting them in the package
``__init__`` itself would make that a cycle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from sqlalchemy.orm import Session

from src.core.model_defs.discovery_execution import ProviderExecution
from src.core.model_defs.discovery_run import DiscoveryRun


@dataclass(frozen=True)
class ProviderCapabilities:
    provider_id: str
    execution_mode: str  # ExecutionMode value
    supported_discovery_stages: frozenset[str]
    supported_auth_mechanisms: frozenset[str] = frozenset()
    execution_requirements: dict = field(default_factory=dict)
    dependency_requirements: dict = field(default_factory=dict)
    timeout_recommendation_seconds: int = 300
    retry_recommendation: dict = field(default_factory=lambda: {"maxAttempts": 3, "backoffSeconds": 30})
    estimated_execution_characteristics: dict = field(default_factory=dict)
    # CA-09V — whether this provider's command should carry the hosts discovery
    # already found rather than the approved scope itself. A declared capability
    # rather than a branch on provider_id, so the target resolver keeps the
    # registry's own rule: nothing outside this package decides what a provider
    # is by name. Defaults False — a discovery provider's whole job is to find
    # what is not yet known, and narrowing it to what is known would make it
    # incapable of discovering anything.
    targets_discovered_hosts: bool = False


@dataclass(frozen=True)
class ProviderExecutionResult:
    """Populated only for a DIRECT provider's outcome."""

    status: str  # ProviderExecutionStatus value
    checkpoint: dict | None = None
    failure_code: str | None = None
    failure_message: str | None = None


@dataclass(frozen=True)
class ProviderExecutionOutcome:
    """What one call to a provider's execute() produced. mode mirrors the
    provider's own declared ExecutionMode. DIRECT: `result` is populated
    immediately. DELEGATED: `delegated_command_id` is populated instead —
    the caller must not treat the job as finished."""

    mode: str  # ExecutionMode value
    result: ProviderExecutionResult | None = None
    delegated_command_id: str | None = None


class DiscoveryProvider(Protocol):
    provider_id: str

    def capabilities(self) -> ProviderCapabilities: ...

    def execute(
        self, db: Session, *, run: DiscoveryRun, provider_execution: ProviderExecution
    ) -> ProviderExecutionOutcome: ...


class ProviderNotRegisteredError(ValueError):
    pass
