"""Step 4.2 Part 2 — the DiscoveryProvider registry.

Mirrors organization_registry_provider.py's exact shape (a Protocol,
concrete implementations, a dict-keyed registry, a resolver function
raising a typed error on no match) rather than inventing a new pattern —
see TASKS.md DISC-17/DISC-20 and this repo's Protocol-based provider
convention (organization_registry_provider.py, provider_adapters.py,
discovery_normalization_service.py's CollectorOutputAdapter).

Adding a new provider means adding one new class + one registry entry here
— the plan generator and DAG runner never branch on provider identity.
Shared types live in ``base.py`` (not here) to avoid a circular import
between this registry and the concrete provider modules it imports.
"""

from __future__ import annotations

from src.core.services.discovery_providers.base import (
    DiscoveryProvider,
    ProviderCapabilities,
    ProviderExecutionOutcome,
    ProviderExecutionResult,
    ProviderNotRegisteredError,
)
from src.core.services.discovery_providers.nmap_provider import NmapProvider
from src.core.services.discovery_providers.nuclei_provider import NucleiProvider
from src.core.services.discovery_providers.subfinder_provider import SubfinderProvider

_PROVIDERS_BY_ID: dict[str, DiscoveryProvider] = {
    NmapProvider.provider_id: NmapProvider(),
    SubfinderProvider.provider_id: SubfinderProvider(),
    NucleiProvider.provider_id: NucleiProvider(),
}


def get_provider(provider_id: str) -> DiscoveryProvider:
    provider = _PROVIDERS_BY_ID.get(provider_id)
    if provider is None:
        raise ProviderNotRegisteredError(provider_id)
    return provider


def get_registered_providers() -> tuple[DiscoveryProvider, ...]:
    return tuple(_PROVIDERS_BY_ID.values())


__all__ = [
    "ProviderCapabilities",
    "ProviderExecutionResult",
    "ProviderExecutionOutcome",
    "DiscoveryProvider",
    "ProviderNotRegisteredError",
    "get_provider",
    "get_registered_providers",
]
