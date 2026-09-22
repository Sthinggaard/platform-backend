"""Organisation registry provider abstraction (Step 1 spec §4).

``organization_identity_service.run_registry_lookup`` depends only on
``OrganisationRegistryProvider`` — never on a concrete registry client — so
no single country's registry is hard-coded into core organisation-identity
logic. A small country-keyed factory selects the concrete provider; today
only Denmark (CVR, via the existing ``CvrEnrichmentClient``) has a real
implementation. Requesting an unsupported country now fails explicitly
(``RegistryProviderNotSupportedError``) instead of the previous behaviour,
where ``registration_country`` was accepted but never actually used to pick
a provider — every lookup silently went to CVR regardless of the country
the user selected.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from src.pretenant.enrichment import (
    CvrEnrichmentClient,
    CvrEnrichmentResult,
    CvrNotFoundError,
    CvrTimeoutError,
)


class RegistryProviderNotFoundError(Exception):
    """Raised when the registry has no record for the given number."""


class RegistryProviderUnavailableError(Exception):
    """Raised when the upstream registry provider times out or errors."""


class RegistryProviderNotSupportedError(Exception):
    """Raised when no provider is configured for the requested country."""


class RegistryProviderInactiveError(Exception):
    """Raised when a registry record is no longer active."""


@dataclass(frozen=True)
class RegistryLookupResult:
    reference: str
    legal_name: str
    legal_form: str | None
    industry_code: str | None
    address: str | None
    postal_code: str | None
    city: str | None
    country: str
    observed_at: datetime


class RegistryProviderMultipleMatchesError(Exception):
    """Raised when a registry cannot identify one unambiguous company."""

    def __init__(self, candidates: list[RegistryLookupResult]) -> None:
        super().__init__("More than one registry match was found.")
        self.candidates = candidates


class OrganisationRegistryProvider(Protocol):
    def lookup(self, registration_number: str) -> RegistryLookupResult:
        ...


class CvrRegistryProvider:
    """Denmark's CVR registry — adapts the existing, already provider-
    agnostic-shaped ``CvrEnrichmentClient`` to this interface."""

    def __init__(self, client: CvrEnrichmentClient | None = None) -> None:
        self._client = client or CvrEnrichmentClient()

    def lookup(self, registration_number: str) -> RegistryLookupResult:
        try:
            result: CvrEnrichmentResult = self._client.enrich(registration_number)
        except CvrNotFoundError as exc:
            raise RegistryProviderNotFoundError(str(exc)) from exc
        except CvrTimeoutError as exc:
            raise RegistryProviderUnavailableError(str(exc)) from exc
        return RegistryLookupResult(
            reference=result.cvr,
            legal_name=result.legal_name,
            legal_form=result.trade_name,
            industry_code=result.industry_code,
            address=result.address,
            postal_code=result.postal_code,
            city=result.city,
            country=result.country,
            observed_at=result.enriched_at,
        )


class MockRegistryProvider:
    """Deterministic dev/test/seed-fixture provider — no network call, no
    stub-mode env vars to configure. A fixed sentinel number reproduces the
    not-found path; any other well-formed number returns a fixed result."""

    NOT_FOUND_SENTINEL = "00000000"
    MULTIPLE_MATCHES_SENTINEL = "99999999"
    INACTIVE_SENTINEL = "88888888"
    UNAVAILABLE_SENTINEL = "77777777"

    def lookup(self, registration_number: str) -> RegistryLookupResult:
        if registration_number == self.NOT_FOUND_SENTINEL:
            raise RegistryProviderNotFoundError("No registry match was found.")
        if registration_number == self.MULTIPLE_MATCHES_SENTINEL:
            observed_at = datetime.now()
            raise RegistryProviderMultipleMatchesError(
                [
                    RegistryLookupResult(
                        reference="99999990",
                        legal_name="Mock Group Denmark ApS",
                        legal_form="ApS",
                        industry_code="62.01",
                        address="1 Mock Street",
                        postal_code="00000",
                        city="Mockville",
                        country="DK",
                        observed_at=observed_at,
                    ),
                    RegistryLookupResult(
                        reference="99999991",
                        legal_name="Mock Group Services ApS",
                        legal_form="ApS",
                        industry_code="62.02",
                        address="2 Mock Street",
                        postal_code="00000",
                        city="Mockville",
                        country="DK",
                        observed_at=observed_at,
                    ),
                ]
            )
        if registration_number == self.INACTIVE_SENTINEL:
            raise RegistryProviderInactiveError("The registry record is inactive.")
        if registration_number == self.UNAVAILABLE_SENTINEL:
            raise RegistryProviderUnavailableError(
                "The registry service is temporarily unavailable."
            )
        return RegistryLookupResult(
            reference=registration_number,
            legal_name=f"Mock Registered Company {registration_number}",
            legal_form="Mock Ltd",
            industry_code="00.00",
            address="1 Mock Street",
            postal_code="00000",
            city="Mockville",
            country="ZZ",
            observed_at=datetime.now(),
        )


_PROVIDERS_BY_COUNTRY: dict[str, type[CvrRegistryProvider]] = {
    "DK": CvrRegistryProvider,
}


def get_registry_provider_for_country(registration_country: str) -> OrganisationRegistryProvider:
    provider_cls = _PROVIDERS_BY_COUNTRY.get(registration_country.strip().upper())
    if provider_cls is None:
        raise RegistryProviderNotSupportedError(
            f"No registry provider is configured for country {registration_country}."
        )
    return provider_cls()
