"""#460 — the resilience answers an owner gives about one dependency.

They used to live only on bundle nodes, written by the service setup page, and were validated
inline in `bundle_common.py` as string literals. Since #460 (Søren, 2026-09-15) they live on
the service's slot record, the one live record of a dependency decision, so their allowed
values are defined once here and read by the model, the write path and the migration docs.

Not DB-level enums: validated in the service layer, matching `slot_instances`' own
String-not-Enum precedent for `mapping_status` and `provenance`.
"""

from enum import StrEnum


class FallbackStatus(StrEnum):
    """Whether something can take over when the dependency is unavailable."""

    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"


class DependencyImpactType(StrEnum):
    """What a failure of the dependency does to the service."""

    AVAILABILITY = "availability"
    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    COMBINED = "combined"


class DependencyImpactLevel(StrEnum):
    """How much a failure of the dependency matters to the service."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DependencyBusinessChoice(StrEnum):
    """The owner's plain-language answer from which the impact type is derived."""

    SERVICE_STOPS = "service_stops"
    SERVICE_DEGRADED = "service_degraded"
    DATA_EXPOSED = "data_exposed"
    RECORDS_INCORRECT = "records_incorrect"
    COMBINED = "combined"


#: The impact type each business choice implies. A lookup, not an if-chain
#: (AGENTS.md §3.1), so a choice and its classification cannot drift apart.
IMPACT_TYPE_BY_BUSINESS_CHOICE: dict[DependencyBusinessChoice, DependencyImpactType] = {
    DependencyBusinessChoice.SERVICE_STOPS: DependencyImpactType.AVAILABILITY,
    DependencyBusinessChoice.SERVICE_DEGRADED: DependencyImpactType.AVAILABILITY,
    DependencyBusinessChoice.DATA_EXPOSED: DependencyImpactType.CONFIDENTIALITY,
    DependencyBusinessChoice.RECORDS_INCORRECT: DependencyImpactType.INTEGRITY,
    DependencyBusinessChoice.COMBINED: DependencyImpactType.COMBINED,
}
