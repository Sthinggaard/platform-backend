"""Canonical service-first runtime constants for Risklence.

Business services are the primary runtime object. The CMDB is the validated set
of supporting assets around those services, not a generic infrastructure list.
"""

from __future__ import annotations

from enum import StrEnum


class ServiceTier(StrEnum):
    """The only persisted vocabulary for BusinessService.tier.

    A service tier is a BIA-derived classification. It is not an asset,
    scanner, or UI-local label, so every writer and downstream calculation must
    consume this one vocabulary.
    """

    MISSION_CRITICAL = "Mission Critical"
    BUSINESS_CRITICAL = "Business Critical"
    STANDARD_CRITICAL = "Standard Critical"


SERVICE_TIER_MISSION_CRITICAL = ServiceTier.MISSION_CRITICAL
SERVICE_TIER_BUSINESS_CRITICAL = ServiceTier.BUSINESS_CRITICAL
SERVICE_TIER_STANDARD_CRITICAL = ServiceTier.STANDARD_CRITICAL

DEFAULT_SERVICE_TIER = SERVICE_TIER_BUSINESS_CRITICAL

SERVICE_TIERS = (
    SERVICE_TIER_MISSION_CRITICAL,
    SERVICE_TIER_BUSINESS_CRITICAL,
    SERVICE_TIER_STANDARD_CRITICAL,
)

# Known historical stored values. These are read compatibility only; writes are
# constrained to SERVICE_TIERS and the migration repairs persisted rows.
LEGACY_SERVICE_TIER_VALUES: dict[str, ServiceTier] = {
    "mission-critical": ServiceTier.MISSION_CRITICAL,
    "business-critical": ServiceTier.BUSINESS_CRITICAL,
    "standard-critical": ServiceTier.STANDARD_CRITICAL,
    "Operational": ServiceTier.STANDARD_CRITICAL,
    "operational": ServiceTier.STANDARD_CRITICAL,
}

SERVICE_TIER_SQL_CHECK_CONSTRAINT = "ck_business_services_tier"
SERVICE_TIER_SQL_CHECK = "tier IN ({})".format(
    ", ".join(f"'{tier}'" for tier in SERVICE_TIERS)
)

SERVICE_TIER_PATTERN = (
    rf"^({'|'.join(SERVICE_TIERS)})$"
)

SERVICE_TIER_DEFINITIONS = {
    SERVICE_TIER_MISSION_CRITICAL: (
        "Immediate customer, regulatory, or revenue harm if disrupted."
    ),
    SERVICE_TIER_BUSINESS_CRITICAL: (
        "Material business disruption within tolerance windows; fast recovery and governance required."
    ),
    SERVICE_TIER_STANDARD_CRITICAL: (
        "Important supporting capability that still matters to resilience, but sits within normal operating tolerance."
    ),
}

SERVICE_TIER_DEFAULT_FINANCIAL_EXPOSURE: dict[ServiceTier, int] = {
    ServiceTier.MISSION_CRITICAL: 3_200_000,
    ServiceTier.BUSINESS_CRITICAL: 1_800_000,
    ServiceTier.STANDARD_CRITICAL: 900_000,
}


def normalize_service_tier(value: str | None) -> ServiceTier | None:
    """Return a canonical tier for a known current or historical value.

    This guards read calculations during rollout. It deliberately does not
    guess at arbitrary casing or punctuation: unknown classifications must be
    repaired through governed data migration rather than treated as safe.
    """

    if value is None:
        return None
    try:
        return ServiceTier(value)
    except ValueError:
        return LEGACY_SERVICE_TIER_VALUES.get(value)

CMDB_SUPPORT_LEVELS = ("l1", "l2", "l3")

CMDB_SUPPORT_LEVEL_DEFINITIONS = {
    "l1": "Primary business-critical supporting assets directly required for the service to operate.",
    "l2": "Secondary direct dependencies that the primary assets rely on.",
    "l3": "Supplier and external dependencies that sit behind the direct stack.",
}

CMDB_DEFINITION = (
    "Risklence CMDB is the curated set of business-critical supporting assets declared "
    "and validated through onboarding and runtime review. It is not a generic technical inventory."
)
