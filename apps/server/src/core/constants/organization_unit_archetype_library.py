"""Organisation Unit archetype library — suggests a starter set of
organisation units from an industry family + size band the user selects on
the Organisation Structure step, mirroring ``value_stream_library.py``'s
NACE-inference pattern for Business Processes.

Deliberately a simpler industry-family + size-band lookup rather than a
full NACE-code engine (per Søren's 2026-07-17 decision) — NACE codes are
precise but not something a user recognises on sight, and this step only
needs "roughly the right shape to start from," not a certified industry
classification. No I/O, no side effects — safe to call from any layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class OrganisationIndustryFamily(StrEnum):
    MANUFACTURING = "manufacturing"
    RETAIL = "retail"
    TECHNOLOGY = "technology"
    FINANCIAL_SERVICES = "financial_services"
    HEALTHCARE = "healthcare"
    PROFESSIONAL_SERVICES = "professional_services"
    OTHER = "other"


class OrganisationSizeBand(StrEnum):
    SMALL = "small"  # under ~50 employees
    MEDIUM = "medium"  # ~50-500 employees
    LARGE = "large"  # 500+ employees


_SIZE_BAND_ORDER: dict[OrganisationSizeBand, int] = {
    OrganisationSizeBand.SMALL: 0,
    OrganisationSizeBand.MEDIUM: 1,
    OrganisationSizeBand.LARGE: 2,
}


@dataclass(frozen=True)
class ArchetypeUnitSuggestion:
    name: str
    unit_type: str  # OrganizationUnitType value
    min_size_band: OrganisationSizeBand  # first size band this unit appears at


# Present for every industry once the org is at least this size — a very
# small organisation (under ~50 people) rarely has these as distinct units.
_UNIVERSAL_UNITS: list[ArchetypeUnitSuggestion] = [
    ArchetypeUnitSuggestion("Finance", "shared_service", OrganisationSizeBand.SMALL),
    ArchetypeUnitSuggestion("Technology", "shared_service", OrganisationSizeBand.SMALL),
    ArchetypeUnitSuggestion("People & Culture", "shared_service", OrganisationSizeBand.MEDIUM),
    ArchetypeUnitSuggestion("Risk & Compliance", "shared_service", OrganisationSizeBand.MEDIUM),
]

# Industry-specific units, ordered so that a smaller organisation gets the
# leading (most universally-true-for-that-industry) subset and a larger one
# gets the full, more granular list — the same "prefix by size" shape as the
# mock manufacturing company Søren tested with (680 employees → 15 units).
_INDUSTRY_UNITS: dict[OrganisationIndustryFamily, list[ArchetypeUnitSuggestion]] = {
    OrganisationIndustryFamily.MANUFACTURING: [
        ArchetypeUnitSuggestion("Production", "business_unit", OrganisationSizeBand.SMALL),
        ArchetypeUnitSuggestion("Sales and Customer Service", "department", OrganisationSizeBand.SMALL),
        ArchetypeUnitSuggestion("Supply Chain", "department", OrganisationSizeBand.MEDIUM),
        ArchetypeUnitSuggestion("Quality", "department", OrganisationSizeBand.MEDIUM),
        ArchetypeUnitSuggestion("Procurement", "department", OrganisationSizeBand.LARGE),
        ArchetypeUnitSuggestion("Warehousing", "department", OrganisationSizeBand.LARGE),
        ArchetypeUnitSuggestion("Distribution", "department", OrganisationSizeBand.LARGE),
        ArchetypeUnitSuggestion("Infrastructure", "department", OrganisationSizeBand.LARGE),
        ArchetypeUnitSuggestion("Business Applications", "department", OrganisationSizeBand.LARGE),
        ArchetypeUnitSuggestion("Cybersecurity", "department", OrganisationSizeBand.LARGE),
    ],
    OrganisationIndustryFamily.RETAIL: [
        ArchetypeUnitSuggestion("Store Operations", "business_unit", OrganisationSizeBand.SMALL),
        ArchetypeUnitSuggestion("Merchandising", "department", OrganisationSizeBand.SMALL),
        ArchetypeUnitSuggestion("E-commerce", "department", OrganisationSizeBand.MEDIUM),
        ArchetypeUnitSuggestion("Logistics", "department", OrganisationSizeBand.MEDIUM),
        ArchetypeUnitSuggestion("Regional Operations", "department", OrganisationSizeBand.LARGE),
        ArchetypeUnitSuggestion("Loss Prevention", "department", OrganisationSizeBand.LARGE),
        ArchetypeUnitSuggestion("Customer Experience", "department", OrganisationSizeBand.LARGE),
    ],
    OrganisationIndustryFamily.TECHNOLOGY: [
        ArchetypeUnitSuggestion("Engineering", "business_unit", OrganisationSizeBand.SMALL),
        ArchetypeUnitSuggestion("Product", "department", OrganisationSizeBand.SMALL),
        ArchetypeUnitSuggestion("Customer Success", "department", OrganisationSizeBand.MEDIUM),
        ArchetypeUnitSuggestion("DevOps and Platform", "department", OrganisationSizeBand.MEDIUM),
        ArchetypeUnitSuggestion("Security Engineering", "department", OrganisationSizeBand.LARGE),
        ArchetypeUnitSuggestion("Data and Analytics", "department", OrganisationSizeBand.LARGE),
        ArchetypeUnitSuggestion("Site Reliability", "department", OrganisationSizeBand.LARGE),
    ],
    OrganisationIndustryFamily.FINANCIAL_SERVICES: [
        ArchetypeUnitSuggestion("Retail Banking", "business_unit", OrganisationSizeBand.SMALL),
        ArchetypeUnitSuggestion("Operations", "department", OrganisationSizeBand.SMALL),
        ArchetypeUnitSuggestion("Treasury", "department", OrganisationSizeBand.MEDIUM),
        ArchetypeUnitSuggestion("Fraud Prevention", "department", OrganisationSizeBand.MEDIUM),
        ArchetypeUnitSuggestion("Trading and Markets", "department", OrganisationSizeBand.LARGE),
        ArchetypeUnitSuggestion("Regulatory Affairs", "department", OrganisationSizeBand.LARGE),
    ],
    OrganisationIndustryFamily.HEALTHCARE: [
        ArchetypeUnitSuggestion("Clinical Operations", "business_unit", OrganisationSizeBand.SMALL),
        ArchetypeUnitSuggestion("Patient Services", "department", OrganisationSizeBand.SMALL),
        ArchetypeUnitSuggestion("Medical Records", "department", OrganisationSizeBand.MEDIUM),
        ArchetypeUnitSuggestion("Regulatory Affairs", "department", OrganisationSizeBand.MEDIUM),
        ArchetypeUnitSuggestion("Pharmacy", "department", OrganisationSizeBand.LARGE),
        ArchetypeUnitSuggestion("Laboratory Services", "department", OrganisationSizeBand.LARGE),
        ArchetypeUnitSuggestion("Facilities and Biomedical Engineering", "department", OrganisationSizeBand.LARGE),
    ],
    OrganisationIndustryFamily.PROFESSIONAL_SERVICES: [
        ArchetypeUnitSuggestion("Client Delivery", "business_unit", OrganisationSizeBand.SMALL),
        ArchetypeUnitSuggestion("Business Development", "department", OrganisationSizeBand.SMALL),
        ArchetypeUnitSuggestion("Practice Management", "department", OrganisationSizeBand.MEDIUM),
        ArchetypeUnitSuggestion("Knowledge Management", "department", OrganisationSizeBand.LARGE),
        ArchetypeUnitSuggestion("Regional Offices", "department", OrganisationSizeBand.LARGE),
    ],
    OrganisationIndustryFamily.OTHER: [
        ArchetypeUnitSuggestion("Operations", "business_unit", OrganisationSizeBand.SMALL),
        ArchetypeUnitSuggestion("Sales", "department", OrganisationSizeBand.SMALL),
        ArchetypeUnitSuggestion("Customer Support", "department", OrganisationSizeBand.MEDIUM),
        ArchetypeUnitSuggestion("Regional Operations", "department", OrganisationSizeBand.LARGE),
    ],
}


def suggest_units_for_archetype(
    industry_family: OrganisationIndustryFamily,
    size_band: OrganisationSizeBand,
) -> list[ArchetypeUnitSuggestion]:
    """Return the ordered, deduplicated unit suggestions for a given
    industry family + size band. Always includes the size-appropriate
    universal units first, then the industry-specific ones."""
    size_rank = _SIZE_BAND_ORDER[size_band]

    def _applies(item: ArchetypeUnitSuggestion) -> bool:
        return _SIZE_BAND_ORDER[item.min_size_band] <= size_rank

    seen_names: set[str] = set()
    results: list[ArchetypeUnitSuggestion] = []
    for item in _UNIVERSAL_UNITS + _INDUSTRY_UNITS[industry_family]:
        if not _applies(item):
            continue
        if item.name in seen_names:
            continue
        seen_names.add(item.name)
        results.append(item)
    return results
