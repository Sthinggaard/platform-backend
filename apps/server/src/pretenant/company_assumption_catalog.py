from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AssumptionFocus:
    key: str
    title: str
    priority: str
    rationale: str


@dataclass(frozen=True)
class ContinuityAssumption:
    label: str
    description: str
    benchmark: str


@dataclass(frozen=True)
class CompanyArchetype:
    key: str
    label: str
    summary: str
    process_template_keys: tuple[str, ...]
    critical_process_template_keys: tuple[str, ...]
    focus_areas: tuple[AssumptionFocus, ...]
    continuity_assumption: ContinuityAssumption


SOFTWARE_ARCHETYPE = CompanyArchetype(
    key="software",
    label="Software and SaaS",
    summary="A digital product business where product delivery, customer data, and privileged access are likely central to operations.",
    process_template_keys=("software_delivery", "platform_operations", "quote_to_cash", "customer_service", "contract_to_renewal"),
    critical_process_template_keys=("software_delivery", "platform_operations"),
    focus_areas=(
        AssumptionFocus("identity_access", "Identity and access", "high", "Product and cloud operations typically depend on controlled privileged access."),
        AssumptionFocus("secure_development", "Secure development", "high", "Software delivery creates a need to protect code, build pipelines, and release paths."),
        AssumptionFocus("data_resilience", "Data and service resilience", "medium", "Customer-facing digital services require recoverable data and service continuity."),
    ),
    continuity_assumption=ContinuityAssumption(
        "Very low — availability supports delivery",
        "For a digital product business, service interruption can prevent customers from using what the organisation sells.",
        "Starting assumption from the software industry pattern; a human must confirm the acceptable downtime during setup.",
    ),
)

PROFESSIONAL_SERVICES_ARCHETYPE = CompanyArchetype(
    key="professional_services",
    label="Professional services",
    summary="A knowledge-led business where client information, collaboration, and supplier or partner access are likely important to delivery.",
    process_template_keys=("quote_to_cash", "contract_to_renewal", "customer_service", "record_to_report"),
    critical_process_template_keys=("quote_to_cash", "customer_service"),
    focus_areas=(
        AssumptionFocus("identity_access", "Identity and access", "high", "Client work and internal knowledge are commonly accessed through shared digital workspaces."),
        AssumptionFocus("data_protection", "Client data protection", "high", "Professional services often handle confidential information on behalf of clients."),
        AssumptionFocus("third_party_risk", "Third-party access", "medium", "Partners, contractors, and specialist suppliers may participate in client delivery."),
    ),
    continuity_assumption=ContinuityAssumption(
        "Low — client delivery depends on access",
        "Client work can be delayed when core collaboration and information services are unavailable.",
        "Starting assumption from the professional-services pattern; a human must confirm the acceptable downtime during setup.",
    ),
)

RETAIL_ARCHETYPE = CompanyArchetype(
    key="retail",
    label="Retail and commerce",
    summary="A commerce business where customer transactions, supplier dependencies, and operational availability are likely central to performance.",
    process_template_keys=("order_to_cash", "customer_acquisition", "customer_service", "procure_to_pay", "warehouse_to_delivery"),
    critical_process_template_keys=("order_to_cash", "warehouse_to_delivery"),
    focus_areas=(
        AssumptionFocus("identity_access", "Identity and access", "high", "Sales, fulfilment, and administration depend on reliable access across operational roles."),
        AssumptionFocus("payment_resilience", "Payment and transaction resilience", "high", "Interrupted transaction paths can directly stop revenue-generating activity."),
        AssumptionFocus("third_party_risk", "Supplier and platform dependencies", "medium", "Commerce operations commonly rely on suppliers, platforms, logistics, or payment partners."),
    ),
    continuity_assumption=ContinuityAssumption(
        "Low — transactions support revenue",
        "Interrupted payment, order, or fulfilment paths can stop sales and affect customer trust.",
        "Starting assumption from the commerce pattern; a human must confirm the acceptable downtime during setup.",
    ),
)

GENERAL_ARCHETYPE = CompanyArchetype(
    key="general_business",
    label="General business",
    summary="An initial company profile based on the available registry facts. The suggested focus areas are starting hypotheses to review.",
    process_template_keys=("identity_and_access", "security_incident_response", "hire_to_retire"),
    critical_process_template_keys=("identity_and_access", "security_incident_response"),
    focus_areas=(
        AssumptionFocus("identity_access", "Identity and access", "high", "Every organisation needs controlled access to its people, systems, and information."),
        AssumptionFocus("data_protection", "Data protection", "medium", "The organisation is likely to handle information that should be protected from loss or misuse."),
        AssumptionFocus("data_resilience", "Operational resilience", "medium", "Continuity of core operations is a useful first resilience hypothesis while more context is gathered."),
    ),
    continuity_assumption=ContinuityAssumption(
        "To be confirmed during setup",
        "The registry data does not establish how quickly the organisation must recover its core operations.",
        "No approved downtime tolerance exists yet; this must be decided by the organisation.",
    ),
)

_ARCHETYPE_BY_PREFIX: tuple[tuple[tuple[str, ...], CompanyArchetype], ...] = (
    (("58", "59", "60", "61", "62", "63"), SOFTWARE_ARCHETYPE),
    (("69", "70", "71", "72", "73", "74", "75"), PROFESSIONAL_SERVICES_ARCHETYPE),
    (("45", "46", "47"), RETAIL_ARCHETYPE),
)


def resolve_company_archetype(industry_code: str | None) -> CompanyArchetype:
    normalized = (industry_code or "").strip()
    for prefixes, archetype in _ARCHETYPE_BY_PREFIX:
        if normalized.startswith(prefixes):
            return archetype
    return GENERAL_ARCHETYPE
