"""
Canonical Value Stream Library and NACE inference engine.

Two responsibilities:
  1. VALUE_STREAM_LIBRARY — the 27-stream canonical library seeded from the
     product spec. Imported by API routes and onboarding flows.
  2. infer_value_streams_from_nace() — pure function that maps a NACE code
     and company attributes to a prioritised list of InferredValueStream items.
     No I/O, no side effects — safe to call from any layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from src.core.constants.process_template_variant_enums import ProcessBusinessOutcomeKey

# ---------------------------------------------------------------------------
# Canonical library
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ValueStreamLibraryItem:
    key: str
    name: str
    description: str
    process_family: str  # universal | customer_revenue | supply_chain | finance_compliance | industry_specific
    business_outcome_key: ProcessBusinessOutcomeKey
    template_version: int = 1
    is_active: bool = True
    core_service_keys: list[str] = field(default_factory=list)
    typical_industries: list[str] = field(default_factory=list)  # NACE range strings e.g. "64-66"


VALUE_STREAM_LIBRARY: list[ValueStreamLibraryItem] = [
    # ------------------------------------------------------------------
    # Universal — every organisation
    # ------------------------------------------------------------------
    ValueStreamLibraryItem(
        key="identity_and_access",
        name="Identity & Access",
        description="Controls who can access what across the organisation",
        process_family="universal",
        business_outcome_key=ProcessBusinessOutcomeKey.IDENTITY_ACCESS_GOVERNANCE,
        core_service_keys=["identity_service", "sso_service", "privileged_access"],
    ),
    ValueStreamLibraryItem(
        key="security_incident_response",
        name="Security Incident Response",
        description="Detects, responds to, and recovers from security incidents",
        process_family="universal",
        business_outcome_key=ProcessBusinessOutcomeKey.SECURITY_INCIDENT_RESPONSE,
        core_service_keys=["siem_service", "incident_management", "vulnerability_management"],
    ),
    ValueStreamLibraryItem(
        key="hire_to_retire",
        name="Hire to Retire",
        description="Manages the full employee lifecycle from recruitment to exit",
        process_family="universal",
        business_outcome_key=ProcessBusinessOutcomeKey.WORKFORCE_LIFECYCLE,
        core_service_keys=["hr_system", "payroll_service", "onboarding_service"],
    ),

    # ------------------------------------------------------------------
    # Customer & Revenue
    # ------------------------------------------------------------------
    ValueStreamLibraryItem(
        key="order_to_cash",
        name="Order to Cash",
        description="Processes customer orders through to payment collection",
        process_family="customer_revenue",
        business_outcome_key=ProcessBusinessOutcomeKey.CUSTOMER_REVENUE_TO_CASH,
        core_service_keys=["order_management", "billing_service", "payment_processing"],
        typical_industries=["45-47", "10-33", "55-56"],
    ),
    ValueStreamLibraryItem(
        key="quote_to_cash",
        name="Quote to Cash",
        description="Converts sales opportunities into revenue",
        process_family="customer_revenue",
        business_outcome_key=ProcessBusinessOutcomeKey.CUSTOMER_REVENUE_TO_CASH,
        core_service_keys=["crm_service", "quoting_service", "contract_management", "billing_service"],
        typical_industries=["58-63", "69-75", "45-47"],
    ),
    ValueStreamLibraryItem(
        key="apply_to_approve",
        name="Apply to Approve",
        description="Processes customer applications through to approval decisions",
        process_family="customer_revenue",
        business_outcome_key=ProcessBusinessOutcomeKey.APPLICATION_TO_APPROVAL,
        core_service_keys=["application_service", "decisioning_engine", "notification_service"],
        typical_industries=["64-66", "65", "84"],
    ),
    ValueStreamLibraryItem(
        key="contract_to_renewal",
        name="Contract to Renewal",
        description="Manages customer contracts from signing through to renewal",
        process_family="customer_revenue",
        business_outcome_key=ProcessBusinessOutcomeKey.CONTRACT_RENEWAL,
        core_service_keys=["contract_management", "billing_service", "crm_service"],
        typical_industries=["58-63", "69-75"],
    ),
    ValueStreamLibraryItem(
        key="customer_acquisition",
        name="Customer Acquisition",
        description="Attracts and converts new customers",
        process_family="customer_revenue",
        business_outcome_key=ProcessBusinessOutcomeKey.CUSTOMER_ACQUISITION,
        core_service_keys=["marketing_platform", "web_channel", "lead_management"],
        typical_industries=["45-47", "58-63", "64-66"],
    ),
    ValueStreamLibraryItem(
        key="customer_service",
        name="Customer Service",
        description="Handles customer queries, complaints, and support",
        process_family="customer_revenue",
        business_outcome_key=ProcessBusinessOutcomeKey.CUSTOMER_SUPPORT,
        core_service_keys=["helpdesk_service", "crm_service", "knowledge_base"],
        typical_industries=["45-47", "55-56", "58-63"],
    ),

    # ------------------------------------------------------------------
    # Supply Chain
    # ------------------------------------------------------------------
    ValueStreamLibraryItem(
        key="procure_to_pay",
        name="Procure to Pay",
        description="Manages procurement from purchase order to supplier payment",
        process_family="supply_chain",
        business_outcome_key=ProcessBusinessOutcomeKey.PROCUREMENT_TO_PAYMENT,
        core_service_keys=["procurement_system", "accounts_payable", "inventory_service"],
        typical_industries=["10-33", "45-47", "49-53"],
    ),
    ValueStreamLibraryItem(
        key="plan_to_produce",
        name="Plan to Produce",
        description="Plans and executes production or service delivery",
        process_family="supply_chain",
        business_outcome_key=ProcessBusinessOutcomeKey.DELIVERY_PLANNING,
        core_service_keys=["erp_service", "production_planning", "quality_management"],
        typical_industries=["10-33"],
    ),
    ValueStreamLibraryItem(
        key="warehouse_to_delivery",
        name="Warehouse to Delivery",
        description="Manages inventory through to customer delivery",
        process_family="supply_chain",
        business_outcome_key=ProcessBusinessOutcomeKey.WAREHOUSE_TO_DELIVERY,
        core_service_keys=["warehouse_management", "transport_management", "tracking_service"],
        typical_industries=["10-33", "45-47", "49-53"],
    ),

    # ------------------------------------------------------------------
    # Finance & Compliance
    # ------------------------------------------------------------------
    ValueStreamLibraryItem(
        key="record_to_report",
        name="Record to Report",
        description="Captures financial transactions and produces management reports",
        process_family="finance_compliance",
        business_outcome_key=ProcessBusinessOutcomeKey.FINANCIAL_REPORTING,
        core_service_keys=["finance_system", "reporting_service", "data_warehouse"],
        typical_industries=["64-66", "69-75", "84"],
    ),
    ValueStreamLibraryItem(
        key="close_to_disclose",
        name="Close to Disclose",
        description="Performs period-end close and produces statutory disclosures",
        process_family="finance_compliance",
        business_outcome_key=ProcessBusinessOutcomeKey.FINANCIAL_REPORTING,
        core_service_keys=["finance_system", "consolidation_service", "regulatory_reporting"],
        typical_industries=["64-66", "84"],
    ),
    ValueStreamLibraryItem(
        key="risk_to_mitigate",
        name="Risk to Mitigate",
        description="Identifies, assesses, and manages organisational risk",
        process_family="finance_compliance",
        business_outcome_key=ProcessBusinessOutcomeKey.RISK_MITIGATION,
        core_service_keys=["risk_platform", "compliance_service", "audit_service"],
        typical_industries=["64-66", "84", "86-88"],
    ),
    ValueStreamLibraryItem(
        key="grant_to_report",
        name="Grant to Report",
        description="Manages grant funding from application through to reporting",
        process_family="finance_compliance",
        business_outcome_key=ProcessBusinessOutcomeKey.GRANT_REPORTING,
        core_service_keys=["grant_management", "finance_system", "reporting_service"],
        typical_industries=["84", "85", "88-90"],
    ),

    # ------------------------------------------------------------------
    # Industry Specific — Healthcare
    # ------------------------------------------------------------------
    ValueStreamLibraryItem(
        key="patient_to_discharge",
        name="Patient to Discharge",
        description="Manages patient care from admission through to discharge",
        process_family="industry_specific",
        business_outcome_key=ProcessBusinessOutcomeKey.PATIENT_DISCHARGE,
        core_service_keys=["patient_records", "clinical_system", "pharmacy_service", "scheduling_service"],
        typical_industries=["86", "87", "88"],
    ),

    # ------------------------------------------------------------------
    # Industry Specific — IT / SaaS
    # ------------------------------------------------------------------
    ValueStreamLibraryItem(
        key="software_delivery",
        name="Software Delivery",
        description="Delivers software changes from development to production",
        process_family="industry_specific",
        business_outcome_key=ProcessBusinessOutcomeKey.SOFTWARE_DELIVERY,
        core_service_keys=["ci_cd_pipeline", "source_control", "deployment_service", "monitoring_service"],
        typical_industries=["58-63"],
    ),
    ValueStreamLibraryItem(
        key="platform_operations",
        name="Platform Operations",
        description="Keeps the production platform available and performant",
        process_family="industry_specific",
        business_outcome_key=ProcessBusinessOutcomeKey.PLATFORM_OPERATIONS,
        core_service_keys=["infrastructure_service", "monitoring_service", "incident_management"],
        typical_industries=["58-63"],
    ),
    ValueStreamLibraryItem(
        key="data_operations",
        name="Data Operations",
        description="Ingests, processes, and serves data products",
        process_family="industry_specific",
        business_outcome_key=ProcessBusinessOutcomeKey.DATA_OPERATIONS,
        core_service_keys=["data_pipeline", "data_warehouse", "reporting_service"],
        typical_industries=["58-63", "69-75"],
    ),

    # ------------------------------------------------------------------
    # Industry Specific — Financial Services
    # ------------------------------------------------------------------
    ValueStreamLibraryItem(
        key="trade_to_settle",
        name="Trade to Settle",
        description="Executes and settles financial trades",
        process_family="industry_specific",
        business_outcome_key=ProcessBusinessOutcomeKey.TRADE_SETTLEMENT,
        core_service_keys=["trading_platform", "settlement_service", "custody_service"],
        typical_industries=["64", "65", "66"],
    ),
    ValueStreamLibraryItem(
        key="loan_origination",
        name="Loan Origination",
        description="Processes loan applications from submission to disbursement",
        process_family="industry_specific",
        business_outcome_key=ProcessBusinessOutcomeKey.APPLICATION_TO_APPROVAL,
        core_service_keys=["application_service", "decisioning_engine", "core_banking"],
        typical_industries=["64", "65"],
    ),

    # ------------------------------------------------------------------
    # Industry Specific — Public Sector / Education
    # ------------------------------------------------------------------
    ValueStreamLibraryItem(
        key="citizen_service_delivery",
        name="Citizen Service Delivery",
        description="Delivers public services to citizens",
        process_family="industry_specific",
        business_outcome_key=ProcessBusinessOutcomeKey.CITIZEN_SERVICE_DELIVERY,
        core_service_keys=["citizen_portal", "case_management", "identity_service"],
        typical_industries=["84", "85"],
    ),
    ValueStreamLibraryItem(
        key="regulatory_reporting",
        name="Regulatory Reporting",
        description="Prepares and submits mandatory regulatory reports",
        process_family="industry_specific",
        business_outcome_key=ProcessBusinessOutcomeKey.REGULATORY_REPORTING,
        core_service_keys=["regulatory_reporting", "data_warehouse", "compliance_service"],
        typical_industries=["64-66", "84", "86-88"],
    ),

    # ------------------------------------------------------------------
    # Industry Specific — Hospitality / F&B
    # ------------------------------------------------------------------
    ValueStreamLibraryItem(
        key="reservation_to_checkout",
        name="Reservation to Checkout",
        description="Manages bookings from reservation through to guest checkout",
        process_family="industry_specific",
        business_outcome_key=ProcessBusinessOutcomeKey.RESERVATION_TO_CHECKOUT,
        core_service_keys=["booking_system", "pms_service", "payment_processing"],
        typical_industries=["55", "56"],
    ),

    # ------------------------------------------------------------------
    # Industry Specific — Logistics / Transport
    # ------------------------------------------------------------------
    ValueStreamLibraryItem(
        key="shipment_to_delivery",
        name="Shipment to Delivery",
        description="Tracks shipments from dispatch to confirmed delivery",
        process_family="industry_specific",
        business_outcome_key=ProcessBusinessOutcomeKey.SHIPMENT_TO_DELIVERY,
        core_service_keys=["tms_service", "tracking_service", "notification_service"],
        typical_industries=["49", "50", "51", "52", "53"],
    ),
]

# Fast lookup by key
VALUE_STREAM_BY_KEY: dict[str, ValueStreamLibraryItem] = {
    vs.key: vs for vs in VALUE_STREAM_LIBRARY
}

# Universal streams are always included regardless of NACE
UNIVERSAL_STREAM_KEYS: set[str] = {
    "identity_and_access",
    "security_incident_response",
    "hire_to_retire",
}

# Revenue-generating streams — always critical when present
REVENUE_STREAM_KEYS: set[str] = {
    "order_to_cash",
    "quote_to_cash",
    "apply_to_approve",
    "contract_to_renewal",
}


# ---------------------------------------------------------------------------
# Inference result type
# ---------------------------------------------------------------------------

@dataclass
class InferredValueStream:
    key: str
    name: str
    confidence: Literal["high", "medium", "low"]
    inference_reason: str
    suggested_priority: Literal["critical", "important", "standard"]
    source: Literal["inferred"] = "inferred"


# ---------------------------------------------------------------------------
# NACE → value stream inference rules
# ---------------------------------------------------------------------------

def _nace_to_int_range(nace_code: str) -> int | None:
    """Parse first numeric segment from a NACE code like '64.19' → 64."""
    try:
        return int(nace_code.split(".")[0].strip())
    except (ValueError, AttributeError):
        return None


def _in_range(code_int: int, range_str: str) -> bool:
    """Check whether code_int falls within a range string like '64-66' or '64'."""
    parts = range_str.split("-")
    try:
        if len(parts) == 1:
            return code_int == int(parts[0])
        return int(parts[0]) <= code_int <= int(parts[1])
    except ValueError:
        return False


def is_nace_match(nace_code: str | None, typical_industries: list[str]) -> bool:
    """Return whether a registered NACE code directly matches a template."""
    nace_number = _nace_to_int_range(nace_code or "")
    return nace_number is not None and any(_in_range(nace_number, industry) for industry in typical_industries)


def infer_value_streams_from_nace(
    nace_code: str,
    company_form: str = "",
    company_size: str = "",
) -> list[InferredValueStream]:
    """Return a ranked list of InferredValueStream for the given company profile.

    Args:
        nace_code: NACE Rev. 2 code, e.g. "64.19" or "47".
        company_form: Legal form string, e.g. "A/S", "ApS", "Forening".
        company_size: Size band, e.g. "micro", "small", "medium", "large", "enterprise".

    Returns:
        List of InferredValueStream, ordered by descending confidence then name.
        Always includes universal streams.
    """
    code_int = _nace_to_int_range(nace_code)
    results: dict[str, InferredValueStream] = {}

    def _add(key: str, confidence: Literal["high", "medium", "low"], reason: str,
             priority: Literal["critical", "important", "standard"]) -> None:
        if key in results:
            # Upgrade confidence if we already have it from another rule
            order = {"high": 0, "medium": 1, "low": 2}
            if order[confidence] < order[results[key].confidence]:
                results[key] = InferredValueStream(
                    key=key,
                    name=VALUE_STREAM_BY_KEY[key].name,
                    confidence=confidence,
                    inference_reason=reason,
                    suggested_priority=priority,
                )
        else:
            results[key] = InferredValueStream(
                key=key,
                name=VALUE_STREAM_BY_KEY[key].name,
                confidence=confidence,
                inference_reason=reason,
                suggested_priority=priority,
            )

    # 1. Universal streams — always included
    _add("identity_and_access", "high", "Required by all organisations", "important")
    _add("security_incident_response", "high", "Required by all organisations", "important")
    _add("hire_to_retire", "medium", "Standard for all organisations with employees", "standard")

    if code_int is None:
        # Can't infer further without a valid NACE code
        return sorted(results.values(), key=lambda x: ({"high": 0, "medium": 1, "low": 2}[x.confidence], x.name))

    # 2. Retail & wholesale (45-47)
    if _in_range(code_int, "45-47"):
        _add("order_to_cash", "high", "Core revenue process for retail/wholesale", "critical")
        _add("customer_acquisition", "high", "Customer-facing revenue driver", "critical")
        _add("customer_service", "medium", "Operational for retail/wholesale", "important")
        _add("procure_to_pay", "high", "Inventory and supplier management", "important")
        _add("warehouse_to_delivery", "medium", "Fulfilment process", "important")
        _add("record_to_report", "medium", "Financial management", "standard")

    # 3. Transport & logistics (49-53)
    if _in_range(code_int, "49-53"):
        _add("shipment_to_delivery", "high", "Core operational process for logistics", "critical")
        _add("order_to_cash", "high", "Revenue collection", "critical")
        _add("procure_to_pay", "medium", "Fleet and asset procurement", "important")
        _add("customer_service", "medium", "Operational for logistics", "standard")

    # 4. Hospitality & F&B (55-56)
    if _in_range(code_int, "55-56"):
        _add("reservation_to_checkout", "high", "Core revenue process for hospitality", "critical")
        _add("order_to_cash", "high", "Revenue collection", "critical")
        _add("customer_service", "medium", "Guest experience", "important")

    # 5. IT / SaaS / Media (58-63)
    if _in_range(code_int, "58-63"):
        _add("software_delivery", "high", "Core delivery process for technology companies", "critical")
        _add("platform_operations", "high", "Production availability is critical for SaaS", "critical")
        _add("quote_to_cash", "high", "Subscription/contract revenue", "critical")
        _add("data_operations", "medium", "Data products often core for tech companies", "important")
        _add("customer_service", "medium", "Operational for SaaS", "important")
        _add("contract_to_renewal", "medium", "Recurring revenue management", "important")

    # 6. Financial services — banks (64)
    if _in_range(code_int, "64"):
        _add("apply_to_approve", "high", "Core lending/account opening process", "critical")
        _add("order_to_cash", "high", "Payment and collection processing", "critical")
        _add("record_to_report", "high", "Regulatory financial reporting", "critical")
        _add("close_to_disclose", "high", "Statutory reporting obligation", "critical")
        _add("risk_to_mitigate", "high", "Risk management is core for banks", "critical")
        _add("trade_to_settle", "medium", "Trading and settlement if applicable", "important")
        _add("loan_origination", "medium", "Loan processing", "important")
        _add("regulatory_reporting", "high", "Mandatory regulatory submissions", "critical")

    # 7. Insurance (65)
    if _in_range(code_int, "65"):
        _add("apply_to_approve", "high", "Policy application and underwriting", "critical")
        _add("order_to_cash", "high", "Premium collection", "critical")
        _add("record_to_report", "high", "Financial reporting", "critical")
        _add("close_to_disclose", "high", "Statutory reporting", "critical")
        _add("risk_to_mitigate", "high", "Core insurance risk management", "critical")
        _add("regulatory_reporting", "high", "Solvency and regulatory reporting", "critical")

    # 8. Financial services — other (66)
    if _in_range(code_int, "66"):
        _add("record_to_report", "high", "Financial reporting", "critical")
        _add("risk_to_mitigate", "high", "Risk management", "critical")
        _add("trade_to_settle", "medium", "Settlement activities", "important")
        _add("regulatory_reporting", "medium", "Regulatory submissions", "important")

    # 9. Professional services (69-75)
    if _in_range(code_int, "69-75"):
        _add("quote_to_cash", "high", "Revenue collection for professional services", "critical")
        _add("contract_to_renewal", "medium", "Client contract management", "important")
        _add("record_to_report", "medium", "Financial management", "important")

    # 10. Public sector (84)
    if _in_range(code_int, "84"):
        _add("citizen_service_delivery", "high", "Primary mandate for public sector", "critical")
        _add("grant_to_report", "high", "Mandatory for grant-funded public bodies", "critical")
        _add("record_to_report", "high", "Public financial accountability", "critical")
        _add("close_to_disclose", "high", "Statutory accounts", "critical")
        _add("risk_to_mitigate", "medium", "Risk governance", "important")
        _add("regulatory_reporting", "medium", "Compliance reporting", "important")

    # 11. Education (85)
    if _in_range(code_int, "85"):
        _add("citizen_service_delivery", "medium", "Student service delivery", "important")
        _add("grant_to_report", "high", "Grant funding management", "critical")
        _add("record_to_report", "medium", "Financial management", "important")

    # 12. Healthcare (86-88)
    if _in_range(code_int, "86-88"):
        _add("patient_to_discharge", "high", "Core clinical process", "critical")
        _add("record_to_report", "medium", "Clinical and financial reporting", "important")
        _add("risk_to_mitigate", "medium", "Patient safety and clinical risk", "critical")
        if _in_range(code_int, "88"):
            _add("grant_to_report", "medium", "Social care is often grant-funded", "important")

    # 13. Manufacturing (10-33)
    if _in_range(code_int, "10-33"):
        _add("plan_to_produce", "high", "Core manufacturing process", "critical")
        _add("order_to_cash", "high", "Revenue collection", "critical")
        _add("procure_to_pay", "high", "Materials procurement", "critical")
        _add("warehouse_to_delivery", "medium", "Inventory and dispatch", "important")
        _add("record_to_report", "medium", "Financial reporting", "standard")

    # ---------------------------------------------------------------------------
    # Company form modifiers
    # ---------------------------------------------------------------------------
    form_upper = company_form.upper()

    # Listed companies always need close_to_disclose
    if any(f in form_upper for f in ("A/S", "ASA", "PLC", "LISTED")):
        _add("close_to_disclose", "high", "Listed company — statutory disclosure required", "critical")

    # Associations / NGOs need grant_to_report
    if any(f in form_upper for f in ("FORENING", "NGO", "FOND", "FOUNDATION", "STIFTELSE")):
        _add("grant_to_report", "high", "Membership/grant-funded entity", "critical")

    # ---------------------------------------------------------------------------
    # Company size modifiers
    # ---------------------------------------------------------------------------
    size_lower = company_size.lower()

    # Micro companies unlikely to run platform/software delivery
    if size_lower == "micro":
        results.pop("software_delivery", None)
        results.pop("platform_operations", None)
        results.pop("data_operations", None)

    # Enterprise / large companies get finance compliance streams promoted
    if size_lower in ("large", "enterprise"):
        if "record_to_report" in results:
            results["record_to_report"] = InferredValueStream(
                key="record_to_report",
                name=VALUE_STREAM_BY_KEY["record_to_report"].name,
                confidence="high",
                inference_reason="Large organisation — financial reporting is always material",
                suggested_priority="important",
            )
        if "risk_to_mitigate" in results:
            results["risk_to_mitigate"] = InferredValueStream(
                key="risk_to_mitigate",
                name=VALUE_STREAM_BY_KEY["risk_to_mitigate"].name,
                confidence="high",
                inference_reason="Large organisation — formal risk management expected",
                suggested_priority="important",
            )

    # ---------------------------------------------------------------------------
    # Sort: high confidence first, then critical priority, then alphabetical
    # ---------------------------------------------------------------------------
    priority_order = {"critical": 0, "important": 1, "standard": 2}
    confidence_order = {"high": 0, "medium": 1, "low": 2}

    return sorted(
        results.values(),
        key=lambda x: (confidence_order[x.confidence], priority_order[x.suggested_priority], x.name),
    )
