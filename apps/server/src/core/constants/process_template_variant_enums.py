"""Stable values for governed Business Process template variants."""

from enum import StrEnum


class ProcessBusinessOutcomeKey(StrEnum):
    IDENTITY_ACCESS_GOVERNANCE = "identity_access_governance"
    SECURITY_INCIDENT_RESPONSE = "security_incident_response"
    WORKFORCE_LIFECYCLE = "workforce_lifecycle"
    CUSTOMER_REVENUE_TO_CASH = "customer_revenue_to_cash"
    APPLICATION_TO_APPROVAL = "application_to_approval"
    CONTRACT_RENEWAL = "contract_renewal"
    CUSTOMER_ACQUISITION = "customer_acquisition"
    CUSTOMER_SUPPORT = "customer_support"
    PROCUREMENT_TO_PAYMENT = "procurement_to_payment"
    DELIVERY_PLANNING = "delivery_planning"
    WAREHOUSE_TO_DELIVERY = "warehouse_to_delivery"
    FINANCIAL_REPORTING = "financial_reporting"
    RISK_MITIGATION = "risk_mitigation"
    GRANT_REPORTING = "grant_reporting"
    PATIENT_DISCHARGE = "patient_discharge"
    SOFTWARE_DELIVERY = "software_delivery"
    PLATFORM_OPERATIONS = "platform_operations"
    DATA_OPERATIONS = "data_operations"
    TRADE_SETTLEMENT = "trade_settlement"
    CITIZEN_SERVICE_DELIVERY = "citizen_service_delivery"
    REGULATORY_REPORTING = "regulatory_reporting"
    RESERVATION_TO_CHECKOUT = "reservation_to_checkout"
    SHIPMENT_TO_DELIVERY = "shipment_to_delivery"


class ProcessTemplateIndustryFit(StrEnum):
    DIRECT = "direct"
    COMPARABLE = "comparable"
    UNKNOWN = "unknown"


class ProcessTemplateApplicabilityReason(StrEnum):
    MATCHED_REGISTERED_INDUSTRY = "matched_registered_industry"
    COMPARABLE_BUSINESS_OUTCOME = "comparable_business_outcome"
    ORGANISATION_INDUSTRY_UNKNOWN = "organisation_industry_unknown"


class ProcessTemplateVariantAuditEvent(StrEnum):
    APPLIED = "business_process_template_variant_applied"


class ProcessTemplateVariantErrorMessage(StrEnum):
    PROCESS_NOT_FOUND = "Business Process not found in this organisation"
    PROCESS_TEMPLATE_REQUIRED = "Template alternatives are available only for a template-backed Business Process"
    TEMPLATE_VARIANT_NOT_FOUND = "The requested Business Process template alternative was not found"
    TEMPLATE_VARIANT_OUTCOME_MISMATCH = "The requested template does not deliver the same business outcome"
    REBASE_ACKNOWLEDGEMENT_REQUIRED = "Confirm that applying this alternative replaces the current flow baseline"
