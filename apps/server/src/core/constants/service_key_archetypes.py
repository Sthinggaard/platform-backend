"""Maps canonical service keys (from ValueStreamLibraryItem.core_service_keys)
to their corresponding archetype, and provides human-readable business names.

This is the single source of truth for service key → archetype resolution.
Used by the template library API and the slot-mapping wizard.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Service key → archetype mapping
# ---------------------------------------------------------------------------
# Each key matches a string that can appear in ValueStreamLibraryItem.core_service_keys.
# The archetype must be a key in ARCHETYPE_TEMPLATES from dependency_templates.py.

SERVICE_KEY_ARCHETYPES: dict[str, str] = {
    # Transactional systems
    "payment_processing":     "transactional_system",
    "billing_service":        "transactional_system",
    "order_management":       "transactional_system",
    "core_banking":           "transactional_system",
    "settlement_service":     "transactional_system",
    "custody_service":        "transactional_system",
    "trading_platform":       "transactional_system",
    "accounts_payable":       "transactional_system",
    "finance_system":         "transactional_system",
    "payroll_service":        "transactional_system",
    "grant_management":       "transactional_system",

    # Customer channels
    "web_channel":            "customer_channel",
    "marketing_platform":     "customer_channel",
    "helpdesk_service":       "customer_channel",
    "notification_service":   "customer_channel",
    "citizen_portal":         "customer_channel",
    "booking_system":         "customer_channel",
    "application_service":    "customer_channel",

    # Identity & access
    "identity_service":       "identity_access",
    "sso_service":            "identity_access",
    "privileged_access":      "identity_access",

    # Data stores
    "data_warehouse":         "data_store",
    "patient_records":        "data_store",
    "knowledge_base":         "data_store",
    "source_control":         "data_store",

    # Processing engines
    "decisioning_engine":     "processing_engine",
    "siem_service":           "processing_engine",
    "risk_platform":          "processing_engine",
    "compliance_service":     "processing_engine",
    "audit_service":          "processing_engine",
    "data_pipeline":          "processing_engine",
    "consolidation_service":  "processing_engine",
    "regulatory_reporting":   "processing_engine",
    "reporting_service":      "processing_engine",
    "vulnerability_management": "processing_engine",
    "incident_management":    "processing_engine",
    "quality_management":     "processing_engine",
    "production_planning":    "processing_engine",
    "deployment_service":     "processing_engine",
    "monitoring_service":     "processing_engine",

    # Support services
    "crm_service":            "support_service",
    "quoting_service":        "support_service",
    "contract_management":    "support_service",
    "lead_management":        "support_service",
    "case_management":        "support_service",
    "scheduling_service":     "support_service",
    "hr_system":              "support_service",
    "onboarding_service":     "support_service",
    "pms_service":            "support_service",
    "procurement_system":     "support_service",
    "erp_service":            "support_service",
    "clinical_system":        "support_service",
    "pharmacy_service":       "support_service",

    # Platform infrastructure
    "infrastructure_service": "platform_infrastructure",
    "ci_cd_pipeline":         "platform_infrastructure",
    "inventory_service":      "platform_infrastructure",
    "warehouse_management":   "platform_infrastructure",
    "transport_management":   "platform_infrastructure",
    "tms_service":            "platform_infrastructure",
    "tracking_service":       "platform_infrastructure",
}

# Human-readable business names for service keys
SERVICE_KEY_NAMES: dict[str, str] = {
    "payment_processing":     "Payment Processing",
    "billing_service":        "Billing Service",
    "order_management":       "Order Management",
    "core_banking":           "Core Banking",
    "settlement_service":     "Settlement Service",
    "custody_service":        "Custody Service",
    "trading_platform":       "Trading Platform",
    "accounts_payable":       "Accounts Payable",
    "finance_system":         "Finance System",
    "payroll_service":        "Payroll Service",
    "grant_management":       "Grant Management",
    "web_channel":            "Web Channel",
    "marketing_platform":     "Marketing Platform",
    "helpdesk_service":       "Helpdesk Service",
    "notification_service":   "Notification Service",
    "citizen_portal":         "Citizen Portal",
    "booking_system":         "Booking System",
    "application_service":    "Application Service",
    "identity_service":       "Identity Service",
    "sso_service":            "SSO Service",
    "privileged_access":      "Privileged Access",
    "data_warehouse":         "Data Warehouse",
    "patient_records":        "Patient Records",
    "knowledge_base":         "Knowledge Base",
    "source_control":         "Source Control",
    "decisioning_engine":     "Decisioning Engine",
    "siem_service":           "SIEM Service",
    "risk_platform":          "Risk Platform",
    "compliance_service":     "Compliance Service",
    "audit_service":          "Audit Service",
    "data_pipeline":          "Data Pipeline",
    "consolidation_service":  "Consolidation Service",
    "regulatory_reporting":   "Regulatory Reporting",
    "reporting_service":      "Reporting Service",
    "vulnerability_management": "Vulnerability Management",
    "incident_management":    "Incident Management",
    "quality_management":     "Quality Management",
    "production_planning":    "Production Planning",
    "deployment_service":     "Deployment Service",
    "monitoring_service":     "Monitoring Service",
    "crm_service":            "CRM Service",
    "quoting_service":        "Quoting Service",
    "contract_management":    "Contract Management",
    "lead_management":        "Lead Management",
    "case_management":        "Case Management",
    "scheduling_service":     "Scheduling Service",
    "hr_system":              "HR System",
    "onboarding_service":     "Onboarding Service",
    "pms_service":            "PMS Service",
    "procurement_system":     "Procurement System",
    "erp_service":            "ERP Service",
    "clinical_system":        "Clinical System",
    "pharmacy_service":       "Pharmacy Service",
    "infrastructure_service": "Infrastructure Service",
    "ci_cd_pipeline":         "CI/CD Pipeline",
    "inventory_service":      "Inventory Service",
    "warehouse_management":   "Warehouse Management",
    "transport_management":   "Transport Management",
    "tms_service":            "TMS Service",
    "tracking_service":       "Tracking Service",
}


def get_service_key_name(key: str) -> str:
    """Return a human-readable name for a service key, falling back to title-cased key."""
    if key in SERVICE_KEY_NAMES:
        return SERVICE_KEY_NAMES[key]
    return key.replace("_", " ").title()


def get_archetype_for_service_key(key: str) -> str | None:
    """Return the archetype for a service key, or None if not mapped."""
    return SERVICE_KEY_ARCHETYPES.get(key)
