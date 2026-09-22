"""Business Service Profiles — internal Risklence knowledge models.

Profiles enrich the archetype-seeded service templates with business
semantics: a capability statement, default impact assumptions, common risk
patterns, and per-slot enrichment (service-specific labels, matching hints
for the intelligence engine, expected evidence types).

Profiles are internal only. Customers see Business Services and
recommendations; they never see "profile versions" (skill rule: versioning
is audit/provenance, not a customer-facing update).

Seed set follows the skill's reference examples, mapped onto existing
canonical service keys (service_key_archetypes.py). Grow this catalogue
incrementally — an absent profile simply means the archetype defaults apply.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class ProfileSlotEnrichment:
    """Service-specific overlay for one canonical dependency pattern."""

    pattern_key: str
    matching_hints: tuple[str, ...] = ()
    expected_evidence_types: tuple[str, ...] = ()
    risk_patterns: tuple[str, ...] = ()
    label_override: str | None = None
    required_override: bool | None = None


@dataclass(frozen=True)
class BusinessServiceProfile:
    service_key: str
    capability_statement: str
    default_impact_model: Mapping[str, str]
    operational_expectations: tuple[str, ...] = ()
    common_risk_patterns: tuple[str, ...] = ()
    slot_enrichments: tuple[ProfileSlotEnrichment, ...] = ()
    override_policy: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType(
            {
                "impact_model": "structured_reason_required",
                "slot_removal": "structured_reason_required",
                "criticality": "owner_approval_required",
            }
        )
    )


def _impact(**values: str) -> Mapping[str, str]:
    return MappingProxyType(values)


BUSINESS_SERVICE_PROFILES: dict[str, BusinessServiceProfile] = {
    "payment_processing": BusinessServiceProfile(
        service_key="payment_processing",
        capability_statement=(
            "Payment Processing enables customers to complete purchases and allows the "
            "organisation to collect revenue. If unavailable, revenue collection may stop "
            "immediately and customer trust may be affected."
        ),
        default_impact_model=_impact(
            business_criticality="Mission Critical",
            downtime_tolerance="30 minutes to 4 hours depending on industry",
            financial_impact="High",
            customer_impact="High",
            regulatory_impact="Medium to High",
            data_sensitivity="Financial / personal / regulated",
            fallback_expectation="Partial or none",
        ),
        operational_expectations=(
            "Failover provider or documented manual fallback",
            "Backups restore-tested for transactional data",
            "24/7 incident response path for payment incidents",
        ),
        common_risk_patterns=(
            "payment gateway outage",
            "database backup failure",
            "expired certificate",
            "identity provider outage",
            "transaction latency increase",
            "secrets exposure",
            "missing failover provider",
            "monitoring gap",
        ),
        slot_enrichments=(
            ProfileSlotEnrichment(
                pattern_key="external_provider",
                label_override="Payment Gateway",
                matching_hints=("stripe", "adyen", "nets", "worldline", "paypal", "klarna"),
                expected_evidence_types=("integration", "api_credential", "network_flow", "contract"),
                risk_patterns=("payment gateway outage", "missing failover provider"),
            ),
            ProfileSlotEnrichment(
                pattern_key="transaction_data_store",
                matching_hints=("azure sql", "postgresql", "rds", "oracle", "sql server"),
                expected_evidence_types=("database_inventory", "backup_job", "restore_test"),
                risk_patterns=("database backup failure", "transaction latency increase"),
            ),
            ProfileSlotEnrichment(
                pattern_key="identity_provider",
                matching_hints=("azure entra id", "entra", "okta", "auth0", "ping"),
                expected_evidence_types=("identity_inventory", "sso_configuration"),
                risk_patterns=("identity provider outage",),
            ),
            ProfileSlotEnrichment(
                pattern_key="monitoring_service",
                required_override=True,
                matching_hints=("datadog", "azure monitor", "splunk", "grafana"),
                expected_evidence_types=("telemetry_source", "alert_rule"),
                risk_patterns=("monitoring gap",),
            ),
            ProfileSlotEnrichment(
                pattern_key="audit_logging",
                matching_hints=("splunk", "elk", "cloudwatch", "sentinel"),
                expected_evidence_types=("log_pipeline", "retention_policy"),
                risk_patterns=("secrets exposure",),
            ),
        ),
    ),
    "identity_service": BusinessServiceProfile(
        service_key="identity_service",
        capability_statement=(
            "Customer Authentication verifies user identity before granting access to "
            "customer-facing services. If unavailable, customers may be unable to access "
            "accounts, complete transactions, or receive support."
        ),
        default_impact_model=_impact(
            business_criticality="Business Critical",
            downtime_tolerance="1 to 4 hours, often lower for financial services",
            customer_impact="High",
            regulatory_impact="Medium to High",
            data_sensitivity="Personal / regulated",
            fallback_expectation="None for digital-first products",
        ),
        operational_expectations=(
            "MFA enforced for regulated contexts",
            "Certificate expiry tracked and alerted",
            "Failed-login anomaly monitoring",
        ),
        common_risk_patterns=(
            "MFA bypass or outage",
            "certificate expiry",
            "identity provider outage",
            "account takeover indicators",
            "session store degradation",
            "excessive failed login attempts",
        ),
        slot_enrichments=(
            ProfileSlotEnrichment(
                pattern_key="identity_provider",
                matching_hints=("okta", "azure entra id", "entra", "auth0", "ping"),
                expected_evidence_types=("identity_inventory", "sso_configuration"),
                risk_patterns=("identity provider outage",),
            ),
            ProfileSlotEnrichment(
                pattern_key="authentication_service",
                label_override="MFA Provider",
                matching_hints=("duo", "azure mfa", "okta verify", "yubico"),
                expected_evidence_types=("mfa_policy", "identity_inventory"),
                risk_patterns=("MFA bypass or outage",),
            ),
            ProfileSlotEnrichment(
                pattern_key="network_connectivity",
                label_override="Network / Edge Protection",
                matching_hints=("cloudflare", "akamai", "load balancer", "waf"),
                expected_evidence_types=("network_flow", "dns_record", "certificate"),
                risk_patterns=("certificate expiry",),
            ),
            ProfileSlotEnrichment(
                pattern_key="monitoring_service",
                required_override=True,
                matching_hints=("datadog", "azure monitor", "splunk"),
                expected_evidence_types=("telemetry_source", "alert_rule"),
                risk_patterns=("excessive failed login attempts", "account takeover indicators"),
            ),
        ),
    ),
    "billing_service": BusinessServiceProfile(
        service_key="billing_service",
        capability_statement=(
            "Invoice Generation turns completed orders or delivered services into billable "
            "records. If unavailable, cash collection may be delayed and finance operations "
            "may lose visibility."
        ),
        default_impact_model=_impact(
            business_criticality="Business Critical",
            financial_impact="Medium to High",
            customer_impact="Medium",
            regulatory_impact="Medium",
            downtime_tolerance="4 to 24 hours",
            fallback_expectation="Often partial/manual",
        ),
        operational_expectations=(
            "Invoice archive retained for audit evidence",
            "ERP integration failures alerted to finance operations",
        ),
        common_risk_patterns=(
            "invoice generation failure",
            "missing customer/order data",
            "email delivery outage",
            "archive/audit storage unavailable",
            "ERP integration failure",
        ),
        slot_enrichments=(
            ProfileSlotEnrichment(
                pattern_key="processing_logic",
                label_override="ERP / Finance System",
                matching_hints=("sap", "netsuite", "dynamics", "e-conomic", "xero"),
                expected_evidence_types=("integration", "application_inventory"),
                risk_patterns=("ERP integration failure", "invoice generation failure"),
            ),
            ProfileSlotEnrichment(
                pattern_key="transaction_data_store",
                label_override="Customer / Order Data",
                matching_hints=("azure sql", "postgresql", "crm"),
                expected_evidence_types=("database_inventory", "backup_job"),
                risk_patterns=("missing customer/order data",),
            ),
            ProfileSlotEnrichment(
                pattern_key="external_provider",
                label_override="Email / Delivery Channel",
                matching_hints=("sendgrid", "postmark", "exchange", "mailgun"),
                expected_evidence_types=("integration", "dns_record"),
                risk_patterns=("email delivery outage",),
            ),
        ),
    ),
    "helpdesk_service": BusinessServiceProfile(
        service_key="helpdesk_service",
        capability_statement=(
            "Customer Support enables customers to get help, report issues, and resolve "
            "operational problems. If unavailable, customer trust may decline and unresolved "
            "business issues may increase."
        ),
        default_impact_model=_impact(
            business_criticality="Business Critical",
            customer_impact="Medium to High",
            financial_impact="Low to Medium unless support is part of revenue operations",
            regulatory_impact="Low to Medium, higher in regulated services",
            downtime_tolerance="4 to 24 hours",
            fallback_expectation="Partial/manual possible",
        ),
        operational_expectations=(
            "Escalation path documented for priority incidents",
            "Customer record access available to support staff",
        ),
        common_risk_patterns=(
            "ticketing outage",
            "telephony outage",
            "missing customer record access",
            "communication delivery failure",
            "SLA breach risk",
        ),
        slot_enrichments=(
            ProfileSlotEnrichment(
                pattern_key="application_platform",
                label_override="Ticketing System",
                matching_hints=("zendesk", "servicenow", "jira service management", "freshdesk"),
                expected_evidence_types=("application_inventory", "integration"),
                risk_patterns=("ticketing outage", "SLA breach risk"),
            ),
            ProfileSlotEnrichment(
                pattern_key="communication_service",
                required_override=True,
                matching_hints=("twilio", "teams", "genesys", "exchange"),
                expected_evidence_types=("integration", "telephony_inventory"),
                risk_patterns=("telephony outage", "communication delivery failure"),
            ),
            ProfileSlotEnrichment(
                pattern_key="general_data_store",
                label_override="Customer Records",
                matching_hints=("crm", "salesforce", "hubspot", "dynamics"),
                expected_evidence_types=("application_inventory", "database_inventory"),
                risk_patterns=("missing customer record access",),
            ),
        ),
    ),
}


def get_business_service_profile(service_key: str) -> BusinessServiceProfile | None:
    return BUSINESS_SERVICE_PROFILES.get(service_key)
