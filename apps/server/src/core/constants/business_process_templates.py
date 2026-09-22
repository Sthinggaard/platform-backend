from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BusinessProcessReasoningTemplate:
    plain_name: str
    business_owner_summary: str
    why_this_matters: str
    what_can_go_wrong: str
    when_to_accept: str
    matched_input_phrases: dict[str, str]
    evidence_phrases: dict[str, str]


@dataclass(frozen=True, slots=True)
class BusinessProcessTemplate:
    id: str
    name: str
    category: str
    industry_tags: tuple[str, ...]
    size_tags: tuple[str, ...]
    region_tags: tuple[str, ...]
    regulatory_tags: tuple[str, ...]
    business_model_tags: tuple[str, ...]
    default_criticality: str
    explanation: str


BUSINESS_PROCESS_TEMPLATES: tuple[BusinessProcessTemplate, ...] = (
    BusinessProcessTemplate(
        id="saas-core-platform",
        name="SaaS Core Platform",
        category="operations",
        industry_tags=("saas", "software", "platform"),
        size_tags=("startup", "smb", "mid_market", "enterprise"),
        region_tags=("global", "emea", "nordics"),
        regulatory_tags=("gdpr", "nis2"),
        business_model_tags=("subscription", "b2b", "recurring_revenue"),
        default_criticality="high",
        explanation="Core product delivery, identity, availability, and data access patterns for a SaaS platform.",
    ),
    BusinessProcessTemplate(
        id="customer-lifecycle",
        name="Customer Lifecycle",
        category="commercial",
        industry_tags=("saas", "software", "platform"),
        size_tags=("startup", "smb", "mid_market", "enterprise"),
        region_tags=("global", "emea", "nordics"),
        regulatory_tags=("gdpr",),
        business_model_tags=("subscription", "b2b", "customer_success"),
        default_criticality="high",
        explanation="Onboarding, support, renewals, and retention processes that shape customer value and churn risk.",
    ),
    BusinessProcessTemplate(
        id="billing-subscription",
        name="Billing & Subscription",
        category="finance",
        industry_tags=("saas", "software", "platform"),
        size_tags=("startup", "smb", "mid_market", "enterprise"),
        region_tags=("global", "emea", "nordics"),
        regulatory_tags=("gdpr", "pci"),
        business_model_tags=("subscription", "usage_based", "b2b"),
        default_criticality="high",
        explanation="Revenue collection, renewals, invoicing, and entitlement management for recurring SaaS revenue.",
    ),
    BusinessProcessTemplate(
        id="security-operations",
        name="Security Operations",
        category="security",
        industry_tags=("saas", "software", "platform"),
        size_tags=("startup", "smb", "mid_market", "enterprise"),
        region_tags=("global", "emea", "nordics"),
        regulatory_tags=("gdpr", "nis2", "iso27001"),
        business_model_tags=("subscription", "b2b", "security_program"),
        default_criticality="high",
        explanation="Monitoring, triage, response, vulnerability management, and security control execution across the platform.",
    ),
    BusinessProcessTemplate(
        id="compliance-governance",
        name="Compliance & Governance",
        category="governance",
        industry_tags=("saas", "software", "platform"),
        size_tags=("startup", "smb", "mid_market", "enterprise"),
        region_tags=("global", "emea", "nordics"),
        regulatory_tags=("gdpr", "nis2", "dora", "iso27001"),
        business_model_tags=("subscription", "b2b", "risk_management"),
        default_criticality="medium",
        explanation="Policy, control, audit, and evidence workflows that keep the SaaS operating model explainable and auditable.",
    ),
)

BUSINESS_PROCESS_TEMPLATE_BY_ID: dict[str, BusinessProcessTemplate] = {
    template.id: template for template in BUSINESS_PROCESS_TEMPLATES
}

# Bridge to the canonical value-stream library (value_stream_library.py).
# Each recommendation template materialises as a ValueStream linked to exactly
# one canonical stream key, which activates the persisted template library
# (process templates → service slots → dependency bundles) for that process.
BUSINESS_PROCESS_TEMPLATE_STREAM_KEYS: dict[str, str] = {
    "saas-core-platform": "platform_operations",
    "customer-lifecycle": "contract_to_renewal",
    "billing-subscription": "order_to_cash",
    "security-operations": "security_incident_response",
    "compliance-governance": "risk_to_mitigate",
}


BUSINESS_PROCESS_REASONING_TEMPLATES: dict[str, BusinessProcessReasoningTemplate] = {
    "saas-core-platform": BusinessProcessReasoningTemplate(
        plain_name="Your Digital Product & Systems",
        business_owner_summary="Helps identify the systems your business depends on to deliver its product or service.",
        why_this_matters="If these systems fail, customers may not be able to use your service, your team may stop working efficiently, and revenue can be delayed or lost.",
        what_can_go_wrong="If this is missing, Risklence may not track the systems that keep your business running day to day.",
        when_to_accept="Accept this if your business depends on software, cloud tools, apps, websites, internal systems, or digital services to operate.",
        matched_input_phrases={
            "RULE_INDUSTRY_SOFTWARE": "industry code starts with 62 or 63",
            "RULE_IT_DEPENDENCY_CRITICAL": "it_dependency = high or critical",
            "RULE_SUBSCRIPTION_MODEL_CORE": "business_model_tags includes subscription",
            "RULE_MULTI_SITE_CORE": "locations > 1",
            "RULE_CORE_ASSET_SURFACE": "asset categories include identity, cloud, application, data, or network",
        },
        evidence_phrases={
            "RULE_INDUSTRY_SOFTWARE": "Your business appears to depend heavily on IT or digital systems",
            "RULE_IT_DEPENDENCY_CRITICAL": "Software or digital services are part of your business profile",
            "RULE_SUBSCRIPTION_MODEL_CORE": "Core digital assets were selected during setup",
            "RULE_MULTI_SITE_CORE": "Multiple locations increase coordination needs",
            "RULE_CORE_ASSET_SURFACE": "Core digital assets were selected during setup",
        },
    ),
    "customer-lifecycle": BusinessProcessReasoningTemplate(
        plain_name="Customers, Sales & Retention",
        business_owner_summary="Helps map how customers find you, start using your service, get support, and stay with your business.",
        why_this_matters="If this area is weak, customers may wait too long, get poor service, leave earlier, or never complete the buying process.",
        what_can_go_wrong="If this is missing, Risklence may not track risks that affect customer onboarding, support, renewals, churn, or revenue growth.",
        when_to_accept="Accept this if your business depends on winning, onboarding, supporting, or retaining customers.",
        matched_input_phrases={
            "RULE_INDUSTRY_SOFTWARE": "industry code starts with 62 or 63",
            "RULE_CUSTOMER_SUCCESS_MODEL": "business_model_tags includes subscription or customer_success",
            "RULE_CUSTOMER_COMMUNICATIONS": "asset categories include email, application, or data",
            "RULE_GROWTH_FOCUS": "size = startup / smb / mid_market",
            "RULE_BALANCED_RISK": "risk_appetite = balanced or aggressive",
        },
        evidence_phrases={
            "RULE_INDUSTRY_SOFTWARE": "Your profile indicates customer-facing activity",
            "RULE_CUSTOMER_SUCCESS_MODEL": "Your business model suggests recurring or customer-based revenue",
            "RULE_CUSTOMER_COMMUNICATIONS": "Growth or retention appears important to the business",
            "RULE_GROWTH_FOCUS": "Customer communication systems were selected during setup",
            "RULE_BALANCED_RISK": "Growth or retention appears important to the business",
        },
    ),
    "billing-subscription": BusinessProcessReasoningTemplate(
        plain_name="Getting Paid",
        business_owner_summary="Helps map how your business sends invoices, collects payments, manages subscriptions, and protects cash flow.",
        why_this_matters="If billing or payment processes fail, customers may not be charged correctly, payments may be delayed, and revenue can be lost.",
        what_can_go_wrong="If this is missing, Risklence may not track risks that affect payment collection, subscription renewals, invoice accuracy, or cash flow.",
        when_to_accept="Accept this if your business invoices customers, charges subscriptions, handles online payments, or depends on recurring revenue.",
        matched_input_phrases={
            "RULE_INDUSTRY_SOFTWARE": "industry code starts with 62 or 63",
            "RULE_RECURRING_REVENUE": "business_model_tags includes subscription, usage_based, or recurring_revenue",
            "RULE_PCI_PAYMENT_EXPOSURE": "regulatory_flags includes PCI",
            "RULE_FINANCE_SYSTEM_SURFACE": "asset categories include data, application, or cloud",
            "RULE_SCALE_REVENUE": "size = mid_market or enterprise",
        },
        evidence_phrases={
            "RULE_INDUSTRY_SOFTWARE": "Subscription or recurring revenue was detected",
            "RULE_RECURRING_REVENUE": "Payment or finance exposure may be relevant",
            "RULE_PCI_PAYMENT_EXPOSURE": "Business model suggests ongoing customer billing",
            "RULE_FINANCE_SYSTEM_SURFACE": "Payment or finance exposure may be relevant",
            "RULE_SCALE_REVENUE": "Business model suggests ongoing customer billing",
        },
    ),
    "security-operations": BusinessProcessReasoningTemplate(
        plain_name="Keeping the Business Safe",
        business_owner_summary="Helps map how your business notices, handles, and resolves security issues before they become business problems.",
        why_this_matters="Security issues are not just technical problems. They can stop operations, expose customer data, create emergency work, and damage trust.",
        what_can_go_wrong="If this is missing, Risklence may not track risks that could lead to account misuse, data exposure, downtime, or expensive incident cleanup.",
        when_to_accept="Accept this if your business uses digital systems, customer data, cloud tools, employee accounts, suppliers, or connected devices.",
        matched_input_phrases={
            "RULE_INDUSTRY_SOFTWARE": "industry code starts with 62 or 63",
            "RULE_SECURITY_REGULATORY_PRESSURE": "regulatory_flags includes GDPR, NIS2, ISO27001, or DORA",
            "RULE_SECURITY_DEPENDENCY": "it_dependency = high or critical",
            "RULE_SECURITY_ASSET_SURFACE": "asset categories include endpoint, network, email, backup, vendor, identity, or cloud",
            "RULE_DISTRIBUTED_OPERATIONS": "locations > 1",
        },
        evidence_phrases={
            "RULE_INDUSTRY_SOFTWARE": "Your profile shows high dependency on digital systems",
            "RULE_SECURITY_REGULATORY_PRESSURE": "Identity, cloud, email, network, or endpoint assets were selected",
            "RULE_SECURITY_DEPENDENCY": "Security-related obligations may apply to your business",
            "RULE_SECURITY_ASSET_SURFACE": "Identity, cloud, email, network, or endpoint assets were selected",
            "RULE_DISTRIBUTED_OPERATIONS": "Security-related obligations may apply to your business",
        },
    ),
    "compliance-governance": BusinessProcessReasoningTemplate(
        plain_name="Proof & Business Accountability",
        business_owner_summary="Helps keep track of important decisions, responsibilities, and proof that the business handled issues properly.",
        why_this_matters="Most business owners see compliance as a hassle, but the real problem comes when something goes wrong and you cannot prove what happened or who handled it.",
        what_can_go_wrong="If this is missing, you may spend days reconstructing decisions, responding to customer or authority questions, or proving that the business acted responsibly.",
        when_to_accept="Accept this if your business has customers, contracts, suppliers, payments, personal data, insurance, or legal obligations where documentation may matter.",
        matched_input_phrases={
            "RULE_INDUSTRY_SOFTWARE": "industry code starts with 62 or 63",
            "RULE_COMPLIANCE_REGULATORY_PRESSURE": "regulatory_flags are present",
            "RULE_NORDIC_GOVERNANCE_CONTEXT": "geography = DK / SE / NO / FI / IS / EMEA / NORDICS",
            "RULE_COMPLIANCE_SCALE": "size = mid_market or enterprise",
            "RULE_CONSERVATIVE_RISK_PROFILE": "risk_appetite = conservative or balanced",
        },
        evidence_phrases={
            "RULE_INDUSTRY_SOFTWARE": "Your operating region may require stronger documentation",
            "RULE_COMPLIANCE_REGULATORY_PRESSURE": "Your profile suggests obligations where proof can matter later",
            "RULE_NORDIC_GOVERNANCE_CONTEXT": "Your selected risk approach suggests you want fewer surprises",
            "RULE_COMPLIANCE_SCALE": "Your profile suggests obligations where proof can matter later",
            "RULE_CONSERVATIVE_RISK_PROFILE": "Your business may need to answer questions from customers, partners, banks, insurers, or authorities",
        },
    ),
}


def get_business_process_reasoning_template(template_id: str) -> BusinessProcessReasoningTemplate:
    try:
        return BUSINESS_PROCESS_REASONING_TEMPLATES[template_id]
    except KeyError as exc:
        raise KeyError(f"Unknown business process reasoning template: {template_id}") from exc


def get_business_process_template(template_id: str) -> BusinessProcessTemplate:
    try:
        return BUSINESS_PROCESS_TEMPLATE_BY_ID[template_id]
    except KeyError as exc:
        raise KeyError(f"Unknown business process template: {template_id}") from exc


def get_canonical_stream_key_for_template(template_id: str) -> str | None:
    """Return the canonical value-stream library key this template maps to, if any."""
    return BUSINESS_PROCESS_TEMPLATE_STREAM_KEYS.get(template_id)
