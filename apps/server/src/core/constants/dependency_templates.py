"""Archetype-driven dependency templates for the BIA v2 dependency bundling engine.

Each archetype maps to a list of dependency groups. Groups are presented to users
in business language — never as technical CMDB categories.

Structure per group:
  key          — stable identifier (used for MappingDecision training signals)
  label        — shown in the UI as group heading
  question     — business-framed question the user is answering
  description  — short explanation shown below the question
  required     — True if group must have ≥1 node before bundle can be validated
  template_nodes — optional pre-populated example nodes (label + template_key only)

⚠️ A group is a question, and a question exists only because a slot answers it.
Every group key must be the group of at least one of its archetype's patterns
(``ARCHETYPE_PATTERN_EXPECTATIONS`` + ``PATTERN_GROUP_BY_KEY``), every pattern's
group must be asked, and ``required`` must be True exactly when one of those
patterns is required — ``get_template`` derives it anyway, so a literal that
disagrees is a second, wrong answer. ``tests/test_capability_questions.py``
fails on any of the three. Until 2026-09-13 nothing held them together: ``teams``
was asked by every archetype and answered by none.
"""

from __future__ import annotations

from copy import deepcopy
from typing import NotRequired, TypedDict


class TemplateNode(TypedDict):
    template_key: str
    label: str
    # Absent on the static example nodes written in ARCHETYPE_TEMPLATES below;
    # `get_template` resolves and adds it before any node leaves this module.
    pattern_key: NotRequired[str]


class DependencyGroupTemplate(TypedDict):
    key: str
    label: str
    question: str
    description: str
    required: bool
    template_nodes: list[TemplateNode]


CANONICAL_PATTERN_NAMES: dict[str, str] = {
    "transaction_data_store": "Transaction Data Storage",
    "general_data_store": "Data Storage",
    "processing_logic": "Processing Logic",
    "application_platform": "Application Platform",
    "identity_provider": "Identity Provider",
    "authentication_service": "Authentication Service",
    "network_connectivity": "Network Connectivity",
    "external_provider": "External Service Provider",
    "communication_service": "Communication Service",
    "monitoring_service": "Monitoring and Alerting",
    "audit_logging": "Audit Logging",
    "backup_recovery": "Backup and Recovery",
    "compute_resource": "Compute Resource",
    "encryption_service": "Encryption Service",
    "human_operations": "Human Operations",
}

CANONICAL_PATTERN_PURPOSES: dict[str, str] = {
    "transaction_data_store": "Stores the transactional records this service must read or write to operate.",
    "general_data_store": "Stores the state, reference data, or content this service depends on.",
    "processing_logic": "Executes the core business or technical processing required by this service.",
    "application_platform": "Hosts or exposes the user-facing or API-facing application layer for this service.",
    "identity_provider": "Provides the identity trust or directory source required to authorize access.",
    "authentication_service": "Performs the authentication or step-up verification this service relies on.",
    "network_connectivity": "Provides the network path, ingress, or connectivity needed for the service to stay reachable.",
    "external_provider": "Represents the third-party provider or external dependency that is part of the service flow.",
    "communication_service": "Enables outbound or inbound communications used by this service.",
    "monitoring_service": "Detects, alerts on, or reports failures affecting this service.",
    "audit_logging": "Captures the audit trail or operational logs needed for traceability.",
    "backup_recovery": "Provides backup, recovery, or replica capability for this service.",
    "compute_resource": "Supplies the compute or runtime capacity that keeps this service available.",
    "encryption_service": "Protects the service's data through key management or encryption controls.",
    "human_operations": "Represents the human operational capability required to keep the service running.",
}

CANONICAL_PATTERN_EXPECTED_ASSET_TYPES: dict[str, list[str]] = {
    "transaction_data_store": ["Database", "Ledger", "Transactional Data Store"],
    "general_data_store": ["Database", "Data Store", "Knowledge Base"],
    "processing_logic": ["Application", "Processing Engine", "Workflow Engine"],
    "application_platform": ["Application", "API Gateway", "Web Application"],
    "identity_provider": ["Identity Provider", "SSO Service", "Directory Service"],
    "authentication_service": ["Authentication Service", "MFA Service", "PAM"],
    "network_connectivity": ["Network", "Load Balancer", "Connectivity Service"],
    "external_provider": ["External Service", "Third-Party API", "Provider"],
    "communication_service": ["Messaging Platform", "Email Service", "Telephony"],
    "monitoring_service": ["Monitoring Platform", "Alerting Service", "SIEM"],
    "audit_logging": ["Audit Log Platform", "Log Store", "Immutable Log Service"],
    "backup_recovery": ["Backup Service", "Recovery Vault", "Replica Store"],
    "compute_resource": ["Compute", "Cluster", "Host", "Cloud Region"],
    "encryption_service": ["KMS", "HSM", "Encryption Service"],
    "human_operations": ["Operations Team", "Support Team", "On-call Team"],
}

PATTERN_GROUP_BY_KEY: dict[str, str] = {
    "processing_logic": "systems",
    "application_platform": "systems",
    "monitoring_service": "systems",
    "transaction_data_store": "data",
    "general_data_store": "data",
    "backup_recovery": "data",
    "encryption_service": "data",
    "audit_logging": "data",
    "external_provider": "external_providers",
    "communication_service": "external_providers",
    "compute_resource": "infrastructure",
    "network_connectivity": "infrastructure",
    "identity_provider": "identity_access",
    "authentication_service": "identity_access",
    # ⚠️ Asked by no archetype, deliberately. Søren, 2026-09-13: "the team
    # accountable is also the ones who needs to restore it" — the team behind a
    # service is derived from who is accountable for it, not picked as an
    # artefact. Kept only because the internal-tenant seed still writes it.
    "human_operations": "teams",
}

ARCHETYPE_PATTERN_EXPECTATIONS: dict[str, dict[str, list[str]]] = {
    "transactional_system": {
        "required": [
            "transaction_data_store",
            "processing_logic",
            "identity_provider",
            "network_connectivity",
        ],
        "optional": [
            "external_provider",
            "monitoring_service",
            "audit_logging",
        ],
    },
    "customer_channel": {
        "required": [
            "application_platform",
            "identity_provider",
            "network_connectivity",
        ],
        "optional": [
            "communication_service",
            "monitoring_service",
            "general_data_store",
        ],
    },
    "identity_access": {
        "required": [
            "identity_provider",
            "authentication_service",
            "network_connectivity",
        ],
        "optional": [
            "audit_logging",
            "monitoring_service",
        ],
    },
    "data_store": {
        "required": [
            "general_data_store",
            "network_connectivity",
        ],
        "optional": [
            "backup_recovery",
            "encryption_service",
            "monitoring_service",
        ],
    },
    "processing_engine": {
        "required": [
            "processing_logic",
            "general_data_store",
            "network_connectivity",
        ],
        "optional": [
            "external_provider",
            "monitoring_service",
        ],
    },
    "support_service": {
        "required": ["application_platform"],
        "optional": [
            "general_data_store",
            "communication_service",
            "monitoring_service",
        ],
    },
    "platform_infrastructure": {
        "required": [
            "compute_resource",
            "network_connectivity",
        ],
        "optional": [
            "general_data_store",
            "backup_recovery",
            "monitoring_service",
            "audit_logging",
        ],
    },
}


ARCHETYPE_TEMPLATES: dict[str, list[DependencyGroupTemplate]] = {
    "transactional_system": [
        {
            "key": "systems",
            "label": "Systems that run this service",
            "question": "What systems handle this service?",
            "description": "The core platforms, applications, or systems that this payment service depends on to operate.",
            "required": True,
            "template_nodes": [
                {"template_key": "systems.payment_gateway", "label": "Payment gateway"},
                {"template_key": "systems.fraud_engine", "label": "Fraud detection system"},
                {"template_key": "systems.card_scheme_interface", "label": "Card scheme interface"},
            ],
        },
        {
            "key": "data",
            "label": "Data this service depends on",
            "question": "What data must be available for this service to work?",
            "description": "Databases, transaction logs, or data feeds that must be accessible for the service to process payments.",
            "required": True,
            "template_nodes": [
                {"template_key": "data.transaction_db", "label": "Transaction database"},
                {"template_key": "data.customer_records", "label": "Customer records"},
            ],
        },
        {
            "key": "external_providers",
            "label": "External providers this service relies on",
            "question": "Which external providers does this service rely on?",
            "description": "Third-party payment networks, acquiring banks, or external APIs that are part of the payment flow.",
            "required": False,
            "template_nodes": [
                {"template_key": "external.acquiring_bank", "label": "Acquiring bank"},
                {
                    "template_key": "external.card_network",
                    "label": "Card network (Visa/Mastercard/Nets)",
                },
                {"template_key": "external.psp", "label": "Payment service provider"},
            ],
        },
        {
            "key": "infrastructure",
            "label": "Infrastructure this service runs on",
            "question": "What infrastructure does this service need to stay running?",
            "description": "Cloud regions, data centres, network connections, or hosting that the payment service depends on.",
            "required": True,
            "template_nodes": [
                {"template_key": "infra.primary_region", "label": "Primary cloud region"},
                {"template_key": "infra.network_connectivity", "label": "Network connectivity"},
            ],
        },
        {
            "key": "identity_access",
            "label": "Identity & access controls",
            "question": "Which access controls must work for this service to operate?",
            "description": "Authentication systems, access management tools, or privileged access paths required by operators and systems.",
            "required": True,
            "template_nodes": [
                {"template_key": "iam.operator_access", "label": "Operator access management"},
            ],
        },
    ],
    "customer_channel": [
        {
            "key": "systems",
            "label": "Systems that deliver this channel",
            "question": "What systems power this customer channel?",
            "description": "Applications, portals, or platforms that serve customers through this channel.",
            "required": True,
            "template_nodes": [
                {"template_key": "systems.web_app", "label": "Web application"},
                {"template_key": "systems.mobile_app", "label": "Mobile application"},
                {"template_key": "systems.api_gateway", "label": "API gateway"},
            ],
        },
        {
            "key": "data",
            "label": "Data this channel depends on",
            "question": "What data must be accessible for customers to use this channel?",
            "description": "Customer profiles, product data, or session data that must be available.",
            "required": False,
            "template_nodes": [
                {"template_key": "data.customer_profiles", "label": "Customer profiles"},
                {"template_key": "data.product_catalogue", "label": "Product catalogue"},
            ],
        },
        {
            "key": "external_providers",
            "label": "External services this channel uses",
            "question": "Which external services does this channel rely on?",
            "description": "Third-party services integrated into the customer experience.",
            "required": False,
            "template_nodes": [
                {"template_key": "external.cdn", "label": "Content delivery network"},
                {"template_key": "external.auth_provider", "label": "Authentication provider"},
            ],
        },
        {
            "key": "infrastructure",
            "label": "Infrastructure hosting this channel",
            "question": "What infrastructure keeps this channel reachable?",
            "description": "Hosting, DNS, load balancers, or edge networks the channel depends on.",
            "required": True,
            "template_nodes": [
                {"template_key": "infra.dns", "label": "DNS / domain"},
                {"template_key": "infra.load_balancer", "label": "Load balancer"},
            ],
        },
        {
            "key": "identity_access",
            "label": "Identity & access controls",
            "question": "Which access controls must work for customers to authenticate?",
            "description": "Login, SSO, or MFA systems that customers use to access the channel.",
            "required": True,
            "template_nodes": [
                {"template_key": "iam.customer_auth", "label": "Customer authentication"},
                {"template_key": "iam.sso", "label": "Single sign-on"},
            ],
        },
    ],
    "identity_access": [
        {
            "key": "identity_access",
            "label": "Identity systems that make up this service",
            "question": "Which identity providers and sign-in systems does this service run on?",
            "description": "Identity providers, directory services, or authentication and MFA systems.",
            "required": True,
            "template_nodes": [
                {"template_key": "systems.identity_provider", "label": "Identity provider (IdP)"},
                {"template_key": "systems.directory_service", "label": "Directory service"},
                {"template_key": "systems.pam", "label": "Privileged access management"},
            ],
        },
        {
            "key": "systems",
            "label": "Systems that watch over this service",
            "question": "What monitors or alerts on this identity service?",
            "description": "Monitoring and alerting that would notice this service failing.",
            "required": False,
            "template_nodes": [
                {
                    "template_key": "systems.monitoring_tools",
                    "label": "Monitoring and alerting tools",
                },
            ],
        },
        {
            "key": "data",
            "label": "Data this service manages",
            "question": "What identity and access data must be available?",
            "description": "User directories, role definitions, or policy stores the service depends on.",
            "required": False,
            "template_nodes": [
                {"template_key": "data.user_directory", "label": "User directory"},
                {"template_key": "data.role_policies", "label": "Role and policy store"},
            ],
        },
        {
            "key": "infrastructure",
            "label": "Infrastructure this service runs on",
            "question": "What infrastructure must be available for identity services to function?",
            "description": "Servers, cloud services, or network segments that host identity infrastructure.",
            "required": True,
            "template_nodes": [
                {"template_key": "infra.auth_servers", "label": "Authentication servers"},
            ],
        },
    ],
    "data_store": [
        {
            "key": "systems",
            "label": "Systems that record transactions",
            "question": "What systems capture and store transaction records?",
            "description": "Ledger systems, accounting platforms, or recording engines this service depends on.",
            "required": False,
            "template_nodes": [
                {"template_key": "systems.ledger", "label": "Core ledger system"},
                {"template_key": "systems.reconciliation_engine", "label": "Reconciliation engine"},
            ],
        },
        {
            "key": "data",
            "label": "Data this service depends on",
            "question": "What data feeds or stores must be available to record transactions accurately?",
            "description": "Transaction streams, reference data, or master data required for accurate recording.",
            "required": True,
            "template_nodes": [
                {
                    "template_key": "data.transaction_stream",
                    "label": "Transaction feed / event stream",
                },
                {"template_key": "data.reference_data", "label": "Reference data (rates, codes)"},
            ],
        },
        {
            "key": "infrastructure",
            "label": "Infrastructure this service runs on",
            "question": "What infrastructure must be available for this service to record reliably?",
            "description": "Storage, database infrastructure, or backup systems for transaction data.",
            "required": True,
            "template_nodes": [
                {"template_key": "infra.primary_db", "label": "Primary database"},
                {"template_key": "infra.backup_storage", "label": "Backup storage"},
            ],
        },
    ],
    "processing_engine": [
        {
            "key": "systems",
            "label": "Systems that support operations",
            "question": "What systems does your operations team depend on to work?",
            "description": "Operational platforms, workflow tools, or coordination systems.",
            "required": True,
            "template_nodes": [
                {"template_key": "systems.ops_platform", "label": "Operations platform"},
                {"template_key": "systems.workflow_tool", "label": "Workflow / task management"},
                {
                    "template_key": "systems.monitoring_tools",
                    "label": "Monitoring and alerting tools",
                },
            ],
        },
        {
            "key": "data",
            "label": "Data your operations depend on",
            "question": "What data must be available for operations to run normally?",
            "description": "Operational dashboards, reports, or data feeds operations staff rely on.",
            "required": True,
            "template_nodes": [
                {"template_key": "data.ops_dashboards", "label": "Operational dashboards"},
                {"template_key": "data.reporting_data", "label": "Reporting data"},
            ],
        },
        {
            "key": "external_providers",
            "label": "External services operations relies on",
            "question": "Which external services does your operations team depend on?",
            "description": "Communication tools, vendor portals, or external platforms used in daily operations.",
            "required": False,
            "template_nodes": [
                {
                    "template_key": "external.communication_platform",
                    "label": "Communication platform",
                },
                {"template_key": "external.vendor_portals", "label": "Vendor management portals"},
            ],
        },
        {
            "key": "infrastructure",
            "label": "Infrastructure supporting operations",
            "question": "What infrastructure must stay available for operations to continue?",
            "description": "Network access, office connectivity, or remote access infrastructure.",
            "required": True,
            "template_nodes": [
                {"template_key": "infra.network_access", "label": "Network access"},
                {"template_key": "infra.remote_access", "label": "Remote access / VPN"},
            ],
        },
    ],
    "support_service": [
        {
            "key": "systems",
            "label": "Systems this service uses",
            "question": "What systems does this support service depend on?",
            "description": "Helpdesk platforms, ticketing systems, or knowledge bases this service relies on.",
            "required": True,
            "template_nodes": [
                {"template_key": "systems.helpdesk", "label": "Helpdesk / ticketing system"},
                {"template_key": "systems.knowledge_base", "label": "Knowledge base"},
                {"template_key": "systems.communication", "label": "Communication tools"},
            ],
        },
        {
            "key": "data",
            "label": "Data this service depends on",
            "question": "What data must be available for this service to help effectively?",
            "description": "Customer data, case history, or product information needed to resolve issues.",
            "required": False,
            "template_nodes": [
                {"template_key": "data.customer_data", "label": "Customer data access"},
                {"template_key": "data.case_history", "label": "Case and ticket history"},
            ],
        },
        {
            "key": "external_providers",
            "label": "External services used",
            "question": "Which external services or vendors does this support service rely on?",
            "description": "Outsourced support vendors, specialist escalation paths, or external tooling.",
            "required": False,
            "template_nodes": [
                {
                    "template_key": "external.outsourced_support",
                    "label": "Outsourced support vendor",
                },
            ],
        },
    ],
    "platform_infrastructure": [
        {
            "key": "infrastructure",
            "label": "Infrastructure this service runs on",
            "question": "What compute and network does this service need to stay running?",
            "description": "Compute, clusters, cloud regions, and network paths this service depends on.",
            "required": True,
            "template_nodes": [
                {"template_key": "systems.compute", "label": "Compute resource"},
                {"template_key": "systems.network", "label": "Network connectivity"},
            ],
        },
        {
            "key": "systems",
            "label": "Systems that watch over this service",
            "question": "What monitors or alerts on this infrastructure service?",
            "description": "Monitoring and alerting that would notice this service failing.",
            "required": False,
            "template_nodes": [
                {
                    "template_key": "systems.monitoring_tools",
                    "label": "Monitoring and alerting tools",
                },
            ],
        },
        {
            "key": "data",
            "label": "Data and configuration storage",
            "question": "Where does this service store state or configuration?",
            "description": "Data stores, configuration services, or state management this infrastructure relies on.",
            "required": False,
            "template_nodes": [
                {"template_key": "data.general_store", "label": "General data store"},
                {"template_key": "data.backup", "label": "Backup and recovery"},
                {"template_key": "data.audit", "label": "Audit logging"},
            ],
        },
    ],
}

TEMPLATE_PATTERN_KEY_BY_TEMPLATE_KEY: dict[str, str] = {
    "systems.payment_gateway": "external_provider",
    "systems.fraud_engine": "processing_logic",
    "systems.card_scheme_interface": "external_provider",
    "data.transaction_db": "transaction_data_store",
    "data.customer_records": "general_data_store",
    "external.acquiring_bank": "external_provider",
    "external.card_network": "external_provider",
    "external.psp": "external_provider",
    "infra.primary_region": "compute_resource",
    "infra.network_connectivity": "network_connectivity",
    "iam.operator_access": "identity_provider",
    "teams.payments_ops": "human_operations",
    "teams.platform_engineering": "human_operations",
    "systems.web_app": "application_platform",
    "systems.mobile_app": "application_platform",
    "systems.api_gateway": "application_platform",
    "data.customer_profiles": "general_data_store",
    "data.product_catalogue": "general_data_store",
    "external.cdn": "external_provider",
    "external.auth_provider": "identity_provider",
    "infra.dns": "network_connectivity",
    "infra.load_balancer": "network_connectivity",
    "iam.customer_auth": "authentication_service",
    "iam.sso": "authentication_service",
    "teams.digital_product": "human_operations",
    "teams.customer_ops": "human_operations",
    "systems.identity_provider": "identity_provider",
    "systems.directory_service": "authentication_service",
    "systems.pam": "authentication_service",
    "data.user_directory": "general_data_store",
    "data.role_policies": "general_data_store",
    "external.mfa_provider": "authentication_service",
    "external.federation": "identity_provider",
    "infra.auth_servers": "compute_resource",
    "teams.security_ops": "human_operations",
    "teams.it_administration": "human_operations",
    "systems.ledger": "transaction_data_store",
    "systems.reconciliation_engine": "processing_logic",
    "data.transaction_stream": "transaction_data_store",
    "data.reference_data": "general_data_store",
    "external.regulatory_reporting": "external_provider",
    "external.clearing_house": "external_provider",
    "infra.primary_db": "transaction_data_store",
    "infra.backup_storage": "backup_recovery",
    "teams.finance_ops": "human_operations",
    "teams.data_engineering": "human_operations",
    "systems.ops_platform": "application_platform",
    "systems.workflow_tool": "processing_logic",
    "systems.monitoring_tools": "monitoring_service",
    "data.ops_dashboards": "general_data_store",
    "data.reporting_data": "general_data_store",
    "external.communication_platform": "communication_service",
    "external.vendor_portals": "external_provider",
    "infra.network_access": "network_connectivity",
    "infra.remote_access": "network_connectivity",
    "teams.operations": "human_operations",
    "teams.management": "human_operations",
    "systems.helpdesk": "application_platform",
    "systems.knowledge_base": "application_platform",
    "systems.communication": "communication_service",
    "data.customer_data": "general_data_store",
    "data.case_history": "general_data_store",
    "external.outsourced_support": "external_provider",
    "infra.telephony": "communication_service",
    "infra.connectivity": "network_connectivity",
    "teams.support": "human_operations",
    "teams.escalation": "human_operations",
    # platform_infrastructure template keys
    "systems.compute": "compute_resource",
    "systems.network": "network_connectivity",
    "systems.platform": "application_platform",
    "data.general_store": "general_data_store",
    "data.backup": "backup_recovery",
    "data.audit": "audit_logging",
    "teams.platform": "human_operations",
}

# Backward-compatibility map: old transitional keys → canonical archetype IDs.
# Used to resolve stored archetype values written before the canonical key migration.
_ARCHETYPE_COMPAT: dict[str, str] = {
    "payment_processing": "transactional_system",
    "transaction_recording": "data_store",
    "operations_execution": "processing_engine",
}

VALID_ARCHETYPES = frozenset(ARCHETYPE_TEMPLATES.keys()) | frozenset(_ARCHETYPE_COMPAT.keys())


def get_canonical_pattern_key_for_template_key(template_key: str) -> str:
    return TEMPLATE_PATTERN_KEY_BY_TEMPLATE_KEY.get(template_key, template_key)


def _build_library_pattern_options(
    archetype: str, group_key: str, fallback: list[TemplateNode]
) -> list[TemplateNode]:
    expected = ARCHETYPE_PATTERN_EXPECTATIONS.get(archetype)
    pattern_keys = []
    if expected:
        unique_pattern_keys = list(dict.fromkeys(expected["required"] + expected["optional"]))
        pattern_keys = [
            pattern_key
            for pattern_key in unique_pattern_keys
            if PATTERN_GROUP_BY_KEY.get(pattern_key) == group_key
        ]

    if pattern_keys:
        return [
            {
                "template_key": pattern_key,
                "label": CANONICAL_PATTERN_NAMES[pattern_key],
                "pattern_key": pattern_key,
            }
            for pattern_key in pattern_keys
            if pattern_key in CANONICAL_PATTERN_NAMES
        ]

    return [
        {
            **node,
            "pattern_key": get_canonical_pattern_key_for_template_key(node["template_key"]),
        }
        for node in fallback
    ]


def get_template(archetype: str) -> list[DependencyGroupTemplate] | None:
    """Return the dependency group template for the given archetype, or None if unknown.

    Accepts both canonical archetype IDs and legacy transitional keys so that
    existing database rows written before the canonical key migration continue to work.
    """
    # Remap legacy transitional keys to canonical IDs transparently.
    archetype = _ARCHETYPE_COMPAT.get(archetype, archetype)

    template = ARCHETYPE_TEMPLATES.get(archetype)
    if template is None:
        return None

    groups = deepcopy(template)
    expected = ARCHETYPE_PATTERN_EXPECTATIONS.get(archetype, {"required": [], "optional": []})
    required_group_keys = {
        PATTERN_GROUP_BY_KEY[pattern_key]
        for pattern_key in expected["required"]
        if pattern_key in PATTERN_GROUP_BY_KEY
    }

    for group in groups:
        group["required"] = group["key"] in required_group_keys
        group["template_nodes"] = _build_library_pattern_options(
            archetype,
            group["key"],
            group.get("template_nodes", []),
        )
    return [group for group in groups if group["template_nodes"]]
