from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy.orm import Session

from src.core.constants.decision_runtime import (
    DECISION_ACTION_ACCEPTED,
    DECISION_ACTION_ESCALATED,
    DECISION_ACTION_JIRA,
    DECISION_TYPE_RECOMMENDED,
    RECOMMENDATION_STATUS_DECIDED,
)
from src.core.model_defs.assets_runtime import AssetStatus, ConnectivityStatus, Criticality, Environment, SetupConfidence
from src.core.models import (
    Asset,
    AssetAppetiteConfig,
    BusinessService,
    DecisionRecord,
    DependencyBundle,
    DependencyBundleVersion,
    MappingDecision,
    OrgProcessConfig,
    OrgServiceConfig,
    Organization,
    Recommendation,
    ResolutionRecord,
    SlotInstance,
    Threat,
    ValueStream,
    ValueStreamSignal,
    VerificationRecord,
)
from src.core.services.recommendation_generation_service import generate_live_recommendations_for_org
from src.core.seeds.risklence_internal_tenant_risks import DECISION_BLUEPRINTS, WEAKNESS_BLUEPRINTS
from src.core.seeds.risklence_internal_tenant_structure import (
    ASSET_BLUEPRINTS,
    BUSINESS_PROCESS_BLUEPRINTS,
    DEPENDENCY_BLUEPRINTS,
    MOCK_CVR_NUMBER,
    ORGANIZATION_NAME,
    ORGANIZATION_SLUG,
    SERVICE_BLUEPRINTS,
)


def build_risklence_service_suggestions() -> list[dict[str, Any]]:
    return [
        {
            "name": item["name"],
            "description": description,
            "source": "ai_suggested",
            "confirmed": False,
        }
        for item, description in zip(
            SERVICE_BLUEPRINTS,
            [
                "Guided suggestion for the API surface that runs customer transactions and integrations.",
                "Guided suggestion for the web channel that serves the customer-facing application.",
                "Guided suggestion for identity and access control across the tenant.",
                "Guided suggestion for the shared data layer that powers reporting and billing.",
                "Guided suggestion for the onboarding flow that activates a new tenant.",
                "Guided suggestion for billing and subscription operations.",
            ],
        )
    ]


def build_risklence_internal_tenant_blueprint() -> dict[str, Any]:
    services = build_risklence_service_suggestions()
    return {
        "organization": {
            "name": ORGANIZATION_NAME,
            "slug": ORGANIZATION_SLUG,
            "registration_number": MOCK_CVR_NUMBER,
            "registration_country": "DK",
            "identity_source": "mock_company_registry",
            "industry": "Cybersecurity SaaS",
            "size": 10,
            "region": "EU",
            "hosting_model": "Cloud-native",
            "plan_tier": "enterprise",
            "subscription_status": "active",
            "risk_appetite": "Balanced",
            "status": "PUBLISHED",
        },
        "business_processes": BUSINESS_PROCESS_BLUEPRINTS,
        "business_services": [
            {
                "name": service["name"],
                "template_key": spec["template_key"],
                "service_key": spec["service_key"],
                "archetype": spec["archetype"],
                "tier": spec["tier"],
                "suggested": True,
                "confirmed": True,
                "tolerance_window": spec["tolerance_window"],
                "suggested_mtd_hours": spec["suggested_mtd_hours"],
                "validated_mtd_hours": spec["validated_mtd_hours"],
                "value_stream_keys": spec["value_stream_keys"],
                "dependencies": spec["dependencies"],
                "trading_impact": spec["trading_impact"],
                "status": "PUBLISHED",
            }
            for service, spec in zip(services, SERVICE_BLUEPRINTS)
        ],
        "dependencies": DEPENDENCY_BLUEPRINTS,
        "assets": ASSET_BLUEPRINTS,
        "dependency_mappings": [
            {
                "service": spec["name"],
                "dependencies": spec["dependencies"],
            }
            for spec in SERVICE_BLUEPRINTS
        ],
        "weaknesses": [
            {
                "key": item["key"],
                "dependency": item["dependency"],
                "asset": item["asset"],
                "title": item["title"],
                "business_impact": item["business_impact"],
                "recommendation": item["recommendation"],
                "severity": item["severity"],
                "mitigation_status": "unmitigated",
                "visible_to_engine": True,
            }
            for item in WEAKNESS_BLUEPRINTS
        ],
        "interventions": [
            {
                "key": item["key"],
                "title": item["title"],
                "business_impact": item["business_impact"],
                "recommendation": item["recommendation"],
                "severity": item["severity"],
                "suggested_action": item["recommended_action"],
                "state": "decided" if item["key"] in {bp["intervention_key"] for bp in DECISION_BLUEPRINTS} else "open",
                "visible_to_engine": True,
            }
            for item in WEAKNESS_BLUEPRINTS
        ],
        "decisions": DECISION_BLUEPRINTS,
    }
