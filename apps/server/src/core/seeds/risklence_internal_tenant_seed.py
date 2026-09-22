from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy.orm import Session

from src.core.model_defs.assets_runtime import (
    Criticality,
    Environment,
    SetupConfidence,
)
from src.core.models import (
    Asset,
    AssetAppetiteConfig,
    BusinessService,
    DecisionRecord,
    DependencyBundle,
    DependencyBundleVersion,
    MappingDecision,
    Organization,
    OrgProcessConfig,
    OrgServiceConfig,
    Recommendation,
    ResolutionRecord,
    SlotInstance,
    Threat,
    ValueStream,
    ValueStreamSignal,
    VerificationRecord,
)
from src.core.seeds.risklence_internal_tenant import build_risklence_internal_tenant_blueprint
from src.core.services.asset_context_service import asset_reference
from src.core.seeds.risklence_internal_tenant_interventions import (
    seed_risklence_internal_tenant_interventions,
)
from src.core.seeds.risklence_internal_tenant_structure import (
    ASSET_BLUEPRINTS,
    BUSINESS_PROCESS_BLUEPRINTS,
    FIXTURE_TIMESTAMP,
    MOCK_CVR_NUMBER,
    ORGANIZATION_NAME,
    ORGANIZATION_SLUG,
    SERVICE_BLUEPRINTS,
)


def _stable_id(*parts: str) -> str:
    return str(uuid5(NAMESPACE_URL, "risklence::" + "::".join(parts)))


# The reference format has one definition, in asset_context_service. This file
# used to carry its own copy and then bypassed it at the one place that mattered.
_asset_ref = asset_reference


def _json_safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    return value


def _clear_seed_rows(db: Session, org_id: int) -> None:
    for model in (
        VerificationRecord,
        ResolutionRecord,
        DecisionRecord,
        Recommendation,
        Threat,
        ValueStreamSignal,
        SlotInstance,
        DependencyBundleVersion,
        MappingDecision,
        DependencyBundle,
        BusinessService,
        OrgServiceConfig,
        OrgProcessConfig,
        AssetAppetiteConfig,
        ValueStream,
        Asset,
    ):
        db.query(model).filter(model.organization_id == org_id).delete(synchronize_session=False)


def _upsert_organization(db: Session) -> Organization:
    org = db.query(Organization).filter(Organization.slug == ORGANIZATION_SLUG).one_or_none()
    if org is None:
        org = Organization(slug=ORGANIZATION_SLUG, name=ORGANIZATION_NAME)
        db.add(org)

    org.name = ORGANIZATION_NAME
    org.slug = ORGANIZATION_SLUG
    org.industry = "Cybersecurity SaaS"
    org.company_size = "1_50"
    org.country = "DK"
    org.cvr_number = MOCK_CVR_NUMBER
    org.required_frameworks = ["NIS2", "GDPR"]
    org.compliance_level = "balanced"
    org.regulatory_requirements = {"region": "EU", "hosting_model": "cloud-native"}
    org.plan_tier = "enterprise"
    org.subscription_status = "active"
    org.nace_code = "62.01"
    org.settings = {
        "region": "EU",
        "hosting_model": "cloud-native",
        "seed": "risklence_internal_tenant",
    }
    org.onboarding_completed = True
    org.onboarding_data = _json_safe(build_risklence_internal_tenant_blueprint())
    org.org_value_stream_profile = {
        "confirmedAt": FIXTURE_TIMESTAMP.isoformat(),
        "streams": [
            {
                "key": bp["key"],
                "name": bp["name"],
                "priority": bp["priority"],
                "source": bp["source"],
            }
            for bp in BUSINESS_PROCESS_BLUEPRINTS
        ],
    }
    db.flush()
    return org


def _seed_value_streams(db: Session, org_id: int) -> dict[str, ValueStream]:
    streams: dict[str, ValueStream] = {}
    for item in BUSINESS_PROCESS_BLUEPRINTS:
        stream = (
            db.query(ValueStream)
            .filter(
                ValueStream.organization_id == org_id,
                ValueStream.library_item_id == item["library_item_id"],
            )
            .one_or_none()
        )
        if stream is None:
            stream = ValueStream(
                id=_stable_id("stream", item["key"]),
                organization_id=org_id,
                library_item_id=item["library_item_id"],
                name=item["name"],
                priority=item["priority"],
                source=item["source"],
            )
            db.add(stream)
        else:
            stream.name = item["name"]
            stream.priority = item["priority"]
            stream.source = item["source"]
        streams[item["key"]] = stream
    db.flush()
    return streams


def _seed_assets(db: Session, org_id: int) -> dict[str, Asset]:
    assets: dict[str, Asset] = {}
    for item in ASSET_BLUEPRINTS:
        asset = (
            db.query(Asset)
            .filter(Asset.organization_id == org_id, Asset.display_name == item["display_name"])
            .one_or_none()
        )
        if asset is None:
            asset = Asset(
                organization_id=org_id,
                type=item["type"],
                provider=item["provider"],
                provider_display_name=item["provider_display_name"],
                display_name=item["display_name"],
                layer=item["layer"],
                environment=Environment.PROD,
                criticality=item["criticality"],
                status=item["status"],
                connectivity_status=item["connectivity_status"],
                setup_confidence=SetupConfidence.HIGH
                if item["confidence"] >= 0.9
                else SetupConfidence.MEDIUM,
                is_spof=item["is_spof"],
                risk_score=item["risk_score"],
                findings_count=item["findings_count"],
                confidence=item["confidence"],
                last_observed_at=FIXTURE_TIMESTAMP,
            )
            db.add(asset)
        else:
            asset.type = item["type"]
            asset.provider = item["provider"]
            asset.provider_display_name = item["provider_display_name"]
            asset.layer = item["layer"]
            asset.environment = Environment.PROD
            asset.criticality = item["criticality"]
            asset.status = item["status"]
            asset.connectivity_status = item["connectivity_status"]
            asset.setup_confidence = (
                SetupConfidence.HIGH if item["confidence"] >= 0.9 else SetupConfidence.MEDIUM
            )
            asset.is_spof = item["is_spof"]
            asset.risk_score = item["risk_score"]
            asset.findings_count = item["findings_count"]
            asset.confidence = item["confidence"]
            asset.last_observed_at = FIXTURE_TIMESTAMP
        assets[item["display_name"]] = asset
    db.flush()
    return assets


def _seed_services(
    db: Session,
    org_id: int,
    streams: dict[str, ValueStream],
    assets: dict[str, Asset],
) -> dict[str, BusinessService]:
    services: dict[str, BusinessService] = {}
    for spec in SERVICE_BLUEPRINTS:
        service = (
            db.query(BusinessService)
            .filter(BusinessService.organization_id == org_id, BusinessService.name == spec["name"])
            .one_or_none()
        )
        if service is None:
            service = BusinessService(
                id=_stable_id("service", spec["name"]),
                organization_id=org_id,
                name=spec["name"],
                tier=spec["tier"],
                tolerance_window=spec["tolerance_window"],
                trading_impact=spec["trading_impact"],
                bia_answers=None,
                archetype=spec["archetype"],
                library_item_id=spec["service_key"],
                template_key=spec["template_key"],
                template_version=1,
                value_stream_ids=[streams[key].id for key in spec["value_stream_keys"]],
                l1=[],
                l2=[],
                l3=[],
            )
            db.add(service)
        else:
            service.tier = spec["tier"]
            service.tolerance_window = spec["tolerance_window"]
            service.trading_impact = spec["trading_impact"]
            service.bia_answers = None
            service.archetype = spec["archetype"]
            service.library_item_id = spec["service_key"]
            service.template_key = spec["template_key"]
            service.template_version = 1
            service.value_stream_ids = [streams[key].id for key in spec["value_stream_keys"]]
        services[spec["name"]] = service
    db.flush()

    service_assets = {
        "API Platform": [
            "API Service",
            "App Platform (API)",
            "Managed PostgreSQL",
            "CI/CD Pipeline",
            "Engineering Team",
        ],
        "Frontend Application": [
            "Frontend App",
            "Cloudflare DNS",
            "Cloudflare Edge Hosting",
            "Cloudflare WAF",
            "Engineering Team",
        ],
        "Authentication & Access": ["Auth Service", "Managed PostgreSQL", "Engineering Team"],
        "Data Platform": ["Managed PostgreSQL", "App Platform (SCORM service)", "Engineering Team"],
        "Customer Onboarding": ["Frontend App", "API Service", "Auth Service", "Engineering Team"],
        "Billing & Subscription Management": [
            "API Service",
            "Managed PostgreSQL",
            "CI/CD Pipeline",
            "Engineering Team",
        ],
    }

    for service_name, asset_names in service_assets.items():
        service = services[service_name]
        refs = [_asset_ref(assets[name].id) for name in asset_names]
        service.l1 = refs[:1]
        service.l2 = refs[1:3]
        service.l3 = refs[3:]
    db.flush()
    return services


def _build_bundle_groups(service_name: str, asset_map: dict[str, Asset]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {
        "application": [],
        "infrastructure": [],
        "operations": [],
    }
    for item in next(spec for spec in SERVICE_BLUEPRINTS if spec["name"] == service_name)[
        "dependencies"
    ]:
        asset = asset_map[item]
        if item in {"API Service", "Frontend App", "Auth Service", "Engineering Team"}:
            group_key = "application" if item != "Engineering Team" else "operations"
        elif item == "CI/CD Pipeline":
            group_key = "operations"
        else:
            group_key = "infrastructure"

        groups[group_key].append(
            {
                "id": _stable_id("node", service_name, item),
                "label": item,
                "linked_asset_ids": [_asset_ref(asset.id)],
                "source": "manual",
                "validation_status": "mapped",
                "fallback_status": None,
                "spof": asset.is_spof,
                "confidence": asset.confidence,
                "template_key": item.lower().replace(" ", "_"),
                "pattern_key": "application_platform"
                if group_key == "application"
                else (
                    "audit_logging"
                    if item == "CI/CD Pipeline"
                    else (
                        "human_operations"
                        if item == "Engineering Team"
                        else (
                            "network_connectivity"
                            if "Cloudflare" in item
                            else (
                                "transaction_data_store"
                                if "PostgreSQL" in item
                                else "compute_resource"
                            )
                        )
                    )
                ),
                "critical_for_business": True,
                "business_consequence": f"{item} is required to keep {service_name} operating.",
                "impact_type": "availability",
                "business_impact_level": "high"
                if asset.criticality in {Criticality.CRITICAL, Criticality.HIGH}
                else "medium",
                "recovery_dependent": item
                in {"Managed PostgreSQL", "CI/CD Pipeline", "Engineering Team"},
                "deferred_asset_mapping": False,
            }
        )

    return [
        {
            "key": group_key,
            "label": group_key.replace("_", " ").title(),
            "question": f"What supports the {group_key.replace('_', ' ')} for this service?",
            "description": f"Mapped dependencies for {service_name}.",
            "required": bool(nodes),
            "template_nodes": [],
            "nodes": nodes,
        }
        for group_key, nodes in groups.items()
        if nodes
    ]


def _seed_bundles_and_slots(
    db: Session,
    org_id: int,
    services: dict[str, BusinessService],
    assets: dict[str, Asset],
) -> None:
    for service_name, service in services.items():
        groups = _build_bundle_groups(service_name, assets)
        bundle = (
            db.query(DependencyBundle)
            .filter(
                DependencyBundle.organization_id == org_id,
                DependencyBundle.service_id == service.id,
            )
            .one_or_none()
        )
        if bundle is None:
            bundle = DependencyBundle(
                organization_id=org_id,
                service_id=service.id,
                status="published",
                mode="manual_training",
                lifecycle_state="bundle_published",
                groups=groups,
                validation_snapshot={
                    "findings": [],
                    "warning_ids": [],
                    "acknowledged_warning_ids": [],
                },
                acknowledged_warning_ids=[],
            )
            db.add(bundle)
        else:
            bundle.status = "published"
            bundle.mode = "manual_training"
            bundle.lifecycle_state = "bundle_published"
            bundle.groups = groups
            bundle.validation_snapshot = {
                "findings": [],
                "warning_ids": [],
                "acknowledged_warning_ids": [],
            }
            bundle.acknowledged_warning_ids = []
        db.flush()

        version = (
            db.query(DependencyBundleVersion)
            .filter(
                DependencyBundleVersion.organization_id == org_id,
                DependencyBundleVersion.bundle_id == bundle.id,
            )
            .one_or_none()
        )
        if version is None:
            version = DependencyBundleVersion(
                organization_id=org_id,
                bundle_id=bundle.id,
                service_id=service.id,
                version_number=1,
                status="published",
                lifecycle_state="bundle_published",
                groups_snapshot=groups,
                validation_snapshot=bundle.validation_snapshot,
                acknowledged_warning_ids=[],
            )
            db.add(version)
        else:
            version.status = "published"
            version.lifecycle_state = "bundle_published"
            version.groups_snapshot = groups
            version.validation_snapshot = bundle.validation_snapshot
            version.acknowledged_warning_ids = []

        for group in groups:
            for node in group["nodes"]:
                slot_id = f"{service_name.lower().replace(' & ', '_').replace(' ', '_')}.{group['key']}.{node['label'].lower().replace(' ', '_')}"
                slot = (
                    db.query(SlotInstance)
                    .filter(
                        SlotInstance.organization_id == org_id,
                        SlotInstance.service_id == service.id,
                        SlotInstance.slot_id == slot_id,
                    )
                    .one_or_none()
                )
                asset_ref = node["linked_asset_ids"][0]
                if slot is None:
                    db.add(
                        SlotInstance(
                            id=_stable_id("slot", service_name, slot_id),
                            organization_id=org_id,
                            service_id=service.id,
                            slot_id=slot_id,
                            template_version=1,
                            status="mapped",
                            asset_id=_asset_ref(asset_ref),
                            asset_label=node["label"],
                            group_key=group["key"],
                        )
                    )
                else:
                    slot.template_version = 1
                    slot.status = "mapped"
                    slot.asset_id = _asset_ref(asset_ref)
                    slot.asset_label = node["label"]
                    slot.group_key = group["key"]
    db.flush()


def seed_risklence_internal_tenant(db: Session) -> dict[str, Any]:
    org = _upsert_organization(db)
    _clear_seed_rows(db, org.id)
    db.flush()

    streams = _seed_value_streams(db, org.id)
    assets = _seed_assets(db, org.id)
    services = _seed_services(db, org.id, streams, assets)
    _seed_bundles_and_slots(db, org.id, services, assets)
    seed_risklence_internal_tenant_interventions(db, org.id)
    db.commit()
    db.refresh(org)
    return build_risklence_internal_tenant_blueprint()
