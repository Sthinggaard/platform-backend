"""Provider-agnostic OSI archetypes used for dynamic asset onboarding."""

from enum import Enum
from typing import Dict, List

from .osi import OSILayer


class AssetArchetype(str, Enum):
    CLOUD_ACCOUNT_GOVERNANCE = "CLOUD_ACCOUNT_GOVERNANCE"
    IDENTITY_PROVIDER = "IDENTITY_PROVIDER"
    POLICY_ENGINE = "POLICY_ENGINE"
    CLOUD_NETWORK_SEGMENT = "CLOUD_NETWORK_SEGMENT"
    PERIMETER_FIREWALL = "PERIMETER_FIREWALL"
    LOAD_BALANCER_INGRESS = "LOAD_BALANCER_INGRESS"
    CONTAINER_PLATFORM = "CONTAINER_PLATFORM"
    APPLICATION_SERVICE = "APPLICATION_SERVICE"
    OBJECT_STORAGE = "OBJECT_STORAGE"
    RELATIONAL_DATABASE = "RELATIONAL_DATABASE"


ALLOWED_LAYERS_BY_ARCHETYPE: Dict[AssetArchetype, List[str]] = {
    AssetArchetype.CLOUD_ACCOUNT_GOVERNANCE: [OSILayer.L7_GOVERNANCE.value],
    AssetArchetype.IDENTITY_PROVIDER: [OSILayer.L7_GOVERNANCE.value],
    AssetArchetype.POLICY_ENGINE: [OSILayer.L7_GOVERNANCE.value],
    AssetArchetype.CLOUD_NETWORK_SEGMENT: [OSILayer.L2_NETWORK.value],
    AssetArchetype.PERIMETER_FIREWALL: [OSILayer.L2_NETWORK.value],
    AssetArchetype.LOAD_BALANCER_INGRESS: [OSILayer.L3_TRANSPORT.value],
    AssetArchetype.CONTAINER_PLATFORM: [OSILayer.L5_APPLICATION.value],
    AssetArchetype.APPLICATION_SERVICE: [OSILayer.L5_APPLICATION.value],
    AssetArchetype.OBJECT_STORAGE: [OSILayer.L6_DATA.value],
    AssetArchetype.RELATIONAL_DATABASE: [OSILayer.L6_DATA.value],
}


OPTIONAL_SECONDARY_LAYERS: Dict[AssetArchetype, List[str]] = {
    AssetArchetype.CONTAINER_PLATFORM: [OSILayer.L7_GOVERNANCE.value],
    AssetArchetype.APPLICATION_SERVICE: [OSILayer.L7_GOVERNANCE.value],
    AssetArchetype.OBJECT_STORAGE: [OSILayer.L7_GOVERNANCE.value],
    AssetArchetype.RELATIONAL_DATABASE: [OSILayer.L7_GOVERNANCE.value],
}


ARCHETYPE_LABELS: Dict[AssetArchetype, str] = {
    AssetArchetype.CLOUD_ACCOUNT_GOVERNANCE: "Cloud account / Control plane",
    AssetArchetype.IDENTITY_PROVIDER: "Identity provider (SSO/LDAP)",
    AssetArchetype.POLICY_ENGINE: "Policy engine / governance automation",
    AssetArchetype.CLOUD_NETWORK_SEGMENT: "Network segment (VPC/VNet/Subnet)",
    AssetArchetype.PERIMETER_FIREWALL: "Perimeter firewall/security group",
    AssetArchetype.LOAD_BALANCER_INGRESS: "Load balancer/ingress gateway",
    AssetArchetype.CONTAINER_PLATFORM: "Container platform/orchestrator",
    AssetArchetype.APPLICATION_SERVICE: "Application runtime/service",
    AssetArchetype.OBJECT_STORAGE: "Object storage/bucket",
    AssetArchetype.RELATIONAL_DATABASE: "Relational database instance",
}


ARCHETYPE_DESCRIPTIONS: Dict[AssetArchetype, str] = {
    AssetArchetype.CLOUD_ACCOUNT_GOVERNANCE: "Cloud account or subscription owning the control plane.",
    AssetArchetype.IDENTITY_PROVIDER: "SSO/Identity platform for authentication and federation.",
    AssetArchetype.POLICY_ENGINE: "Policy automation that governs compliance and drift.",
    AssetArchetype.CLOUD_NETWORK_SEGMENT: "Network boundary such as VPC, VNet, or subnet.",
    AssetArchetype.PERIMETER_FIREWALL: "Firewall, security group, or perimeter ACL.",
    AssetArchetype.LOAD_BALANCER_INGRESS: "Transport termination (load balancer, ingress gateway).",
    AssetArchetype.CONTAINER_PLATFORM: "Container/cluster orchestration platform (EKS/AKS/GKE).",
    AssetArchetype.APPLICATION_SERVICE: "Application service or internal API runtime.",
    AssetArchetype.OBJECT_STORAGE: "Object storage system (S3/Blob/GCS).",
    AssetArchetype.RELATIONAL_DATABASE: "Postgres/MySQL/CloudSQL or managed RDB.",
}


LAYER_ARCHETYPES: Dict[str, List[AssetArchetype]] = {}
for archetype, layers in ALLOWED_LAYERS_BY_ARCHETYPE.items():
    for layer in layers:
        LAYER_ARCHETYPES.setdefault(layer, []).append(archetype)


__all__ = [
    "AssetArchetype",
    "ALLOWED_LAYERS_BY_ARCHETYPE",
    "OPTIONAL_SECONDARY_LAYERS",
    "ARCHETYPE_LABELS",
    "ARCHETYPE_DESCRIPTIONS",
    "LAYER_ARCHETYPES",
]
