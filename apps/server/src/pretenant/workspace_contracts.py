from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from src.api.schemas.timestamps import UtcTimestamp


class WorkspaceOrganizationProfile(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    cvr: str | None = None
    legal_name: str | None = Field(default=None, alias="legalName")
    trade_name: str | None = Field(default=None, alias="tradeName")
    industry_code: str | None = Field(default=None, alias="industryCode")
    industry: str | None = None
    geography: str | None = None
    country: str | None = None
    locations: int | None = None
    confirmed: bool = False


class BusinessService(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    description: str | None = None
    source: Literal["ai_suggested", "manual", "imported"] = "ai_suggested"
    confirmed: bool = False


class WorkspaceAsset(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    asset_type: str = Field(alias="assetType")
    source: Literal["guided", "csv", "json", "cmdb", "manual"]
    provider: str | None = None
    layer: str | None = None
    environment: str | None = None
    critical: bool = False
    import_batch_id: str | None = Field(default=None, alias="importBatchId")
    metadata: dict[str, object] = Field(default_factory=dict)


class BusinessServiceAssetLink(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    business_service_id: str = Field(alias="businessServiceId")
    asset_id: str = Field(alias="assetId")
    relationship_type: Literal["supports", "depends_on", "hosts"] = Field(alias="relationshipType")
    critical: bool = False


class DependencyEdge(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    from_ref: str = Field(alias="fromRef")
    to_ref: str = Field(alias="toRef")
    edge_type: Literal["service_to_service", "asset_to_asset", "service_to_asset"] = Field(alias="edgeType")
    confidence: float = 0.5
    source: Literal["manual", "imported", "ai_inferred"] = "manual"


class CriticalityProfile(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    target_ref: str = Field(alias="targetRef")
    target_type: Literal["business_service", "asset"] = Field(alias="targetType")
    criticality: Literal["low", "medium", "high", "critical"]
    rationale: str | None = None


class RiskAppetiteProfile(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    profile: Literal["conservative", "balanced", "aggressive"]
    narrative: str | None = None
    max_tolerable_disruption_hours: int | None = Field(default=None, alias="maxTolerableDisruptionHours")
    max_tolerable_data_exposure_level: str | None = Field(default=None, alias="maxTolerableDataExposureLevel")


class OnboardingValueStream(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    key: str
    name: str
    description: str | None = None
    priority: Literal["critical", "important", "standard"]
    source: Literal["inferred", "user_added"]
    confidence: str | None = None
    inference_reason: str | None = Field(default=None, alias="inferenceReason")


class OnboardingValueStreamProfile(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    nace_code: str | None = Field(default=None, alias="naceCode")
    confirmed_at: UtcTimestamp | None = Field(default=None, alias="confirmedAt")
    streams: list[OnboardingValueStream] = Field(default_factory=list)


class KriDefinition(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    code: str
    name: str
    domain: str
    rationale: str | None = None
    threshold_hint: str | None = Field(default=None, alias="thresholdHint")


class InitialStructuralInsight(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    summary: str
    focal_points: list[str] = Field(default_factory=list, alias="focalPoints")
    inferred_dependencies: int = Field(default=0, alias="inferredDependencies")
    confidence_band: Literal["low", "medium", "high"] = Field(default="medium", alias="confidenceBand")


class OnboardingWorkspace(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    version: str = "workspace.v1"
    session_id: str = Field(alias="sessionId")
    current_step: str = Field(alias="currentStep")
    organization: WorkspaceOrganizationProfile
    business_services: list[BusinessService] = Field(default_factory=list, alias="businessServices")
    assets: list[WorkspaceAsset] = Field(default_factory=list)
    service_asset_links: list[BusinessServiceAssetLink] = Field(default_factory=list, alias="serviceAssetLinks")
    dependency_edges: list[DependencyEdge] = Field(default_factory=list, alias="dependencyEdges")
    criticality_profiles: list[CriticalityProfile] = Field(default_factory=list, alias="criticalityProfiles")
    risk_appetite_profile: RiskAppetiteProfile | None = Field(default=None, alias="riskAppetiteProfile")
    value_stream_profile: OnboardingValueStreamProfile | None = Field(default=None, alias="valueStreamProfile")
    starter_kris: list[KriDefinition] = Field(default_factory=list, alias="starterKris")
    initial_structural_insight: InitialStructuralInsight | None = Field(default=None, alias="initialStructuralInsight")
    updated_at: UtcTimestamp = Field(default_factory=lambda: datetime.now(timezone.utc), alias="updatedAt")


class OnboardingWorkspacePatch(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    organization: WorkspaceOrganizationProfile | None = None
    business_services: list[BusinessService] | None = Field(default=None, alias="businessServices")
    assets: list[WorkspaceAsset] | None = None
    service_asset_links: list[BusinessServiceAssetLink] | None = Field(default=None, alias="serviceAssetLinks")
    dependency_edges: list[DependencyEdge] | None = Field(default=None, alias="dependencyEdges")
    criticality_profiles: list[CriticalityProfile] | None = Field(default=None, alias="criticalityProfiles")
    risk_appetite_profile: RiskAppetiteProfile | None = Field(default=None, alias="riskAppetiteProfile")
    value_stream_profile: OnboardingValueStreamProfile | None = Field(default=None, alias="valueStreamProfile")
    starter_kris: list[KriDefinition] | None = Field(default=None, alias="starterKris")
    initial_structural_insight: InitialStructuralInsight | None = Field(default=None, alias="initialStructuralInsight")


class WorkspaceSynthesisResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    workspace: OnboardingWorkspace
    generated: bool = True
