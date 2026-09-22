from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class BusinessProcessLearningCompanyProfileVector(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    industry: str = Field(default="", min_length=0, alias="industry")
    size: str = Field(default="", min_length=0, alias="size")
    geography: str = Field(default="", min_length=0, alias="geography")
    business_model_tags: list[str] = Field(default_factory=list, alias="businessModelTags")
    regulatory_flags: list[str] = Field(default_factory=list, alias="regulatoryFlags")
    asset_categories: list[str] = Field(default_factory=list, alias="assetCategories")
    risk_appetite: str = Field(default="", min_length=0, alias="riskAppetite")
    service_count: int = Field(default=0, ge=0, alias="serviceCount")
    asset_count: int = Field(default=0, ge=0, alias="assetCount")
    criticality_distribution: dict[str, int] = Field(default_factory=dict, alias="criticalityDistribution")


class BusinessProcessLearningTemplateLabel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    template_id: str = Field(alias="templateId")
    name: str
    category: str
    source_rule: str = Field(alias="sourceRule")
    status: str


class BusinessProcessLearningDecisionReason(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    decision_log_id: str = Field(alias="decisionLogId")
    recommendation_id: str | None = Field(default=None, alias="recommendationId")
    template_id: str | None = Field(default=None, alias="templateId")
    template_name: str | None = Field(default=None, alias="templateName")
    action: str
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    model_version: str = Field(alias="modelVersion")
    created_at: datetime = Field(alias="createdAt")


class BusinessProcessLearningLabels(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    accepted_process_templates: list[BusinessProcessLearningTemplateLabel] = Field(
        default_factory=list,
        alias="acceptedProcessTemplates",
    )
    removed_process_templates: list[BusinessProcessLearningTemplateLabel] = Field(
        default_factory=list,
        alias="removedProcessTemplates",
    )
    added_process_templates: list[BusinessProcessLearningTemplateLabel] = Field(
        default_factory=list,
        alias="addedProcessTemplates",
    )
    decision_reasons: list[BusinessProcessLearningDecisionReason] = Field(
        default_factory=list,
        alias="decisionReasons",
    )


class BusinessProcessLearningExample(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    organization_id: int = Field(alias="organizationId")
    organization_name: str = Field(alias="organizationName")
    company_profile_vector: BusinessProcessLearningCompanyProfileVector = Field(
        alias="companyProfileVector"
    )
    labels: BusinessProcessLearningLabels


class BusinessProcessLearningDataset(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    generated_at: datetime = Field(alias="generatedAt")
    examples: list[BusinessProcessLearningExample] = Field(default_factory=list)

