from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from src.pretenant.risk_intelligence import MODEL_VERSION, OrganisationProfile, RiskIntelligenceEngine

router = APIRouter(prefix="/risk-intel", tags=["Risk Intelligence"])

_ALLOWED_ASSET_CATEGORIES = {
    "identity",
    "endpoint",
    "email",
    "network",
    "cloud",
    "backup",
    "vendor",
    "application",
    "data",
}
_ALLOWED_REGULATORY_FLAGS = {"GDPR", "NIS2", "PCI", "ISO27001", "DORA", "SOC2"}


class OrganisationProfileIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    industry_code: str = Field(alias="industryCode", min_length=1, max_length=20)
    size_bracket: Literal["micro", "small", "smb", "mid", "enterprise"] = Field(alias="sizeBracket")
    geography: str = Field(min_length=2, max_length=2)
    locations: int = Field(ge=0, le=100000)
    it_dependency: Literal["low", "medium", "high", "critical"] = Field(alias="itDependency")
    risk_appetite: Literal["conservative", "balanced", "aggressive"] = Field(alias="riskAppetite")
    selected_asset_categories: list[str] = Field(alias="selectedAssetCategories", min_length=1, max_length=50)
    regulatory_flags: list[str] | None = Field(default=None, alias="regulatoryFlags", max_length=20)
    business_model_tags: list[str] | None = Field(default=None, alias="businessModelTags", max_length=20)


class ComputeBaselineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_version: str | None = Field(default=None, alias="modelVersion")
    organisation_profile: OrganisationProfileIn = Field(alias="organisationProfile")


class ComputeBaselineResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    model_version: str = Field(alias="modelVersion")
    baseline_risk_landscape: dict = Field(alias="baselineRiskLandscape")


def _resolve_model_version(requested: str | None) -> str:
    if requested in (None, "", "current", MODEL_VERSION):
        return MODEL_VERSION
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={
            "error_type": "unsupported_model_version",
            "message": "Unsupported model version",
        },
    )


def _normalize_unique(values: list[str] | None, *, upper: bool = False) -> list[str]:
    normalized = [v.strip() for v in (values or []) if v and v.strip()]
    normalized = [v.upper() if upper else v.lower() for v in normalized]
    return sorted(set(normalized))


def _validate_allowed(values: list[str], *, allowed: set[str], field_name: str) -> list[str]:
    invalid = [v for v in values if v not in allowed]
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error_type": "validation_failed",
                "message": f"Invalid values for {field_name}",
                "invalidValues": invalid,
            },
        )
    return values


@router.post("/baseline", response_model=ComputeBaselineResponse)
def compute_baseline(payload: ComputeBaselineRequest):
    profile_in = payload.organisation_profile
    selected_asset_categories = _validate_allowed(
        _normalize_unique(profile_in.selected_asset_categories),
        allowed=_ALLOWED_ASSET_CATEGORIES,
        field_name="selectedAssetCategories",
    )
    if not selected_asset_categories:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error_type": "insufficient_data",
                "message": "selectedAssetCategories is required",
            },
        )

    regulatory_flags = _validate_allowed(
        _normalize_unique(profile_in.regulatory_flags, upper=True),
        allowed=_ALLOWED_REGULATORY_FLAGS,
        field_name="regulatoryFlags",
    )
    business_model_tags = _normalize_unique(profile_in.business_model_tags)
    model_version = _resolve_model_version(payload.model_version)
    engine = RiskIntelligenceEngine(model_version=model_version)
    profile = OrganisationProfile(
        cvr="draft-only",
        legal_name="draft-only",
        industry_code=profile_in.industry_code,
        size_bracket=profile_in.size_bracket,
        geography=profile_in.geography.upper(),
        locations=profile_in.locations,
        it_dependency=profile_in.it_dependency,
        risk_appetite=profile_in.risk_appetite,
        selected_asset_categories=selected_asset_categories,
        regulatory_flags=regulatory_flags,
        business_model_tags=business_model_tags,
    )
    baseline = engine.generate_baseline(profile)
    return {
        "modelVersion": baseline.model_version,
        "baselineRiskLandscape": baseline.as_contract_payload(),
    }
