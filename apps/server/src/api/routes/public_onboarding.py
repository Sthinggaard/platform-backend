from __future__ import annotations

import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.core.logging_config import get_logger
from src.pretenant.enrichment import (
    CvrEnrichmentClient,
    CvrNotFoundError,
    CvrOrganisationLookupResult,
    CvrTimeoutError,
    normalize_vat,
)
from src.pretenant.company_assumptions import build_company_assumption_preview
from src.pretenant.company_context_enums import (
    CriticalBusinessActivity,
    CustomerVisibleImpact,
    HardToReplaceQuickly,
    OperationalReach,
    PrimaryBusinessActivity,
    TimeSensitivity,
)
from src.pretenant.risk_intel_client import RiskIntelligenceClient
from src.pretenant.risk_intelligence import (
    OrganisationProfile,
    RiskIntelligenceEngine,
    RiskModelUnavailableError,
)
from src.pretenant.store import (
    PRETENANT_STORE,
    DraftOrganisation,
    DraftStatus,
    VerifiedOrganisationProfile,
)
from src.pretenant.workspace_service import load_workspace
from src.utils.feature_flags import is_enabled
from src.api.schemas.timestamps import UtcTimestamp

router = APIRouter(prefix="/public/onboarding", tags=["Public Onboarding"])

_RATE_LIMIT_PER_MINUTE = 30
_ORG_LOOKUP_RATE_LIMIT_PER_MINUTE = int(os.getenv("PRETENANT_ORG_LOOKUP_RATE_LIMIT_PER_MINUTE", "12"))
_ORG_CONFIRM_RATE_LIMIT_PER_MINUTE = int(os.getenv("PRETENANT_ORG_CONFIRM_RATE_LIMIT_PER_MINUTE", "8"))
_rate_limit_counters: dict[str, dict[str, float]] = {}
logger = get_logger(__name__)
_enrichment_client = CvrEnrichmentClient()
_risk_intelligence_engine = RiskIntelligenceEngine()
_risk_intelligence_client = RiskIntelligenceClient(
    engine_factory=lambda: _risk_intelligence_engine,
    mode=os.getenv("PRETENANT_RI_CLIENT_MODE", "inprocess").strip().lower() or "inprocess",
)
_SESSION_ID_HEADER = "x-onboarding-session-id"
PUBLIC_BASELINE_ASSUMPTION_STATUS = "preview"


class PublicOnboardingEventRequest(BaseModel):
    event_type: str = Field(..., min_length=1, max_length=80)
    details: dict[str, Any] = Field(default_factory=dict)


def _sleep_remaining(start: float, min_duration_ms: int) -> None:
    elapsed_ms = (time.monotonic() - start) * 1000
    remaining = max(0.0, (min_duration_ms - elapsed_ms) / 1000.0)
    if remaining:
        time.sleep(remaining)


def _enforce_public_rate_limit(
    request: Request,
    route_key: str,
    limit_per_minute: int,
    *,
    session_hint: str | None = None,
) -> None:
    client_ip = request.client.host if request.client else "unknown"
    effective_session_hint = session_hint or (request.headers.get(_SESSION_ID_HEADER) or "-").strip() or "-"
    now = time.time()
    window = int(now // 60)
    key = f"{route_key}:{client_ip}:{effective_session_hint}:{window}"
    counter = _rate_limit_counters.get(key, {"count": 0, "ts": window})
    counter["count"] += 1
    _rate_limit_counters[key] = counter

    stale_keys = [k for k in _rate_limit_counters if k.endswith(f":{window-2}")]
    for stale_key in stale_keys:
        _rate_limit_counters.pop(stale_key, None)

    if counter["count"] > limit_per_minute:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error_type": "rate_limit",
                "message": "Rate limit exceeded",
            },
            headers={"Retry-After": "60"},
        )


def _resolve_confirm_session_id(session_id: str) -> str:
    session_id = session_id.strip()
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_type": "invalid_session_id",
                "message": "Invalid onboarding session id",
            },
        )

    status_value = PRETENANT_STORE.get_session_status(session_id)
    if status_value == "expired":
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={
                "error_type": "session_expired",
                "message": "Onboarding session expired",
            },
        )
    if status_value == "missing":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )

    draft_org = PRETENANT_STORE.get_draft_org(session_id)
    if not draft_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )
    if draft_org.status.upper() != "DRAFT":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_type": "draft_locked",
                "message": "Draft is locked",
            },
        )
    return session_id


def _lookup_org_core(vat: str) -> CvrOrganisationLookupResult:
    try:
        return _enrichment_client.lookup_verified_organisation(vat)
    except CvrNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "cvr_not_found",
                "message": "Company information unavailable",
            },
        ) from err
    except CvrTimeoutError as err:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error_type": "enrichment_timeout",
                "message": "Enrichment service unavailable",
            },
        ) from err


def _lookup_response_payload(result: CvrOrganisationLookupResult) -> dict[str, Any]:
    return {
        "vat": result.vat,
        "name": result.name,
        "legalForm": result.legal_form,
        "industry": result.industry,
        "orgSizeBand": result.org_size_band,
        "employeeCount": result.employee_count,
        "siteCount": result.site_count,
        "multiSite": result.multi_site,
        "lifecycleStage": result.lifecycle_stage,
    }


class StartPublicOnboardingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class StartPublicOnboardingResponse(BaseModel):
    session_id: str = Field(alias="sessionId")
    expires_at: UtcTimestamp = Field(alias="expiresAt")
    next_step: str = Field(alias="nextStep")


class ResumeDraftCompanyDetails(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    legal_name: str | None = Field(default=None, alias="legalName")
    industry_code: str | None = Field(default=None, alias="industryCode")
    geography: str | None = None


class ResumeDraftSnapshot(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    cvr: str | None = None
    company_details: ResumeDraftCompanyDetails | None = Field(default=None, alias="companyDetails")
    risk_appetite: str | None = Field(default=None, alias="riskAppetite")
    selected_asset_categories: list[str] | None = Field(default=None, alias="selectedAssetCategories")
    baseline_computed: bool = Field(alias="baselineComputed")


class ResumePublicOnboardingResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    session_id: str = Field(alias="sessionId")
    expires_at: UtcTimestamp = Field(alias="expiresAt")
    current_step: str = Field(alias="currentStep")
    draft_snapshot: ResumeDraftSnapshot = Field(alias="draftSnapshot")
    # Kept during transition to avoid breaking existing clients relying on nextStep.
    next_step: str = Field(alias="nextStep")


class CvrEnrichmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cvr: str = Field(..., min_length=1, max_length=64)

    @field_validator("cvr")
    @classmethod
    def _normalize_cvr(cls, value: str) -> str:
        normalized = re.sub(r"\D+", "", value or "")
        if len(normalized) != 8 or not normalized.isdigit():
            raise ValueError("cvr must be 8 digits")
        return normalized


class BusinessContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    primary_business_activity: PrimaryBusinessActivity | None = Field(default=None, alias="primaryBusinessActivity")
    critical_business_activity: CriticalBusinessActivity | None = Field(default=None, alias="criticalBusinessActivity")
    customer_visible_impact: list[CustomerVisibleImpact] | None = Field(default=None, alias="customerVisibleImpact")
    time_sensitivity: TimeSensitivity | None = Field(default=None, alias="timeSensitivity")
    hard_to_replace_quickly: list[HardToReplaceQuickly] | None = Field(default=None, alias="hardToReplaceQuickly")
    operational_reach: OperationalReach | None = Field(default=None, alias="operationalReach")


class CvrEnrichmentResponse(BaseModel):
    cvr: str
    legal_name: str = Field(alias="legalName")
    trade_name: str | None = Field(default=None, alias="tradeName")
    address: str | None = None
    postal_code: str | None = Field(default=None, alias="postalCode")
    city: str | None = None
    country: str = "DK"
    industry_code: str | None = Field(default=None, alias="industryCode")
    industry: str | None = None
    size_bracket: str | None = Field(default=None, alias="sizeBracket")
    geography: str | None = None


class CvrAssumptionPreviewResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    archetype_key: str = Field(alias="archetypeKey")
    archetype_label: str = Field(alias="archetypeLabel")
    summary: str
    headline: str
    source: dict[str, Any]
    business_context: dict[str, str | list[str]] = Field(default_factory=dict, alias="businessContext")
    confidence: dict[str, Any]
    completeness: dict[str, Any]
    suggested_processes: list[dict[str, Any]] = Field(alias="suggestedProcesses")
    flagship_process: dict[str, Any] | None = Field(default=None, alias="flagshipProcess")
    focus_areas: list[dict[str, Any]] = Field(alias="focusAreas")
    continuity_assumption: dict[str, Any] = Field(alias="continuityAssumption")
    assumptions: list[dict[str, str]]


class CvrLookupDraftOrganisationResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    cvr: str
    legal_name: str = Field(alias="legalName")
    trade_name: str | None = Field(default=None, alias="tradeName")
    address: str | None = None
    postal_code: str | None = Field(default=None, alias="postalCode")
    city: str | None = None
    country: str | None = None
    industry_code: str | None = Field(default=None, alias="industryCode")
    industry: str | None = None
    size_bracket: str | None = Field(default=None, alias="sizeBracket")
    geography: str | None = None


class CvrLookupResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    session_id: str = Field(alias="sessionId")
    expires_at: UtcTimestamp = Field(alias="expiresAt")
    next_step: str = Field(alias="nextStep")
    draft_organisation: CvrLookupDraftOrganisationResponse = Field(alias="draftOrganisation")
    assumption_preview: CvrAssumptionPreviewResponse = Field(alias="assumptionPreview")


class OrgLookupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vat: str = Field(..., min_length=1, max_length=64)

    @field_validator("vat")
    @classmethod
    def _normalize_vat(cls, value: str) -> str:
        normalized = normalize_vat(value)
        if not normalized:
            raise ValueError("vat must be 8 digits")
        return normalized


class OrgLookupResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    vat: str
    name: str
    legal_form: str = Field(alias="legalForm")
    industry: str
    org_size_band: str = Field(alias="orgSizeBand")
    employee_count: int = Field(alias="employeeCount")
    site_count: int = Field(alias="siteCount")
    multi_site: bool = Field(alias="multiSite")
    lifecycle_stage: str = Field(alias="lifecycleStage")


class OrgConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vat: str = Field(..., min_length=1, max_length=64)
    session_id: str = Field(..., alias="sessionId", min_length=3, max_length=256)
    confirmed: bool

    @field_validator("vat")
    @classmethod
    def _normalize_vat(cls, value: str) -> str:
        normalized = normalize_vat(value)
        if not normalized:
            raise ValueError("vat must be 8 digits")
        return normalized

    @field_validator("session_id")
    @classmethod
    def _validate_session_id(cls, value: str) -> str:
        session_id = value.strip()
        if not re.fullmatch(r"^[A-Za-z0-9_-]{3,256}$", session_id):
            raise ValueError("sessionId is invalid")
        return session_id


class OrgConfirmResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    vat: str
    name: str
    industry_cluster: str = Field(alias="industryCluster")
    org_size_band: str = Field(alias="orgSizeBand")
    legal_form_band: str = Field(alias="legalFormBand")
    site_count: int = Field(alias="siteCount")
    multi_site: bool = Field(alias="multiSite")
    lifecycle_stage: str = Field(alias="lifecycleStage")
    confirmation_timestamp: UtcTimestamp = Field(alias="confirmationTimestamp")
    session_id: str = Field(alias="sessionId")


class BaselineRiskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    force_recompute: bool = Field(default=False, alias="forceRecompute")


class BaselineRiskResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    session_id: str | None = Field(default=None, alias="sessionId")
    expires_at: UtcTimestamp | None = Field(default=None, alias="expiresAt")
    baseline: dict | None = None
    model_version: str = Field(alias="modelVersion")
    baseline_risk_landscape: dict | None = Field(default=None, alias="baselineRiskLandscape")
    baseline_status: str | None = Field(default=None, alias="baselineStatus")
    baseline_computed_at: UtcTimestamp | None = Field(default=None, alias="baselineComputedAt")
    assumption_status: str = Field(alias="assumptionStatus")
    requires_human_review: bool = Field(alias="requiresHumanReview")


class PublicOnboardingDraftResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    session_id: str = Field(alias="sessionId")
    expires_at: UtcTimestamp = Field(alias="expiresAt")
    current_step: str | None = Field(default=None, alias="currentStep")
    cvr: str | None = None
    legal_name: str | None = Field(default=None, alias="legalName")
    trade_name: str | None = Field(default=None, alias="tradeName")
    address: str | None = None
    postal_code: str | None = Field(default=None, alias="postalCode")
    city: str | None = None
    country: str | None = None
    industry_code: str | None = Field(default=None, alias="industryCode")
    size_bracket: str | None = Field(default=None, alias="sizeBracket")
    geography: str | None = None
    locations: int | None = None
    it_dependency: str | None = Field(default=None, alias="itDependency")
    risk_appetite: str | None = Field(default=None, alias="riskAppetite")
    selected_asset_categories: list[str] | None = Field(default=None, alias="selectedAssetCategories")
    regulatory_flags: list[str] | None = Field(default=None, alias="regulatoryFlags")
    baseline_status: str | None = Field(default=None, alias="baselineStatus")
    model_version: str | None = Field(default=None, alias="modelVersion")
    baseline_risk_landscape: dict | None = Field(default=None, alias="baselineRiskLandscape")
    draft_organisation: Optional["PublicOnboardingDraftOrganisationResponse"] = Field(
        default=None,
        alias="draftOrganisation",
    )


class PublicOnboardingDraftOrganisationResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    cvr: str | None = None
    legal_name: str | None = Field(default=None, alias="legalName")
    trade_name: str | None = Field(default=None, alias="tradeName")
    address: str | None = None
    postal_code: str | None = Field(default=None, alias="postalCode")
    city: str | None = None
    country: str | None = None
    industry_code: str | None = Field(default=None, alias="industryCode")
    size_bracket: str | None = Field(default=None, alias="sizeBracket")
    geography: str | None = None
    locations: int | None = None
    it_dependency: str | None = Field(default=None, alias="itDependency")
    risk_appetite: str | None = Field(default=None, alias="riskAppetite")
    selected_asset_categories: list[str] | None = Field(default=None, alias="selectedAssetCategories")
    regulatory_flags: list[str] | None = Field(default=None, alias="regulatoryFlags")
    baseline_status: str | None = Field(default=None, alias="baselineStatus")


PublicOnboardingDraftResponse.model_rebuild()


class FinalizePublicOnboardingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FinalizePublicOnboardingResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    session_id: str = Field(alias="sessionId")
    draft_status: str = Field(alias="draftStatus")
    redirect_url: str = Field(alias="redirectUrl")
    token_expires_at: UtcTimestamp = Field(alias="tokenExpiresAt")


_PATCH_FIELD_MAP = {
    "legalName": "legal_name",
    "tradeName": "trade_name",
    "address": "address",
    "postalCode": "postal_code",
    "city": "city",
    "country": "country",
    "industryCode": "industry_code",
    "sizeBracket": "size_bracket",
    "geography": "geography",
    "locations": "locations",
    "itDependency": "it_dependency",
    "riskAppetite": "risk_appetite",
    "selectedAssetCategories": "selected_asset_categories",
    "regulatoryFlags": "regulatory_flags",
    "rerunBaseline": "rerun_baseline",
}

_PATCH_MAX_LENGTHS = {
    "legalName": 200,
    "tradeName": 200,
    "address": 300,
    "postalCode": 20,
    "city": 100,
    "country": 2,
    "industryCode": 20,
    "sizeBracket": 40,
    "geography": 8,
}

_IT_DEPENDENCY_ALLOWED = {"low", "medium", "high", "critical"}
_RISK_APPETITE_ALLOWED = {"conservative", "balanced", "aggressive"}
_SIZE_BRACKET_ALLOWED = {"micro", "small", "smb", "mid", "enterprise"}
_REGULATORY_FLAGS_ALLOWED = {"GDPR", "NIS2", "PCI", "ISO27001", "DORA", "SOC2"}
_ASSET_CATEGORY_ALLOWED = {
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

_BASELINE_MATERIAL_PATCH_FIELDS = {
    "cvr",
    "legal_name",
    "country",
    "industry_code",
    "city",
    "size_bracket",
    "geography",
    "locations",
    "it_dependency",
    "risk_appetite",
    "selected_asset_categories",
    "regulatory_flags",
}

_SIGNUP_REDIRECT_PATH = "/signup"


def _draft_hash(session_id: str) -> str | None:
    draft_org = PRETENANT_STORE.get_draft_org(session_id)
    if not draft_org:
        return None
    payload = {
        "id": draft_org.id,
        "status": draft_org.status,
        "cvr": draft_org.cvr,
        "legal_name": draft_org.legal_name,
        "trade_name": draft_org.trade_name,
        "address": draft_org.address,
        "postal_code": draft_org.postal_code,
        "city": draft_org.city,
        "country": draft_org.country,
        "industry_code": draft_org.industry_code,
        "size_bracket": draft_org.size_bracket,
        "geography": draft_org.geography,
        "locations": draft_org.locations,
        "it_dependency": draft_org.it_dependency,
        "risk_appetite": draft_org.risk_appetite,
        "selected_asset_categories": draft_org.selected_asset_categories,
        "regulatory_flags": draft_org.regulatory_flags,
        "baseline_snapshot": draft_org.baseline_snapshot,
        "baseline_model_version": draft_org.baseline_model_version,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _baseline_status(draft_org: DraftOrganisation) -> str:
    if not draft_org.baseline_snapshot or not draft_org.baseline_model_version:
        return "MISSING"
    return "STALE" if draft_org.baseline_stale else "FRESH"


def _baseline_input_hash_for_draft(draft_org: DraftOrganisation) -> str:
    selected_asset_categories = sorted(set(draft_org.selected_asset_categories or [])) or None
    regulatory_flags = sorted(set(draft_org.regulatory_flags or [])) or None
    payload = {
        "cvr": draft_org.cvr,
        "legal_name": draft_org.legal_name,
        "country": draft_org.country,
        "industry_code": draft_org.industry_code,
        "city": draft_org.city,
        "size_bracket": draft_org.size_bracket,
        "geography": draft_org.geography,
        "locations": draft_org.locations,
        "it_dependency": draft_org.it_dependency,
        "risk_appetite": draft_org.risk_appetite,
        "selected_asset_categories": selected_asset_categories,
        "regulatory_flags": regulatory_flags,
        "workspace_snapshot": draft_org.workspace_snapshot,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=lambda value: value.isoformat() if isinstance(value, datetime) else str(value),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _workspace_asset_categories(session_id: str, draft_org: DraftOrganisation) -> list[str]:
    workspace = load_workspace(session_id, draft_org)
    categories: set[str] = set()
    for asset in workspace.assets:
        candidate = asset.layer or asset.asset_type or asset.name
        if candidate and candidate.strip():
            categories.add(
                re.sub(r"[^a-z0-9]+", "_", candidate.strip().lower()).strip("_")[:64]
            )
    return sorted(categories)


def _workspace_business_model_tags(session_id: str, draft_org: DraftOrganisation) -> list[str]:
    workspace = load_workspace(session_id, draft_org)
    tags: set[str] = set()
    for service in workspace.business_services:
        if service.confirmed:
            tags.add(f"service:{service.id}")
    for profile in workspace.criticality_profiles:
        if profile.target_type == "business_service":
            tags.add(f"criticality:{profile.criticality}")
    if workspace.service_asset_links:
        tags.add(f"mapped_services:{len({link.business_service_id for link in workspace.service_asset_links})}")
        tags.add(f"mapped_assets:{len({link.asset_id for link in workspace.service_asset_links})}")
    return sorted(tags)


def _draft_response(session_id: str):
    session = PRETENANT_STORE.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )
    draft_org = PRETENANT_STORE.get_draft_org(session_id)
    if not draft_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )
    baseline_status = _baseline_status(draft_org)
    draft_organisation = {
        "cvr": draft_org.cvr,
        "legalName": draft_org.legal_name,
        "tradeName": draft_org.trade_name,
        "address": draft_org.address,
        "postalCode": draft_org.postal_code,
        "city": draft_org.city,
        "country": draft_org.country,
        "industryCode": draft_org.industry_code,
        "sizeBracket": draft_org.size_bracket,
        "geography": draft_org.geography,
        "locations": draft_org.locations,
        "itDependency": draft_org.it_dependency,
        "riskAppetite": draft_org.risk_appetite,
        "selectedAssetCategories": draft_org.selected_asset_categories,
        "regulatoryFlags": draft_org.regulatory_flags,
        "baselineStatus": baseline_status,
    }
    return {
        "sessionId": session.id,
        "expiresAt": session.expires_at,
        "currentStep": _resume_current_step(draft_org),
        "cvr": draft_org.cvr,
        "legalName": draft_org.legal_name,
        "tradeName": draft_org.trade_name,
        "address": draft_org.address,
        "postalCode": draft_org.postal_code,
        "city": draft_org.city,
        "country": draft_org.country,
        "industryCode": draft_org.industry_code,
        "sizeBracket": draft_org.size_bracket,
        "geography": draft_org.geography,
        "locations": draft_org.locations,
        "itDependency": draft_org.it_dependency,
        "riskAppetite": draft_org.risk_appetite,
        "selectedAssetCategories": draft_org.selected_asset_categories,
        "regulatoryFlags": draft_org.regulatory_flags,
        "baselineStatus": baseline_status,
        "modelVersion": draft_org.baseline_model_version,
        "baselineRiskLandscape": draft_org.baseline_snapshot,
        "draftOrganisation": draft_organisation,
    }


def _resume_current_step(draft_org: DraftOrganisation) -> str:
    if not draft_org.cvr:
        return "CVR_ENTRY"
    if not draft_org.baseline_snapshot or not draft_org.baseline_model_version:
        return "CONTEXT_CONFIRM"
    return "BASELINE_PREVIEW"


def _resume_draft_snapshot(draft_org: DraftOrganisation) -> dict[str, Any]:
    company_details: dict[str, Any] = {}
    if draft_org.legal_name:
        company_details["legalName"] = draft_org.legal_name
    if draft_org.industry_code:
        company_details["industryCode"] = draft_org.industry_code
    if draft_org.size_bracket:
        company_details["sizeBracket"] = draft_org.size_bracket
    if draft_org.country:
        company_details["geography"] = draft_org.country

    snapshot: dict[str, Any] = {
        "baselineComputed": bool(draft_org.baseline_snapshot and draft_org.baseline_model_version),
    }
    if draft_org.cvr:
        snapshot["cvr"] = draft_org.cvr
    if company_details:
        snapshot["companyDetails"] = company_details
    return snapshot


def _enrich_cvr_core(session_id: str, cvr: str) -> tuple[Any, DraftOrganisation, Any]:
    start = time.monotonic()
    min_duration_ms = 250
    status_value = PRETENANT_STORE.get_session_status(session_id)
    if status_value == "expired":
        _sleep_remaining(start, min_duration_ms)
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={
                "error_type": "session_expired",
                "message": "Onboarding session expired",
            },
        )
    if status_value == "missing":
        _sleep_remaining(start, min_duration_ms)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )

    session = PRETENANT_STORE.get_session(session_id)
    draft_org = PRETENANT_STORE.get_draft_org(session_id)
    if not session or not draft_org:
        _sleep_remaining(start, min_duration_ms)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )
    if draft_org.status.upper() != "DRAFT":
        _sleep_remaining(start, min_duration_ms)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_type": "draft_locked",
                "message": "Draft is locked",
            },
        )

    try:
        result = _enrichment_client.enrich(cvr)
    except CvrNotFoundError as err:
        _sleep_remaining(start, min_duration_ms)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "cvr_not_found",
                "message": "Company information unavailable",
            },
        ) from err
    except CvrTimeoutError as err:
        _sleep_remaining(start, min_duration_ms)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error_type": "enrichment_timeout",
                "message": "Enrichment service unavailable",
            },
        ) from err

    updated = PRETENANT_STORE.update_draft_org(
        session_id,
        cvr=result.cvr,
        legal_name=result.legal_name,
        trade_name=result.trade_name,
        address=result.address,
        postal_code=result.postal_code,
        city=result.city,
        country=result.country,
        industry_code=result.industry_code,
        industry_description=result.industry_desc,
        size_bracket=result.size_bracket,
        geography=result.geography,
        last_enriched_at=result.enriched_at,
    )
    if not updated:
        _sleep_remaining(start, min_duration_ms)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )
    _sleep_remaining(start, min_duration_ms)
    return session, updated, result


def _bad_patch_request(message: str, **kwargs):
    detail: dict[str, Any] = {"error_type": "invalid_fields", "message": message}
    detail.update(kwargs)
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _bad_patch_semantic(message: str, **kwargs):
    detail: dict[str, Any] = {"error_type": "validation_failed", "message": message}
    detail.update(kwargs)
    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=detail)


def _require_active_session(session_id: str) -> None:
    status_value = PRETENANT_STORE.get_session_status(session_id)
    if status_value == "expired":
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={
                "error_type": "session_expired",
                "message": "Onboarding session expired",
            },
        )
    if status_value == "missing":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )


def _validate_finalize_completeness(session_id: str) -> None:
    draft_org = PRETENANT_STORE.get_draft_org(session_id)
    if not draft_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )
    missing_fields: list[str] = []
    if not draft_org.cvr:
        missing_fields.append("cvr")
    if not draft_org.legal_name:
        missing_fields.append("legal_name")
    if not draft_org.country:
        missing_fields.append("country")
    if missing_fields:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_type": "incomplete_draft",
                "message": "Draft is incomplete",
                "missing_fields": missing_fields,
            },
        )


def _validate_patch_payload(payload: Any) -> tuple[dict[str, Any], bool]:
    if not isinstance(payload, dict):
        _bad_patch_request("Payload must be a JSON object")

    unknown_fields = sorted([key for key in payload if key not in _PATCH_FIELD_MAP])
    if unknown_fields:
        _bad_patch_request("Invalid fields in payload", invalid_fields=unknown_fields)

    updates: dict[str, Any] = {}
    rerun_baseline = False
    for key, value in payload.items():
        if key == "rerunBaseline":
            if not isinstance(value, bool):
                _bad_patch_request("rerunBaseline must be a boolean", field=key)
            rerun_baseline = value
            continue
        if value is None:
            continue
        if key == "locations":
            if not isinstance(value, int) or isinstance(value, bool):
                _bad_patch_request("locations must be an integer", field=key)
            if value < 0 or value > 100000:
                _bad_patch_semantic("locations out of range", field=key)
            updates[_PATCH_FIELD_MAP[key]] = value
            continue

        if key in {"selectedAssetCategories", "regulatoryFlags"}:
            if not isinstance(value, list):
                _bad_patch_request(f"{key} must be an array", field=key)
            if len(value) > 50:
                _bad_patch_semantic(f"{key} exceeds max length 50", field=key)
            normalized_list: list[str] = []
            seen: set[str] = set()
            allowed = _ASSET_CATEGORY_ALLOWED if key == "selectedAssetCategories" else _REGULATORY_FLAGS_ALLOWED
            for item in value:
                if not isinstance(item, str):
                    _bad_patch_request(f"{key} values must be strings", field=key)
                token = item.strip()
                if not token:
                    _bad_patch_request(f"{key} contains empty value", field=key)
                canon = token.lower() if key == "selectedAssetCategories" else token.upper()
                if canon in seen:
                    continue
                if canon not in allowed:
                    _bad_patch_semantic(f"{key} contains unsupported value", field=key, value=canon)
                seen.add(canon)
                normalized_list.append(canon)
            updates[_PATCH_FIELD_MAP[key]] = normalized_list
            continue

        if not isinstance(value, str):
            _bad_patch_request(f"{key} must be a string", field=key)
        normalized = value.strip()
        if not normalized:
            _bad_patch_request(f"{key} cannot be empty", field=key)
        max_len = _PATCH_MAX_LENGTHS.get(key)
        if max_len is not None and len(normalized) > max_len:
            _bad_patch_request(f"{key} exceeds max length {max_len}", field=key)

        if key == "country":
            if len(normalized) != 2 or not normalized.isalpha():
                _bad_patch_request("country must be a 2-letter code", field=key)
            normalized = normalized.upper()
        elif key == "geography":
            if len(normalized) != 2 or not normalized.isalpha():
                _bad_patch_semantic("geography must be a 2-letter country code", field=key)
            normalized = normalized.upper()
        elif key == "itDependency":
            normalized = normalized.lower()
            if normalized not in _IT_DEPENDENCY_ALLOWED:
                _bad_patch_semantic("Unsupported itDependency", field=key, value=normalized)
        elif key == "riskAppetite":
            normalized = normalized.lower()
            if normalized not in _RISK_APPETITE_ALLOWED:
                _bad_patch_semantic("Unsupported riskAppetite", field=key, value=normalized)
        elif key == "sizeBracket":
            normalized = normalized.lower()
            if normalized not in _SIZE_BRACKET_ALLOWED:
                _bad_patch_semantic("Unsupported sizeBracket", field=key, value=normalized)

        updates[_PATCH_FIELD_MAP[key]] = normalized

    if not updates and not rerun_baseline:
        _bad_patch_request("At least one allowed field or rerunBaseline=true is required")
    return updates, rerun_baseline


def _build_organisation_profile(session_id: str) -> OrganisationProfile:
    draft_org = PRETENANT_STORE.get_draft_org(session_id)
    if not draft_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )
    workspace = load_workspace(session_id, draft_org)
    selected_asset_categories = _workspace_asset_categories(session_id, draft_org) or list(draft_org.selected_asset_categories or [])
    missing_fields = []
    if not draft_org.cvr:
        missing_fields.append("cvr")
    if not draft_org.legal_name:
        missing_fields.append("legalName")
    if not draft_org.industry_code:
        missing_fields.append("industryCode")
    geography = draft_org.geography or draft_org.country
    if not geography:
        missing_fields.append("geography")
    if draft_org.locations is None:
        missing_fields.append("locations")
    if not draft_org.it_dependency:
        missing_fields.append("itDependency")
    if not draft_org.risk_appetite:
        missing_fields.append("riskAppetite")
    if not selected_asset_categories:
        missing_fields.append("selectedAssetCategories")
    if not workspace.service_asset_links:
        missing_fields.append("serviceAssetLinks")
    if not workspace.criticality_profiles:
        missing_fields.append("criticalityProfiles")
    if missing_fields:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error_type": "draft_incomplete",
                "message": "Draft profile is incomplete for baseline generation",
                "missingFields": missing_fields,
            },
        )
    return OrganisationProfile(
        cvr=draft_org.cvr,
        legal_name=draft_org.legal_name,
        industry_code=draft_org.industry_code,
        size_bracket=draft_org.size_bracket or "smb",
        geography=geography or "DK",
        locations=int(draft_org.locations or 0),
        it_dependency=draft_org.it_dependency or "medium",
        risk_appetite=draft_org.risk_appetite or "balanced",
        selected_asset_categories=selected_asset_categories,
        regulatory_flags=list(draft_org.regulatory_flags or []),
        business_model_tags=_workspace_business_model_tags(session_id, draft_org),
    )


def _baseline_response_payload(session: Any, draft_org: DraftOrganisation) -> dict[str, Any]:
    contract_baseline = draft_org.baseline_snapshot or {}
    legacy_baseline = contract_baseline.get("_legacy") if isinstance(contract_baseline, dict) else None
    if not isinstance(legacy_baseline, dict):
        legacy_baseline = contract_baseline
    public_contract_baseline = (
        {k: v for k, v in contract_baseline.items() if k != "_legacy"} if isinstance(contract_baseline, dict) else {}
    )
    payload = {
        "sessionId": session.id,
        "expiresAt": session.expires_at,
        "baseline": public_contract_baseline,
        "modelVersion": draft_org.baseline_model_version,
        "baselineStatus": _baseline_status(draft_org),
        "baselineComputedAt": draft_org.baseline_generated_at,
        "assumptionStatus": PUBLIC_BASELINE_ASSUMPTION_STATUS,
        "requiresHumanReview": True,
    }
    if is_enabled("public-baseline-legacy-field", default=True):
        payload["baselineRiskLandscape"] = legacy_baseline
    return payload


@router.post("/sessions", status_code=status.HTTP_201_CREATED, response_model=StartPublicOnboardingResponse)
async def start_onboarding_session(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    try:
        try:
            payload = await request.json()
        except Exception as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_type": "invalid_schema",
                    "message": "Invalid schema",
                },
            ) from err
        if not isinstance(payload, dict) or payload:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_type": "invalid_schema",
                    "message": "Invalid schema",
                },
            )
        _enforce_public_rate_limit(request, "start", _RATE_LIMIT_PER_MINUTE)

        session, draft_org = PRETENANT_STORE.create_session()
        logger.info(
            "public_onboarding_session_created",
            session_id=session.id,
            draft_org_id=draft_org.id,
            expires_at=session.expires_at.isoformat(),
            client_ip=client_ip,
        )
        return {
            "sessionId": session.id,
            "expiresAt": session.expires_at,
            "nextStep": "/onboarding",
        }
    except Exception as exc:  # pragma: no cover - surfaced via logs
        logger.exception(
            "public_onboarding_session_failed",
            client_ip=client_ip,
            error=str(exc),
        )
        raise


@router.post("/org-lookup", response_model=OrgLookupResponse)
def public_org_lookup(payload: OrgLookupRequest, request: Request):
    _enforce_public_rate_limit(request, "org_lookup", _ORG_LOOKUP_RATE_LIMIT_PER_MINUTE)
    result = _lookup_org_core(payload.vat)
    return _lookup_response_payload(result)


@router.post("/org-confirm", response_model=OrgConfirmResponse)
def public_org_confirm(payload: OrgConfirmRequest, request: Request):
    _enforce_public_rate_limit(
        request,
        "org_confirm",
        _ORG_CONFIRM_RATE_LIMIT_PER_MINUTE,
        session_hint=payload.session_id,
    )
    if not payload.confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_type": "invalid_confirmation",
                "message": "confirmed must be true",
            },
        )

    session_id = _resolve_confirm_session_id(payload.session_id)
    result = _lookup_org_core(payload.vat)
    confirmation_timestamp = datetime.now(timezone.utc)
    profile = VerifiedOrganisationProfile(
        vat=result.vat,
        name=result.name,
        industry_cluster=result.industry_cluster,
        org_size_band=result.org_size_band,
        legal_form_band=result.legal_form_band,
        site_count=result.site_count,
        multi_site=result.multi_site,
        lifecycle_stage=result.lifecycle_stage,
        confirmation_timestamp=confirmation_timestamp,
        session_id=session_id,
    )
    stored = PRETENANT_STORE.save_verified_org_profile(session_id, profile)
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )

    PRETENANT_STORE.record_audit_event(
        event_type="org_profile_verified",
        session_id=session_id,
        details={
            "vat": stored.vat,
            "org_size_band": stored.org_size_band,
            "site_count": stored.site_count,
            "multi_site": stored.multi_site,
            "lifecycle_stage": stored.lifecycle_stage,
        },
    )

    return {
        "vat": stored.vat,
        "name": stored.name,
        "industryCluster": stored.industry_cluster,
        "orgSizeBand": stored.org_size_band,
        "legalFormBand": stored.legal_form_band,
        "siteCount": stored.site_count,
        "multiSite": stored.multi_site,
        "lifecycleStage": stored.lifecycle_stage,
        "confirmationTimestamp": stored.confirmation_timestamp,
        "sessionId": stored.session_id,
    }


@router.get("/sessions/{session_id}", response_model=ResumePublicOnboardingResponse)
def get_onboarding_session(session_id: str):
    status_value = PRETENANT_STORE.get_session_status(session_id)
    if status_value == "expired":
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={
                "error_type": "session_expired",
                "message": "Onboarding session expired",
            },
        )
    if status_value == "missing":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )
    session = PRETENANT_STORE.get_session(session_id)
    draft_org = PRETENANT_STORE.get_draft_org(session_id)
    if not session or not draft_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )
    if draft_org.status.upper() != "DRAFT":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_type": "session_unavailable",
                "message": "Onboarding session unavailable",
            },
        )
    return {
        "sessionId": session.id,
        "expiresAt": session.expires_at,
        "currentStep": _resume_current_step(draft_org),
        "draftSnapshot": _resume_draft_snapshot(draft_org),
        "nextStep": "/onboarding",
    }


@router.patch("/sessions/{session_id}", response_model=PublicOnboardingDraftResponse)
async def update_onboarding_answers(session_id: str, request: Request):
    status_value = PRETENANT_STORE.get_session_status(session_id)
    if status_value == "expired":
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={
                "error_type": "session_expired",
                "message": "Onboarding session expired",
            },
        )
    if status_value == "missing":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )

    draft_org = PRETENANT_STORE.get_draft_org(session_id)
    if not draft_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )
    if draft_org.status == DraftStatus.LOCKED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_type": "draft_locked",
                "message": "Draft is locked",
            },
        )

    try:
        payload = await request.json()
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_type": "invalid_schema",
                "message": "Invalid JSON payload",
            },
        ) from err

    updates, rerun_baseline = _validate_patch_payload(payload)
    material_change = False
    if updates:
        for field, new_value in updates.items():
            if field not in _BASELINE_MATERIAL_PATCH_FIELDS:
                continue
            if getattr(draft_org, field) != new_value:
                material_change = True
                break

    if updates:
        updated = PRETENANT_STORE.update_draft_org(session_id, **updates)
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error_type": "session_not_found",
                    "message": "Onboarding session not found",
                },
            )
        draft_org = updated

    if material_change and draft_org.baseline_snapshot and not rerun_baseline:
        updated = PRETENANT_STORE.update_draft_org(session_id, baseline_stale=True)
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error_type": "session_not_found",
                    "message": "Onboarding session not found",
                },
            )
        draft_org = updated

    if rerun_baseline:
        profile = _build_organisation_profile(session_id)
        try:
            ri_result = _risk_intelligence_client.compute_baseline(profile)
        except RiskModelUnavailableError as err:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error_type": "modeling_unavailable",
                    "message": "Risk model is unavailable",
                },
            ) from err
        updated = PRETENANT_STORE.update_draft_org(
            session_id,
            baseline_snapshot={
                **ri_result.contract_payload,
                "_legacy": ri_result.legacy_payload,
            },
            baseline_model_version=ri_result.model_version,
            baseline_generated_at=datetime.now(timezone.utc),
            baseline_input_hash=_baseline_input_hash_for_draft(draft_org),
            baseline_stale=False,
        )
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error_type": "session_not_found",
                    "message": "Onboarding session not found",
                },
            )
        draft_org = updated

    return _draft_response(session_id)


@router.post("/sessions/{session_id}/events", status_code=status.HTTP_204_NO_CONTENT)
async def record_onboarding_event(session_id: str, payload: PublicOnboardingEventRequest) -> Response:
    status_value = PRETENANT_STORE.get_session_status(session_id)
    if status_value == "expired":
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={
                "error_type": "session_expired",
                "message": "Onboarding session expired",
            },
        )
    if status_value == "missing":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )

    draft_org = PRETENANT_STORE.get_draft_org(session_id)
    if not draft_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )
    if draft_org.status == DraftStatus.LOCKED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_type": "draft_locked",
                "message": "Draft is locked",
            },
        )

    PRETENANT_STORE.record_audit_event(
        event_type=payload.event_type,
        session_id=session_id,
        details=payload.details,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/sessions/{session_id}/finalize", response_model=FinalizePublicOnboardingResponse)
def finalize_onboarding_session(session_id: str, _: FinalizePublicOnboardingRequest):
    _require_active_session(session_id)
    draft_org = PRETENANT_STORE.get_draft_org(session_id)
    if not draft_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )
    if draft_org.status == DraftStatus.LOCKED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_type": "draft_locked",
                "message": "Draft is already locked",
            },
        )

    _validate_finalize_completeness(session_id)
    updated = PRETENANT_STORE.update_draft_org(session_id, status=DraftStatus.LOCKED)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )

    activation = PRETENANT_STORE.create_activation_token(
        session_id=session_id,
    )
    if not activation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )

    PRETENANT_STORE.record_audit_event(
        event_type="draft_finalized",
        session_id=session_id,
        details={
            "draft_status": "LOCKED",
            "token_expires_at": activation.expires_at.isoformat(),
        },
    )
    PRETENANT_STORE.record_audit_event(
        event_type="activation_token_issued",
        session_id=session_id,
        details={
            "token_hash_prefix": activation.token_hash[:16],
            "token_expires_at": activation.expires_at.isoformat(),
            "draft_hash": _draft_hash(session_id),
            "model_version": updated.baseline_model_version,
        },
    )
    logger.info(
        "public_onboarding_draft_finalized",
        session_id=session_id,
        token_expires_at=activation.expires_at.isoformat(),
    )

    redirect_url = f"{_SIGNUP_REDIRECT_PATH}?{urlencode({'activationToken': activation.token})}"
    return {
        "sessionId": session_id,
        "draftStatus": "LOCKED",
        "redirectUrl": redirect_url,
        "tokenExpiresAt": activation.expires_at,
    }


@router.post("/sessions/{session_id}/cvr", response_model=CvrEnrichmentResponse)
def enrich_cvr(session_id: str, payload: CvrEnrichmentRequest):
    _, updated, result = _enrich_cvr_core(session_id, payload.cvr)
    return {
        "cvr": updated.cvr or result.cvr,
        "legalName": updated.legal_name or result.legal_name,
        "tradeName": updated.trade_name,
        "address": updated.address,
        "postalCode": updated.postal_code,
        "city": updated.city,
        "country": updated.country or "DK",
        "industryCode": updated.industry_code,
        "industry": result.industry_desc or updated.industry_code,
        "sizeBracket": updated.size_bracket,
        "geography": updated.geography or updated.country,
    }


@router.post("/sessions/{session_id}/cvr/lookup", response_model=CvrLookupResponse)
def enrich_cvr_lookup(session_id: str, payload: CvrEnrichmentRequest):
    session, updated, result = _enrich_cvr_core(session_id, payload.cvr)
    assumption_preview = build_company_assumption_preview(
        cvr=updated.cvr or result.cvr,
        legal_name=updated.legal_name or result.legal_name,
        retrieved_at=result.enriched_at,
        industry_code=updated.industry_code,
        industry=result.industry_desc,
        size_bracket=updated.size_bracket,
        geography=updated.geography or updated.country,
        business_context=updated.business_context,
    )
    return {
        "sessionId": session.id,
        "expiresAt": session.expires_at,
        "nextStep": "CONFIRM_CONTEXT",
        "draftOrganisation": {
            "cvr": updated.cvr or result.cvr,
            "legalName": updated.legal_name or result.legal_name,
            "tradeName": updated.trade_name,
            "address": updated.address,
            "postalCode": updated.postal_code,
            "city": updated.city,
            "country": updated.country,
            "industryCode": updated.industry_code,
            "industry": result.industry_desc or updated.industry_code,
            "sizeBracket": updated.size_bracket,
            "geography": updated.geography or updated.country,
        },
        "assumptionPreview": assumption_preview,
    }


@router.post("/sessions/{session_id}/business-context", response_model=CvrLookupResponse)
def refine_company_context(session_id: str, payload: BusinessContextRequest):
    status_value = PRETENANT_STORE.get_session_status(session_id)
    if status_value == "expired":
        raise HTTPException(status_code=status.HTTP_410_GONE, detail={"error_type": "session_expired", "message": "Onboarding session expired"})
    session = PRETENANT_STORE.get_session(session_id)
    draft_org = PRETENANT_STORE.get_draft_org(session_id)
    if not session or not draft_org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error_type": "session_not_found", "message": "Onboarding session not found"})
    if draft_org.status.upper() != DraftStatus.DRAFT:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"error_type": "draft_locked", "message": "Draft is locked"})
    if not draft_org.cvr or not draft_org.legal_name:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"error_type": "cvr_required", "message": "Company information must be prepared first"})

    business_context = {key: value for key, value in payload.model_dump(by_alias=True).items() if value is not None}
    updated = PRETENANT_STORE.update_draft_org(session_id, business_context=business_context)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error_type": "session_not_found", "message": "Onboarding session not found"})
    PRETENANT_STORE.record_audit_event(
        "business_context_refined", session_id, {"answer_count": len(business_context)}
    )
    assumption_preview = build_company_assumption_preview(
        cvr=updated.cvr,
        legal_name=updated.legal_name,
        retrieved_at=updated.last_enriched_at,
        industry_code=updated.industry_code,
        industry=updated.industry_description or updated.industry_code,
        size_bracket=updated.size_bracket,
        geography=updated.geography or updated.country,
        business_context=updated.business_context,
    )
    return {
        "sessionId": session.id,
        "expiresAt": session.expires_at,
        "nextStep": "CONFIRM_CONTEXT",
        "draftOrganisation": {
            "cvr": updated.cvr,
            "legalName": updated.legal_name,
            "tradeName": updated.trade_name,
            "address": updated.address,
            "postalCode": updated.postal_code,
            "city": updated.city,
            "country": updated.country,
            "industryCode": updated.industry_code,
            "industry": updated.industry_description or updated.industry_code,
            "sizeBracket": updated.size_bracket,
            "geography": updated.geography or updated.country,
        },
        "assumptionPreview": assumption_preview,
    }


@router.post(
    "/sessions/{session_id}/baseline",
    response_model=BaselineRiskResponse,
    response_model_exclude_none=True,
)
def generate_baseline(session_id: str, payload: BaselineRiskRequest):
    status_value = PRETENANT_STORE.get_session_status(session_id)
    if status_value == "expired":
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={
                "error_type": "session_expired",
                "message": "Onboarding session expired",
            },
        )
    if status_value == "missing":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )

    draft_org = PRETENANT_STORE.get_draft_org(session_id)
    if not draft_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )
    if draft_org.status.upper() != "DRAFT":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_type": "draft_unavailable",
                "message": "Draft is unavailable for baseline generation",
            },
        )

    if draft_org.baseline_snapshot and draft_org.baseline_model_version and not payload.force_recompute:
        session = PRETENANT_STORE.get_session(session_id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error_type": "session_not_found", "message": "Onboarding session not found"},
            )
        return _baseline_response_payload(session, draft_org)

    profile = _build_organisation_profile(session_id)
    try:
        ri_result = _risk_intelligence_client.compute_baseline(profile)
    except RiskModelUnavailableError as err:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error_type": "modeling_unavailable",
                "message": "Risk model is unavailable",
            },
        ) from err

    contract_baseline = dict(ri_result.contract_payload)
    contract_baseline["_legacy"] = ri_result.legacy_payload
    draft_org_for_hash = PRETENANT_STORE.get_draft_org(session_id)
    if not draft_org_for_hash:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )

    computed_at = datetime.now(timezone.utc)
    updated = PRETENANT_STORE.update_draft_org(
        session_id,
        baseline_snapshot=contract_baseline,
        baseline_model_version=ri_result.model_version,
        baseline_generated_at=computed_at,
        baseline_input_hash=_baseline_input_hash_for_draft(draft_org_for_hash),
        baseline_stale=False,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )
    session = PRETENANT_STORE.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_type": "session_not_found", "message": "Onboarding session not found"},
        )
    return _baseline_response_payload(session, updated)


@router.get(
    "/sessions/{session_id}/baseline",
    response_model=BaselineRiskResponse,
    response_model_exclude_none=True,
)
def get_baseline(session_id: str):
    status_value = PRETENANT_STORE.get_session_status(session_id)
    if status_value == "expired":
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={
                "error_type": "session_expired",
                "message": "Onboarding session expired",
            },
        )
    if status_value == "missing":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )

    draft_org = PRETENANT_STORE.get_draft_org(session_id)
    if not draft_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )

    if not draft_org.baseline_snapshot or not draft_org.baseline_model_version:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "baseline_not_found",
                "message": "Baseline preview is not available yet",
                "nextAction": "generate_baseline",
            },
        )

    session = PRETENANT_STORE.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_type": "session_not_found",
                "message": "Onboarding session not found",
            },
        )

    return _baseline_response_payload(session, draft_org)
