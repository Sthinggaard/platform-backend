from __future__ import annotations

import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.database import get_session_factory
from src.core.model_defs.business_process_recommendation import BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION
from src.core.constants.business_process_templates import (
    get_business_process_reasoning_template,
    get_business_process_template,
)
from src.core.models import (
    BusinessProcessDecisionAction,
    BusinessProcessDecisionLog,
    BusinessProcessRecommendation,
    Organization,
)
from src.core.services.business_process_recommendation_engine import BusinessProcessRecommendationEngine
from src.core.services.business_process_repository import BusinessProcessRepository
from src.pretenant.risk_intelligence import OrganisationProfile
from src.pretenant.workspace_contracts import OnboardingWorkspace

router = APIRouter(
    prefix="/api/v1/organizations/{organization_id}/business-processes",
    tags=["Business Processes"],
)


class BusinessProcessOrganisationProfileRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    cvr: str = Field(..., min_length=1, max_length=64)
    legal_name: str = Field(..., alias="legalName", min_length=1, max_length=200)
    industry_code: str = Field(..., alias="industryCode", min_length=1, max_length=20)
    size_bracket: str = Field(..., alias="sizeBracket", min_length=1, max_length=40)
    geography: str = Field(..., min_length=1, max_length=20)
    locations: int = Field(..., ge=0)
    it_dependency: str = Field(..., alias="itDependency", min_length=1, max_length=40)
    risk_appetite: str = Field(..., alias="riskAppetite", min_length=1, max_length=40)
    selected_asset_categories: list[str] = Field(..., alias="selectedAssetCategories")
    regulatory_flags: list[str] = Field(default_factory=list, alias="regulatoryFlags")
    business_model_tags: list[str] = Field(default_factory=list, alias="businessModelTags")

    @field_validator("selected_asset_categories", "regulatory_flags", "business_model_tags")
    @classmethod
    def _clean_tags(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise ValueError("all tag values must be strings")
            token = item.strip()
            if not token:
                continue
            canonical = token.lower()
            if canonical in seen:
                continue
            seen.add(canonical)
            cleaned.append(canonical)
        return cleaned


class BusinessProcessDecisionReason(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(..., min_length=1, max_length=300)
    details: dict[str, Any] = Field(default_factory=dict)
    source: str | None = Field(default=None, max_length=120)


class BusinessProcessGenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organisation_profile: BusinessProcessOrganisationProfileRequest = Field(alias="organisationProfile")


class BusinessProcessAddRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    template_id: str = Field(alias="templateId", min_length=1, max_length=100)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    reason: BusinessProcessDecisionReason | None = None


class BusinessProcessActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: BusinessProcessDecisionReason | None = None


class BusinessProcessCrownDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    process_id: str = Field(alias="processId", min_length=1)
    process_name: str = Field(alias="processName", min_length=1, max_length=200)
    service_id: str = Field(alias="serviceId", min_length=1)
    service_name: str = Field(alias="serviceName", min_length=1, max_length=200)
    decision: Literal["confirm", "reject", "defer"]
    reason: BusinessProcessDecisionReason | None = None


class BusinessProcessRemoveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: BusinessProcessDecisionReason


class BusinessProcessUserReasoningRead(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    plain_name: str = Field(alias="plainName")
    business_owner_summary: str = Field(alias="businessOwnerSummary")
    why_this_matters: str = Field(alias="whyThisMatters")
    what_can_go_wrong: str = Field(alias="whatCanGoWrong")
    when_to_accept: str = Field(alias="whenToAccept")
    relevance_label: str = Field(alias="relevanceLabel")
    evidence_summary: list[str] = Field(alias="evidenceSummary")
    technical_details: "BusinessProcessTechnicalDetailsRead" = Field(alias="technicalDetails")


class BusinessProcessTechnicalDetailsRead(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    original_template_name: str = Field(alias="originalTemplateName")
    template_id: str = Field(alias="templateId")
    source_rule: str = Field(alias="sourceRule")
    confidence: float
    matched_inputs: list[str] = Field(alias="matchedInputs")
    old_reason: str = Field(alias="oldReason")


BusinessProcessUserReasoningRead.model_rebuild()


class BusinessProcessRecommendationRead(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    organization_id: int = Field(alias="organizationId")
    user_id: int | None = Field(default=None, alias="userId")
    process_template_id: str = Field(alias="processTemplateId")
    name: str
    category: str
    score: float
    confidence: float
    matched_inputs: list[str] = Field(alias="matchedInputs")
    recommendation_reason: str = Field(alias="recommendationReason")
    source_rule: str = Field(alias="sourceRule")
    user_reasoning: BusinessProcessUserReasoningRead = Field(alias="userReasoning")
    status: str
    model_version: str = Field(alias="modelVersion")
    created_at: Any = Field(alias="createdAt")
    updated_at: Any | None = Field(default=None, alias="updatedAt")


class BusinessProcessDecisionLogRead(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    organization_id: int = Field(alias="organizationId")
    recommendation_id: str | None = Field(default=None, alias="recommendationId")
    user_id: int | None = Field(default=None, alias="userId")
    action: str
    reason: dict[str, Any] | None = None
    reason_details: dict[str, Any] | None = Field(default=None, alias="reasonDetails")
    model_version: str = Field(alias="modelVersion")
    created_at: Any = Field(alias="createdAt")


class BusinessProcessStateResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    organization_id: int = Field(alias="organizationId")
    model_version: str = Field(alias="modelVersion")
    action: str
    recommendations: list[BusinessProcessRecommendationRead]
    decision_logs: list[BusinessProcessDecisionLogRead] = Field(alias="decisionLogs")
    generated_recommendation_ids: list[str] = Field(default_factory=list, alias="generatedRecommendationIds")
    affected_recommendation_id: str | None = Field(default=None, alias="affectedRecommendationId")
    confirmed_recommendation_ids: list[str] = Field(default_factory=list, alias="confirmedRecommendationIds")


def _get_db():
    session_factory = get_session_factory()
    db = session_factory()
    try:
        yield db
    finally:
        db.close()


def _ensure_organization_match(organization_id: int, ctx: TenantContext) -> None:
    """This router is the only one in the tree that puts organization_id in
    the URL path rather than deriving it from the token alone (every other
    route uses Depends(get_tenant_context) exclusively) — the path value
    still needs cross-checking against the caller's actual, JWT-verified
    organisation, the same 403 shape the previous per-route helper raised."""
    if organization_id != ctx.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error_type": "organization_mismatch",
                "message": "Organization context does not match route",
            },
        )


def _to_profile(payload: BusinessProcessOrganisationProfileRequest) -> OrganisationProfile:
    return OrganisationProfile(
        cvr=payload.cvr,
        legal_name=payload.legal_name,
        industry_code=payload.industry_code,
        size_bracket=payload.size_bracket,
        geography=payload.geography,
        locations=payload.locations,
        it_dependency=payload.it_dependency,
        risk_appetite=payload.risk_appetite,
        selected_asset_categories=payload.selected_asset_categories,
        regulatory_flags=payload.regulatory_flags,
        business_model_tags=payload.business_model_tags,
    )


def _organization_profile(db: Session, organization_id: int) -> OrganisationProfile:
    return _to_profile(_build_fallback_profile(db, organization_id))


def _clean_string(value: Any | None, fallback: str) -> str:
    if isinstance(value, str):
        candidate = value.strip()
        if candidate:
            return candidate
    return fallback


def _clean_int(value: Any | None, fallback: int = 0) -> int:
    if isinstance(value, bool):
        return fallback
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str):
        try:
            parsed = int(value.strip())
        except ValueError:
            return fallback
        return parsed if parsed >= 0 else fallback
    return fallback


def _workspace_asset_categories(workspace: OnboardingWorkspace) -> list[str]:
    categories: set[str] = set()
    for asset in workspace.assets:
        candidate = asset.layer or asset.asset_type or asset.name
        if not isinstance(candidate, str):
            continue
        token = candidate.strip().lower()
        if not token:
            continue
        categories.add(re.sub(r"[^a-z0-9]+", "_", token).strip("_")[:64])
    return sorted(categories)


def _workspace_business_model_tags(workspace: OnboardingWorkspace) -> list[str]:
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


def _build_fallback_profile(db: Session, organization_id: int) -> BusinessProcessOrganisationProfileRequest:
    org = db.get(Organization, organization_id)
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_type": "organization_not_found", "message": "Organisation not found"},
        )

    onboarding_data = org.onboarding_data if isinstance(org.onboarding_data, dict) else {}
    workspace: OnboardingWorkspace | None = None
    raw_workspace = onboarding_data.get("workspace")
    if isinstance(raw_workspace, dict):
        try:
            workspace = OnboardingWorkspace.model_validate(raw_workspace)
        except Exception:
            workspace = None

    workspace_org = workspace.organization if workspace else None
    cvr = _clean_string(
        org.cvr_number or onboarding_data.get("cvr") or (workspace_org.cvr if workspace_org else None),
        f"org-{organization_id}",
    )
    legal_name = _clean_string(
        (workspace_org.legal_name if workspace_org else None) or org.name or org.slug,
        f"Organization {organization_id}",
    )
    industry_code = _clean_string(
        org.industry
        or org.nace_code
        or (workspace_org.industry_code if workspace_org else None)
        or (workspace_org.industry if workspace_org else None),
        "unknown",
    )
    size_bracket = _clean_string(org.company_size, "smb")
    geography = _clean_string(
        (workspace_org.geography if workspace_org else None)
        or (workspace_org.country if workspace_org else None)
        or org.country,
        "DK",
    )
    locations = _clean_int(
        (workspace_org.locations if workspace_org and workspace_org.locations is not None else None)
        or onboarding_data.get("locations"),
        0,
    )
    it_dependency = _clean_string(
        onboarding_data.get("it_dependency")
        or onboarding_data.get("itDependency"),
        "medium",
    )
    risk_appetite = _clean_string(
        (workspace.risk_appetite_profile.profile if workspace and workspace.risk_appetite_profile else None)
        or onboarding_data.get("risk_appetite")
        or onboarding_data.get("riskAppetite"),
        "balanced",
    )

    selected_asset_categories = _workspace_asset_categories(workspace) if workspace else []
    if not selected_asset_categories:
        raw_categories = onboarding_data.get("selected_asset_categories") or onboarding_data.get("selectedAssetCategories")
        if isinstance(raw_categories, list):
            selected_asset_categories = [
                token.strip().lower()
                for token in raw_categories
                if isinstance(token, str) and token.strip()
            ]

    regulatory_flags = onboarding_data.get("regulatory_flags") or onboarding_data.get("regulatoryFlags") or []
    if isinstance(regulatory_flags, list):
        cleaned_regulatory_flags = [
            token.strip().upper()
            for token in regulatory_flags
            if isinstance(token, str) and token.strip()
        ]
    else:
        cleaned_regulatory_flags = []

    business_model_tags = _workspace_business_model_tags(workspace) if workspace else []
    if not business_model_tags:
        raw_tags = onboarding_data.get("business_model_tags") or onboarding_data.get("businessModelTags")
        if isinstance(raw_tags, list):
            business_model_tags = [
                token.strip().lower()
                for token in raw_tags
                if isinstance(token, str) and token.strip()
            ]

    return BusinessProcessOrganisationProfileRequest(
        cvr=cvr,
        legal_name=legal_name,
        industry_code=industry_code,
        size_bracket=size_bracket,
        geography=geography,
        locations=locations,
        it_dependency=it_dependency,
        risk_appetite=risk_appetite,
        selected_asset_categories=selected_asset_categories,
        regulatory_flags=cleaned_regulatory_flags,
        business_model_tags=business_model_tags,
    )


def _serialize_recommendation(
    row: BusinessProcessRecommendation,
    *,
    profile: OrganisationProfile,
    engine: BusinessProcessRecommendationEngine,
) -> BusinessProcessRecommendationRead:
    explanation = engine.explain_recommendation(
        row.process_template_id,
        profile,
        row.source_rule,
        row.confidence,
    )
    reasoning_template = get_business_process_reasoning_template(row.process_template_id)
    template = get_business_process_template(row.process_template_id)
    return BusinessProcessRecommendationRead(
        id=row.id,
        organizationId=row.organization_id,
        userId=row.user_id,
        processTemplateId=row.process_template_id,
        name=row.name,
        category=row.category,
        score=explanation.score,
        confidence=row.confidence,
        matchedInputs=list(explanation.matched_inputs),
        recommendationReason=row.recommendation_reason,
        sourceRule=row.source_rule,
        userReasoning=BusinessProcessUserReasoningRead(
            plainName=reasoning_template.plain_name,
            businessOwnerSummary=reasoning_template.business_owner_summary,
            whyThisMatters=reasoning_template.why_this_matters,
            whatCanGoWrong=reasoning_template.what_can_go_wrong,
            whenToAccept=reasoning_template.when_to_accept,
            relevanceLabel=explanation.user_reasoning.relevance_label,
            evidenceSummary=list(explanation.user_reasoning.evidence_summary),
            technicalDetails=BusinessProcessTechnicalDetailsRead(
                originalTemplateName=template.name,
                templateId=template.id,
                sourceRule=row.source_rule,
                confidence=row.confidence,
                matchedInputs=list(explanation.matched_inputs),
                oldReason=row.recommendation_reason,
            ),
        ),
        status=row.status,
        modelVersion=row.model_version,
        createdAt=row.created_at,
        updatedAt=row.updated_at,
    )


def _serialize_decision_log(row: BusinessProcessDecisionLog) -> BusinessProcessDecisionLogRead:
    reason_details = None
    if isinstance(row.reason, dict):
        details = row.reason.get("details")
        if isinstance(details, dict):
            reason_details = details
    return BusinessProcessDecisionLogRead.model_validate(
        {
            "id": row.id,
            "organizationId": row.organization_id,
            "recommendationId": row.recommendation_id,
            "userId": row.user_id,
            "action": row.action,
            "reason": row.reason,
            "reasonDetails": reason_details,
            "modelVersion": row.model_version,
            "createdAt": row.created_at,
        }
    )


def _current_state(db: Session, organization_id: int, action: str) -> BusinessProcessStateResponse:
    profile = _organization_profile(db, organization_id)
    engine = BusinessProcessRecommendationEngine()
    recommendations = db.execute(
        select(BusinessProcessRecommendation)
        .where(BusinessProcessRecommendation.organization_id == organization_id)
        .order_by(BusinessProcessRecommendation.created_at.desc(), BusinessProcessRecommendation.id.desc())
    ).scalars().all()
    decision_logs = db.execute(
        select(BusinessProcessDecisionLog)
        .where(BusinessProcessDecisionLog.organization_id == organization_id)
        .order_by(BusinessProcessDecisionLog.created_at.desc(), BusinessProcessDecisionLog.id.desc())
    ).scalars().all()
    model_version = recommendations[0].model_version if recommendations else BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION
    return BusinessProcessStateResponse(
        organizationId=organization_id,
        modelVersion=model_version,
        action=action,
        recommendations=[_serialize_recommendation(row, profile=profile, engine=engine) for row in recommendations],
        decisionLogs=[_serialize_decision_log(row) for row in decision_logs],
    )


@router.get("/recommendations", response_model=BusinessProcessStateResponse)
def get_business_process_recommendations(
    organization_id: int = Path(..., ge=1),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(_get_db),
):
    _ensure_organization_match(organization_id, ctx)
    return _current_state(db, ctx.organization_id, action="list")


@router.post("/recommendations/generate", response_model=BusinessProcessStateResponse)
def generate_business_process_recommendations(
    payload: BusinessProcessGenerateRequest | None = None,
    organization_id: int = Path(..., ge=1),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(_get_db),
):
    _ensure_organization_match(organization_id, ctx)
    repo = BusinessProcessRepository(db, ctx.organization_id, user_id=ctx.user_id)
    profile = (
        _to_profile(payload.organisation_profile)
        if payload is not None
        else _to_profile(_build_fallback_profile(db, ctx.organization_id))
    )
    recommendations = BusinessProcessRecommendationEngine().recommend(profile)
    rows = repo.merge_recommendations(recommendations)
    db.commit()
    state = _current_state(db, ctx.organization_id, action="generate")
    state.generated_recommendation_ids = [row.id for row in rows]
    state.confirmed_recommendation_ids = []
    if rows:
        state.affected_recommendation_id = rows[0].id
    return state


@router.post("/recommendations/{recommendation_id}/accept", response_model=BusinessProcessStateResponse)
def accept_business_process_recommendation(
    recommendation_id: str,
    payload: BusinessProcessActionRequest | None = None,
    organization_id: int = Path(..., ge=1),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(_get_db),
):
    _ensure_organization_match(organization_id, ctx)
    repo = BusinessProcessRepository(db, ctx.organization_id, user_id=ctx.user_id)
    try:
        repo.accept_recommendation(recommendation_id, reason=payload.reason if payload else None)
        db.commit()
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_type": "recommendation_not_found", "message": str(exc)},
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_type": "invalid_transition", "message": str(exc)},
        ) from exc
    state = _current_state(db, ctx.organization_id, action="accept")
    state.affected_recommendation_id = recommendation_id
    return state


@router.post("/recommendations/{recommendation_id}/remove", response_model=BusinessProcessStateResponse)
def remove_business_process_recommendation(
    recommendation_id: str,
    payload: BusinessProcessRemoveRequest,
    organization_id: int = Path(..., ge=1),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(_get_db),
):
    _ensure_organization_match(organization_id, ctx)
    repo = BusinessProcessRepository(db, ctx.organization_id, user_id=ctx.user_id)
    try:
        repo.remove_recommendation(recommendation_id, reason=payload.reason.model_dump(exclude_none=True))
        db.commit()
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_type": "recommendation_not_found", "message": str(exc)},
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_type": "invalid_transition", "message": str(exc)},
        ) from exc
    state = _current_state(db, ctx.organization_id, action="remove")
    state.affected_recommendation_id = recommendation_id
    return state


@router.post("/library/add", response_model=BusinessProcessStateResponse)
def add_business_process_from_library(
    payload: BusinessProcessAddRequest,
    organization_id: int = Path(..., ge=1),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(_get_db),
):
    _ensure_organization_match(organization_id, ctx)
    repo = BusinessProcessRepository(db, ctx.organization_id, user_id=ctx.user_id)
    try:
        row = repo.add_from_library(
            payload.template_id,
            confidence=payload.confidence,
            reason=payload.reason.model_dump(exclude_none=True) if payload.reason else None,
        )
        db.commit()
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_type": "template_not_found", "message": str(exc)},
        ) from exc
    state = _current_state(db, ctx.organization_id, action="add")
    state.affected_recommendation_id = row.id
    return state


@router.post("/confirm", response_model=BusinessProcessStateResponse)
def confirm_business_process_model(
    payload: BusinessProcessActionRequest | None = None,
    organization_id: int = Path(..., ge=1),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(_get_db),
):
    _ensure_organization_match(organization_id, ctx)
    reason = payload.reason if payload and payload.reason else BusinessProcessDecisionReason(
        summary="Business process model confirmed",
        details={"confirmed": True},
    )
    repo = BusinessProcessRepository(db, ctx.organization_id, user_id=ctx.user_id)
    try:
        snapshot = repo.confirm_model(reason=reason.model_dump(exclude_none=True))
        db.commit()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_type": "no_suggested_recommendations",
                "message": "No suggested recommendations available to confirm",
            },
        ) from exc
    state = _current_state(db, ctx.organization_id, action="confirm")
    state.confirmed_recommendation_ids = list(snapshot["activeRecommendationIds"])
    state.affected_recommendation_id = state.confirmed_recommendation_ids[0] if state.confirmed_recommendation_ids else None
    return state


@router.post("/crown-jewel", response_model=BusinessProcessStateResponse)
def record_crown_jewel_decision(
    payload: BusinessProcessCrownDecisionRequest,
    organization_id: int = Path(..., ge=1),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(_get_db),
):
    _ensure_organization_match(organization_id, ctx)
    action_by_decision: dict[str, BusinessProcessDecisionAction] = {
        "confirm": BusinessProcessDecisionAction.CROWN_CONFIRM,
        "reject": BusinessProcessDecisionAction.CROWN_REJECT,
        "defer": BusinessProcessDecisionAction.CROWN_DEFER,
    }
    action = action_by_decision[payload.decision]
    reason = payload.reason.model_dump(exclude_none=True) if payload.reason else {}
    details = dict(reason.get("details") or {})
    details.update(
        {
            "processId": payload.process_id,
            "processName": payload.process_name,
            "serviceId": payload.service_id,
            "serviceName": payload.service_name,
            "decision": payload.decision,
        }
    )
    log = BusinessProcessDecisionLog(
        organization_id=ctx.organization_id,
        recommendation_id=None,
        user_id=ctx.user_id,
        action=action.value,
        reason={
            "summary": reason.get("summary")
            or f"Crown jewel decision {payload.decision} for {payload.service_name}",
            "details": details,
            "source": reason.get("source") or "crown_jewel_review",
        },
        model_version=BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION,
    )
    db.add(log)
    db.commit()
    return _current_state(db, ctx.organization_id, action=f"crown_{payload.decision}")
