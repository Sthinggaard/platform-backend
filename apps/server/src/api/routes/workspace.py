from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import get_tenant_context
from src.core.database import get_db
from src.core.models import Organization
from src.core.services.baseline_risk_hypothesis_service import (
    PUBLIC_ONBOARDING_HANDOFF_KEY,
    get_current_hypothesis,
)
from src.api.schemas.timestamps import UtcTimestamp

router = APIRouter(prefix="/app/workspace", tags=["Workspace"])


class WorkspaceSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    organization_id: int = Field(alias="organizationId")
    organization_name: str = Field(alias="organizationName")
    organization_slug: str = Field(alias="organizationSlug")
    user_id: int = Field(alias="userId")
    user_email: str = Field(alias="userEmail")


class BaselineSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    model_version: str | None = Field(default=None, alias="modelVersion")
    generated_at: UtcTimestamp | None = Field(default=None, alias="generatedAt")
    overall_risk_score: int | None = Field(default=None, alias="overallRiskScore")
    risk_level: str | None = Field(default=None, alias="riskLevel")
    focus_areas: list[str] = Field(default_factory=list, alias="focusAreas")
    hypotheses_count: int = Field(default=0, alias="hypothesesCount")
    hypothesis_status: str | None = Field(default=None, alias="hypothesisStatus")


class NextStep(BaseModel):
    code: str
    title: str
    description: str


class WorkspaceBootstrapResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    workspace: WorkspaceSummary
    baseline_summary: BaselineSummary | None = Field(default=None, alias="baselineSummary")
    next_steps: list[NextStep] = Field(default_factory=list, alias="nextSteps")
    auto_monitoring_enabled: bool = Field(alias="autoMonitoringEnabled")


def _coerce_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _build_baseline_summary_from_hypothesis(hypothesis) -> BaselineSummary | None:
    if hypothesis is None:
        return None
    company_context = hypothesis.company_context if isinstance(hypothesis.company_context, dict) else {}
    handoff = company_context.get(PUBLIC_ONBOARDING_HANDOFF_KEY)
    if not isinstance(handoff, dict):
        return None

    landscape = handoff.get("baseline_snapshot")
    if not isinstance(landscape, dict):
        landscape = {}
    focus_areas = landscape.get("focusAreas")
    if not isinstance(focus_areas, list):
        focus_areas = []
    hypotheses = landscape.get("hypotheses")
    hypotheses_count = len(hypotheses) if isinstance(hypotheses, list) else 0

    return BaselineSummary(
        modelVersion=handoff.get("model_version") if isinstance(handoff.get("model_version"), str) else None,
        generatedAt=_coerce_datetime(handoff.get("generated_at")),
        overallRiskScore=landscape.get("overallRiskScore")
        if isinstance(landscape.get("overallRiskScore"), int)
        else None,
        riskLevel=landscape.get("riskLevel") if isinstance(landscape.get("riskLevel"), str) else None,
        focusAreas=[item for item in focus_areas if isinstance(item, str)],
        hypothesesCount=hypotheses_count,
        hypothesisStatus=hypothesis.status,
    )


def _build_legacy_baseline_summary(onboarding_data: dict[str, Any] | None) -> BaselineSummary | None:
    if not isinstance(onboarding_data, dict):
        return None
    baseline = onboarding_data.get("baseline")
    if not isinstance(baseline, dict):
        return None

    landscape = baseline.get("landscape") if isinstance(baseline.get("landscape"), dict) else {}
    if not isinstance(landscape, dict):
        landscape = {}

    focus_areas = landscape.get("focusAreas")
    if not isinstance(focus_areas, list):
        focus_areas = []

    hypotheses = landscape.get("hypotheses")
    hypotheses_count = len(hypotheses) if isinstance(hypotheses, list) else 0

    return BaselineSummary(
        modelVersion=baseline.get("model_version") if isinstance(baseline.get("model_version"), str) else None,
        generatedAt=_coerce_datetime(baseline.get("generated_at")),
        overallRiskScore=landscape.get("overallRiskScore")
        if isinstance(landscape.get("overallRiskScore"), int)
        else None,
        riskLevel=landscape.get("riskLevel") if isinstance(landscape.get("riskLevel"), str) else None,
        focusAreas=[item for item in focus_areas if isinstance(item, str)],
        hypothesesCount=hypotheses_count,
    )


def _default_next_steps(has_baseline: bool) -> list[NextStep]:
    steps = [
        NextStep(
            code="analyze_resilience_gaps",
            title="Analyze resilience gaps",
            description="Review the weak points and single points of failure promoted from onboarding into your tenant workspace.",
        ),
        NextStep(
            code="simulate_business_impact",
            title="Simulate business impact",
            description="Use dependency intelligence to see what happens if a critical service, asset, or supplier fails.",
        ),
        NextStep(
            code="recommend_next_action",
            title="Recommend next action",
            description="Open the operations workspace to review the recommended actions and the rationale behind them.",
        ),
        NextStep(
            code="capture_human_decision",
            title="Capture human decision",
            description="Accept, modify, reject, or escalate the recommended action with a clear audit trail.",
        ),
        NextStep(
            code="monitor_document_improve",
            title="Monitor, document, and improve",
            description="Keep monitoring off until a human enables it, then document outcomes and improve the operating model over time.",
        ),
    ]
    if has_baseline:
        steps.insert(
            0,
            NextStep(
                code="review_proposed_business_model",
                title="Review proposed business model",
                description="Confirm or dismiss the proposed baseline assumptions before they become Business Processes or Services.",
            ),
        )
    return steps


@router.get("/bootstrap", response_model=WorkspaceBootstrapResponse)
def get_workspace_bootstrap(request: Request, db: Session = Depends(get_db)):
    tenant = get_tenant_context(request)
    organization = db.get(Organization, tenant.organization_id)
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_type": "organization_not_found", "message": "Organization not found"},
        )

    hypothesis = get_current_hypothesis(db, organization.id)
    baseline_summary = _build_baseline_summary_from_hypothesis(hypothesis)
    if baseline_summary is None:
        # Older tenants retain their existing read-only bootstrap projection.
        baseline_summary = _build_legacy_baseline_summary(
            organization.onboarding_data if isinstance(organization.onboarding_data, dict) else None
        )
    return WorkspaceBootstrapResponse(
        workspace=WorkspaceSummary(
            organizationId=organization.id,
            organizationName=organization.name,
            organizationSlug=organization.slug,
            userId=tenant.user_id,
            userEmail=tenant.email,
        ),
        baselineSummary=baseline_summary,
        nextSteps=_default_next_steps(has_baseline=baseline_summary is not None),
        autoMonitoringEnabled=False,
    )
