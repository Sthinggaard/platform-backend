from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256

from pydantic import ValidationError

from src.pretenant.store import DraftOrganisation
from src.pretenant.workspace_contracts import (
    BusinessService,
    InitialStructuralInsight,
    KriDefinition,
    OnboardingWorkspace,
    OnboardingWorkspacePatch,
    RiskAppetiteProfile,
    WorkspaceOrganizationProfile,
)
from src.core.seeds.risklence_internal_tenant import build_risklence_service_suggestions


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stable_id(prefix: str, value: str) -> str:
    digest = sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def _seed_business_services(organization: WorkspaceOrganizationProfile) -> list[BusinessService]:
    industry_text = (organization.industry or organization.industry_code or "").lower()
    if any(token in industry_text for token in ("saas", "soft", "it", "tech", "cyber", "62")):
        suggestions = build_risklence_service_suggestions()
        return [
            BusinessService(
                id=_stable_id("svc", suggestion["name"]),
                name=suggestion["name"],
                description=suggestion.get("description"),
                source="ai_suggested",
                confirmed=False,
            )
            for suggestion in suggestions
        ]

    if "fin" in industry_text or "64" in industry_text or "65" in industry_text:
        candidates = ["Customer transaction processing", "Core financial operations"]
    elif "health" in industry_text or "86" in industry_text:
        candidates = ["Clinical service delivery", "Patient data operations"]
    else:
        legal_name = organization.legal_name or organization.trade_name or "Core operations"
        candidates = [f"{legal_name} core operations", "Customer-facing service delivery"]

    return [
        BusinessService(
            id=_stable_id("svc", name),
            name=name,
            source="ai_suggested",
            confirmed=False,
        )
        for name in candidates
    ]


def _ensure_workspace_defaults(workspace: OnboardingWorkspace) -> OnboardingWorkspace:
    if workspace.organization.confirmed and not workspace.business_services:
        workspace = workspace.model_copy(update={"business_services": _seed_business_services(workspace.organization)})
    workspace.current_step = derive_workspace_step(workspace)
    workspace.updated_at = _now()
    return workspace


def derive_workspace_step(workspace: OnboardingWorkspace) -> str:
    if not workspace.organization.cvr:
        return "identify_organization"
    if not workspace.organization.confirmed:
        return "confirm_organization"
    if not workspace.business_services:
        return "business_services"
    if not workspace.assets:
        return "assets"
    if not workspace.service_asset_links or not workspace.criticality_profiles:
        return "criticality_and_dependencies"
    if workspace.risk_appetite_profile is None:
        return "risk_appetite"
    if workspace.initial_structural_insight is None:
        return "synthesis"
    if not workspace.starter_kris:
        return "starter_monitoring"
    return "activation"


def build_workspace_from_draft(session_id: str, draft_org: DraftOrganisation) -> OnboardingWorkspace:
    organization = WorkspaceOrganizationProfile(
        cvr=draft_org.cvr,
        legalName=draft_org.legal_name,
        tradeName=draft_org.trade_name,
        industryCode=draft_org.industry_code,
        geography=draft_org.geography,
        country=draft_org.country,
        locations=draft_org.locations,
        confirmed=bool(draft_org.cvr and draft_org.legal_name),
    )
    workspace = OnboardingWorkspace(
        sessionId=session_id,
        currentStep="identify_organization",
        organization=organization,
        riskAppetiteProfile=(
            RiskAppetiteProfile(profile=draft_org.risk_appetite)
            if draft_org.risk_appetite in {"conservative", "balanced", "aggressive"}
            else None
        ),
        valueStreamProfile=None,
        assets=[],
        businessServices=[],
        serviceAssetLinks=[],
        dependencyEdges=[],
        criticalityProfiles=[],
        starterKris=[],
        initialStructuralInsight=None,
        updatedAt=_now(),
    )
    return _ensure_workspace_defaults(workspace)


def load_workspace(session_id: str, draft_org: DraftOrganisation) -> OnboardingWorkspace:
    snapshot = draft_org.workspace_snapshot
    if isinstance(snapshot, dict):
        try:
            workspace = OnboardingWorkspace.model_validate(snapshot)
            return _ensure_workspace_defaults(workspace)
        except ValidationError:
            # Older or malformed persisted snapshots should not break onboarding resume.
            # Rebuild from the draft record and let the caller persist the repaired snapshot.
            return build_workspace_from_draft(session_id, draft_org)
    return build_workspace_from_draft(session_id, draft_org)


def merge_workspace(current: OnboardingWorkspace, patch: OnboardingWorkspacePatch) -> OnboardingWorkspace:
    data = current.model_dump(by_alias=True)
    updates = patch.model_dump(exclude_none=True, by_alias=True)
    data.update(updates)
    merged = OnboardingWorkspace.model_validate(data)
    return _ensure_workspace_defaults(merged)


def synthesize_workspace(current: OnboardingWorkspace) -> OnboardingWorkspace:
    service_names = [service.name for service in current.business_services[:3]]
    asset_names = [asset.name for asset in current.assets[:3]]
    focal_points: list[str] = []
    if service_names:
        focal_points.append(f"Critical business streams: {', '.join(service_names)}")
    if asset_names:
        focal_points.append(f"Priority assets: {', '.join(asset_names)}")
    if current.risk_appetite_profile is not None:
        focal_points.append(f"Risk posture: {current.risk_appetite_profile.profile}")

    insight = InitialStructuralInsight(
        summary=(
            "Initial structural model created from organization profile, declared business services, "
            "and starter asset inventory."
        ),
        focalPoints=focal_points,
        inferredDependencies=len(current.dependency_edges),
        confidenceBand="medium",
    )

    starter_kris = current.starter_kris or [
        KriDefinition(
            id=_stable_id("kri", "critical_service_coverage"),
            code="KRI-SVC-001",
            name="Critical service coverage ratio",
            domain="business_service_resilience",
            rationale="Measures whether declared critical business services are mapped to explicit supporting assets.",
            thresholdHint=">= 90% mapped",
        ),
        KriDefinition(
            id=_stable_id("kri", "critical_asset_observability"),
            code="KRI-AST-001",
            name="Critical asset observability readiness",
            domain="monitoring_readiness",
            rationale="Tracks how many critical assets are ready for starter monitoring.",
            thresholdHint=">= 80% ready",
        ),
    ]

    updated = current.model_copy(
        update={
            "initial_structural_insight": insight,
            "starter_kris": starter_kris,
            "updated_at": _now(),
        }
    )
    return _ensure_workspace_defaults(updated)
