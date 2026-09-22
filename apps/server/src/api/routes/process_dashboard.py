"""Tenant-scoped Business Process dashboard projection endpoint."""

from dataclasses import asdict

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.schemas.process_dashboard import ProcessDashboardResponse
from src.core.database import get_db
from src.core.models import (
    Asset,
    BusinessService,
    BusinessServiceAppetiteConfig,
    DecisionRecord,
    DependencyBundle,
    ForecastImpact,
    ResolutionRecord,
    RiskEvaluation,
    Threat,
    ValueStream,
    VerificationRecord,
)
from src.core.repository import TenantRepository
from src.core.services.effective_process_bia_service import resolve_effective_process_bia_by_process
from src.core.services.process_access_resolution_service import resolve_org_access
from src.core.services.process_activation_service import resolve_process_activation_readiness
from src.core.services.process_dashboard_projection_service import (
    ProcessDashboardProjectionInput,
    build_process_dashboard_projection,
)
from src.core.services.review_reopening_service import (
    find_outstanding_reviews,
    run_review_reopening_pass,
)
from src.core.services.risk_appetite_resolution_service import resolve_appetite_for_processes
from src.core.services.risk_evaluation_service import run_risk_evaluation_pass
from src.core.services.service_bia_exception_service import active_bia_exceptions

router = APIRouter(prefix="/api/v1/process-dashboard", tags=["Process dashboard"])


def load_process_dashboard_projection_input(
    db: Session,
    organization_id: int,
    viewer_user_id: int | None = None,
) -> ProcessDashboardProjectionInput:
    """Load only tenant-scoped records required by the read-model projection.

    Rows the viewer may not see are filtered here, server-side — the client
    never receives them (org-access contract).
    """
    processes = TenantRepository(db, ValueStream, organization_id).get_all()
    services = TenantRepository(db, BusinessService, organization_id).get_all()
    resolution = resolve_org_access(
        db,
        organization_id=organization_id,
        viewer_user_id=viewer_user_id,
        processes=processes,
        services=services,
    )
    processes = [
        process
        for process in processes
        if (access := resolution.access_by_process_id.get(process.id)) is None or access.visible
    ]
    activation_by_process_id = resolve_process_activation_readiness(
        db,
        organization_id=organization_id,
        processes=processes,
    )
    effective_process_bia_by_process = (
        resolve_effective_process_bia_by_process(
            db,
            organization_id=organization_id,
            processes=processes,
        )
        if processes
        else {}
    )
    return ProcessDashboardProjectionInput(
        processes=processes,
        services=services,
        dependency_bundles=TenantRepository(db, DependencyBundle, organization_id).get_all(),
        legacy_service_appetite_configs=TenantRepository(
            db,
            BusinessServiceAppetiteConfig,
            organization_id,
        ).get_all(),
        assets=TenantRepository(db, Asset, organization_id).get_all(),
        threats=TenantRepository(db, Threat, organization_id).get_all(),
        decisions=TenantRepository(db, DecisionRecord, organization_id).get_all(),
        verifications=TenantRepository(db, VerificationRecord, organization_id).get_all(),
        # Canonical resolution: decision exception → process override → org policy.
        resolved_process_appetites=resolve_appetite_for_processes(
            db,
            organization_id=organization_id,
            process_ids=[process.id for process in processes],
        ),
        latest_evaluations={
            process_id: evaluation
            for process_id, evaluation in _load_latest_evaluations(db, organization_id).items()
            if activation_by_process_id.get(process_id)
            and activation_by_process_id[process_id].impact_model_active
        },
        forecasts_by_id={
            forecast.id: forecast
            for forecast in TenantRepository(db, ForecastImpact, organization_id).get_all()
        },
        resolutions=TenantRepository(db, ResolutionRecord, organization_id).get_all(),
        overdue_reviews_by_process=_group_overdue_reviews(db, organization_id),
        access_by_process_id=resolution.access_by_process_id,
        access_model_configured=resolution.configured,
        activation_by_process_id=activation_by_process_id,
        effective_process_bia_answers={
            process_id: effective_bia.answers
            for process_id, effective_bia in effective_process_bia_by_process.items()
        },
        # #463 — each service's BIA exceptions, per visible process.
        bia_exceptions=active_bia_exceptions(
            db,
            organization_id=organization_id,
            process_ids=[process.id for process in processes],
        ),
        viewer_user_id=viewer_user_id,
    )


def _group_overdue_reviews(db: Session, organization_id: int) -> dict[str, list[object]]:
    grouped: dict[str, list[object]] = {}
    for item in find_outstanding_reviews(db, organization_id=organization_id):
        grouped.setdefault(item.process_id, []).append(item)
    return grouped


def _load_latest_evaluations(db: Session, organization_id: int) -> dict[str, RiskEvaluation]:
    latest: dict[str, RiskEvaluation] = {}
    for evaluation in TenantRepository(db, RiskEvaluation, organization_id).get_all():
        current = latest.get(evaluation.process_id)
        if current is None or evaluation.evaluated_at > current.evaluated_at:
            latest[evaluation.process_id] = evaluation
    return latest


@router.post("/evaluate", response_model=ProcessDashboardResponse)
def evaluate_process_dashboard(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessDashboardResponse:
    """Run the reopening + Risk Evaluation passes and return the refreshed projection.

    Lapsed reviews reopen their Business Process first (fresh evaluation,
    scenario snapshot, notification signal); the engine evaluates and
    explains — decisions stay with humans.
    """
    run_review_reopening_pass(db, organization_id=ctx.organization_id)
    outstanding: dict[str, list[dict]] = {}
    for item in find_outstanding_reviews(db, organization_id=ctx.organization_id):
        outstanding.setdefault(item.process_id, []).append(item.__dict__)
    run_risk_evaluation_pass(
        db,
        organization_id=ctx.organization_id,
        overdue_reviews_by_process=outstanding,
    )
    db.commit()
    projection_input = load_process_dashboard_projection_input(db, ctx.organization_id, ctx.user_id)
    projection = build_process_dashboard_projection(projection_input)
    return ProcessDashboardResponse.model_validate(asdict(projection))


@router.get("", response_model=ProcessDashboardResponse)
def list_process_dashboard(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessDashboardResponse:
    projection_input = load_process_dashboard_projection_input(db, ctx.organization_id, ctx.user_id)
    projection = build_process_dashboard_projection(projection_input)
    return ProcessDashboardResponse.model_validate(asdict(projection))
