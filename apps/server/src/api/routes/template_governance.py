"""Template Governance API — UC-TDM-02.

Endpoints for the Risklence platform team to:
  - Trigger a template learning analysis run
  - List pending/staged TemplateCandidate rows for review
  - Approve or reject candidates, publishing new template versions
  - Check which services in an org have template upgrades available

All routes above except the upgrade-check require
``_require_platform_operator_secret`` (A1 security remediation) — they are
platform-wide, not tenant-scoped, and were previously gated only by
``org_admin``, which every paying customer's own admin satisfies. The
tenant Settings UI no longer surfaces this module at all. The upgrade-check
endpoint is genuinely per-org and stays available to all authenticated
users so the tenant UI can surface the "Upgrade available" prompt.
"""

from __future__ import annotations

from secrets import compare_digest

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi import Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.config import settings
from src.core.constants.internal_routes import TEMPLATE_GOVERNANCE_SCHEDULED_RUN_PATH
from src.core.database import get_db
from src.core.models import TemplateCandidate, TemplateLearningRun
from src.core.services.template_learning_service import (
    get_upgrades_for_org,
    publish_candidate,
    reject_candidate,
    run_learning_analysis,
)
from src.api.schemas.timestamps import UtcTimestamp

router = APIRouter(prefix="/api/v1/template-governance", tags=["Template Governance"])
internal_router = APIRouter(prefix="/api/v1/internal/template-governance", tags=["Template Governance"])


# ── Contracts ──────────────────────────────────────────────────────────────────

class TriggerRunRequest(BaseModel):
    service_keys: list[str] | None = None


class ReviewRequest(BaseModel):
    review_note: str | None = None


class LearningRunResponse(BaseModel):
    id: str
    status: str
    triggered_by: str
    service_keys_analysed: list[str]
    candidates_generated: int
    candidates_auto_staged: int
    summary: dict
    error: str | None
    started_at: UtcTimestamp
    finished_at: UtcTimestamp | None


class ProposedChange(BaseModel):
    type: str
    slot_id: str | None = None
    rationale: str
    evidence: dict


class CandidateResponse(BaseModel):
    id: str
    run_id: str
    service_key: str
    current_version: int
    candidate_version: int
    governance_class: str
    status: str
    analysis: dict
    proposed_changes: list[dict]
    reviewed_by: str | None
    review_note: str | None
    created_at: UtcTimestamp
    updated_at: UtcTimestamp


class UpgradeAvailableItem(BaseModel):
    service_id: str
    service_name: str
    service_key: str
    current_version: int
    latest_version: int


SCHEDULED_TRIGGER_SECRET_HEADER = "x-template-governance-cron-secret"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _require_platform_operator_secret(request: Request) -> None:
    """Gate that only Risklence's own trusted internal environment can satisfy.

    Every route below except list_upgrades is platform-wide, not tenant-
    scoped: run_learning_analysis reads SlotInstance patterns across every
    organisation, and approve_candidate/reject_candidate_endpoint publish a
    new active ServiceTemplate version for a service_key platform-wide (no
    organization_id on ServiceTemplate at all), immediately changing what
    every other tenant sees via list_upgrades. "org_admin" was never the
    right check for that — every paying customer's own admin satisfies it —
    but it was the only check available, since this codebase has no
    separate platform-operator role, and the tenant Settings UI wired this
    module's whole surface into ordinary customer navigation on that
    mistaken assumption (A1 security remediation — see the newly-discovered
    Critical finding alongside H1/H2: any org_admin could reach
    /settings → Template Governance and publish a template change affecting
    every other tenant). Reuses the same secret already configured for the
    scheduled/cron trigger below rather than inventing a new gate; the
    tenant Settings page no longer renders this tab or calls these routes.
    """
    configured_secret = settings.template_governance.scheduled_trigger_secret
    expected_secret = configured_secret.get_secret_value().strip() if configured_secret else ""
    if not expected_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform operator secret is not configured.",
        )

    provided_secret = request.headers.get(SCHEDULED_TRIGGER_SECRET_HEADER, "").strip()
    if not provided_secret or not compare_digest(provided_secret, expected_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid platform operator secret.",
        )

def _run_to_response(run: TemplateLearningRun) -> LearningRunResponse:
    return LearningRunResponse(
        id=run.id,
        status=run.status,
        triggered_by=run.triggered_by,
        service_keys_analysed=run.service_keys_analysed or [],
        candidates_generated=run.candidates_generated,
        candidates_auto_staged=run.candidates_auto_staged,
        summary=run.summary or {},
        error=run.error,
        started_at=run.started_at.isoformat(),
        finished_at=run.finished_at.isoformat() if run.finished_at else None,
    )


def _candidate_to_response(c: TemplateCandidate) -> CandidateResponse:
    return CandidateResponse(
        id=c.id,
        run_id=c.run_id,
        service_key=c.service_key,
        current_version=c.current_version,
        candidate_version=c.candidate_version,
        governance_class=c.governance_class,
        status=c.status,
        analysis=c.analysis or {},
        proposed_changes=c.proposed_changes or [],
        reviewed_by=c.reviewed_by,
        review_note=c.review_note,
        created_at=c.created_at.isoformat(),
        updated_at=c.updated_at.isoformat(),
    )


def _trigger_learning_run(
    db: Session,
    *,
    service_keys: list[str] | None,
    triggered_by: str,
) -> LearningRunResponse:
    run = run_learning_analysis(
        db,
        service_keys=service_keys,
        triggered_by=triggered_by,
    )
    return _run_to_response(run)


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post(
    "/runs",
    response_model=LearningRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger a template learning analysis run",
    response_description="The created learning run record. The run completes synchronously.",
)
def trigger_learning_run(
    request: Request,
    body: TriggerRunRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LearningRunResponse:
    """Analyse SlotInstance patterns across all orgs and generate TemplateCandidate rows.

    Restricted to Risklence platform operators (see
    _require_platform_operator_secret) — not org_admin, which every paying
    customer's own admin would satisfy. In production this will be called
    by a scheduled job; the endpoint exists so the platform team can
    trigger a run on demand without deploying code.
    """
    _require_platform_operator_secret(request)

    return _trigger_learning_run(
        db,
        service_keys=body.service_keys,
        triggered_by="manual",
    )


@internal_router.post(
    "/runs/scheduled",
    response_model=LearningRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
    include_in_schema=False,
)
def trigger_scheduled_learning_run(
    request: Request,
    db: Session = Depends(get_db),
) -> LearningRunResponse:
    _require_platform_operator_secret(request)
    return _trigger_learning_run(
        db,
        service_keys=None,
        triggered_by="scheduled",
    )


@router.get(
    "/runs",
    response_model=list[LearningRunResponse],
    summary="List recent learning runs",
)
def list_learning_runs(
    request: Request,
    limit: int = 20,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[LearningRunResponse]:
    _require_platform_operator_secret(request)

    runs = (
        db.query(TemplateLearningRun)
        .order_by(TemplateLearningRun.started_at.desc())
        .limit(min(limit, 100))
        .all()
    )
    return [_run_to_response(r) for r in runs]


@router.get(
    "/runs/{run_id}",
    response_model=LearningRunResponse,
    summary="Get a single learning run",
)
def get_learning_run(
    request: Request,
    run_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LearningRunResponse:
    _require_platform_operator_secret(request)

    run = db.query(TemplateLearningRun).filter(TemplateLearningRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found.")
    return _run_to_response(run)


@router.get(
    "/candidates",
    response_model=list[CandidateResponse],
    summary="List template candidates pending review",
)
def list_candidates(
    request: Request,
    governance_class: str | None = None,
    candidate_status: str | None = None,
    limit: int = 50,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[CandidateResponse]:
    _require_platform_operator_secret(request)

    q = db.query(TemplateCandidate)
    if governance_class:
        q = q.filter(TemplateCandidate.governance_class == governance_class.upper())
    if candidate_status:
        q = q.filter(TemplateCandidate.status == candidate_status)
    else:
        # Default: only actionable candidates.
        q = q.filter(TemplateCandidate.status.in_(["pending", "auto_staged"]))

    candidates = (
        q.order_by(
            TemplateCandidate.governance_class.asc(),
            TemplateCandidate.created_at.desc(),
        )
        .limit(min(limit, 200))
        .all()
    )
    return [_candidate_to_response(c) for c in candidates]


@router.get(
    "/candidates/{candidate_id}",
    response_model=CandidateResponse,
    summary="Get a single template candidate",
)
def get_candidate(
    request: Request,
    candidate_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> CandidateResponse:
    _require_platform_operator_secret(request)

    candidate = db.query(TemplateCandidate).filter(TemplateCandidate.id == candidate_id).first()
    if not candidate:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Candidate not found.")
    return _candidate_to_response(candidate)


@router.post(
    "/candidates/{candidate_id}/approve",
    response_model=CandidateResponse,
    summary="Approve a candidate and publish the new template version",
)
def approve_candidate(
    request: Request,
    candidate_id: str,
    body: ReviewRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> CandidateResponse:
    # Publishes a new active ServiceTemplate version platform-wide (no
    # organization_id on ServiceTemplate at all) — this is the Critical
    # finding from the A1 security remediation: any org_admin previously
    # satisfied ctx.is_admin() here, meaning any single customer's admin
    # could change what every other tenant sees as the active template.
    _require_platform_operator_secret(request)

    candidate = db.query(TemplateCandidate).filter(TemplateCandidate.id == candidate_id).first()
    if not candidate:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Candidate not found.")
    if candidate.status not in ("pending", "auto_staged"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Candidate is already '{candidate.status}' and cannot be approved.",
        )

    publish_candidate(db, candidate, reviewed_by=ctx.email or str(ctx.user_id), review_note=body.review_note)
    db.refresh(candidate)
    return _candidate_to_response(candidate)


@router.post(
    "/candidates/{candidate_id}/reject",
    response_model=CandidateResponse,
    summary="Reject a candidate — no new template version is created",
)
def reject_candidate_endpoint(
    request: Request,
    candidate_id: str,
    body: ReviewRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> CandidateResponse:
    _require_platform_operator_secret(request)

    candidate = db.query(TemplateCandidate).filter(TemplateCandidate.id == candidate_id).first()
    if not candidate:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Candidate not found.")
    if candidate.status not in ("pending", "auto_staged"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Candidate is already '{candidate.status}' and cannot be rejected.",
        )

    reject_candidate(db, candidate, reviewed_by=ctx.email or str(ctx.user_id), review_note=body.review_note)
    db.refresh(candidate)
    return _candidate_to_response(candidate)


@router.get(
    "/upgrades",
    response_model=list[UpgradeAvailableItem],
    summary="List services in this org that have a newer template version available",
)
def list_upgrades(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[UpgradeAvailableItem]:
    """Available to all authenticated users — powers the 'Upgrade available' prompt
    on the process detail view."""
    upgrades = get_upgrades_for_org(db, ctx.organization_id)
    return [UpgradeAvailableItem(**u) for u in upgrades]
