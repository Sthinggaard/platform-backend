"""Learning loop API for governed execution-signal aggregation."""

from __future__ import annotations

from datetime import datetime, timezone
from secrets import compare_digest

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.schemas.learning import (
    LearningCandidateResponse,
    LearningLoopRunResponse,
    LearningSignalSummaryResponse,
    TrainingSignalCountResponse,
    TriggerLearningLoopRequest,
)
from src.core.config import settings
from src.core.constants.learning_loop import TRIGGERED_BY_MANUAL, TRIGGERED_BY_SCHEDULED
from src.core.database import get_db
from src.core.models import LearningImprovementCandidate, LearningLoopRun, TrainingSignal
from src.core.services.learning_loop_service import run_learning_loop

router = APIRouter(prefix="/api/v1/learning", tags=["Learning"])
internal_router = APIRouter(prefix="/api/v1/internal/learning", tags=["Learning"])

SCHEDULED_TRIGGER_SECRET_HEADER = "x-learning-loop-cron-secret"


def _run_to_response(run: LearningLoopRun) -> LearningLoopRunResponse:
    return LearningLoopRunResponse(
        id=run.id,
        status=run.status,
        triggered_by=run.triggered_by,
        since=run.since.isoformat() if run.since else None,
        signals_ingested=run.signals_ingested,
        candidates_generated=run.candidates_generated,
        candidates_auto_staged=run.candidates_auto_staged,
        summary=run.summary or {},
        error=run.error,
        started_at=run.started_at.isoformat(),
        finished_at=run.finished_at.isoformat() if run.finished_at else None,
    )


def _candidate_to_response(candidate: LearningImprovementCandidate) -> LearningCandidateResponse:
    return LearningCandidateResponse(
        id=candidate.id,
        runId=candidate.run_id,
        candidateType=candidate.candidate_type,
        targetType=candidate.target_type,
        targetKey=candidate.target_key,
        governanceClass=candidate.governance_class,
        status=candidate.status,
        sampleSize=candidate.sample_size,
        confidenceScore=candidate.confidence_score,
        summary=candidate.summary or {},
        proposedChanges=candidate.proposed_changes or [],
        reviewedBy=candidate.reviewed_by,
        reviewNote=candidate.review_note,
        createdAt=candidate.created_at.isoformat(),
        updatedAt=candidate.updated_at.isoformat(),
    )


def _require_platform_operator_secret(request: Request) -> None:
    """Gate that only Risklence's own trusted internal environment can satisfy.

    Both `run_learning_loop` routes read every organisation's TrainingSignal
    rows (deliberately, by design — the loop aggregates across all tenants
    to tune the shared recommendation engine). That means "authenticated
    org_admin" is never the correct check here, since every paying
    customer's own admin would satisfy it (this was the A1 security-gate
    H1/H2 finding: is_admin() means "admin of my own org," not "Risklence
    platform staff," and this codebase has no separate platform-operator
    role to check instead). Reuses the same secret already configured for
    the scheduled/cron trigger below rather than inventing a new gate.
    """
    configured_secret = settings.learning_loop.scheduled_trigger_secret
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


@router.post(
    "/runs",
    response_model=LearningLoopRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger a governed learning-loop run",
)
def trigger_learning_run(
    request: Request,
    body: TriggerLearningLoopRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LearningLoopRunResponse:
    _require_platform_operator_secret(request)
    run = run_learning_loop(
        db,
        since=body.since,
        triggered_by=TRIGGERED_BY_MANUAL,
    )
    return _run_to_response(run)


@internal_router.post(
    "/runs/scheduled",
    response_model=LearningLoopRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
    include_in_schema=False,
)
def trigger_scheduled_learning_run(
    request: Request,
    db: Session = Depends(get_db),
) -> LearningLoopRunResponse:
    _require_platform_operator_secret(request)
    run = run_learning_loop(
        db,
        since=None,
        triggered_by=TRIGGERED_BY_SCHEDULED,
    )
    return _run_to_response(run)


@router.get(
    "/signals",
    response_model=LearningSignalSummaryResponse,
    summary="Inspect aggregated learning signals and staged candidates",
)
def get_learning_signal_summary(
    request: Request,
    since: datetime | None = None,
    limit: int = 50,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LearningSignalSummaryResponse:
    _require_platform_operator_secret(request)
    return _load_signal_summary(db, since=since, limit=limit)


def _load_signal_summary(
    db: Session,
    *,
    since: datetime | None,
    limit: int,
) -> LearningSignalSummaryResponse:
    # Deliberately cross-organisation, not a missing tenant filter: this is
    # the platform-wide aggregation the learning loop exists to produce, and
    # both callers above now require _require_platform_operator_secret, so a
    # tenant admin can no longer reach this at all (A1 security remediation,
    # H1). Do not add an organization_id filter here — that would silently
    # break the platform-operator view without closing anything, since the
    # real fix is who can call this, not what it returns.
    signals_query = db.query(TrainingSignal)
    candidates_query = db.query(LearningImprovementCandidate)
    if since is not None:
        signals_query = signals_query.filter(TrainingSignal.source_created_at >= since)
        candidates_query = candidates_query.filter(LearningImprovementCandidate.created_at >= since)

    signals = signals_query.order_by(TrainingSignal.source_created_at.desc()).all()
    counts: dict[str, int] = {}
    for signal in signals:
        counts[signal.signal_type] = counts.get(signal.signal_type, 0) + 1

    candidates = (
        candidates_query.order_by(LearningImprovementCandidate.created_at.desc())
        .limit(min(limit, 100))
        .all()
    )

    return LearningSignalSummaryResponse(
        since=since.isoformat() if since else None,
        generatedAt=datetime.now(timezone.utc).isoformat(),
        signalCounts=[
            TrainingSignalCountResponse(signalType=signal_type, count=count)
            for signal_type, count in sorted(counts.items())
        ],
        candidates=[_candidate_to_response(candidate) for candidate in candidates],
    )
