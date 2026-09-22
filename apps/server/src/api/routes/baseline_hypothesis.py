"""Baseline Risk Hypothesis routes (BSP-10).

Read and regenerate the organisation's cold-start business-model draft.
The hypothesis is assumption-based decision support: every item carries
provenance, confidence, and an explainable reason, and a human validates —
these routes never create Business Processes or Services themselves
(that is the BSP-13 review flow).
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.value_stream_events import ValueStreamEvent
from src.core.database import get_db
from src.core.models import Organization, ValueStreamSignal
from src.core.services.baseline_risk_hypothesis_service import (
    AssumptionDecision,
    apply_validated_hypothesis,
    backfill_hypothesis_from_org_profile,
    generate_baseline_hypothesis,
    get_current_hypothesis,
    record_assumption_decisions,
)
from src.core.services.service_discovery_service import run_service_discovery_pass
from src.api.schemas.timestamps import UtcTimestamp

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/organisation/baseline-hypothesis", tags=["Baseline Hypothesis"])


class HypothesisAssumptionOut(BaseModel):
    kind: str
    key: str
    name: str
    parent_key: str | None = None
    provenance: str
    confidence: str
    reason: str
    suggested_priority: str | None = None
    validation: str
    decided_by: str | None = None
    decided_at: UtcTimestamp | None = None
    # BSP-11 — scanner evidence backing a discovered/strengthened item.
    evidence: list[dict] | None = None
    evidence_confidence: float | None = None


class BaselineHypothesisResponse(BaseModel):
    id: str
    status: str
    company_context: dict
    assumptions: list[HypothesisAssumptionOut]
    generated_at: UtcTimestamp
    validated_by: str | None = None
    validated_at: UtcTimestamp | None = None


# ─── BSP-11 — evidence-driven service discovery ──────────────────────────────


class DiscoveredServiceOut(BaseModel):
    service_key: str
    service_name: str
    confidence: float
    reason: str
    evidence: list[dict]


class ServiceDiscoveryResponse(BaseModel):
    hypothesis: BaselineHypothesisResponse
    newly_proposed: list[str]
    strengthened: list[str]
    skipped_modelled: list[str]
    discovered: list[DiscoveredServiceOut]


# ─── BSP-13 — human review: decisions + accountable apply ────────────────────


class AssumptionDecisionIn(BaseModel):
    key: str
    kind: str  # business_process | business_service
    validation: str  # confirmed | dismissed


class AssumptionDecisionsRequest(BaseModel):
    decisions: list[AssumptionDecisionIn]


class AssumptionDecisionsResponse(BaseModel):
    hypothesis: BaselineHypothesisResponse
    unmatched: list[str]


class HypothesisApplyResponse(BaseModel):
    hypothesis: BaselineHypothesisResponse
    created_process_keys: list[str]
    created_service_keys: list[str]
    linked_service_keys: list[str]
    already_modelled_keys: list[str]


def _to_response(hypothesis) -> BaselineHypothesisResponse:
    return BaselineHypothesisResponse(
        id=hypothesis.id,
        status=hypothesis.status,
        company_context=hypothesis.company_context or {},
        assumptions=[HypothesisAssumptionOut(**item) for item in (hypothesis.assumptions or [])],
        generated_at=hypothesis.generated_at.isoformat(),
        validated_by=hypothesis.validated_by,
        validated_at=hypothesis.validated_at.isoformat() if hypothesis.validated_at else None,
    )


def _get_org(db: Session, organization_id: int) -> Organization:
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
    return org


@router.get("", response_model=BaselineHypothesisResponse)
def get_baseline_hypothesis(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> BaselineHypothesisResponse:
    """Current hypothesis; lazily backfills pre-hypothesis orgs from their profile."""
    hypothesis = get_current_hypothesis(db, ctx.organization_id)
    if hypothesis is None:
        org = _get_org(db, ctx.organization_id)
        hypothesis = backfill_hypothesis_from_org_profile(db, org)
        if hypothesis is not None:
            db.commit()
            db.refresh(hypothesis)
    if hypothesis is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No baseline hypothesis exists yet. Generate one first.",
        )
    return _to_response(hypothesis)


@router.post("/generate", response_model=BaselineHypothesisResponse)
def regenerate_baseline_hypothesis(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> BaselineHypothesisResponse:
    """Generate a fresh hypothesis draft from current company context (supersedes the live one)."""
    org = _get_org(db, ctx.organization_id)
    hypothesis = generate_baseline_hypothesis(db, org)
    db.commit()
    db.refresh(hypothesis)

    logger.info(
        "baseline_hypothesis_generated",
        org_id=ctx.organization_id,
        hypothesis_id=hypothesis.id,
        assumption_count=len(hypothesis.assumptions or []),
    )
    return _to_response(hypothesis)


@router.post("/discover", response_model=ServiceDiscoveryResponse)
def discover_services_from_evidence(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ServiceDiscoveryResponse:
    """Propose unmodelled Business Services from scanner evidence into the hypothesis.

    The engine proposes; nothing is created — confirmation happens in the
    hypothesis review flow.
    """
    hypothesis = get_current_hypothesis(db, ctx.organization_id)
    if hypothesis is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No baseline hypothesis exists yet. Generate one first.",
        )

    result = run_service_discovery_pass(
        db, organization_id=ctx.organization_id, hypothesis=hypothesis
    )
    db.commit()
    db.refresh(hypothesis)

    logger.info(
        "service_discovery_completed",
        org_id=ctx.organization_id,
        hypothesis_id=hypothesis.id,
        newly_proposed=result.newly_proposed,
        strengthened=result.strengthened,
        skipped_modelled=result.skipped_modelled,
    )
    return ServiceDiscoveryResponse(
        hypothesis=_to_response(hypothesis),
        newly_proposed=result.newly_proposed,
        strengthened=result.strengthened,
        skipped_modelled=result.skipped_modelled,
        discovered=[
            DiscoveredServiceOut(
                service_key=d.service_key,
                service_name=d.service_name,
                confidence=d.confidence,
                reason=d.reason,
                evidence=d.evidence,
            )
            for d in result.discovered
        ],
    )


def _require_current_hypothesis(db: Session, organization_id: int):
    hypothesis = get_current_hypothesis(db, organization_id)
    if hypothesis is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No baseline hypothesis exists yet. Generate one first.",
        )
    return hypothesis


@router.patch("/assumptions", response_model=AssumptionDecisionsResponse)
def decide_hypothesis_assumptions(
    body: AssumptionDecisionsRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AssumptionDecisionsResponse:
    """Record accountable confirm/dismiss decisions on hypothesis items."""
    hypothesis = _require_current_hypothesis(db, ctx.organization_id)

    unmatched = record_assumption_decisions(
        db,
        hypothesis,
        [AssumptionDecision(key=d.key, kind=d.kind, validation=d.validation) for d in body.decisions],
        decided_by=str(ctx.user_id) if ctx.user_id is not None else "unknown",
    )
    db.commit()
    db.refresh(hypothesis)

    return AssumptionDecisionsResponse(hypothesis=_to_response(hypothesis), unmatched=unmatched)


@router.post("/apply", response_model=HypothesisApplyResponse)
def apply_hypothesis(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> HypothesisApplyResponse:
    """The accountable creation moment: confirmed items become real processes and services."""
    hypothesis = _require_current_hypothesis(db, ctx.organization_id)
    org = _get_org(db, ctx.organization_id)

    result = apply_validated_hypothesis(
        db,
        org,
        hypothesis,
        validated_by=str(ctx.user_id) if ctx.user_id is not None else "unknown",
    )
    db.add(ValueStreamSignal(
        organization_id=ctx.organization_id,
        user_id=ctx.user_id,
        event=ValueStreamEvent.HYPOTHESIS_VALIDATED,
        stream_id=None,
        library_item_id=None,
        stream_key=None,
        name=None,
        priority=None,
        source="baseline_hypothesis_review",
        payload={
            "hypothesis_id": hypothesis.id,
            "created_process_keys": result.created_process_keys,
            "created_service_keys": result.created_service_keys,
            "linked_service_keys": result.linked_service_keys,
            "already_modelled_keys": result.already_modelled_keys,
        },
    ))
    db.commit()
    db.refresh(hypothesis)

    logger.info(
        "baseline_hypothesis_applied",
        org_id=ctx.organization_id,
        hypothesis_id=hypothesis.id,
        created_processes=result.created_process_keys,
        created_services=result.created_service_keys,
        linked_services=result.linked_service_keys,
    )
    return HypothesisApplyResponse(
        hypothesis=_to_response(hypothesis),
        created_process_keys=result.created_process_keys,
        created_service_keys=result.created_service_keys,
        linked_service_keys=result.linked_service_keys,
        already_modelled_keys=result.already_modelled_keys,
    )
