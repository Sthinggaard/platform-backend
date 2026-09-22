"""Resolve the BIA context a Business Process and its services inherit."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.model_defs.organization_bia_baseline import OrganizationBiaBaseline
from src.core.model_defs.process_bia_assessment import (
    BIA_ASSESSMENT_ATTESTED,
    BIA_ASSESSMENT_SUPERSEDED,
    ProcessBiaAssessment,
)
from src.core.model_defs.value_streams import ValueStream
from src.core.repository import TenantRepository
from src.core.services.organization_bia_baseline_service import (
    get_current_organization_bia_baseline,
)


@dataclass(frozen=True)
class EffectiveProcessBia:
    """Current process BIA with the record that governs its provenance."""

    answers: dict | None
    process_assessment_id: str | None
    organization_baseline_id: str | None
    process_assessment_started: bool


def resolve_effective_process_bia_by_process(
    db: Session,
    *,
    organization_id: int,
    processes: list[ValueStream],
) -> dict[str, EffectiveProcessBia]:
    """Resolve process exception, organisation baseline, then legacy projection.

    An attested process assessment is a deliberate process-level exception. In
    every other case, the active organisation baseline is the one shared BIA
    source. ``ValueStream.bia_answers`` remains a compatibility fallback for
    pre-baseline records only; a baseline is never copied into each process.
    """
    baseline = get_current_organization_bia_baseline(db, organization_id=organization_id)
    assessments = TenantRepository(db, ProcessBiaAssessment, organization_id).get_all()
    assessment_by_process = _current_assessments_by_process(assessments)
    return {
        process.id: _resolve_process_bia(
            process=process,
            assessment=assessment_by_process.get(process.id),
            baseline=baseline,
            process_assessment_started=process.id in assessment_by_process,
        )
        for process in processes
    }


def _current_assessments_by_process(
    assessments: list[ProcessBiaAssessment],
) -> dict[str, ProcessBiaAssessment]:
    current: dict[str, ProcessBiaAssessment] = {}
    for assessment in assessments:
        if assessment.status == BIA_ASSESSMENT_SUPERSEDED:
            continue
        existing = current.get(assessment.process_id)
        if existing is None or assessment.created_at > existing.created_at:
            current[assessment.process_id] = assessment
    return current


def _resolve_process_bia(
    *,
    process: ValueStream,
    assessment: ProcessBiaAssessment | None,
    baseline: OrganizationBiaBaseline | None,
    process_assessment_started: bool,
) -> EffectiveProcessBia:
    if assessment is not None and assessment.status == BIA_ASSESSMENT_ATTESTED:
        return EffectiveProcessBia(
            answers=dict(assessment.answers),
            process_assessment_id=assessment.id,
            organization_baseline_id=None,
            process_assessment_started=True,
        )
    if baseline is not None:
        return EffectiveProcessBia(
            answers=dict(baseline.answers),
            process_assessment_id=None,
            organization_baseline_id=baseline.id,
            process_assessment_started=process_assessment_started,
        )
    if assessment is not None:
        return EffectiveProcessBia(
            answers=None,
            process_assessment_id=None,
            organization_baseline_id=None,
            process_assessment_started=True,
        )
    return EffectiveProcessBia(
        answers=dict(process.bia_answers) if process.bia_answers else None,
        process_assessment_id=None,
        organization_baseline_id=None,
        process_assessment_started=process_assessment_started,
    )
