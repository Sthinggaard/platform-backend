"""Governed learning loop for execution-layer signal aggregation."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable
import uuid

from sqlalchemy import or_
from sqlalchemy.orm import Session

from src.core.constants.decision_runtime import (
    RECOMMENDATION_GENERATOR_VERSION,
    VERIFICATION_STATUS_ALTERNATIVE,
    VERIFICATION_STATUS_INSUFFICIENT,
    VERIFICATION_STATUS_SUCCESSFUL,
)
from src.core.constants.learning_loop import (
    CANDIDATE_STATUS_AUTO_STAGED,
    CANDIDATE_STATUS_PENDING,
    CANDIDATE_TYPE_RECOMMENDATION_RANKING,
    CANDIDATE_TYPE_RESOLUTION_GUIDANCE,
    CANDIDATE_TYPE_TEMPLATE_PATTERN,
    GOVERNANCE_CLASS_C,
    GOVERNANCE_CLASS_A,
    GOVERNANCE_CLASS_B,
    RECOMMENDATION_SIGNAL_OUTCOME_CONTEXT_REFRESHED,
    RECOMMENDATION_SIGNAL_OUTCOME_GENERATED,
    RECOMMENDATION_SIGNAL_OUTCOME_UNCERTAINTY_FLAGGED,
    RUN_STATUS_COMPLETED,
    RUN_STATUS_FAILED,
    RUN_STATUS_RUNNING,
    SIGNAL_TYPE_RECOMMENDATION_GENERATION,
    SIGNAL_TYPE_RECOMMENDATION_DECISION,
    SIGNAL_TYPE_RESOLUTION_OUTCOME,
    SIGNAL_TYPE_TEMPLATE_PATTERN,
    SIGNAL_TYPE_VERIFICATION_OUTCOME,
    TARGET_TYPE_RECOMMENDATION_CONTEXT,
    TARGET_TYPE_RECOMMENDATION_ACTION,
    TARGET_TYPE_RESOLUTION_ACTION,
    TARGET_TYPE_SERVICE_TEMPLATE_GROUP,
    TRAINING_SIGNAL_SOURCE_DECISION_RECORD,
    TRAINING_SIGNAL_SOURCE_MAPPING_DECISION,
    TRAINING_SIGNAL_SOURCE_RECOMMENDATION,
    TRAINING_SIGNAL_SOURCE_RESOLUTION_RECORD,
    TRAINING_SIGNAL_SOURCE_VERIFICATION_RECORD,
)
from src.core.constants.value_stream_events import ValueStreamEvent
from src.core.models import (
    BusinessService,
    DecisionRecord,
    LearningImprovementCandidate,
    LearningLoopRun,
    MappingDecision,
    Recommendation,
    ResolutionRecord,
    TrainingSignal,
    ValueStreamSignal,
    VerificationRecord,
)

MIN_SAMPLE_CLASS_A = 12
MIN_SAMPLE_CLASS_B = 6
MIN_SAMPLE_CLASS_C = 3
HIGH_CONFIDENCE_THRESHOLD = 85
MEDIUM_CONFIDENCE_THRESHOLD = 65
MAPPING_REVIEW_RATIO = 0.5
DECISION_OVERRIDE_RATIO = 0.35
OUTCOME_DOMINANCE_RATIO = 0.6
PLATFORM_ORGANIZATION_ID = 0
PLATFORM_USER_ID = 0
RECOMMENDATION_GENERATION_SUFFIX = "generated"
RECOMMENDATION_UNCERTAINTY_SUFFIX = "uncertain"
RECOMMENDATION_REFRESHED_SUFFIX = "refreshed"


@dataclass(frozen=True)
class CandidateDraft:
    candidate_type: str
    target_type: str
    target_key: str
    sample_size: int
    confidence_score: int
    summary: dict[str, Any]
    proposed_changes: list[dict[str, Any]]


def run_learning_loop(
    db: Session,
    *,
    since: datetime | None = None,
    triggered_by: str = "manual",
) -> LearningLoopRun:
    """Aggregate new execution signals and stage governed improvement candidates."""

    effective_since = since or _latest_completed_run_timestamp(db)
    run = LearningLoopRun(
        id=str(uuid.uuid4()),
        status=RUN_STATUS_RUNNING,
        triggered_by=triggered_by,
        since=effective_since,
        started_at=datetime.now(timezone.utc),
    )
    db.add(run)
    db.commit()

    try:
        signals = _collect_training_signals(db, run.id, since=effective_since)
        candidates = _generate_candidates(db, run.id, signals)

        run.status = RUN_STATUS_COMPLETED
        run.signals_ingested = len(signals)
        run.candidates_generated = len(candidates)
        run.candidates_auto_staged = sum(
            1 for candidate in candidates if candidate.status == CANDIDATE_STATUS_AUTO_STAGED
        )
        run.summary = {
            "since": effective_since.isoformat() if effective_since else None,
            "signalCounts": _summarize_signal_counts(signals),
            "candidateCounts": _summarize_candidate_counts(candidates),
        }
        run.finished_at = datetime.now(timezone.utc)
        _emit_platform_event(
            db,
            ValueStreamEvent.LEARNING_RUN_COMPLETED,
            {
                "runId": run.id,
                "signalsIngested": run.signals_ingested,
                "candidatesGenerated": run.candidates_generated,
                "candidatesAutoStaged": run.candidates_auto_staged,
                "since": run.summary["since"],
            },
        )
        db.commit()
    except Exception as exc:
        run.status = RUN_STATUS_FAILED
        run.error = str(exc)
        run.finished_at = datetime.now(timezone.utc)
        db.commit()
        raise

    return run


def _latest_completed_run_timestamp(db: Session) -> datetime | None:
    latest_run = (
        db.query(LearningLoopRun)
        .filter(LearningLoopRun.status == RUN_STATUS_COMPLETED)
        .order_by(LearningLoopRun.finished_at.desc())
        .first()
    )
    return latest_run.finished_at if latest_run else None


def _collect_training_signals(
    db: Session,
    run_id: str,
    *,
    since: datetime | None,
) -> list[TrainingSignal]:
    collected: list[TrainingSignal] = []
    collected.extend(_build_mapping_signals(db, run_id, since=since))
    collected.extend(_build_recommendation_generation_signals(db, run_id, since=since))
    collected.extend(_build_decision_signals(db, run_id, since=since))
    collected.extend(_build_resolution_signals(db, run_id, since=since))
    collected.extend(_build_verification_signals(db, run_id, since=since))
    db.commit()
    return collected


def _build_mapping_signals(
    db: Session, run_id: str, *, since: datetime | None
) -> list[TrainingSignal]:
    query = (
        db.query(MappingDecision, BusinessService.template_key)
        .outerjoin(BusinessService, BusinessService.id == MappingDecision.service_id)
        .order_by(MappingDecision.created_at.asc())
    )
    if since is not None:
        query = query.filter(MappingDecision.created_at >= since)

    signals: list[TrainingSignal] = []
    for decision, template_key in query.all():
        if _signal_exists(db, TRAINING_SIGNAL_SOURCE_MAPPING_DECISION, decision.id):
            continue

        normalized_service_key = template_key or decision.service_id or "unknown_service"
        normalized_group_key = decision.group_key or "ungrouped"
        target_key = f"{normalized_service_key}:{normalized_group_key}"
        signal = TrainingSignal(
            id=str(uuid.uuid4()),
            run_id=run_id,
            organization_id=decision.organization_id,
            source_type=TRAINING_SIGNAL_SOURCE_MAPPING_DECISION,
            source_id=decision.id,
            signal_type=SIGNAL_TYPE_TEMPLATE_PATTERN,
            target_type=TARGET_TYPE_SERVICE_TEMPLATE_GROUP,
            target_key=target_key,
            outcome=decision.action,
            payload={
                "serviceId": decision.service_id,
                "serviceKey": normalized_service_key,
                "bundleId": decision.bundle_id,
                "groupKey": decision.group_key,
                "actorType": decision.actor_type,
                "reason": decision.reason,
            },
            source_created_at=decision.created_at,
        )
        db.add(signal)
        signals.append(signal)
    return signals


def _build_recommendation_generation_signals(
    db: Session,
    run_id: str,
    *,
    since: datetime | None,
) -> list[TrainingSignal]:
    query = db.query(Recommendation).order_by(Recommendation.created_at.asc())
    if since is not None:
        query = query.filter(
            or_(Recommendation.created_at >= since, Recommendation.updated_at >= since)
        )

    signals: list[TrainingSignal] = []
    for recommendation in query.all():
        for outcome, suffix, source_created_at in _recommendation_signal_outcomes(recommendation):
            source_id = f"{recommendation.id}:{suffix}"
            if _signal_exists(db, TRAINING_SIGNAL_SOURCE_RECOMMENDATION, source_id):
                continue

            signal = TrainingSignal(
                id=str(uuid.uuid4()),
                run_id=run_id,
                organization_id=recommendation.organization_id,
                source_type=TRAINING_SIGNAL_SOURCE_RECOMMENDATION,
                source_id=source_id,
                signal_type=SIGNAL_TYPE_RECOMMENDATION_GENERATION,
                target_type=TARGET_TYPE_RECOMMENDATION_CONTEXT,
                target_key=_recommendation_signal_target_key(recommendation),
                outcome=outcome,
                payload=_recommendation_signal_payload(recommendation),
                source_created_at=source_created_at,
            )
            db.add(signal)
            signals.append(signal)
    return signals


def _build_decision_signals(
    db: Session, run_id: str, *, since: datetime | None
) -> list[TrainingSignal]:
    query = db.query(DecisionRecord).order_by(DecisionRecord.created_at.asc())
    if since is not None:
        query = query.filter(DecisionRecord.created_at >= since)

    signals: list[TrainingSignal] = []
    for record in query.all():
        if _signal_exists(db, TRAINING_SIGNAL_SOURCE_DECISION_RECORD, record.id):
            continue

        suggested_action = (record.recommendation_snapshot or {}).get(
            "suggestedAction"
        ) or record.selected_action
        signal = TrainingSignal(
            id=str(uuid.uuid4()),
            run_id=run_id,
            organization_id=record.organization_id,
            source_type=TRAINING_SIGNAL_SOURCE_DECISION_RECORD,
            source_id=record.id,
            signal_type=SIGNAL_TYPE_RECOMMENDATION_DECISION,
            target_type=TARGET_TYPE_RECOMMENDATION_ACTION,
            target_key=suggested_action,
            outcome=record.decision_type,
            payload={
                "suggestedAction": suggested_action,
                "selectedAction": record.selected_action,
                "decisionType": record.decision_type,
                "businessDecisionTaxonomy": (record.reasoning_snapshot or {}).get(
                    "businessDecisionTaxonomy"
                )
                or (record.recommendation_snapshot or {}).get("businessDecisionTaxonomy")
                or {},
                "stale": record.stale,
                "threatId": record.threat_id,
            },
            source_created_at=record.created_at,
        )
        db.add(signal)
        signals.append(signal)
    return signals


def _build_resolution_signals(
    db: Session, run_id: str, *, since: datetime | None
) -> list[TrainingSignal]:
    query = db.query(ResolutionRecord).order_by(ResolutionRecord.created_at.asc())
    if since is not None:
        query = query.filter(ResolutionRecord.created_at >= since)

    signals: list[TrainingSignal] = []
    for record in query.all():
        if _signal_exists(db, TRAINING_SIGNAL_SOURCE_RESOLUTION_RECORD, record.id):
            continue

        signal = TrainingSignal(
            id=str(uuid.uuid4()),
            run_id=run_id,
            organization_id=record.organization_id,
            source_type=TRAINING_SIGNAL_SOURCE_RESOLUTION_RECORD,
            source_id=record.id,
            signal_type=SIGNAL_TYPE_RESOLUTION_OUTCOME,
            target_type=TARGET_TYPE_RESOLUTION_ACTION,
            target_key=record.selected_action_option,
            outcome=record.resolution_type,
            payload={
                "resolutionType": record.resolution_type,
                "selectedActionOption": record.selected_action_option,
                "alternativeCategory": record.alternative_category,
                "status": record.status,
                "verificationStatus": record.verification_status,
                "recoveryActionId": record.recovery_action_id,
            },
            source_created_at=record.created_at,
        )
        db.add(signal)
        signals.append(signal)
    return signals


def _build_verification_signals(
    db: Session, run_id: str, *, since: datetime | None
) -> list[TrainingSignal]:
    resolution_map = {resolution.id: resolution for resolution in db.query(ResolutionRecord).all()}
    query = db.query(VerificationRecord).order_by(VerificationRecord.created_at.asc())
    if since is not None:
        query = query.filter(VerificationRecord.created_at >= since)

    signals: list[TrainingSignal] = []
    for record in query.all():
        if _signal_exists(db, TRAINING_SIGNAL_SOURCE_VERIFICATION_RECORD, record.id):
            continue

        resolution = resolution_map.get(record.resolution_record_id)
        target_key = (
            resolution.selected_action_option if resolution else record.resolution_record_id
        )
        signal = TrainingSignal(
            id=str(uuid.uuid4()),
            run_id=run_id,
            organization_id=record.organization_id,
            source_type=TRAINING_SIGNAL_SOURCE_VERIFICATION_RECORD,
            source_id=record.id,
            signal_type=SIGNAL_TYPE_VERIFICATION_OUTCOME,
            target_type=TARGET_TYPE_RESOLUTION_ACTION,
            target_key=target_key,
            outcome=record.verification_status,
            payload={
                "verificationStatus": record.verification_status,
                "confidenceScore": record.confidence_score,
                "resolutionId": record.resolution_record_id,
                "resolutionType": resolution.resolution_type if resolution else None,
                "selectedActionOption": resolution.selected_action_option if resolution else None,
                "linkedContextType": record.linked_context_type,
            },
            source_created_at=record.created_at,
        )
        db.add(signal)
        signals.append(signal)
    return signals


def _recommendation_signal_outcomes(
    recommendation: Recommendation,
) -> list[tuple[str, str, datetime]]:
    outcomes = [
        (
            RECOMMENDATION_SIGNAL_OUTCOME_GENERATED,
            RECOMMENDATION_GENERATION_SUFFIX,
            recommendation.created_at,
        )
    ]
    snapshot = recommendation.intelligence_snapshot or {}
    if snapshot.get("uncertaintyFactors"):
        outcomes.append(
            (
                RECOMMENDATION_SIGNAL_OUTCOME_UNCERTAINTY_FLAGGED,
                RECOMMENDATION_UNCERTAINTY_SUFFIX,
                recommendation.created_at,
            )
        )
    if recommendation.is_stale:
        outcomes.append(
            (
                RECOMMENDATION_SIGNAL_OUTCOME_CONTEXT_REFRESHED,
                RECOMMENDATION_REFRESHED_SUFFIX,
                recommendation.updated_at,
            )
        )
    return outcomes


def _recommendation_signal_target_key(recommendation: Recommendation) -> str:
    snapshot = recommendation.intelligence_snapshot or {}
    recommendation_type = snapshot.get("recommendationType") or recommendation.linked_context_type
    taxonomy = snapshot.get("businessDecisionTaxonomy") or {}
    business_action = taxonomy.get("recommendedBusinessAction") or recommendation.suggested_action
    return f"{recommendation_type}:{business_action}"


def _recommendation_signal_payload(recommendation: Recommendation) -> dict[str, Any]:
    snapshot = recommendation.intelligence_snapshot or {}
    return {
        "recommendationId": recommendation.id,
        "threatId": recommendation.threat_id,
        "recommendationType": snapshot.get("recommendationType"),
        "suggestedAction": recommendation.suggested_action,
        "linkedContext": {
            "type": recommendation.linked_context_type,
            "id": recommendation.linked_context_id,
            "label": recommendation.linked_context_label,
        },
        "confidenceScore": recommendation.confidence_score,
        "uncertaintyFactors": snapshot.get("uncertaintyFactors") or [],
        "structuralRationale": snapshot.get("structuralRationale") or [],
        "businessDecisionTaxonomy": snapshot.get("businessDecisionTaxonomy") or {},
        "generatorVersion": snapshot.get("generatorVersion") or RECOMMENDATION_GENERATOR_VERSION,
        "isStale": recommendation.is_stale,
    }


def _signal_exists(db: Session, source_type: str, source_id: str) -> bool:
    return (
        db.query(TrainingSignal.id)
        .filter(
            TrainingSignal.source_type == source_type,
            TrainingSignal.source_id == source_id,
        )
        .first()
        is not None
    )


def _generate_candidates(
    db: Session,
    run_id: str,
    signals: list[TrainingSignal],
) -> list[LearningImprovementCandidate]:
    if not signals:
        return []

    candidates: list[LearningImprovementCandidate] = []
    drafts = (
        _build_mapping_candidates(
            [signal for signal in signals if signal.signal_type == SIGNAL_TYPE_TEMPLATE_PATTERN]
        )
        + _build_decision_candidates(
            [
                signal
                for signal in signals
                if signal.signal_type == SIGNAL_TYPE_RECOMMENDATION_DECISION
            ]
        )
        + _build_resolution_candidates(
            resolution_signals=[
                signal for signal in signals if signal.signal_type == SIGNAL_TYPE_RESOLUTION_OUTCOME
            ],
            verification_signals=[
                signal
                for signal in signals
                if signal.signal_type == SIGNAL_TYPE_VERIFICATION_OUTCOME
            ],
        )
    )

    for draft in drafts:
        governance_class = _classify_governance_class(
            sample_size=draft.sample_size,
            confidence_score=draft.confidence_score,
        )
        candidate_status = (
            CANDIDATE_STATUS_AUTO_STAGED
            if governance_class == GOVERNANCE_CLASS_A
            else CANDIDATE_STATUS_PENDING
        )
        candidate = LearningImprovementCandidate(
            id=str(uuid.uuid4()),
            run_id=run_id,
            candidate_type=draft.candidate_type,
            target_type=draft.target_type,
            target_key=draft.target_key,
            governance_class=governance_class,
            status=candidate_status,
            sample_size=draft.sample_size,
            confidence_score=draft.confidence_score,
            summary=draft.summary,
            proposed_changes=draft.proposed_changes,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(candidate)
        candidates.append(candidate)

        _emit_platform_event(
            db,
            ValueStreamEvent.CANDIDATE_IMPROVEMENT_GENERATED,
            {
                "candidateId": candidate.id,
                "candidateType": candidate.candidate_type,
                "targetKey": candidate.target_key,
                "governanceClass": governance_class,
                "sampleSize": candidate.sample_size,
            },
        )
        if candidate_status == CANDIDATE_STATUS_AUTO_STAGED:
            _emit_platform_event(
                db,
                ValueStreamEvent.IMPROVEMENT_AUTO_APPLIED,
                {
                    "candidateId": candidate.id,
                    "targetKey": candidate.target_key,
                    "stagedOnly": True,
                },
            )
        else:
            _emit_platform_event(
                db,
                ValueStreamEvent.IMPROVEMENT_QUEUED_FOR_REVIEW,
                {
                    "candidateId": candidate.id,
                    "targetKey": candidate.target_key,
                    "governanceClass": governance_class,
                },
            )

    db.commit()
    return candidates


def _build_mapping_candidates(signals: Iterable[TrainingSignal]) -> list[CandidateDraft]:
    grouped = _group_signals_by_target(signals)
    drafts: list[CandidateDraft] = []
    review_actions = {"slot_unknown", "slot_not_applicable"}

    for target_key, items in grouped.items():
        total = len(items)
        if total < MIN_SAMPLE_CLASS_C:
            continue

        action_counts = Counter(item.outcome for item in items)
        review_count = sum(action_counts.get(action, 0) for action in review_actions)
        review_ratio = review_count / total if total else 0.0
        if review_ratio < MAPPING_REVIEW_RATIO:
            continue

        service_key, group_key = _split_target_key(target_key)
        confidence = round(review_ratio * 100)
        drafts.append(
            CandidateDraft(
                candidate_type=CANDIDATE_TYPE_TEMPLATE_PATTERN,
                target_type=TARGET_TYPE_SERVICE_TEMPLATE_GROUP,
                target_key=target_key,
                sample_size=total,
                confidence_score=confidence,
                summary={
                    "serviceKey": service_key,
                    "groupKey": group_key,
                    "actionCounts": dict(action_counts),
                    "reviewRatio": round(review_ratio, 3),
                },
                proposed_changes=[
                    {
                        "type": "review_template_group",
                        "serviceKey": service_key,
                        "groupKey": group_key,
                        "rationale": "Runtime mapping signals show the current group pattern is frequently overridden.",
                        "evidence": {
                            "actionCounts": dict(action_counts),
                            "reviewRatio": round(review_ratio, 3),
                        },
                    }
                ],
            )
        )

    return drafts


def _build_decision_candidates(signals: Iterable[TrainingSignal]) -> list[CandidateDraft]:
    grouped = _group_signals_by_target(signals)
    drafts: list[CandidateDraft] = []

    for target_key, items in grouped.items():
        total = len(items)
        if total < MIN_SAMPLE_CLASS_C:
            continue

        outcome_counts = Counter(item.outcome for item in items)
        alternative_count = outcome_counts.get("alternative", 0)
        alternative_ratio = alternative_count / total if total else 0.0
        if alternative_ratio < DECISION_OVERRIDE_RATIO:
            continue

        alternative_actions = Counter(
            (item.payload or {}).get("selectedAction")
            for item in items
            if item.outcome == "alternative" and (item.payload or {}).get("selectedAction")
        )
        dominant_override = (
            alternative_actions.most_common(1)[0][0] if alternative_actions else None
        )
        confidence = round(alternative_ratio * 100)
        drafts.append(
            CandidateDraft(
                candidate_type=CANDIDATE_TYPE_RECOMMENDATION_RANKING,
                target_type=TARGET_TYPE_RECOMMENDATION_ACTION,
                target_key=target_key,
                sample_size=total,
                confidence_score=confidence,
                summary={
                    "suggestedAction": target_key,
                    "decisionCounts": dict(outcome_counts),
                    "dominantAlternativeAction": dominant_override,
                    "alternativeRatio": round(alternative_ratio, 3),
                },
                proposed_changes=[
                    {
                        "type": "adjust_recommendation_ranking",
                        "suggestedAction": target_key,
                        "rationale": "Humans frequently choose an alternative route over the current recommendation.",
                        "evidence": {
                            "decisionCounts": dict(outcome_counts),
                            "dominantAlternativeAction": dominant_override,
                            "alternativeRatio": round(alternative_ratio, 3),
                        },
                    }
                ],
            )
        )

    return drafts


def _build_resolution_candidates(
    *,
    resolution_signals: Iterable[TrainingSignal],
    verification_signals: Iterable[TrainingSignal],
) -> list[CandidateDraft]:
    resolution_grouped = _group_signals_by_target(resolution_signals)
    verification_grouped = _group_signals_by_target(verification_signals)
    drafts: list[CandidateDraft] = []

    for target_key in sorted(set(resolution_grouped) | set(verification_grouped)):
        resolution_items = resolution_grouped.get(target_key, [])
        verification_items = verification_grouped.get(target_key, [])
        total = max(len(resolution_items), len(verification_items))
        if total < MIN_SAMPLE_CLASS_C:
            continue

        resolution_counts = Counter(item.outcome for item in resolution_items)
        verification_counts = Counter(item.outcome for item in verification_items)
        dominant_status, dominant_count = _dominant_verification_status(verification_counts)
        if dominant_status is None or not verification_items:
            continue

        dominance_ratio = dominant_count / len(verification_items) if verification_items else 0.0
        if dominance_ratio < OUTCOME_DOMINANCE_RATIO:
            continue

        confidence = round(dominance_ratio * 100)
        guidance = "promote"
        if dominant_status in {VERIFICATION_STATUS_INSUFFICIENT}:
            guidance = "demote"
        drafts.append(
            CandidateDraft(
                candidate_type=CANDIDATE_TYPE_RESOLUTION_GUIDANCE,
                target_type=TARGET_TYPE_RESOLUTION_ACTION,
                target_key=target_key,
                sample_size=len(verification_items),
                confidence_score=confidence,
                summary={
                    "selectedActionOption": target_key,
                    "resolutionTypeCounts": dict(resolution_counts),
                    "verificationStatusCounts": dict(verification_counts),
                    "dominantVerificationStatus": dominant_status,
                    "dominanceRatio": round(dominance_ratio, 3),
                },
                proposed_changes=[
                    {
                        "type": "adjust_resolution_guidance",
                        "selectedActionOption": target_key,
                        "guidance": guidance,
                        "rationale": "Observed verification outcomes consistently point to the same remediation quality signal.",
                        "evidence": {
                            "resolutionTypeCounts": dict(resolution_counts),
                            "verificationStatusCounts": dict(verification_counts),
                            "dominantVerificationStatus": dominant_status,
                            "dominanceRatio": round(dominance_ratio, 3),
                        },
                    }
                ],
            )
        )

    return drafts


def _dominant_verification_status(counts: Counter[str]) -> tuple[str | None, int]:
    eligible_statuses = (
        VERIFICATION_STATUS_SUCCESSFUL,
        VERIFICATION_STATUS_ALTERNATIVE,
        VERIFICATION_STATUS_INSUFFICIENT,
    )
    eligible_counts = {status: counts.get(status, 0) for status in eligible_statuses}
    dominant_status = max(eligible_counts, key=eligible_counts.get)
    dominant_count = eligible_counts[dominant_status]
    if dominant_count <= 0:
        return None, 0
    return dominant_status, dominant_count


def _classify_governance_class(*, sample_size: int, confidence_score: int) -> str:
    if sample_size >= MIN_SAMPLE_CLASS_A and confidence_score >= HIGH_CONFIDENCE_THRESHOLD:
        return GOVERNANCE_CLASS_A
    if sample_size >= MIN_SAMPLE_CLASS_B and confidence_score >= MEDIUM_CONFIDENCE_THRESHOLD:
        return GOVERNANCE_CLASS_B
    return GOVERNANCE_CLASS_C


def _group_signals_by_target(signals: Iterable[TrainingSignal]) -> dict[str, list[TrainingSignal]]:
    grouped: dict[str, list[TrainingSignal]] = defaultdict(list)
    for signal in signals:
        grouped[signal.target_key].append(signal)
    return grouped


def _split_target_key(target_key: str) -> tuple[str, str]:
    if ":" not in target_key:
        return target_key, "ungrouped"
    service_key, group_key = target_key.split(":", 1)
    return service_key, group_key


def _summarize_signal_counts(signals: Iterable[TrainingSignal]) -> dict[str, int]:
    counts: Counter[str] = Counter(signal.signal_type for signal in signals)
    return dict(sorted(counts.items()))


def _summarize_candidate_counts(
    candidates: Iterable[LearningImprovementCandidate],
) -> dict[str, int]:
    counts: Counter[str] = Counter(candidate.candidate_type for candidate in candidates)
    return dict(sorted(counts.items()))


def _emit_platform_event(db: Session, event: ValueStreamEvent, payload: dict[str, Any]) -> None:
    db.add(
        ValueStreamSignal(
            organization_id=PLATFORM_ORGANIZATION_ID,
            user_id=PLATFORM_USER_ID,
            event=event,
            payload=payload,
        )
    )
