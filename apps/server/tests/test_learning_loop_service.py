from datetime import datetime, timezone

from src.core.constants.decision_runtime import (
    VERIFICATION_STATUS_INSUFFICIENT,
    VERIFICATION_STATUS_SUCCESSFUL,
)
from src.core.constants.learning_loop import (
    CANDIDATE_TYPE_RECOMMENDATION_RANKING,
    CANDIDATE_TYPE_RESOLUTION_GUIDANCE,
    CANDIDATE_TYPE_TEMPLATE_PATTERN,
    RECOMMENDATION_SIGNAL_OUTCOME_CONTEXT_REFRESHED,
    RECOMMENDATION_SIGNAL_OUTCOME_GENERATED,
    RECOMMENDATION_SIGNAL_OUTCOME_UNCERTAINTY_FLAGGED,
    SIGNAL_TYPE_RECOMMENDATION_DECISION,
    SIGNAL_TYPE_RESOLUTION_OUTCOME,
    SIGNAL_TYPE_TEMPLATE_PATTERN,
    SIGNAL_TYPE_VERIFICATION_OUTCOME,
    TARGET_TYPE_RECOMMENDATION_ACTION,
    TARGET_TYPE_RESOLUTION_ACTION,
    TARGET_TYPE_SERVICE_TEMPLATE_GROUP,
)
from src.core.models import Recommendation, TrainingSignal
from src.core.services import learning_loop_service


def _signal(
    *,
    signal_type: str,
    target_type: str,
    target_key: str,
    outcome: str,
    payload: dict | None = None,
) -> TrainingSignal:
    return TrainingSignal(
        id=f"{signal_type}-{target_key}-{outcome}",
        run_id="run-1",
        organization_id=42,
        source_type="test",
        source_id=f"{signal_type}-{target_key}-{outcome}-{len(payload or {})}",
        signal_type=signal_type,
        target_type=target_type,
        target_key=target_key,
        outcome=outcome,
        payload=payload or {},
        source_created_at=datetime(2026, 4, 21, 1, 0, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 21, 1, 0, tzinfo=timezone.utc),
    )


def test_build_mapping_candidates_flags_heavily_overridden_group():
    signals = [
        _signal(
            signal_type=SIGNAL_TYPE_TEMPLATE_PATTERN,
            target_type=TARGET_TYPE_SERVICE_TEMPLATE_GROUP,
            target_key="sso_service:monitoring",
            outcome="slot_unknown",
        ),
        _signal(
            signal_type=SIGNAL_TYPE_TEMPLATE_PATTERN,
            target_type=TARGET_TYPE_SERVICE_TEMPLATE_GROUP,
            target_key="sso_service:monitoring",
            outcome="slot_not_applicable",
        ),
        _signal(
            signal_type=SIGNAL_TYPE_TEMPLATE_PATTERN,
            target_type=TARGET_TYPE_SERVICE_TEMPLATE_GROUP,
            target_key="sso_service:monitoring",
            outcome="slot_unknown",
        ),
    ]

    drafts = learning_loop_service._build_mapping_candidates(signals)

    assert len(drafts) == 1
    assert drafts[0].candidate_type == CANDIDATE_TYPE_TEMPLATE_PATTERN
    assert drafts[0].summary["serviceKey"] == "sso_service"


def test_build_decision_candidates_flags_repeated_human_overrides():
    signals = [
        _signal(
            signal_type=SIGNAL_TYPE_RECOMMENDATION_DECISION,
            target_type=TARGET_TYPE_RECOMMENDATION_ACTION,
            target_key="jira",
            outcome="alternative",
            payload={"selectedAction": "servicenow"},
        ),
        _signal(
            signal_type=SIGNAL_TYPE_RECOMMENDATION_DECISION,
            target_type=TARGET_TYPE_RECOMMENDATION_ACTION,
            target_key="jira",
            outcome="alternative",
            payload={"selectedAction": "servicenow"},
        ),
        _signal(
            signal_type=SIGNAL_TYPE_RECOMMENDATION_DECISION,
            target_type=TARGET_TYPE_RECOMMENDATION_ACTION,
            target_key="jira",
            outcome="recommended",
            payload={"selectedAction": "jira"},
        ),
    ]

    drafts = learning_loop_service._build_decision_candidates(signals)

    assert len(drafts) == 1
    assert drafts[0].candidate_type == CANDIDATE_TYPE_RECOMMENDATION_RANKING
    assert drafts[0].summary["dominantAlternativeAction"] == "servicenow"


def test_recommendation_generation_signal_payload_preserves_evidence_context():
    recommendation = Recommendation(
        id="rec-1",
        organization_id=42,
        threat_id="threat-1",
        status="open",
        linked_context_type="asset",
        linked_context_id="asset-1",
        linked_context_label="Payment Gateway",
        problem="Payment edge is degraded.",
        why_it_matters="Card payments will fail if degradation continues.",
        suggested_action="jira",
        confidence_score=75,
        is_stale=True,
        intelligence_snapshot={
            "recommendationType": "critical_asset",
            "generatorVersion": "euc-11-v1",
            "businessDecisionTaxonomy": {
                "recommendedRoute": "jira",
                "recommendedBusinessAction": "mitigate",
            },
            "uncertaintyFactors": ["service_mapping_incomplete"],
            "structuralRationale": ["single_point_of_failure"],
        },
        generated_at=datetime(2026, 4, 21, 1, 0, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 21, 1, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 21, 2, 0, tzinfo=timezone.utc),
    )

    outcomes = learning_loop_service._recommendation_signal_outcomes(recommendation)
    payload = learning_loop_service._recommendation_signal_payload(recommendation)
    target_key = learning_loop_service._recommendation_signal_target_key(recommendation)

    assert [outcome for outcome, _suffix, _created_at in outcomes] == [
        RECOMMENDATION_SIGNAL_OUTCOME_GENERATED,
        RECOMMENDATION_SIGNAL_OUTCOME_UNCERTAINTY_FLAGGED,
        RECOMMENDATION_SIGNAL_OUTCOME_CONTEXT_REFRESHED,
    ]
    assert target_key == "critical_asset:mitigate"
    assert payload["recommendationId"] == "rec-1"
    assert payload["businessDecisionTaxonomy"]["recommendedBusinessAction"] == "mitigate"
    assert payload["uncertaintyFactors"] == ["service_mapping_incomplete"]
    assert payload["structuralRationale"] == ["single_point_of_failure"]
    assert payload["isStale"] is True


def test_build_resolution_candidates_uses_verification_outcomes():
    resolution_signals = [
        _signal(
            signal_type=SIGNAL_TYPE_RESOLUTION_OUTCOME,
            target_type=TARGET_TYPE_RESOLUTION_ACTION,
            target_key="jira",
            outcome="followed-recommendation",
        ),
        _signal(
            signal_type=SIGNAL_TYPE_RESOLUTION_OUTCOME,
            target_type=TARGET_TYPE_RESOLUTION_ACTION,
            target_key="jira",
            outcome="followed-recommendation",
        ),
        _signal(
            signal_type=SIGNAL_TYPE_RESOLUTION_OUTCOME,
            target_type=TARGET_TYPE_RESOLUTION_ACTION,
            target_key="jira",
            outcome="solved-differently",
        ),
    ]
    verification_signals = [
        _signal(
            signal_type=SIGNAL_TYPE_VERIFICATION_OUTCOME,
            target_type=TARGET_TYPE_RESOLUTION_ACTION,
            target_key="jira",
            outcome=VERIFICATION_STATUS_SUCCESSFUL,
        ),
        _signal(
            signal_type=SIGNAL_TYPE_VERIFICATION_OUTCOME,
            target_type=TARGET_TYPE_RESOLUTION_ACTION,
            target_key="jira",
            outcome=VERIFICATION_STATUS_SUCCESSFUL,
        ),
        _signal(
            signal_type=SIGNAL_TYPE_VERIFICATION_OUTCOME,
            target_type=TARGET_TYPE_RESOLUTION_ACTION,
            target_key="jira",
            outcome=VERIFICATION_STATUS_INSUFFICIENT,
        ),
    ]

    drafts = learning_loop_service._build_resolution_candidates(
        resolution_signals=resolution_signals,
        verification_signals=verification_signals,
    )

    assert len(drafts) == 1
    assert drafts[0].candidate_type == CANDIDATE_TYPE_RESOLUTION_GUIDANCE
    assert drafts[0].summary["dominantVerificationStatus"] == VERIFICATION_STATUS_SUCCESSFUL


def test_classify_governance_class_escalates_with_sample_and_confidence():
    assert (
        learning_loop_service._classify_governance_class(sample_size=12, confidence_score=90) == "A"
    )
    assert (
        learning_loop_service._classify_governance_class(sample_size=6, confidence_score=70) == "B"
    )
    assert (
        learning_loop_service._classify_governance_class(sample_size=3, confidence_score=40) == "C"
    )
