from types import SimpleNamespace

from src.api.routes.workspace import (
    _build_baseline_summary_from_hypothesis,
    _default_next_steps,
)


def test_default_next_steps_without_baseline_follow_tenant_lifecycle():
    steps = _default_next_steps(has_baseline=False)

    assert [step.code for step in steps] == [
        "analyze_resilience_gaps",
        "simulate_business_impact",
        "recommend_next_action",
        "capture_human_decision",
        "monitor_document_improve",
    ]


def test_default_next_steps_with_baseline_starts_with_assumption_review():
    steps = _default_next_steps(has_baseline=True)

    assert steps[0].code == "review_proposed_business_model"
    assert steps[0].title == "Review proposed business model"


def test_workspace_bootstrap_uses_the_canonical_public_handoff_hypothesis():
    summary = _build_baseline_summary_from_hypothesis(
        SimpleNamespace(
            status="generated",
            company_context={
                "public_onboarding_handoff": {
                    "model_version": "risk-intel-baseline-v1",
                    "generated_at": "2026-07-12T12:00:00+00:00",
                    "baseline_snapshot": {
                        "overallRiskScore": 62,
                        "riskLevel": "medium",
                        "focusAreas": ["identity_access"],
                        "hypotheses": [{"riskCode": "R-1"}],
                    },
                }
            },
        )
    )

    assert summary is not None
    assert summary.hypothesis_status == "generated"
    assert summary.overall_risk_score == 62
    assert summary.hypotheses_count == 1
