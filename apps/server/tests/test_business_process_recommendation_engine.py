import pytest

from src.core.model_defs.business_process_recommendation import (
    BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION,
    BUSINESS_PROCESS_RECOMMENDATION_STATUS_SUGGESTED,
)
from src.core.services.business_process_recommendation_engine import (
    BusinessProcessRecommendationEngine,
    relevance_label,
)
from src.pretenant.risk_intelligence import OrganisationProfile


def _profile(
    *,
    industry_code: str = "62010",
    size_bracket: str = "smb",
    geography: str = "DK",
    locations: int = 2,
    it_dependency: str = "medium",
    risk_appetite: str = "balanced",
    selected_asset_categories: list[str] | None = None,
    regulatory_flags: list[str] | None = None,
    business_model_tags: list[str] | None = None,
) -> OrganisationProfile:
    return OrganisationProfile(
        cvr="12345678",
        legal_name="Example ApS",
        industry_code=industry_code,
        size_bracket=size_bracket,
        geography=geography,
        locations=locations,
        it_dependency=it_dependency,
        risk_appetite=risk_appetite,
        selected_asset_categories=selected_asset_categories or ["identity", "email"],
        regulatory_flags=regulatory_flags,
        business_model_tags=business_model_tags or ["subscription", "b2b"],
    )


def test_recommendation_engine_returns_deterministic_output():
    engine = BusinessProcessRecommendationEngine()
    profile = _profile(regulatory_flags=["GDPR", "NIS2"], business_model_tags=["subscription", "customer_success"])

    first = engine.recommend(profile)
    second = engine.recommend(profile)

    assert first == second
    assert first.model_version == BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION
    assert len(first.recommendations) == 5


def test_recommendation_output_includes_required_fields():
    engine = BusinessProcessRecommendationEngine()
    result = engine.recommend(_profile(regulatory_flags=["GDPR"]))

    recommendation = result.recommendations[0]
    assert recommendation.process_template_id
    assert recommendation.name
    assert recommendation.category
    assert recommendation.score > 0
    assert 0.0 <= recommendation.confidence <= 1.0
    assert recommendation.matched_inputs
    assert recommendation.recommendation_reason
    assert recommendation.source_rule
    assert recommendation.user_reasoning is not None
    assert recommendation.user_reasoning.business_function
    assert recommendation.user_reasoning.why_suggested
    assert recommendation.user_reasoning.impact_if_missing
    assert recommendation.user_reasoning.suggested_next_step
    assert recommendation.user_reasoning.evidence_summary
    assert recommendation.user_reasoning.relevance_label in {"High", "Medium", "Low"}
    assert recommendation.status == BUSINESS_PROCESS_RECOMMENDATION_STATUS_SUGGESTED
    assert recommendation.model_version == BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION


@pytest.mark.parametrize(
    ("confidence", "expected"),
    [
        (0.75, "High"),
        (0.50, "Medium"),
        (0.49, "Low"),
    ],
)
def test_relevance_label_mapping(confidence: float, expected: str):
    assert relevance_label(confidence) == expected


@pytest.mark.parametrize(
    ("template_id", "expected_fragment"),
    [
        ("saas-core-platform", "Your Digital Product & Systems"),
        ("customer-lifecycle", "Customers, Sales & Retention"),
        ("billing-subscription", "Getting Paid"),
        ("security-operations", "Keeping the Business Safe"),
        ("compliance-governance", "Proof & Business Accountability"),
    ],
)
def test_each_template_has_business_facing_reasoning(template_id: str, expected_fragment: str):
    engine = BusinessProcessRecommendationEngine()
    result = engine.recommend(_profile(regulatory_flags=["GDPR", "NIS2"], business_model_tags=["subscription", "customer_success"]))

    recommendation = next(item for item in result.recommendations if item.process_template_id == template_id)
    assert recommendation.user_reasoning.business_function == expected_fragment
    assert recommendation.user_reasoning.why_suggested
    assert recommendation.user_reasoning.impact_if_missing
    assert recommendation.user_reasoning.suggested_next_step
    assert recommendation.user_reasoning.relevance_label == relevance_label(recommendation.confidence)
    assert len(recommendation.user_reasoning.evidence_summary) >= 1


def test_rule_set_prioritises_security_and_compliance_for_regulated_high_dependency_profiles():
    engine = BusinessProcessRecommendationEngine()
    profile = _profile(
        it_dependency="critical",
        risk_appetite="conservative",
        selected_asset_categories=["identity", "network", "backup", "cloud"],
        regulatory_flags=["GDPR", "ISO27001", "NIS2"],
        geography="SE",
        size_bracket="enterprise",
    )

    result = engine.recommend(profile)
    top_ids = [item.process_template_id for item in result.recommendations[:2]]

    assert top_ids == ["security-operations", "compliance-governance"]
    assert result.recommendations[0].source_rule in {
        "RULE_SECURITY_REGULATORY_PRESSURE",
        "RULE_SECURITY_DEPENDENCY",
    }
    assert "security" in result.recommendations[0].recommendation_reason.lower()


def test_rule_set_prioritises_billing_for_subscription_revenue_profiles():
    engine = BusinessProcessRecommendationEngine()
    profile = _profile(
        risk_appetite="aggressive",
        selected_asset_categories=["application", "data", "cloud"],
        regulatory_flags=["PCI"],
        business_model_tags=["subscription", "usage_based", "b2b"],
        size_bracket="enterprise",
    )

    result = engine.recommend(profile)

    assert result.recommendations[0].process_template_id == "billing-subscription"
    assert result.recommendations[0].source_rule == "RULE_RECURRING_REVENUE"
    assert "billing" in result.recommendations[0].recommendation_reason.lower()
