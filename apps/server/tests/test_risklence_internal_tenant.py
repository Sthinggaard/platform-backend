from src.core.seeds.risklence_internal_tenant import (
    build_risklence_internal_tenant_blueprint,
    build_risklence_service_suggestions,
)
from src.core.seeds.risklence_internal_tenant_structure import MOCK_CVR_NUMBER


def test_risklence_internal_tenant_blueprint_is_structured_and_complete() -> None:
    blueprint = build_risklence_internal_tenant_blueprint()

    assert blueprint["organization"]["name"] == "Risklence"
    assert blueprint["organization"]["registration_number"] == MOCK_CVR_NUMBER
    assert blueprint["organization"]["registration_country"] == "DK"
    assert blueprint["organization"]["identity_source"] == "mock_company_registry"
    assert blueprint["organization"]["status"] == "PUBLISHED"
    assert blueprint["business_processes"][0]["name"] == "SaaS Core Platform"
    assert len(blueprint["business_processes"]) == 3
    assert len(blueprint["business_services"]) == 6
    assert len(blueprint["dependencies"]) == 8
    assert len(blueprint["assets"]) == 11
    assert len(blueprint["dependency_mappings"]) == 6
    assert len(blueprint["weaknesses"]) == 8
    assert len(blueprint["interventions"]) == 8
    assert len(blueprint["decisions"]) == 5

    billing = next(
        item
        for item in blueprint["business_services"]
        if item["name"] == "Billing & Subscription Management"
    )
    onboarding = next(
        item for item in blueprint["business_services"] if item["name"] == "Customer Onboarding"
    )
    assert billing["validated_mtd_hours"] == 48
    assert onboarding["validated_mtd_hours"] == 4

    decision_actions = {item["selected_action"] for item in blueprint["decisions"]}
    assert decision_actions == {"accepted", "jira", "escalated"}


def test_risklence_service_suggestions_match_guided_saas_tenant() -> None:
    suggestions = build_risklence_service_suggestions()

    assert [item["name"] for item in suggestions] == [
        "API Platform",
        "Frontend Application",
        "Authentication & Access",
        "Data Platform",
        "Customer Onboarding",
        "Billing & Subscription Management",
    ]
    assert all(item["source"] == "ai_suggested" for item in suggestions)
    assert all(item["confirmed"] is False for item in suggestions)
