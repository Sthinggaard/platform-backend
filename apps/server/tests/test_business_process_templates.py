from src.core.constants.business_process_templates import (
    BUSINESS_PROCESS_TEMPLATE_BY_ID,
    BUSINESS_PROCESS_TEMPLATES,
    BusinessProcessTemplate,
    get_business_process_template,
)


def test_business_process_template_library_is_structured_and_deterministic():
    assert isinstance(BUSINESS_PROCESS_TEMPLATES, tuple)
    assert [template.id for template in BUSINESS_PROCESS_TEMPLATES] == [
        "saas-core-platform",
        "customer-lifecycle",
        "billing-subscription",
        "security-operations",
        "compliance-governance",
    ]


def test_business_process_template_fields_cover_expected_saas_library():
    template = get_business_process_template("billing-subscription")

    assert isinstance(template, BusinessProcessTemplate)
    assert template.name == "Billing & Subscription"
    assert template.category == "finance"
    assert template.industry_tags == ("saas", "software", "platform")
    assert template.size_tags == ("startup", "smb", "mid_market", "enterprise")
    assert template.region_tags == ("global", "emea", "nordics")
    assert template.regulatory_tags == ("gdpr", "pci")
    assert template.business_model_tags == ("subscription", "usage_based", "b2b")
    assert template.default_criticality == "high"
    assert "recurring SaaS revenue" in template.explanation


def test_business_process_template_lookup_is_indexed_by_id():
    assert BUSINESS_PROCESS_TEMPLATE_BY_ID["security-operations"].name == "Security Operations"
    assert get_business_process_template("compliance-governance").category == "governance"


def test_business_process_template_lookup_rejects_unknown_ids():
    try:
        get_business_process_template("unknown")
    except KeyError as exc:
        assert "Unknown business process template" in str(exc)
    else:
        raise AssertionError("Expected KeyError for unknown template id")
