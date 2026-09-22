from src.pretenant.company_assumptions import build_company_assumption_preview


def test_software_preview_is_causal_and_provisional():
    preview = build_company_assumption_preview(
        cvr="12345678",
        legal_name="Example Software A/S",
        industry_code="62010",
        industry="Computer programming activities",
        size_bracket="smb",
        geography="DK",
    )

    assert preview["archetypeKey"] == "software"
    assert [item["key"] for item in preview["suggestedProcesses"]] == [
        "software_delivery",
        "platform_operations",
        "quote_to_cash",
        "customer_service",
        "contract_to_renewal",
    ]
    assert preview["suggestedProcesses"][0]["templateKey"] == "software_delivery"
    assert preview["suggestedProcesses"][0]["archetypeKey"] == "software"
    assert [item["key"] for item in preview["suggestedProcesses"] if item["priority"] == "critical"] == [
        "software_delivery",
        "platform_operations",
    ]
    assert "business-critical assumption" in preview["headline"]
    assert preview["focusAreas"][0]["key"] == "identity_access"
    assert preview["confidence"]["band"] == "high"
    assert preview["completeness"]["status"] == "partial"
    assert preview["completeness"]["knownFactCount"] == 6
    assert preview["completeness"]["missingFacts"] == []
    assert preview["focusAreas"][0]["source"] == "industry_archetype"
    assert preview["assumptions"][0]["sourceField"] == "industryCode"


def test_unknown_industry_uses_reviewable_general_fallback():
    preview = build_company_assumption_preview(
        industry_code=None,
        industry=None,
        size_bracket=None,
        geography="DK",
    )

    assert preview["archetypeKey"] == "general_business"
    assert preview["confidence"]["band"] == "medium"
    assert [item["key"] for item in preview["suggestedProcesses"]] == [
        "identity_and_access",
        "security_incident_response",
        "hire_to_retire",
    ]


def test_professional_services_and_retail_use_distinct_canonical_processes():
    professional = build_company_assumption_preview(
        industry_code="70220",
        industry="Business and management consultancy activities",
        size_bracket="smb",
        geography="DK",
    )
    retail = build_company_assumption_preview(
        industry_code="47110",
        industry="Retail sale in non-specialised stores",
        size_bracket="smb",
        geography="DK",
    )

    assert professional["archetypeKey"] == "professional_services"
    assert [item["key"] for item in professional["suggestedProcesses"]] == [
        "quote_to_cash",
        "contract_to_renewal",
        "customer_service",
        "record_to_report",
    ]
    assert retail["archetypeKey"] == "retail"
    assert [item["key"] for item in retail["suggestedProcesses"]] == [
        "order_to_cash",
        "customer_acquisition",
        "customer_service",
        "procure_to_pay",
        "warehouse_to_delivery",
    ]


def test_unrecognised_industry_code_does_not_claim_high_confidence():
    preview = build_company_assumption_preview(
        industry_code="99000",
        industry="Unknown activity",
        size_bracket="smb",
        geography="DK",
    )

    assert preview["archetypeKey"] == "general_business"
    assert preview["confidence"]["band"] == "medium"


def test_business_context_single_value_resolves_flagship_process():
    preview = build_company_assumption_preview(
        industry_code="62010",
        industry="Computer programming activities",
        size_bracket="smb",
        geography="DK",
        business_context={"criticalBusinessActivity": "plan_and_make"},
    )

    assert preview["flagshipProcess"]["templateKey"] == "plan_to_produce"
    assert preview["flagshipProcess"]["source"] == "company_context_suggestion"


def test_business_context_list_value_is_handled_gracefully():
    # criticalBusinessActivity and primaryBusinessActivity are single-select
    # today, but the business_context contract now allows a list per key
    # (multi-select questions). The flagship resolver should not error on a
    # list value and should use its first entry.
    preview = build_company_assumption_preview(
        industry_code="62010",
        industry="Computer programming activities",
        size_bracket="smb",
        geography="DK",
        business_context={"criticalBusinessActivity": ["plan_and_make", "deliver_goods"]},
    )

    assert preview["flagshipProcess"]["templateKey"] == "plan_to_produce"
    assert preview["flagshipProcess"]["source"] == "company_context_suggestion"


def test_business_context_empty_list_value_falls_back_to_industry_inference():
    preview = build_company_assumption_preview(
        industry_code="62010",
        industry="Computer programming activities",
        size_bracket="smb",
        geography="DK",
        business_context={"criticalBusinessActivity": []},
    )

    assert preview["flagshipProcess"]["source"] == "risk_intelligence_engine"


def test_business_context_extra_multi_select_answers_do_not_break_preview():
    # customerVisibleImpact and hardToReplaceQuickly are stored but not (yet)
    # consumed by the flagship resolver; they must simply pass through.
    preview = build_company_assumption_preview(
        industry_code="62010",
        industry="Computer programming activities",
        size_bracket="smb",
        geography="DK",
        business_context={
            "criticalBusinessActivity": "plan_and_make",
            "customerVisibleImpact": ["late_or_missed_deliveries", "cannot_reach_support"],
            "hardToReplaceQuickly": ["key_people_or_expertise"],
        },
    )

    assert preview["businessContext"]["customerVisibleImpact"] == [
        "late_or_missed_deliveries",
        "cannot_reach_support",
    ]
    assert preview["flagshipProcess"]["templateKey"] == "plan_to_produce"
