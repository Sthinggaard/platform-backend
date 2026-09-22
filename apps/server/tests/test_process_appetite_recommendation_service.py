from src.core.services.peer_appetite_benchmark_service import PeerAppetiteBenchmark
from src.core.services.process_appetite_recommendation_service import recommend_process_appetite


def test_recommends_from_bia_and_priority_and_frameworks():
    recommendation = recommend_process_appetite(
        bia_answers={
            "mtd": "le_1h",
            "dataSensitivity": "high",
            "impact1h": "severe",
            "impact4h": "high",
            "impact24h": "medium",
        },
        required_frameworks=["NIS2", "GDPR"],
        process_priority="critical",
    )

    # Base downtime le_1h -> 1, dataSensitivity high -> 1, worst impact severe -> 1,
    # regulatory/security base 1 (regulated); critical priority tightens every
    # dimension by one level further, clamped at 0. The regulated floor only
    # prevents *loosening* below 1 — it does not block further tightening.
    assert recommendation.answers["downtime"] == 0
    assert recommendation.answers["dataLoss"] == 0
    assert recommendation.answers["financial"] == 0
    assert recommendation.answers["reputational"] == 0
    assert recommendation.answers["regulatory"] == 0
    assert recommendation.answers["security"] == 0
    assert recommendation.confidence == "high"
    assert not recommendation.missing_inputs
    assert "NIS2" in recommendation.reasons["regulatory"]


def test_defaults_honestly_when_bia_and_frameworks_are_missing():
    recommendation = recommend_process_appetite(
        bia_answers=None,
        required_frameworks=None,
        process_priority="standard",
    )

    assert recommendation.answers["downtime"] == 4  # moderate 3 + standard shift +1
    assert recommendation.answers["regulatory"] == 4  # unregulated 3 + standard shift +1
    assert recommendation.confidence == "low"
    assert "business_impact_assessment" in recommendation.missing_inputs
    assert "regulatory_context" in recommendation.missing_inputs


def test_regulated_floor_is_never_loosened_by_a_standard_priority_shift():
    recommendation = recommend_process_appetite(
        bia_answers={"mtd": "gt_24h", "dataSensitivity": "low"},
        required_frameworks=["PCI-DSS"],
        process_priority="standard",
    )

    # Regulatory/security floor stays at the regulated level (1) even though
    # a standard-priority shift would otherwise loosen it to 2.
    assert recommendation.answers["regulatory"] == 1
    assert recommendation.answers["security"] == 1


def test_unknown_priority_falls_back_to_important_with_no_shift():
    recommendation = recommend_process_appetite(
        bia_answers={"mtd": "le_4h"},
        required_frameworks=[],
        process_priority="not-a-real-priority",
    )

    assert recommendation.answers["downtime"] == 2


def test_missing_peer_data_never_lowers_confidence():
    recommendation = recommend_process_appetite(
        bia_answers={"mtd": "le_1h", "dataSensitivity": "high"},
        required_frameworks=["NIS2"],
        process_priority="important",
        peer_benchmark=None,
    )
    assert recommendation.confidence == "high"
    assert "peer_benchmark" not in recommendation.missing_inputs


def test_peer_benchmark_nudges_the_level_and_is_named_in_the_reason():
    # BIA alone: le_4h -> level 2. Peers settled at level 0 (tighter);
    # blended = round((2 + 0) / 2) = 1.
    recommendation = recommend_process_appetite(
        bia_answers={"mtd": "le_4h"},
        required_frameworks=[],
        process_priority="important",
        peer_benchmark={"downtime": PeerAppetiteBenchmark(median_level=0, peer_count=5)},
    )

    assert recommendation.answers["downtime"] == 1
    assert "5 similar organisations" in recommendation.reasons["downtime"]
    assert "level 0" in recommendation.reasons["downtime"]


def test_peer_benchmark_agreeing_with_bia_still_names_the_peer_count():
    recommendation = recommend_process_appetite(
        bia_answers={"mtd": "le_4h"},
        required_frameworks=[],
        process_priority="important",
        peer_benchmark={"downtime": PeerAppetiteBenchmark(median_level=2, peer_count=4)},
    )

    assert recommendation.answers["downtime"] == 2
    assert "4 similar organisations" in recommendation.reasons["downtime"]
    assert "also settled" in recommendation.reasons["downtime"]


# --- Cascade redesign: starting answers come from the cascaded org appetite ---


def test_starting_answers_are_the_cascaded_org_baseline_when_one_exists():
    """The draft's actual starting point is what this process currently
    inherits — not an independent BIA-driven guess — once an organisation
    policy exists to cascade from."""
    recommendation = recommend_process_appetite(
        bia_answers={"mtd": "le_1h", "dataSensitivity": "high"},  # would suggest level 1 alone
        required_frameworks=["NIS2"],
        process_priority="important",
        cascaded_org_answers={"downtime": 3, "dataLoss": 3, "financial": 3, "reputational": 3, "regulatory": 3, "security": 3},
    )

    assert recommendation.answers["downtime"] == 3  # the cascaded value, not the BIA-driven 1
    assert "currently inherited from the organisation policy at level 3" in recommendation.reasons["downtime"]
    assert "Risklence would suggest level" in recommendation.reasons["downtime"]


def test_no_divergence_note_when_the_bia_driven_suggestion_matches_the_cascade():
    recommendation = recommend_process_appetite(
        bia_answers=None,
        required_frameworks=None,
        process_priority="important",
        cascaded_org_answers={"downtime": 3, "dataLoss": 3, "financial": 3, "reputational": 3, "regulatory": 3, "security": 3},
    )

    assert recommendation.answers["downtime"] == 3
    assert "inherited from the organisation policy at level 3" in recommendation.reasons["downtime"]
    assert "Risklence would suggest" not in recommendation.reasons["downtime"]


def test_falls_back_to_the_independent_recommendation_without_a_cascaded_baseline():
    """No org policy active yet (a genuine bootstrapping case) — the
    independent BIA-driven computation is the starting point, unchanged
    from this module's original behaviour."""
    recommendation = recommend_process_appetite(
        bia_answers={"mtd": "le_1h", "dataSensitivity": "high"},
        required_frameworks=["NIS2"],
        process_priority="important",
        cascaded_org_answers=None,
    )

    assert recommendation.answers["downtime"] == 1
    assert "inherited from the organisation policy" not in recommendation.reasons["downtime"]
