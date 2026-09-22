from src.core.services.organisation_appetite_recommendation_service import recommend_organisation_appetite
from src.core.services.peer_appetite_benchmark_service import PeerAppetiteBenchmark


def test_defaults_to_a_moderate_baseline_without_regulatory_context():
    recommendation = recommend_organisation_appetite(required_frameworks=None)

    assert recommendation.answers["downtime"] == 3
    assert recommendation.answers["dataLoss"] == 3
    assert recommendation.answers["financial"] == 3
    assert recommendation.answers["reputational"] == 3
    assert recommendation.answers["regulatory"] == 3
    assert recommendation.answers["security"] == 3
    assert recommendation.confidence == "low"
    assert "regulatory_context" in recommendation.missing_inputs


def test_regulated_frameworks_tighten_only_regulatory_and_security():
    recommendation = recommend_organisation_appetite(required_frameworks=["NIS2", "GDPR"])

    assert recommendation.answers["regulatory"] == 1
    assert recommendation.answers["security"] == 1
    # Unrelated dimensions stay at the honest, unverified baseline.
    assert recommendation.answers["downtime"] == 3
    assert recommendation.answers["financial"] == 3
    assert recommendation.confidence == "high"
    assert not recommendation.missing_inputs
    assert "NIS2" in recommendation.reasons["regulatory"]


def test_no_process_level_input_is_ever_read():
    """Organisation Risk Appetite has nothing above it to inherit from —
    confirmed by the function's own signature accepting no BIA/process
    priority parameters at all, unlike the process-level engine."""
    import inspect

    signature = inspect.signature(recommend_organisation_appetite)
    assert "bia_answers" not in signature.parameters
    assert "process_priority" not in signature.parameters


def test_missing_peer_data_never_lowers_confidence():
    recommendation = recommend_organisation_appetite(required_frameworks=["NIS2"], peer_benchmark=None)
    assert recommendation.confidence == "high"


def test_peer_benchmark_nudges_the_level_and_is_named_in_the_reason():
    recommendation = recommend_organisation_appetite(
        required_frameworks=[],
        peer_benchmark={"downtime": PeerAppetiteBenchmark(median_level=1, peer_count=4)},
    )

    # Baseline 3, peer median 1 -> blended = round((3 + 1) / 2) = 2.
    assert recommendation.answers["downtime"] == 2
    assert "4 similar organisations" in recommendation.reasons["downtime"]
    assert "same industry" in recommendation.reasons["downtime"]


def test_regulated_floor_is_never_loosened_by_a_peer_benchmark():
    recommendation = recommend_organisation_appetite(
        required_frameworks=["DORA"],
        peer_benchmark={"regulatory": PeerAppetiteBenchmark(median_level=3, peer_count=5)},
    )

    # Regulated floor stays at 1 even though the peer median (3) would
    # otherwise blend it looser.
    assert recommendation.answers["regulatory"] == 1
