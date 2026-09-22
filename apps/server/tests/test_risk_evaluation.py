"""Dashboard slice 3 — Risk Evaluation status rules, snapshots, forecast honesty."""

from datetime import datetime
from types import SimpleNamespace

from src.core.services import process_activation_service
from src.core.services import risk_evaluation_service as svc
from src.core.services.forecast_impact_service import build_forecast_snapshot
from src.core.services.risk_appetite_resolution_service import ResolvedProcessAppetite

COMPLETE_BIA = {
    "impact1h": "medium",
    "impact4h": "high",
    "impact24h": "severe",
    "mtd": "le_4h",
    "dataSensitivity": "medium",
    "workaround": "partial",
    "alternativeChannel": "partial",
}


def _process(bia=COMPLETE_BIA):
    return SimpleNamespace(
        id="proc-1", organization_id=7, name="Billing & Subscription", bia_answers=bia
    )


def _service(service_id="svc-1", bia=None):
    return SimpleNamespace(
        id=service_id,
        name="Billing",
        bia_answers=bia,
        value_stream_ids=["proc-1"],
        l1=["1"],
        l2=[],
        l3=[],
        archived_at=None,
    )


def _exception(field, value):
    """#463 — one of a service's active BIA exceptions in a process."""
    return SimpleNamespace(field=field, value=value, recorded_before_reasons=False)


def _asset_names():
    return {"1": "payment gateway"}


def _threat(threat_id="t-1", status="detected", severity="high", asset="Payment Gateway"):
    return SimpleNamespace(id=threat_id, status=status, severity=severity, asset=asset)


def _appetite(answers=None, scope="organisation"):
    return ResolvedProcessAppetite(
        answers=answers or {"downtime": 2, "dataLoss": 1},
        source_scope=scope,
        policy_id="pol-1",
        version=1,
        approved_by="2",
        effective_from=datetime(2026, 1, 1),
        effective_to=None,
        review_at=None,
        decision_reference=None,
    )


def _evaluate(**overrides):
    defaults = {
        "process": _process(),
        "services": [_service()],
        "asset_name_by_id": _asset_names(),
        "threats": [],
        "decisions_by_threat_id": {},
        "latest_verification_by_threat_id": {},
        "published_bundle_service_ids": {"svc-1"},
        "resolved_appetite": _appetite(),
        # #463 — the process's resolved BIA; no service holds an exception.
        "process_bia_answers": COMPLETE_BIA,
        "bia_exceptions": {},
    }
    defaults.update(overrides)
    return svc.evaluate_process(**defaults)


def test_missing_inputs_produce_not_proven_with_reasons():
    evaluation, forecast = _evaluate(
        process=_process(bia=None),
        process_bia_answers=None,
        resolved_appetite=None,
        published_bundle_service_ids=set(),
    )

    assert evaluation.status == "not_proven"
    assert evaluation.preparedness == "cannot_prove"
    assert evaluation.confidence == "low"
    assert forecast is None
    decision_text = evaluation.explanation[-1]["text"]
    assert "Business Impact Assessment is incomplete" in decision_text
    assert "appetite is not resolved" in decision_text


def test_zero_tolerance_breach_is_outside_appetite_and_nothing_cancels_it():
    # Verified outcome exists, but the zero-tolerance category is breached by
    # an active risk — the strong dimension must not cancel the breach.
    threat = _threat()
    verification = SimpleNamespace(
        verification_status="verified_successful", created_at=datetime(2026, 7, 1)
    )
    evaluation, _ = _evaluate(
        threats=[threat],
        resolved_appetite=_appetite(answers={"downtime": 0, "dataLoss": 2}),
        latest_verification_by_threat_id={"t-1": verification},
    )

    assert evaluation.status == "outside_appetite"
    assert "downtime" in evaluation.residual["explanation"]


def test_active_critical_threat_is_outside_appetite():
    evaluation, _ = _evaluate(threats=[_threat(severity="critical")])
    assert evaluation.status == "outside_appetite"
    assert evaluation.preparedness == "not_prepared"


def test_active_noncritical_threats_approach_appetite():
    evaluation, _ = _evaluate(threats=[_threat(severity="high")])
    assert evaluation.status == "approaching_appetite"
    # Undecided active risk shows up as the decision ask.
    assert "A decision is needed" in evaluation.explanation[-1]["text"]


def test_all_observed_verified_is_within_appetite_and_prepared():
    threat = _threat(status="kept-safe")
    verification = SimpleNamespace(
        verification_status="verified_successful", created_at=datetime(2026, 7, 1)
    )
    evaluation, _ = _evaluate(
        threats=[threat],
        latest_verification_by_threat_id={"t-1": verification},
    )

    assert evaluation.status == "within_appetite"
    assert evaluation.preparedness == "prepared"


def test_no_observed_evidence_cannot_be_proven_safe():
    evaluation, _ = _evaluate(threats=[])
    assert evaluation.status == "not_proven"
    assert evaluation.preparedness == "cannot_prove"


def test_snapshots_freeze_appetite_provenance_and_evidence():
    evaluation, _ = _evaluate(threats=[_threat()])

    assert evaluation.appetite_snapshot["source_scope"] == "organisation"
    assert evaluation.appetite_snapshot["version"] == 1
    assert evaluation.evidence_snapshot["observed_risk_count"] == 1
    assert evaluation.bia_snapshot["complete"] is True
    assert len(evaluation.explanation) == 8


def test_forecast_is_a_bia_consequence_profile_never_money():
    snapshot = build_forecast_snapshot(
        _process(), [_service()], process_bia_answers=COMPLETE_BIA, bia_exceptions={}
    )

    assert snapshot is not None
    assert snapshot.source == "bia_consequence_profile"
    assert snapshot.estimate["impact_24h"] == "severe"
    assert snapshot.estimate["maximum_tolerable_disruption"] == "le_4h"
    assert not any("€" in str(v) for v in snapshot.estimate.values())
    assert any("not a confirmed loss" in a for a in snapshot.assumptions)
    assert snapshot.confidence == "medium"


def test_forecast_takes_worst_case_across_services():
    """svc-1 inherits the process's BIA; svc-2 differs by exceptions in this process (#463)."""
    process = _process()
    services = [_service("svc-1"), _service("svc-2")]
    exceptions = {
        ("svc-2", "proc-1"): [
            _exception("impact24h", "low"),
            _exception("mtd", "gt_24h"),
            _exception("workaround", "full"),
        ]
    }

    snapshot = build_forecast_snapshot(
        process, services, process_bia_answers=COMPLETE_BIA, bia_exceptions=exceptions
    )

    assert snapshot.estimate["impact_24h"] == "severe"  # worst across services
    assert snapshot.estimate["workaround"] == "partial"  # weakest capability
    assert (
        snapshot.estimate["maximum_tolerable_disruption"] == "gt_24h"
        or snapshot.estimate["maximum_tolerable_disruption"] == "le_4h"
    )


def test_no_forecast_without_complete_bia():
    assert (
        build_forecast_snapshot(
            _process(bia=None), [_service()], process_bia_answers=None, bia_exceptions={}
        )
        is None
    )


def test_a_service_copy_of_the_answers_is_not_read_as_its_bia():
    """#463 — a service's stored `bia_answers` holds copies from before the clean-up; only the
    process's resolved BIA and the service's exceptions count."""
    evaluation, forecast = _evaluate(
        services=[_service(bia=COMPLETE_BIA)], process_bia_answers=None
    )

    assert evaluation.bia_snapshot["complete"] is False
    assert forecast is None


def test_evaluation_pass_skips_processes_before_impact_activation(monkeypatch):
    process = _process()

    class Query:
        def __init__(self, rows):
            self.rows = rows

        def filter(self, *_args, **_kwargs):
            return self

        def all(self):
            return list(self.rows)

    class Database:
        def query(self, model):
            return Query([process] if model.__name__ == "ValueStream" else [])

    monkeypatch.setattr(
        process_activation_service,
        "resolve_process_activation_readiness",
        lambda *_args, **_kwargs: {"proc-1": SimpleNamespace(impact_model_active=False)},
    )

    result = svc.run_risk_evaluation_pass(Database(), organization_id=7)

    assert result.evaluated_process_ids == []
    assert result.evaluations_by_process_id == {}
