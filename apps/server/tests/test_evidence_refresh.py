"""BSP-14 — ingestion-triggered evidence refresh."""

from types import SimpleNamespace

from src.core.constants.value_stream_events import ValueStreamEvent
from src.core.model_defs.baseline_risk_hypothesis import BaselineRiskHypothesis
from src.core.models import BusinessService, ValueStreamSignal
from src.core.services import evidence_refresh_service as svc


class DummyQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def first(self):
        return self._rows[0] if self._rows else None

    def all(self):
        return list(self._rows)


class DummyDB:
    def __init__(self, services=None, hypotheses=None):
        self.services = list(services or [])
        self.hypotheses = list(hypotheses or [])
        self.added: list[object] = []

    def query(self, model):
        if model is BusinessService:
            return DummyQuery(self.services)
        return DummyQuery(self.hypotheses)

    def add(self, row):
        self.added.append(row)


def _service(service_id="svc-1", archetype="identity_access"):
    return SimpleNamespace(id=service_id, archetype=archetype, template_key=None)


def _pass_result(suggestions):
    return SimpleNamespace(
        template_version=1,
        suggestions=suggestions,
        skipped_human_decided=[],
        unmatched_slot_ids=[],
    )


def test_refresh_runs_pass_per_service_and_signals_only_new_suggestions(monkeypatch):
    suggestion = SimpleNamespace(slot_id="network_connectivity")
    results = {"svc-1": _pass_result([suggestion]), "svc-2": _pass_result([])}
    monkeypatch.setattr(
        svc, "run_slot_mapping_suggestion_pass", lambda _db, service: results[service.id]
    )
    monkeypatch.setattr(svc, "get_current_hypothesis", lambda _db, _org: None)
    db = DummyDB(services=[_service("svc-1"), _service("svc-2")])

    summary = svc.refresh_org_evidence_in_session(db, organization_id=7)

    assert summary["services_with_new_suggestions"] == ["svc-1"]
    signals = [r for r in db.added if isinstance(r, ValueStreamSignal)]
    assert len(signals) == 1
    assert signals[0].event == ValueStreamEvent.SLOT_MAPPING_SUGGESTED
    assert signals[0].source == "ingestion_evidence_refresh"
    assert signals[0].payload["service_id"] == "svc-1"
    assert signals[0].user_id is None  # engine-initiated, not a user action


def test_services_without_a_pattern_are_skipped(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        svc,
        "run_slot_mapping_suggestion_pass",
        lambda _db, service: calls.append(service.id) or _pass_result([]),
    )
    monkeypatch.setattr(svc, "get_current_hypothesis", lambda _db, _org: None)
    db = DummyDB(services=[_service("svc-1"), SimpleNamespace(id="svc-raw", archetype=None, template_key=None)])

    svc.refresh_org_evidence_in_session(db, organization_id=7)

    assert calls == ["svc-1"]


def test_discovery_runs_only_while_the_hypothesis_is_a_draft(monkeypatch):
    monkeypatch.setattr(svc, "run_slot_mapping_suggestion_pass", lambda _db, service: _pass_result([]))
    discovery_calls: list[str] = []
    monkeypatch.setattr(
        svc,
        "run_service_discovery_pass",
        lambda _db, organization_id, hypothesis: discovery_calls.append(hypothesis.id)
        or SimpleNamespace(newly_proposed=["payment_processing"], strengthened=[]),
    )

    draft = BaselineRiskHypothesis(id="hyp-draft", organization_id=7, status="under_review")
    monkeypatch.setattr(svc, "get_current_hypothesis", lambda _db, _org: draft)
    summary = svc.refresh_org_evidence_in_session(DummyDB(), organization_id=7)
    assert discovery_calls == ["hyp-draft"]
    assert summary["discovery"] == {"newly_proposed": ["payment_processing"], "strengthened": []}

    # A validated hypothesis is a human decision — new evidence must not mutate it.
    validated = BaselineRiskHypothesis(id="hyp-final", organization_id=7, status="validated")
    monkeypatch.setattr(svc, "get_current_hypothesis", lambda _db, _org: validated)
    summary = svc.refresh_org_evidence_in_session(DummyDB(), organization_id=7)
    assert discovery_calls == ["hyp-draft"]
    assert summary["discovery"] is None
