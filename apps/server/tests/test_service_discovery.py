"""BSP-11 — evidence-driven service discovery into the baseline hypothesis."""

from types import SimpleNamespace

from src.core.model_defs.baseline_risk_hypothesis import BaselineRiskHypothesis
from src.core.models import BusinessService
from src.core.model_defs.assets_runtime import Asset
from src.core.services import service_discovery_service as svc


class DummyQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *_args, **_kwargs):
        return self

    def all(self):
        return list(self._rows)


class DummyDB:
    def __init__(self, assets=None, modelled_rows=None):
        self.assets = list(assets or [])
        # (template_key, library_item_id) tuples, as returned by the column query
        self.modelled_rows = list(modelled_rows or [])
        self.added: list[object] = []

    def query(self, *entities):
        if entities and entities[0] is Asset:
            return DummyQuery(self.assets)
        return DummyQuery(self.modelled_rows)

    def add(self, row):
        if row not in self.added:
            self.added.append(row)


def _asset(asset_id=1, display_name="Stripe", provider="Stripe", type_="Third-Party API", connected=True):
    from src.core.model_defs.assets_runtime import ConnectivityStatus

    return SimpleNamespace(
        id=asset_id,
        display_name=display_name,
        provider=provider,
        provider_display_name=None,
        type=type_,
        connectivity_status=ConnectivityStatus.CONNECTED if connected else ConnectivityStatus.PENDING_VERIFICATION,
    )


def _slot(slot_id="external_provider", label="Payment Gateway", hints=("stripe", "adyen"), expected=("Third-Party API",)):
    return SimpleNamespace(
        slot_id=slot_id,
        label=label,
        matching_hints=list(hints),
        expected_asset_types=list(expected),
        capability_group_key="external_providers",
    )


def _template(service_key="payment_processing", service_name="Payment Processing"):
    return SimpleNamespace(id=f"tmpl-{service_key}", service_key=service_key, service_name=service_name)


def _hypothesis(assumptions=None):
    return BaselineRiskHypothesis(id="hyp-1", organization_id=7, assumptions=list(assumptions or []))


def _patch_templates(monkeypatch, templates_with_slots):
    monkeypatch.setattr(
        svc, "list_active_service_templates", lambda _db: [t for t, _ in templates_with_slots]
    )
    slots_by_template = {t.id: slots for t, slots in templates_with_slots}
    monkeypatch.setattr(
        svc, "list_slot_templates_for_service", lambda _db, template_id: slots_by_template[template_id]
    )


def test_discovers_unmodelled_service_from_provider_evidence(monkeypatch):
    _patch_templates(monkeypatch, [(_template(), [_slot()])])
    db = DummyDB(assets=[_asset()])
    hypothesis = _hypothesis()

    result = svc.run_service_discovery_pass(db, organization_id=7, hypothesis=hypothesis)

    assert result.newly_proposed == ["payment_processing"]
    item = next(a for a in hypothesis.assumptions if a["key"] == "payment_processing")
    assert item["provenance"] == "scanner"
    assert item["validation"] == "proposed"
    assert item["confidence"] == "high"  # provider 0.7 + verified 0.1 + type agreement 0.05 = 0.85 (cap)
    assert item["evidence"][0]["asset_label"] == "Stripe"
    assert item["evidence"][0]["matched_hint"] == "stripe"
    assert "not yet part of your business model" in item["reason"]


def test_bare_type_agreement_is_not_enough_to_claim_a_service(monkeypatch):
    # Asset agrees on type but matches no hint — too generic for a whole-service claim.
    _patch_templates(monkeypatch, [(_template(), [_slot(hints=())])])
    db = DummyDB(assets=[_asset(provider="SomethingElse", display_name="Generic API")])
    hypothesis = _hypothesis()

    result = svc.run_service_discovery_pass(db, organization_id=7, hypothesis=hypothesis)

    assert result.newly_proposed == []
    assert hypothesis.assumptions == []


def test_already_modelled_services_are_skipped(monkeypatch):
    _patch_templates(monkeypatch, [(_template(), [_slot()])])
    db = DummyDB(assets=[_asset()], modelled_rows=[("payment_processing", "payment_processing")])
    hypothesis = _hypothesis()

    result = svc.run_service_discovery_pass(db, organization_id=7, hypothesis=hypothesis)

    assert result.newly_proposed == []
    assert result.skipped_modelled == ["payment_processing"]


def test_evidence_strengthens_a_proposed_template_assumption(monkeypatch):
    _patch_templates(monkeypatch, [(_template(), [_slot()])])
    db = DummyDB(assets=[_asset()])
    hypothesis = _hypothesis(
        assumptions=[
            {
                "kind": "business_service",
                "key": "payment_processing",
                "name": "Payment Processing",
                "provenance": "template",
                "confidence": "medium",
                "reason": "From the process pattern.",
                "validation": "proposed",
            }
        ]
    )

    result = svc.run_service_discovery_pass(db, organization_id=7, hypothesis=hypothesis)

    assert result.strengthened == ["payment_processing"]
    item = hypothesis.assumptions[0]
    assert item["provenance"] == "scanner"
    assert item["confidence"] == "high"
    assert item["evidence_confidence"] == 0.85


def test_human_decided_items_are_never_modified(monkeypatch):
    _patch_templates(monkeypatch, [(_template(), [_slot()])])
    db = DummyDB(assets=[_asset()])
    dismissed = {
        "kind": "business_service",
        "key": "payment_processing",
        "name": "Payment Processing",
        "provenance": "template",
        "confidence": "medium",
        "reason": "From the process pattern.",
        "validation": "dismissed",
    }
    hypothesis = _hypothesis(assumptions=[dict(dismissed)])

    result = svc.run_service_discovery_pass(db, organization_id=7, hypothesis=hypothesis)

    assert result.strengthened == []
    assert result.newly_proposed == []
    assert hypothesis.assumptions[0] == dismissed


def test_discovered_service_attaches_to_a_hypothesis_process(monkeypatch):
    _patch_templates(monkeypatch, [(_template(), [_slot()])])
    db = DummyDB(assets=[_asset()])
    # order_to_cash's core_service_keys include payment_processing in the library.
    hypothesis = _hypothesis(
        assumptions=[
            {
                "kind": "business_process",
                "key": "order_to_cash",
                "name": "Order to Cash",
                "provenance": "inferred",
                "confidence": "high",
                "reason": "r",
                "validation": "proposed",
            }
        ]
    )

    svc.run_service_discovery_pass(db, organization_id=7, hypothesis=hypothesis)

    item = next(a for a in hypothesis.assumptions if a["key"] == "payment_processing")
    assert item["parent_key"] == "order_to_cash"
