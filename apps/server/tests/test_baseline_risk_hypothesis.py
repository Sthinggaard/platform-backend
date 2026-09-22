"""BSP-10 — Baseline Risk Hypothesis generation, backfill, supersession, projection."""

from types import SimpleNamespace

from src.core.model_defs.baseline_risk_hypothesis import (
    ASSUMPTION_CONFIRMED,
    ASSUMPTION_PROPOSED,
    HYPOTHESIS_STATUS_GENERATED,
    HYPOTHESIS_STATUS_SUPERSEDED,
    HYPOTHESIS_STATUS_UNDER_REVIEW,
    HYPOTHESIS_STATUS_VALIDATED,
    BaselineRiskHypothesis,
)
from src.core.model_defs.value_streams import BusinessService, ValueStream
from src.core.services import baseline_risk_hypothesis_service as svc
from src.core.services.baseline_risk_hypothesis_service import AssumptionDecision


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
    def __init__(self, hypotheses=None, streams=None, services=None):
        self.hypotheses = list(hypotheses or [])
        self.streams = list(streams or [])
        self.services = list(services or [])
        self.added: list[object] = []

    def query(self, *entities):
        first = entities[0]
        target = getattr(first, "class_", first)
        if target is ValueStream:
            # Column-entity queries (key scans) get tuples; model queries get rows.
            if first is not ValueStream:
                return DummyQuery([(s.library_item_id,) for s in self.streams])
            return DummyQuery(self.streams)
        if target is BusinessService:
            if first is not BusinessService:
                return DummyQuery([(s.template_key, s.library_item_id) for s in self.services])
            return DummyQuery(self.services)
        return DummyQuery(self.hypotheses)

    def add(self, row):
        if row not in self.added:
            self.added.append(row)

    def flush(self):
        pass


def _org(**overrides):
    base = {
        "id": 7,
        "nace_code": "62.01",
        "industry": "Cybersecurity SaaS",
        "company_size": "1_50",
        "country": "DK",
        "required_frameworks": ["NIS2", "GDPR"],
        "settings": {},
        "org_value_stream_profile": None,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_generate_hypothesis_builds_explainable_assumption_items():
    db = DummyDB()
    hypothesis = svc.generate_baseline_hypothesis(db, _org())

    assert hypothesis.status is None or hypothesis.status != HYPOTHESIS_STATUS_VALIDATED
    assert hypothesis.company_context["nace_code"] == "62.01"
    assert hypothesis.company_context["required_frameworks"] == ["NIS2", "GDPR"]

    processes = [a for a in hypothesis.assumptions if a["kind"] == "business_process"]
    services = [a for a in hypothesis.assumptions if a["kind"] == "business_service"]
    assert processes, "NACE 62.01 must infer at least the universal streams"
    assert services, "each inferred process contributes template service assumptions"

    for item in hypothesis.assumptions:
        # Contract: provenance, confidence, and an explainable reason on every item.
        assert item["provenance"] in {"inferred", "template"}
        assert item["confidence"] in {"high", "medium", "low"}
        assert item["reason"]
        assert item["validation"] == "proposed"

    for service_item in services:
        assert service_item["parent_key"] in {p["key"] for p in processes}


def test_public_onboarding_handoff_stays_a_proposed_tenant_hypothesis():
    db = DummyDB()
    hypothesis = svc.create_public_onboarding_handoff_hypothesis(
        db,
        _org(),
        baseline_snapshot={
            "confidence": {"score": 0.71, "band": "medium_high"},
            "focusAreas": ["identity_access"],
        },
        model_version="risk-intel-baseline-v1",
        generated_at=None,
        process_candidates=[
            {
                "key": "order_to_cash",
                "name": "Order to Cash",
                "priority": "critical",
                "confidence": "high",
                "inference_reason": "Suggested from company context.",
                "public_confirmation_at": "2026-07-12T12:00:00Z",
            }
        ],
        source_session_id="session-1",
        source_draft_id="draft-1",
    )

    assert hypothesis.status == HYPOTHESIS_STATUS_GENERATED
    assert hypothesis.assumptions[0]["validation"] == ASSUMPTION_PROPOSED
    assert hypothesis.assumptions[0]["provenance"] == "public_onboarding"
    assert hypothesis.assumptions[0]["public_confirmation_at"] == "2026-07-12T12:00:00Z"
    handoff = hypothesis.company_context[svc.PUBLIC_ONBOARDING_HANDOFF_KEY]
    assert handoff["model_version"] == "risk-intel-baseline-v1"
    assert handoff["baseline_confidence"]["band"] == "medium_high"
    assert not any(isinstance(row, ValueStream) for row in db.added)


def test_generate_supersedes_the_live_predecessor():
    predecessor = BaselineRiskHypothesis(
        id="hyp-old",
        organization_id=7,
        status=HYPOTHESIS_STATUS_GENERATED,
        assumptions=[],
    )
    db = DummyDB(hypotheses=[predecessor])

    hypothesis = svc.generate_baseline_hypothesis(db, _org())

    assert predecessor.status == HYPOTHESIS_STATUS_SUPERSEDED
    assert predecessor.superseded_by_id == hypothesis.id


def test_backfill_from_org_profile_creates_validated_history():
    org = _org(
        org_value_stream_profile={
            "streams": [
                {"key": "software_delivery", "name": "SaaS Core Platform", "source": "inferred", "priority": "critical"},
            ],
            "confirmedAt": "2026-04-30T09:00:00+00:00",
        }
    )
    db = DummyDB()
    hypothesis = svc.backfill_hypothesis_from_org_profile(db, org)

    assert hypothesis is not None
    assert hypothesis.status == HYPOTHESIS_STATUS_VALIDATED
    item = hypothesis.assumptions[0]
    assert item["validation"] == ASSUMPTION_CONFIRMED
    assert item["key"] == "software_delivery"
    assert item["decided_at"] == "2026-04-30T09:00:00+00:00"


def test_backfill_is_a_noop_without_profile_or_with_existing_hypothesis():
    db = DummyDB()
    assert svc.backfill_hypothesis_from_org_profile(db, _org()) is None

    existing = BaselineRiskHypothesis(id="hyp-1", organization_id=7, status=HYPOTHESIS_STATUS_GENERATED)
    db = DummyDB(hypotheses=[existing])
    org = _org(org_value_stream_profile={"streams": [{"key": "x", "name": "X"}]})
    assert svc.backfill_hypothesis_from_org_profile(db, org) is None


def test_validation_projects_confirmed_processes_onto_the_org_profile():
    hypothesis = BaselineRiskHypothesis(
        id="hyp-2",
        organization_id=7,
        status=HYPOTHESIS_STATUS_GENERATED,
        assumptions=[
            {
                "kind": "business_process",
                "key": "billing_subscription",
                "name": "Billing & Subscription",
                "provenance": "inferred",
                "suggested_priority": "critical",
                "validation": "confirmed",
            },
            {
                "kind": "business_process",
                "key": "grant_management",
                "name": "Grant Management",
                "provenance": "inferred",
                "suggested_priority": "standard",
                "validation": "dismissed",
            },
            {
                "kind": "business_service",
                "key": "billing_service",
                "name": "Billing and Invoicing",
                "provenance": "template",
                "validation": "confirmed",
            },
        ],
    )
    org = _org()
    db = DummyDB(hypotheses=[hypothesis])

    svc.mark_hypothesis_validated(db, hypothesis, org, validated_by="2")

    assert hypothesis.status == HYPOTHESIS_STATUS_VALIDATED
    assert hypothesis.validated_by == "2"
    streams = org.org_value_stream_profile["streams"]
    # Only confirmed business_process items project; dismissed and service items do not.
    assert [s["key"] for s in streams] == ["billing_subscription"]
    assert streams[0]["priority"] == "critical"
    assert org.org_value_stream_profile["confirmedAt"]


# ─── BSP-13 — decisions + accountable apply ───────────────────────────────────


def _review_hypothesis():
    return BaselineRiskHypothesis(
        id="hyp-3",
        organization_id=7,
        status=HYPOTHESIS_STATUS_GENERATED,
        assumptions=[
            {
                "kind": "business_process",
                "key": "billing_subscription",
                "name": "Billing & Subscription",
                "provenance": "inferred",
                "confidence": "high",
                "reason": "r",
                "suggested_priority": "critical",
                "validation": "proposed",
            },
            {
                "kind": "business_service",
                "key": "payment_processing",
                "name": "Payment Processing",
                "parent_key": "billing_subscription",
                "provenance": "scanner",
                "confidence": "medium",
                "reason": "r",
                "validation": "proposed",
            },
            {
                "kind": "business_process",
                "key": "grant_management",
                "name": "Grant Management",
                "provenance": "inferred",
                "confidence": "low",
                "reason": "r",
                "validation": "proposed",
            },
        ],
    )


def test_decisions_are_recorded_with_accountability():
    hypothesis = _review_hypothesis()
    db = DummyDB(hypotheses=[hypothesis])

    unmatched = svc.record_assumption_decisions(
        db,
        hypothesis,
        [
            AssumptionDecision(key="billing_subscription", kind="business_process", validation="confirmed"),
            AssumptionDecision(key="grant_management", kind="business_process", validation="dismissed"),
            AssumptionDecision(key="no-such-item", kind="business_service", validation="confirmed"),
        ],
        decided_by="2",
    )

    assert unmatched == ["business_service:no-such-item"]
    assert hypothesis.status == HYPOTHESIS_STATUS_UNDER_REVIEW
    by_key = {a["key"]: a for a in hypothesis.assumptions}
    assert by_key["billing_subscription"]["validation"] == "confirmed"
    assert by_key["billing_subscription"]["decided_by"] == "2"
    assert by_key["billing_subscription"]["decided_at"]
    assert by_key["grant_management"]["validation"] == "dismissed"
    # Undecided items are untouched.
    assert by_key["payment_processing"]["validation"] == "proposed"


def test_invalid_decision_values_are_ignored():
    hypothesis = _review_hypothesis()
    db = DummyDB(hypotheses=[hypothesis])

    svc.record_assumption_decisions(
        db,
        hypothesis,
        [AssumptionDecision(key="billing_subscription", kind="business_process", validation="approved")],
        decided_by="2",
    )

    assert hypothesis.assumptions[0]["validation"] == "proposed"


def test_apply_materialises_confirmed_items_only(monkeypatch):
    hypothesis = _review_hypothesis()
    svc.record_assumption_decisions(
        DummyDB(),
        hypothesis,
        [
            AssumptionDecision(key="billing_subscription", kind="business_process", validation="confirmed"),
            AssumptionDecision(key="payment_processing", kind="business_service", validation="confirmed"),
            AssumptionDecision(key="grant_management", kind="business_process", validation="dismissed"),
        ],
        decided_by="2",
    )
    monkeypatch.setattr(
        svc, "get_active_service_template", lambda _db, _key: SimpleNamespace(version=3)
    )
    org = _org()
    db = DummyDB(hypotheses=[hypothesis])

    result = svc.apply_validated_hypothesis(db, org, hypothesis, validated_by="2")

    assert result.created_process_keys == ["billing_subscription"]
    assert result.created_service_keys == ["payment_processing"]

    created_streams = [r for r in db.added if isinstance(r, ValueStream)]
    assert len(created_streams) == 1
    assert created_streams[0].library_item_id == "billing_subscription"
    assert created_streams[0].priority == "critical"

    created_services = [r for r in db.added if isinstance(r, BusinessService)]
    assert len(created_services) == 1
    service = created_services[0]
    assert service.library_item_id == "payment_processing"
    assert service.template_key == "payment_processing"
    assert service.template_version == 3
    assert service.value_stream_ids == [created_streams[0].id]

    # Dismissed process was not created; hypothesis is validated and projected.
    assert all(s.library_item_id != "grant_management" for s in created_streams)
    assert hypothesis.status == HYPOTHESIS_STATUS_VALIDATED
    assert [s["key"] for s in org.org_value_stream_profile["streams"]] == ["billing_subscription"]


def test_apply_links_existing_service_instead_of_duplicating(monkeypatch):
    hypothesis = _review_hypothesis()
    svc.record_assumption_decisions(
        DummyDB(),
        hypothesis,
        [
            AssumptionDecision(key="billing_subscription", kind="business_process", validation="confirmed"),
            AssumptionDecision(key="payment_processing", kind="business_service", validation="confirmed"),
        ],
        decided_by="2",
    )
    monkeypatch.setattr(svc, "get_active_service_template", lambda _db, _key: None)
    existing_stream = ValueStream(
        id="stream-1", organization_id=7, library_item_id="billing_subscription", name="Billing & Subscription"
    )
    existing_service = BusinessService(
        id="svc-1", organization_id=7, name="Payment Processing",
        library_item_id="payment_processing", value_stream_ids=[],
    )
    org = _org()
    db = DummyDB(hypotheses=[hypothesis], streams=[existing_stream], services=[existing_service])

    result = svc.apply_validated_hypothesis(db, org, hypothesis, validated_by="2")

    assert result.created_process_keys == []
    assert result.created_service_keys == []
    assert result.linked_service_keys == ["payment_processing"]
    assert existing_service.value_stream_ids == ["stream-1"]
    assert not any(isinstance(r, BusinessService) and r is not existing_service for r in db.added)


def test_generate_preconfirms_items_the_org_already_models():
    class ColumnsDB(DummyDB):
        def query(self, *entities):
            first = entities[0]
            target = getattr(first, "class_", first)
            if target is ValueStream:
                return DummyQuery([("software_delivery",)])
            if target is BusinessService:
                return DummyQuery([("ci_cd_pipeline", "ci_cd_pipeline")])
            return DummyQuery(self.hypotheses)

    db = ColumnsDB()
    hypothesis = svc.generate_baseline_hypothesis(db, _org())

    by_item = {(a["kind"], a["key"]): a for a in hypothesis.assumptions}
    modelled_process = by_item[("business_process", "software_delivery")]
    assert modelled_process["validation"] == ASSUMPTION_CONFIRMED
    assert "Already part of your business model." in modelled_process["reason"]

    modelled_service = by_item.get(("business_service", "ci_cd_pipeline"))
    if modelled_service is not None:
        assert modelled_service["validation"] == ASSUMPTION_CONFIRMED

    # Unmodelled items stay proposed.
    unmodelled = [a for a in hypothesis.assumptions if a["validation"] == "proposed"]
    assert unmodelled
