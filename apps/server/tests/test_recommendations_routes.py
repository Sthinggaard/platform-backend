from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import recommendations
from src.core.models import Recommendation, Threat
from src.core.model_defs.risk_intelligence_ingestion import (
    RiskIngestionBatch,
    RiskIngestionBatchStatus,
)
from src.integrations.decision_adapters import IntegrationDispatchResult


class DummyDB:
    def __init__(self, batch: RiskIngestionBatch | None = None) -> None:
        self.added: list[object] = []
        self.flush_calls = 0
        self.commit_calls = 0
        self.refresh_calls = 0
        self._batch = batch

    def add(self, obj: object) -> None:
        self.added.append(obj)

    def flush(self) -> None:
        self.flush_calls += 1
        for obj in self.added:
            if getattr(obj, "id", None) is None:
                setattr(obj, "id", str(uuid4()))

    def commit(self) -> None:
        self.commit_calls += 1

    def refresh(self, _obj: object) -> None:
        self.refresh_calls += 1

    def get(self, _model: object, ident: object) -> RiskIngestionBatch | None:
        if self._batch is None:
            return None
        return self._batch if getattr(self._batch, "id", None) == ident else None


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=7,
        organization_id=42,
        email="ciso@risklence.test",
        roles=["ciso"],
        permissions=[],
    )


def _admin_ctx() -> TenantContext:
    return TenantContext(
        user_id=1,
        organization_id=42,
        email="admin@risklence.test",
        roles=["org_admin"],
        permissions=[],
    )


def _consultant_ctx() -> TenantContext:
    return TenantContext(
        user_id=9,
        organization_id=42,
        email="consultant@risklence.test",
        roles=["consultant"],
        permissions=[],
    )


def _recommendation() -> Recommendation:
    return Recommendation(
        id="rec-1",
        organization_id=42,
        threat_id="threat-1",
        status="open",
        linked_context_type="asset",
        linked_context_id="asset-1",
        linked_context_label="Payment Gateway",
        problem="Packet loss is rising on the payment edge.",
        why_it_matters="Card payments will fail if the degradation continues.",
        suggested_action="jira",
        confidence_score=91,
        is_stale=True,
        intelligence_snapshot={
            "recommendedAction": "jira",
            "confidence": 91,
            "basis": "Peer evidence",
            "reasoning": "Operational engineering path is fastest.",
        },
        generated_at=datetime(2026, 4, 15, 8, 30, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 15, 8, 30, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 15, 8, 30, tzinfo=timezone.utc),
    )


def _threat(*, batch_id: int | None = None) -> Threat:
    intelligence = {
        "recommendedAction": "jira",
        "confidence": 91,
        "basis": "Peer evidence",
        "reasoning": "Operational engineering path is fastest.",
    }
    if batch_id is not None:
        intelligence["ingestionBatchId"] = batch_id
    return Threat(
        id="threat-1",
        organization_id=42,
        status="detected",
        severity="critical",
        source="glic",
        asset="Payment Gateway",
        tier="Mission Critical",
        signal="Packet loss rising 0.2%→8.4%",
        what_it_means="Payment traffic will fail if left unresolved.",
        recommendation="Replace the failing edge device.",
        intelligence=intelligence,
        daily_cost=8400,
        frameworks=["DORA"],
        requires_escalation=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def test_get_recommendation_returns_latest_decision(monkeypatch):
    recommendation = _recommendation()
    latest_decision = recommendations.DecisionRecord(
        id="decision-1",
        organization_id=42,
        recommendation_id=recommendation.id,
        threat_id=recommendation.threat_id,
        selected_action="jira",
        decision_type="recommended",
        rationale="Engineering owns the operational fix.",
        decided_by="ciso@risklence.test",
        decided_role="ciso",
        review_date=None,
        stale=True,
        recommendation_snapshot={},
        reasoning_snapshot={},
        integration_ref="JIRA-123",
        integration_provider="jira",
        external_url="https://jira.example/browse/JIRA-123",
        created_at=datetime(2026, 4, 16, 9, 0, tzinfo=timezone.utc),
    )

    monkeypatch.setattr(
        recommendations, "_get_recommendation", lambda recommendation_id, org_id, db: recommendation
    )
    monkeypatch.setattr(
        recommendations,
        "get_latest_decision_for_recommendation",
        lambda recommendation_id, org_id, db: latest_decision,
    )
    monkeypatch.setattr(
        recommendations,
        "get_latest_resolution_for_recommendation",
        lambda recommendation_id, org_id, db: None,
    )
    monkeypatch.setattr(
        recommendations, "_count_decision_records", lambda recommendation_id, org_id, db: 2
    )

    response = recommendations.get_recommendation(
        recommendation_id=recommendation.id,
        ctx=_ctx(),
        db=DummyDB(),
    )

    assert response.recommendationId == recommendation.id
    assert response.isStale is True
    assert response.decisionCount == 2
    assert response.decision is not None
    assert response.decision.recommendationId == recommendation.id


def test_create_decision_records_append_only_recommended_route(monkeypatch):
    recommendation = _recommendation()
    threat = _threat(batch_id=17)
    batch = RiskIngestionBatch(
        id=17,
        organization_id=42,
        source_name="telia_full_report.json",
        collector_profile="subfinder_amass_nmap_nuclei",
        file_name="telia_full_report.json",
        content_type="application/json",
        payload_checksum="f" * 64,
        raw_payload={"findings": []},
        raw_payload_size_bytes=2,
        status=RiskIngestionBatchStatus.ANALYZED,
        received_at=datetime(2026, 5, 13, 8, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 5, 13, 8, 20, tzinfo=timezone.utc),
    )
    db = DummyDB(batch)

    monkeypatch.setattr(
        recommendations,
        "_get_recommendation",
        lambda recommendation_id, org_id, db_session: recommendation,
    )
    monkeypatch.setattr(
        recommendations,
        "_get_recommendation_threat",
        lambda recommendation_obj, org_id, db_session: threat,
    )
    monkeypatch.setattr(
        recommendations,
        "_dispatch_integration",
        lambda **kwargs: IntegrationDispatchResult(
            ref="JIRA-123",
            provider="jira",
            external_url="https://jira.example/browse/JIRA-123",
        ),
    )
    monkeypatch.setattr(recommendations, "_ensure_recovery_action", lambda **kwargs: 77)
    # Authority is #374's subject, not this test's.
    monkeypatch.setattr(recommendations, "_require_decision_authority", lambda ctx, threat, db: None)
    # Telling the other owners is #375's subject and needs a real session;
    # these tests are about the decision RECORD, and DummyDB has no query().
    monkeypatch.setattr(recommendations, "_tell_the_other_owners", lambda db, **kwargs: None)

    response = recommendations.create_decision(
        body=recommendations.CreateDecisionRequest(
            recommendationId=recommendation.id,
            selectedAction="jira",
            rationale="Engineering can address this immediately.",
        ),
        ctx=_ctx(),
        db=db,
    )

    assert response.recommendationId == recommendation.id
    assert response.recoveryActionId == 77
    assert response.decision.ref == "JIRA-123"
    assert response.decision.recommendationId == recommendation.id
    assert threat.status == "in-progress"
    assert recommendation.status == "decided"
    decision_record = next(
        obj for obj in db.added if isinstance(obj, recommendations.DecisionRecord)
    )
    assert (
        decision_record.recommendation_snapshot["businessDecisionTaxonomy"][
            "recommendedBusinessAction"
        ]
        == "mitigate"
    )
    assert (
        decision_record.reasoning_snapshot["businessDecisionTaxonomy"]["selectedBusinessAction"]
        == "mitigate"
    )
    assert (
        decision_record.reasoning_snapshot["businessDecisionTaxonomy"]["routeRelationship"]
        == "recommended"
    )
    assert batch.status == RiskIngestionBatchStatus.REVIEWED
    assert batch.decision_evidence is not None
    assert batch.decision_evidence["decisionId"] == decision_record.id
    assert batch.decision_evidence["selectedAction"] == "jira"
    assert db.commit_calls == 1
    assert db.flush_calls >= 1
    assert db.refresh_calls == 2


def test_create_decision_requires_rationale_for_alternative_route(monkeypatch):
    recommendation = _recommendation()
    db = DummyDB()

    monkeypatch.setattr(
        recommendations,
        "_get_recommendation",
        lambda recommendation_id, org_id, db_session: recommendation,
    )
    monkeypatch.setattr(
        recommendations,
        "_get_recommendation_threat",
        lambda recommendation_obj, org_id, db_session: None,
    )
    # Authority is checked BEFORE the business rules, so a person who may not
    # decide never learns whether their rationale would have been accepted.
    # This test is about the rationale rule, so it is reached as the owner.
    monkeypatch.setattr(recommendations, "_require_decision_authority", lambda ctx, threat, db: None)
    # Telling the other owners is #375's subject and needs a real session;
    # these tests are about the decision RECORD, and DummyDB has no query().
    monkeypatch.setattr(recommendations, "_tell_the_other_owners", lambda db, **kwargs: None)

    with pytest.raises(HTTPException) as exc_info:
        recommendations.create_decision(
            body=recommendations.CreateDecisionRequest(
                recommendationId=recommendation.id,
                selectedAction="servicenow",
                rationale="  ",
            ),
            ctx=_ctx(),
            db=db,
        )

    assert exc_info.value.status_code == 422
    assert db.commit_calls == 0


def test_generate_recommendations_requires_admin():
    with pytest.raises(HTTPException) as exc_info:
        recommendations.generate_recommendations(
            ctx=_ctx(),
            db=DummyDB(),
        )

    assert exc_info.value.status_code == 403


def test_generate_recommendations_delegates_to_service(monkeypatch):
    calls: list[tuple[object, int]] = []

    def fake_generate(db, organization_id):
        calls.append((db, organization_id))
        return SimpleNamespace(
            organization_id=organization_id,
            total_threats=4,
            created_count=2,
            refreshed_count=1,
            unchanged_count=1,
            generated_at=datetime(2026, 4, 23, 10, 0, tzinfo=timezone.utc),
        )

    monkeypatch.setattr(recommendations, "generate_live_recommendations_for_org", fake_generate)
    db = DummyDB()

    response = recommendations.generate_recommendations(
        ctx=_admin_ctx(),
        db=db,
    )

    assert calls == [(db, 42)]
    assert response.organizationId == 42
    assert response.createdCount == 2
    assert response.refreshedCount == 1


def test_create_decision_denies_consultant_role(monkeypatch):
    """Epic A4 slice 2 — the time-boxed, external-facing Consultant role
    may not record a binding decision, and must be denied before any
    recommendation lookup runs."""

    def _fail_if_called(*_args, **_kwargs):
        raise AssertionError("_get_recommendation should not be reached for a denied consultant")

    monkeypatch.setattr(recommendations, "_get_recommendation", _fail_if_called)
    db = DummyDB()

    with pytest.raises(HTTPException) as exc_info:
        recommendations.create_decision(
            body=recommendations.CreateDecisionRequest(
                recommendationId="rec-1",
                selectedAction="jira",
                rationale="Attempted consultant decision.",
            ),
            ctx=_consultant_ctx(),
            db=db,
        )

    assert exc_info.value.status_code == 403


def test_create_decision_allows_the_accountable_owner(monkeypatch):
    """The owner of the service the threat concerns may decide (#374).

    ⚠️ This test used to be `..._allows_non_admin_non_consultant_role`, and its
    premise — "ordinary staff must still succeed" — was the defect. Any active
    non-consultant could accept risk on any threat in the organisation. Under
    Søren's ruling, authority follows ownership of the thing decided, so
    ordinary staff who own nothing are now refused; the owner still succeeds.
    """
    recommendation = _recommendation()
    threat = _threat()

    monkeypatch.setattr(
        recommendations, "_get_recommendation", lambda recommendation_id, org_id, db_session: recommendation
    )
    monkeypatch.setattr(
        recommendations, "_get_recommendation_threat", lambda recommendation_obj, org_id, db_session: threat
    )
    monkeypatch.setattr(
        recommendations,
        "_dispatch_integration",
        lambda **kwargs: IntegrationDispatchResult(
            ref="JIRA-124", provider="jira", external_url="https://jira.example/browse/JIRA-124"
        ),
    )
    monkeypatch.setattr(recommendations, "_ensure_recovery_action", lambda **kwargs: 78)
    # Authority is #374's subject, not this test's. Stubbed so a rule about
    # the decision RECORD is not also asserting who may create one.
    monkeypatch.setattr(recommendations, "_require_decision_authority", lambda ctx, threat, db: None)
    # Telling the other owners is #375's subject and needs a real session;
    # these tests are about the decision RECORD, and DummyDB has no query().
    monkeypatch.setattr(recommendations, "_tell_the_other_owners", lambda db, **kwargs: None)
    db = DummyDB()

    response = recommendations.create_decision(
        body=recommendations.CreateDecisionRequest(
            recommendationId=recommendation.id,
            selectedAction="jira",
            rationale="Ordinary staff decision.",
        ),
        ctx=_ctx(),
        db=db,
    )

    assert response.recommendationId == recommendation.id
