from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import threats
from src.core.models import Threat


class DummyDB:
    def __init__(self) -> None:
        self.commit_calls = 0
        self.refresh_calls = 0
        self._threats: list[Threat] = []

    def commit(self) -> None:
        self.commit_calls += 1

    def refresh(self, _obj) -> None:
        self.refresh_calls += 1

    def query(self, model):
        return _FakeThreatQuery(self._threats)


class _FakeThreatQuery:
    def __init__(self, threats_list: list[Threat]) -> None:
        self._threats = threats_list

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def all(self):
        return self._threats


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=7,
        organization_id=42,
        email="ciso@risklence.test",
        roles=["ciso"],
        permissions=[],
    )


def _threat() -> Threat:
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
        intelligence={
            "recommendedAction": "jira",
            "confidence": 91,
            "basis": "Peer evidence",
            "reasoning": "Operational engineering path is fastest.",
            "frameworkGuidance": "Operational maintenance route.",
            "alternativeNote": None,
        },
        daily_cost=8400,
        frameworks=["DORA"],
        requires_escalation=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def test_record_decision_delegates_to_append_only_recommendation_flow(monkeypatch):
    threat = _threat()
    db = DummyDB()
    calls = []
    recommendation = type("Recommendation", (), {"id": "rec-1"})()

    monkeypatch.setattr(threats, "_get_threat", lambda threat_id, org_id, db_session: threat)
    monkeypatch.setattr(threats, "generate_live_recommendations_for_org", lambda db_session, org_id: None)
    monkeypatch.setattr(
        threats,
        "_get_latest_recommendation_for_threat",
        lambda threat_id, org_id, db_session: recommendation,
    )
    monkeypatch.setattr(
        threats.recommendation_routes,
        "create_decision",
        lambda **kwargs: calls.append(kwargs),
    )
    monkeypatch.setattr(
        threats,
        "_build_threat_response",
        lambda threat, org_id, db: threats.ThreatResponse.from_model(threat),
    )

    response = threats.record_decision(
        threat_id=threat.id,
        body=threats.RecordDecisionRequest(action="jira", rationale="Engineering owns this fix."),
        ctx=_ctx(),
        db=db,
    )

    assert response.id == threat.id
    assert len(calls) == 1
    request = calls[0]["body"]
    assert request.recommendationId == recommendation.id
    assert request.selectedAction == "jira"
    assert request.rationale == "Engineering owns this fix."
    assert calls[0]["ctx"] == _ctx()
    assert threat.decision is None
    assert db.commit_calls == 0


def test_record_decision_rejects_missing_recommendation(monkeypatch):
    threat = _threat()
    db = DummyDB()

    monkeypatch.setattr(threats, "_get_threat", lambda threat_id, org_id, db_session: threat)
    monkeypatch.setattr(threats, "generate_live_recommendations_for_org", lambda db_session, org_id: None)
    monkeypatch.setattr(threats, "_get_latest_recommendation_for_threat", lambda *args: None)

    with pytest.raises(HTTPException) as exc_info:
        threats.record_decision(
            threat_id=threat.id,
            body=threats.RecordDecisionRequest(
                action="jira",
                rationale="Formal governance change is required.",
            ),
            ctx=_ctx(),
            db=db,
        )

    assert exc_info.value.status_code == 409
    assert db.commit_calls == 0
    assert db.refresh_calls == 0


def test_record_outcome_returns_explicit_retirement_without_mutation(monkeypatch):
    threat = _threat()
    db = DummyDB()

    monkeypatch.setattr(threats, "_get_threat", lambda threat_id, org_id, db_session: threat)

    with pytest.raises(HTTPException) as exc_info:
        threats.record_outcome(
            threat_id=threat.id,
            body=threats.RecordOutcomeRequest(
                outcome="Remediation was verified.",
                outcome_quality="fully-resolved",
            ),
            ctx=_ctx(),
            db=db,
        )

    assert exc_info.value.status_code == 410
    assert exc_info.value.detail["error_code"] == "LEGACY_OUTCOME_ENDPOINT_RETIRED"
    assert exc_info.value.detail["canonical_endpoint"] == "/api/v1/resolutions"
    assert threat.decision is None
    assert db.commit_calls == 0
    assert db.refresh_calls == 0


def test_list_threats_ensures_live_recommendations(monkeypatch):
    db = DummyDB()
    db._threats = [_threat()]
    calls: list[tuple[object, int]] = []

    monkeypatch.setattr(
        threats,
        "generate_live_recommendations_for_org",
        lambda db_session, organization_id: calls.append((db_session, organization_id)),
    )
    monkeypatch.setattr(
        threats,
        "_build_threat_response",
        lambda threat, org_id, db: threats.ThreatResponse.from_model(threat),
    )

    response = threats.list_threats(ctx=_ctx(), db=db)

    assert calls == [(db, 42)]
    assert len(response) == 1
    assert response[0].id == "threat-1"


def test_threat_response_preserves_legacy_resolution_display_date():
    threat = _threat()
    threat.resolved_on = "22 May 2026"

    response = threats.ThreatResponse.from_model(threat)

    assert response.resolvedOn == "22 May 2026"
