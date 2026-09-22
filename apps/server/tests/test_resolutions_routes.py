from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import resolutions
from src.core.models import DecisionRecord, Recommendation, RecoveryAction


class DummyDB:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.commit_calls = 0
        self.refresh_calls = 0

    def add(self, obj: object) -> None:
        if getattr(obj, "id", None) is None:
            setattr(obj, "id", str(uuid4()))
        self.added.append(obj)

    def commit(self) -> None:
        self.commit_calls += 1

    def refresh(self, _obj: object) -> None:
        self.refresh_calls += 1


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=7,
        organization_id=42,
        email="ciso@risklence.test",
        roles=["ciso"],
        permissions=[],
    )


def _recommendation() -> Recommendation:
    return Recommendation(
        id="rec-1",
        organization_id=42,
        threat_id="threat-1",
        status="decided",
        linked_context_type="asset",
        linked_context_id="asset-1",
        linked_context_label="Payment Gateway",
        problem="Packet loss is rising on the payment edge.",
        why_it_matters="Card payments will fail if the degradation continues.",
        suggested_action="jira",
        confidence_score=91,
        is_stale=False,
        intelligence_snapshot={},
        generated_at=datetime(2026, 4, 20, 8, 30, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 20, 8, 30, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 20, 8, 30, tzinfo=timezone.utc),
    )


def _decision() -> DecisionRecord:
    return DecisionRecord(
        id="dec-1",
        organization_id=42,
        recommendation_id="rec-1",
        threat_id="threat-1",
        selected_action="jira",
        decision_type="recommended",
        rationale="Engineering owns the operational fix.",
        decided_by="ciso@risklence.test",
        decided_role="ciso",
        review_date=None,
        stale=False,
        recommendation_snapshot={},
        reasoning_snapshot={},
        recovery_action_id=77,
        created_at=datetime(2026, 4, 20, 9, 0, tzinfo=timezone.utc),
    )


def _recovery_action() -> RecoveryAction:
    return RecoveryAction(
        id=77,
        organization_id=42,
        threat_id="threat-1",
        title="Fix payment edge",
        issue="Payment traffic is degrading.",
        action="Replace the failing edge device.",
        affected_services=[],
        priority="high",
        status="completed",
        progress=100,
        steps=[],
        created_at=datetime(2026, 4, 20, 9, 5, tzinfo=timezone.utc),
        updated_at=datetime(2026, 4, 20, 9, 5, tzinfo=timezone.utc),
    )


def test_create_resolution_records_append_only_resolution(monkeypatch):
    recommendation = _recommendation()
    latest_decision = _decision()
    recovery_action = _recovery_action()
    db = DummyDB()

    monkeypatch.setattr(resolutions, "_get_recommendation", lambda recommendation_id, org_id, db_session: recommendation)
    monkeypatch.setattr(
        resolutions,
        "get_latest_decision_for_recommendation",
        lambda recommendation_id, org_id, db_session: latest_decision,
    )
    monkeypatch.setattr(
        resolutions,
        "_resolve_recovery_action",
        lambda recovery_action_id, latest_decision_obj, org_id, db_session: recovery_action,
    )

    response = resolutions.create_resolution(
        body=resolutions.CreateResolutionRequest(
            recommendationId=recommendation.id,
            resolutionType="followed-recommendation",
            selectedActionOption="jira",
            alternativeCategory=None,
            resolutionSummary="Engineering deployed the fix and closed the ticket.",
            resolvedBy="ciso@risklence.test",
            recoveryActionId=recovery_action.id,
        ),
        ctx=_ctx(),
        db=db,
    )

    assert response.recommendationId == recommendation.id
    assert response.decisionId == latest_decision.id
    assert response.recoveryActionId == recovery_action.id
    assert response.alternativeCategory is None
    assert response.status == "captured"
    assert response.verificationStatus == "pending"
    assert db.commit_calls == 1
    assert db.refresh_calls == 1


def test_create_resolution_rejects_followed_recommendation_when_action_differs(monkeypatch):
    recommendation = _recommendation()
    db = DummyDB()

    monkeypatch.setattr(resolutions, "_get_recommendation", lambda recommendation_id, org_id, db_session: recommendation)
    monkeypatch.setattr(
        resolutions,
        "get_latest_decision_for_recommendation",
        lambda recommendation_id, org_id, db_session: None,
    )
    monkeypatch.setattr(
        resolutions,
        "_resolve_recovery_action",
        lambda recovery_action_id, latest_decision_obj, org_id, db_session: None,
    )

    with pytest.raises(HTTPException) as exc_info:
        resolutions.create_resolution(
            body=resolutions.CreateResolutionRequest(
                recommendationId=recommendation.id,
                resolutionType="followed-recommendation",
                selectedActionOption="accepted",
                resolvedBy="ciso@risklence.test",
            ),
            ctx=_ctx(),
            db=db,
        )

    assert exc_info.value.status_code == 422
    assert db.commit_calls == 0


def test_create_resolution_requires_category_for_solved_differently(monkeypatch):
    recommendation = _recommendation()
    latest_decision = _decision()
    db = DummyDB()

    monkeypatch.setattr(resolutions, "_get_recommendation", lambda recommendation_id, org_id, db_session: recommendation)
    monkeypatch.setattr(
        resolutions,
        "get_latest_decision_for_recommendation",
        lambda recommendation_id, org_id, db_session: latest_decision,
    )
    monkeypatch.setattr(
        resolutions,
        "_resolve_recovery_action",
        lambda recovery_action_id, latest_decision_obj, org_id, db_session: None,
    )

    with pytest.raises(HTTPException) as exc_info:
        resolutions.create_resolution(
            body=resolutions.CreateResolutionRequest(
                recommendationId=recommendation.id,
                resolutionType="solved-differently",
                selectedActionOption="jira",
                resolvedBy="ciso@risklence.test",
            ),
            ctx=_ctx(),
            db=db,
        )

    assert exc_info.value.status_code == 422
    assert db.commit_calls == 0


def test_create_resolution_records_alternative_category(monkeypatch):
    recommendation = _recommendation()
    latest_decision = _decision()
    db = DummyDB()

    monkeypatch.setattr(resolutions, "_get_recommendation", lambda recommendation_id, org_id, db_session: recommendation)
    monkeypatch.setattr(
        resolutions,
        "get_latest_decision_for_recommendation",
        lambda recommendation_id, org_id, db_session: latest_decision,
    )
    monkeypatch.setattr(
        resolutions,
        "_resolve_recovery_action",
        lambda recovery_action_id, latest_decision_obj, org_id, db_session: None,
    )

    response = resolutions.create_resolution(
        body=resolutions.CreateResolutionRequest(
            recommendationId=recommendation.id,
            resolutionType="solved-differently",
            selectedActionOption="jira",
            alternativeCategory="added_fallback",
            resolvedBy="ciso@risklence.test",
        ),
        ctx=_ctx(),
        db=db,
    )

    assert response.alternativeCategory == "added_fallback"
    assert db.added[0].alternative_category == "added_fallback"
    assert db.commit_calls == 1


def test_create_resolution_rejects_category_for_non_alternative_resolution(monkeypatch):
    recommendation = _recommendation()
    latest_decision = _decision()
    db = DummyDB()

    monkeypatch.setattr(resolutions, "_get_recommendation", lambda recommendation_id, org_id, db_session: recommendation)
    monkeypatch.setattr(
        resolutions,
        "get_latest_decision_for_recommendation",
        lambda recommendation_id, org_id, db_session: latest_decision,
    )
    monkeypatch.setattr(
        resolutions,
        "_resolve_recovery_action",
        lambda recovery_action_id, latest_decision_obj, org_id, db_session: None,
    )

    with pytest.raises(HTTPException) as exc_info:
        resolutions.create_resolution(
            body=resolutions.CreateResolutionRequest(
                recommendationId=recommendation.id,
                resolutionType="followed-recommendation",
                selectedActionOption="jira",
                alternativeCategory="added_fallback",
                resolvedBy="ciso@risklence.test",
            ),
            ctx=_ctx(),
            db=db,
        )

    assert exc_info.value.status_code == 422
    assert db.commit_calls == 0
