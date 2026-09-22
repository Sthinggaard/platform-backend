from datetime import datetime, timezone

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import resolutions
from src.core.models import AssetEvidenceSignal, Recommendation, ResolutionRecord, VerificationRecord
from src.core.services import resolution_verification_service as verification_service


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


def _resolution(resolution_type: str = "followed-recommendation") -> ResolutionRecord:
    return ResolutionRecord(
        id="res-1",
        organization_id=42,
        recommendation_id="rec-1",
        decision_record_id="dec-1",
        threat_id="threat-1",
        recovery_action_id=77,
        resolution_type=resolution_type,
        selected_action_option="jira",
        resolution_summary="Engineering closed the ticket and redeployed the edge.",
        resolved_by="ciso@risklence.test",
        resolved_role="ciso",
        status="captured",
        verification_status="pending",
        created_at=datetime(2026, 4, 20, 9, 0, tzinfo=timezone.utc),
    )


def _signal(confidence: float) -> AssetEvidenceSignal:
    return AssetEvidenceSignal(
        id=1,
        organization_id=42,
        asset_id=1,
        kind="network_scan",
        payload_json={"alerts": 0},
        observed_at=datetime(2026, 4, 20, 10, 0, tzinfo=timezone.utc),
        confidence=confidence,
        risk_score=20.0,
    )


def test_build_verification_outcome_marks_success_for_followed_recommendation():
    outcome = verification_service._build_verification_outcome(
        resolution=_resolution("followed-recommendation"),
        recommendation=_recommendation(),
        baseline=verification_service.ObservationSnapshot(
            status="AT_RISK",
            risk_score=82.0,
            findings_count=4,
            observed_at=datetime(2026, 4, 20, 8, 0, tzinfo=timezone.utc),
        ),
        post_snapshot=verification_service.ObservationSnapshot(
            status="OPERATIONALLY_COMPLIANT",
            risk_score=18.0,
            findings_count=0,
            observed_at=datetime(2026, 4, 20, 10, 0, tzinfo=timezone.utc),
        ),
        post_signals=[_signal(0.92)],
    )

    assert outcome.status == "verified_successful"
    assert outcome.confidence == 92
    assert any(change["type"] == "findings_count" for change in outcome.observed_changes)


def test_build_verification_outcome_marks_alternative_for_solved_differently():
    outcome = verification_service._build_verification_outcome(
        resolution=_resolution("solved-differently"),
        recommendation=_recommendation(),
        baseline=verification_service.ObservationSnapshot(
            status="AT_RISK",
            risk_score=70.0,
            findings_count=2,
            observed_at=datetime(2026, 4, 20, 8, 0, tzinfo=timezone.utc),
        ),
        post_snapshot=verification_service.ObservationSnapshot(
            status="OPERATIONALLY_COMPLIANT",
            risk_score=20.0,
            findings_count=0,
            observed_at=datetime(2026, 4, 20, 10, 0, tzinfo=timezone.utc),
        ),
        post_signals=[_signal(0.88)],
    )

    assert outcome.status == "verified_alternative"


def test_build_verification_outcome_marks_insufficient_when_confidence_is_low():
    outcome = verification_service._build_verification_outcome(
        resolution=_resolution("followed-recommendation"),
        recommendation=_recommendation(),
        baseline=verification_service.ObservationSnapshot(
            status="AT_RISK",
            risk_score=70.0,
            findings_count=2,
            observed_at=datetime(2026, 4, 20, 8, 0, tzinfo=timezone.utc),
        ),
        post_snapshot=verification_service.ObservationSnapshot(
            status="OPERATIONALLY_COMPLIANT",
            risk_score=24.0,
            findings_count=0,
            observed_at=datetime(2026, 4, 20, 10, 0, tzinfo=timezone.utc),
        ),
        post_signals=[_signal(0.4)],
    )

    assert outcome.status == "verified_insufficient"
    assert "confidence" in outcome.notes.lower()


def test_get_resolution_verification_returns_pending_when_no_scan_observation(monkeypatch):
    resolution = _resolution()

    monkeypatch.setattr(resolutions, "_get_resolution", lambda resolution_id, org_id, db: resolution)
    monkeypatch.setattr(
        resolutions,
        "get_latest_verification_for_resolution",
        lambda resolution_id, org_id, db: None,
    )
    monkeypatch.setattr(
        resolutions,
        "verify_resolution_status",
        lambda db, resolution_obj, org_id: None,
    )

    response = resolutions.get_resolution_verification(
        resolution_id=resolution.id,
        ctx=_ctx(),
        db=object(),
    )

    assert response.resolutionId == resolution.id
    assert response.verificationStatus == "pending"
    assert response.verificationTimestamp is None


def test_get_resolution_verification_returns_latest_record(monkeypatch):
    resolution = _resolution()
    verification = VerificationRecord(
        id="ver-1",
        organization_id=42,
        resolution_record_id=resolution.id,
        recommendation_id=resolution.recommendation_id,
        threat_id=resolution.threat_id,
        verification_status="verified_successful",
        confidence_score=91,
        observed_changes=[{"type": "findings_count", "description": "Cleared", "before": "2", "after": "0"}],
        notes="Scanner observations show the issue improved.",
        linked_context_type="asset",
        linked_context_id="asset-1",
        compared_observed_at=datetime(2026, 4, 20, 10, 0, tzinfo=timezone.utc),
        created_at=datetime(2026, 4, 20, 10, 5, tzinfo=timezone.utc),
    )

    monkeypatch.setattr(resolutions, "_get_resolution", lambda resolution_id, org_id, db: resolution)
    monkeypatch.setattr(
        resolutions,
        "get_latest_verification_for_resolution",
        lambda resolution_id, org_id, db: verification,
    )

    response = resolutions.get_resolution_verification(
        resolution_id=resolution.id,
        ctx=_ctx(),
        db=object(),
    )

    assert response.verificationStatus == "verified_successful"
    assert response.confidence == 91
