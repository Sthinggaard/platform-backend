from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import Session

from src.core.constants import SERVICE_TIER_MISSION_CRITICAL
from src.core.models import (
    Asset,
    AssetStatus,
    BusinessService,
    ConnectivityStatus,
    Organization,
    Recommendation,
    ScanStartMode,
    SetupConfidence,
    SlotInstance,
    Threat,
    ValueStream,
)
from src.core.services.recommendation_generation_service import (
    generate_live_recommendations_for_org,
)


@pytest.fixture
def db(db_session: Session) -> Session:
    """The shared Postgres session from `conftest` (#228), not a module-local engine.

    This module used to build its own engine from `TEST_POSTGRES_URL` and
    `drop_all()` at teardown — the same database the session-scoped `test_engine`
    owns. That took the schema out from under every suite that ran afterwards
    (#287). `db_session` rolls its transaction back instead.
    """
    db_session.add(
        Organization(
            id=42,
            name="Test Org",
            slug="test-org",
            plan_tier="trial",
            subscription_status="trial",
            onboarding_completed=False,
        )
    )
    db_session.commit()
    return db_session


def _seed_runtime_context(db: Session) -> None:
    asset = Asset(
        id=1,
        organization_id=42,
        type="network",
        display_name="Payment Gateway",
        layer="L3",
        status=AssetStatus.AT_RISK,
        connectivity_status=ConnectivityStatus.CONNECTED,
        setup_confidence=SetupConfidence.MEDIUM,
        scan_start_mode=ScanStartMode.AFTER_SME_CONFIRM,
        level=3,
        is_spof=True,
        risk_score=88.0,
        findings_count=4,
        confidence=0.92,
    )
    value_stream = ValueStream(
        id="vs-1",
        organization_id=42,
        name="Card Payments",
        priority="critical",
        source="manual",
    )
    service_a = BusinessService(
        id="svc-1",
        organization_id=42,
        name="Payments API",
        tier=SERVICE_TIER_MISSION_CRITICAL,
        trading_impact="EUR 3.2M/hr",
        value_stream_ids=["vs-1"],
    )
    service_b = BusinessService(
        id="svc-2",
        organization_id=42,
        name="Checkout",
        tier=SERVICE_TIER_MISSION_CRITICAL,
        trading_impact="EUR 1.8M/hr",
        value_stream_ids=["vs-1"],
    )
    slot_a = SlotInstance(
        id="slot-1",
        organization_id=42,
        service_id="svc-1",
        slot_id="payment-edge",
        group_key="payment-edge",
        status="mapped",
        asset_id="asset-1",
        asset_label="Payment Gateway",
        template_version=1,
    )
    slot_b = SlotInstance(
        id="slot-2",
        organization_id=42,
        service_id="svc-2",
        slot_id="checkout-edge",
        group_key="checkout-edge",
        status="mapped",
        asset_id="asset-1",
        asset_label="Payment Gateway",
        template_version=1,
    )
    threat = Threat(
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
        },
        daily_cost=8400,
        frameworks=["DORA"],
        requires_escalation=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add_all([asset, value_stream, service_a, service_b, slot_a, slot_b, threat])
    db.commit()


def test_generate_live_recommendations_creates_crown_jewel_snapshot(db: Session):
    _seed_runtime_context(db)

    result = generate_live_recommendations_for_org(db, 42)

    rows = db.query(Recommendation).filter(Recommendation.organization_id == 42).all()
    assert result.created_count == 1
    assert result.refreshed_count == 0
    assert len(rows) == 1
    recommendation = rows[0]
    assert recommendation.threat_id == "threat-1"
    assert recommendation.linked_context_id == "asset-1"
    assert recommendation.suggested_action == "jira"
    assert recommendation.intelligence_snapshot["recommendationType"] == "critical_asset"
    assert (
        recommendation.intelligence_snapshot["businessDecisionTaxonomy"][
            "recommendedBusinessAction"
        ]
        == "mitigate"
    )
    assert (
        recommendation.intelligence_snapshot["businessDecisionTaxonomy"]["recommendedRoute"]
        == "jira"
    )
    assert recommendation.intelligence_snapshot["assetContext"]["crownJewelCandidate"] is True
    assert (
        "derived_crown_jewel_candidate"
        in recommendation.intelligence_snapshot["structuralRationale"]
    )


def test_generate_live_recommendations_refreshes_changed_snapshot(db: Session):
    _seed_runtime_context(db)
    first = generate_live_recommendations_for_org(db, 42)
    assert first.created_count == 1

    threat = db.query(Threat).filter(Threat.id == "threat-1").first()
    assert threat is not None
    threat.what_it_means = (
        "Card authorisation will fail and checkout revenue is immediately exposed."
    )
    db.add(threat)
    db.commit()

    second = generate_live_recommendations_for_org(db, 42)

    rows = (
        db.query(Recommendation)
        .filter(Recommendation.organization_id == 42, Recommendation.threat_id == "threat-1")
        .order_by(Recommendation.generated_at.asc())
        .all()
    )
    assert second.refreshed_count == 1
    assert len(rows) == 2
    assert rows[0].is_stale is True
    assert rows[1].is_stale is False
    assert "checkout revenue is immediately exposed" in rows[1].why_it_matters.lower()
