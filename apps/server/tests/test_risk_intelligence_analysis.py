from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.database import Base
from src.core.models import (
    Asset,
    AssetStatus,
    AuditEvent,
    BusinessService,
    Criticality,
    ConnectivityStatus,
    Environment,
    Organization,
    Recommendation,
    RiskIngestionBatch,
    RiskIngestionBatchStatus,
    ScanStartMode,
    SetupConfidence,
    Threat,
)
from src.core.constants.risk_intelligence_ingestion import INGESTION_BATCH_ANALYZED_EVENT
from src.core.constants import SERVICE_TIER_MISSION_CRITICAL
from src.core.services.risk_intelligence_ingestion_service import create_ingestion_batch
from src.core.services.risk_intelligence_normalization_service import normalize_ingestion_batch
from src.core.services.risk_intelligence_analysis_service import analyze_normalized_ingestion_batch


@pytest.fixture(scope="function")
def db():
    # A private in-memory database: this module shares nothing and drops nothing (#287).
    engine = create_engine("sqlite:///:memory:")
    # SQLite lacks native ARRAY/JSONB; coerce to JSON. conftest restores the types.
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine)
    session.add(
        Organization(
            id=1,
            name="Test Org",
            slug="test-org",
            plan_tier="enterprise",
            subscription_status="active",
            onboarding_completed=False,
        )
    )
    session.commit()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


def _payload() -> dict[str, object]:
    return {
        "hosts": [
            {
                "hostname": "api.example.com",
                "ip": "203.0.113.10",
                "services": [{"port": 443, "protocol": "tcp", "name": "https"}],
                "findings": [
                    {
                        "id": "nuclei-tls-001",
                        "severity": "high",
                        "title": "Outdated TLS configuration",
                        "description": "TLS 1.0 remains enabled on the public endpoint.",
                    }
                ],
            }
        ]
    }


def _create_batch(db: Session) -> RiskIngestionBatch:
    return create_ingestion_batch(
        db,
        organization_id=1,
        actor_user_id=7,
        source_name="telia_full_report.json",
        collector_profile="subfinder_amass_nmap_nuclei",
        raw_payload=_payload(),
        file_name="telia_full_report.json",
    )


def _seed_asset_context(db: Session) -> Asset:
    asset = Asset(
        organization_id=1,
        type="Service",
        provider="internal",
        display_name="api.example.com",
        layer="Application",
        environment=Environment.PROD,
        criticality=Criticality.MEDIUM,
        status=AssetStatus.OPERATIONALLY_COMPLIANT,
        connectivity_status=ConnectivityStatus.PENDING_VERIFICATION,
        setup_confidence=SetupConfidence.MEDIUM,
        scan_start_mode=ScanStartMode.AUDIT_ONLY,
        findings_count=0,
        risk_score=10.0,
        confidence=0.7,
        is_spof=True,
    )
    db.add(asset)
    db.flush()
    db.add_all(
        [
            BusinessService(
                organization_id=1,
                name="Customer API",
                tier=SERVICE_TIER_MISSION_CRITICAL,
                trading_impact="2m revenue",
                value_stream_ids=[],
                l1=[f"asset-{asset.id}"],
                l2=[],
                l3=[],
            ),
            BusinessService(
                organization_id=1,
                name="Public Checkout",
                tier=SERVICE_TIER_MISSION_CRITICAL,
                trading_impact="1m revenue",
                value_stream_ids=[],
                l1=[f"asset-{asset.id}"],
                l2=[],
                l3=[],
            ),
        ]
    )
    db.commit()
    return asset


def test_analyze_normalized_ingestion_batch_creates_threat_and_recommendation(db: Session):
    asset = _seed_asset_context(db)
    batch = _create_batch(db)

    normalize_result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)
    assert normalize_result.finding_count == 1

    result = analyze_normalized_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    assert result.ingestion_batch_id == batch.id
    assert result.batch_status == RiskIngestionBatchStatus.ANALYZED
    assert result.human_decision_required is True
    assert result.finding_count == 1
    assert result.high_severity_finding_count == 1
    assert result.threat_count == 1
    assert result.recommendation_count == 1
    assert result.findings[0].asset_id == asset.id
    assert result.findings[0].threat_id is not None
    assert result.findings[0].recommendation_id is not None
    assert "business operations are significantly disrupted" in result.findings[0].business_consequence.lower()

    stored_batch = db.get(RiskIngestionBatch, batch.id)
    assert stored_batch is not None
    assert stored_batch.status == RiskIngestionBatchStatus.ANALYZED

    threats = db.query(Threat).filter(Threat.organization_id == 1).all()
    recommendations = db.query(Recommendation).filter(Recommendation.organization_id == 1).all()
    assert len(threats) == 1
    assert len(recommendations) == 1
    assert threats[0].what_it_means == result.findings[0].business_consequence
    assert recommendations[0].threat_id == threats[0].id

    audit_event = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.organization_id == 1,
            AuditEvent.event_type == INGESTION_BATCH_ANALYZED_EVENT,
        )
        .one()
    )
    assert audit_event.metadata_json["ingestionBatchId"] == batch.id
    assert audit_event.metadata_json["threatCount"] == 1
    assert audit_event.metadata_json["recommendationCount"] == 1


def test_analyze_normalized_ingestion_batch_is_idempotent_for_existing_threat(db: Session):
    _seed_asset_context(db)
    batch = _create_batch(db)
    normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    first = analyze_normalized_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)
    second = analyze_normalized_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    assert first.threat_count == 1
    assert second.threat_count == 1
    assert db.query(Threat).filter(Threat.organization_id == 1).count() == 1
    assert db.query(Recommendation).filter(Recommendation.organization_id == 1).count() == 1
