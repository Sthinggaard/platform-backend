from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import risk_intelligence_ingestion as ingestion_routes
from src.core.database import Base
from src.core.model_defs.common import utcnow
from src.core.constants import SERVICE_TIER_MISSION_CRITICAL
from src.core.constants.artefact_identity_enums import TechnicalObservationStatus, TechnicalObservationType
from src.core.models import (
    Asset,
    AssetEvidenceSignal,
    AssetFinding,
    AssetFindingStatus,
    AssetIdentifier,
    AssetLifecycleState,
    AssetObservedPort,
    AssetStatus,
    ConnectivityStatus,
    BusinessService,
    Criticality,
    Environment,
    Organization,
    RiskIngestionBatch,
    RiskIngestionBatchStatus,
    ScanStartMode,
    SetupConfidence,
)
from src.core.services.risk_intelligence_ingestion_service import create_ingestion_batch
from src.core.services.risk_intelligence_normalization_service import (
    NormalizedAssetContextSummary,
    NormalizedFindingSummary,
    NormalizationResult,
    normalize_ingestion_batch,
)


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


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=7,
        organization_id=1,
        email="operator@risklence.test",
        roles=["ciso"],
        permissions=[],
    )


def _batch_payload() -> dict[str, object]:
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


def _create_batch(db: Session, *, source_name: str = "telia_full_report.json") -> RiskIngestionBatch:
    return create_ingestion_batch(
        db,
        organization_id=1,
        actor_user_id=7,
        source_name=source_name,
        collector_profile="subfinder_amass_nmap_nuclei",
        raw_payload=_batch_payload(),
        file_name=source_name,
    )


def test_normalize_ingestion_batch_creates_signal_finding_and_business_context(db: Session):
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

    batch = _create_batch(db)
    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    assert result.ingestion_batch_id == batch.id
    assert result.batch_status == RiskIngestionBatchStatus.NEEDS_REVIEW
    assert result.signal_count == 1
    assert result.finding_count == 1
    assert result.matched_asset_ids == [asset.id]
    assert result.created_asset_ids == []
    assert result.human_decision_required is True
    assert result.business_contexts[0].asset_name == "api.example.com"
    assert result.business_contexts[0].linked_service_names == ["Customer API", "Public Checkout"]
    assert result.business_contexts[0].crown_jewel_candidate is True
    assert result.business_contexts[0].blast_radius_mission_critical_count == 2

    stored_batch = db.get(RiskIngestionBatch, batch.id)
    assert stored_batch is not None
    assert stored_batch.status == RiskIngestionBatchStatus.NEEDS_REVIEW
    stored_signal = db.query(AssetEvidenceSignal).filter(AssetEvidenceSignal.asset_id == asset.id).one()
    assert stored_signal.payload_json["ingestionBatchId"] == batch.id
    assert stored_signal.payload_json["asset"]["assetId"] == asset.id
    stored_finding = db.query(AssetFinding).filter(AssetFinding.asset_id == asset.id).one()
    assert stored_finding.status == AssetFindingStatus.NEEDS_REVIEW
    assert stored_finding.evidence_refs[0] == f"ingestion-batch:{batch.id}"
    refreshed_asset = db.get(Asset, asset.id)
    assert refreshed_asset is not None
    assert refreshed_asset.status == AssetStatus.AT_RISK
    assert refreshed_asset.findings_count == 1


def test_normalize_ingestion_batch_creates_missing_asset(db: Session):
    batch = _create_batch(db, source_name="collector_bundle.json")

    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    assert result.created_asset_ids
    created_asset_id = result.created_asset_ids[0]
    created_asset = db.get(Asset, created_asset_id)
    assert created_asset is not None
    assert created_asset.display_name == "api.example.com"
    assert result.business_contexts[0].created is True
    assert result.business_contexts[0].matched_by == "created"


def test_normalize_ingestion_batch_creates_asset_with_real_identity_key(db: Session):
    """Step 4.1A: dedup must never rely on display_name alone — a newly
    created asset must carry a real canonical_identity_key derived from a
    strong signal (hostname here), not a null/absent one."""
    batch = _create_batch(db, source_name="collector_bundle.json")

    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    created_asset = db.get(Asset, result.created_asset_ids[0])
    assert created_asset is not None
    assert created_asset.canonical_identity_key is not None
    assert created_asset.lifecycle_state == AssetLifecycleState.ACTIVE


def test_normalize_ingestion_batch_is_idempotent_on_replay(db: Session):
    """Step 4.1A acceptance criterion: processing the same Collector
    payload twice must not create duplicate artefacts or signals."""
    batch = _create_batch(db, source_name="collector_bundle.json")

    first = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)
    second = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    assert second.created_asset_ids == []
    assert second.matched_asset_ids == first.created_asset_ids
    assert second.signal_count == 0
    assert second.finding_count == 0
    assert db.query(Asset).filter(Asset.organization_id == 1).count() == 1
    assert db.query(AssetEvidenceSignal).filter(AssetEvidenceSignal.organization_id == 1).count() == 1


def test_normalize_ingestion_batch_classifies_observation_with_findings_as_vulnerability(db: Session):
    """Step 4.1B: a signal carrying findings must be classified as the
    most significant fact present (a finding outranks a bare service)."""
    batch = _create_batch(db, source_name="collector_bundle.json")

    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    signal = db.query(AssetEvidenceSignal).filter(AssetEvidenceSignal.asset_id == result.created_asset_ids[0]).one()
    assert signal.observation_type == TechnicalObservationType.VULNERABILITY_OBSERVED.value
    assert signal.status == TechnicalObservationStatus.OBSERVED.value
    assert signal.severity == "high"


def test_normalize_ingestion_batch_classifies_bare_host_as_reachable_with_no_severity(db: Session):
    """Step 4.1B: a signal with neither services nor findings must not
    fabricate a severity — None means no comparison was possible."""
    batch = create_ingestion_batch(
        db,
        organization_id=1,
        actor_user_id=7,
        source_name="bare_host.json",
        collector_profile="subfinder_amass_nmap_nuclei",
        raw_payload={"hosts": [{"hostname": "quiet-host.example.com"}]},
        file_name="bare_host.json",
    )

    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    signal = db.query(AssetEvidenceSignal).filter(AssetEvidenceSignal.asset_id == result.created_asset_ids[0]).one()
    assert signal.observation_type == TechnicalObservationType.HOST_REACHABLE.value
    assert signal.severity is None


def test_normalize_ingestion_batch_never_overwrites_prior_observations(db: Session):
    """Step 4.1B acceptance criterion: historical observations must never
    be overwritten — a second, genuinely new batch about the same asset
    appends a new signal rather than mutating the first one."""
    first_batch = create_ingestion_batch(
        db,
        organization_id=1,
        actor_user_id=7,
        source_name="first_scan.json",
        collector_profile="subfinder_amass_nmap_nuclei",
        raw_payload={"hosts": [{"hostname": "recurring-host.example.com"}]},
        file_name="first_scan.json",
    )
    first_result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=first_batch.id)
    first_signal_id = (
        db.query(AssetEvidenceSignal).filter(AssetEvidenceSignal.asset_id == first_result.created_asset_ids[0]).one().id
    )

    second_batch = create_ingestion_batch(
        db,
        organization_id=1,
        actor_user_id=7,
        source_name="second_scan.json",
        collector_profile="subfinder_amass_nmap_nuclei",
        raw_payload={
            "hosts": [
                {
                    "hostname": "recurring-host.example.com",
                    "findings": [{"id": "new-finding", "severity": "critical", "title": "New critical finding"}],
                }
            ]
        },
        file_name="second_scan.json",
    )
    second_result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=second_batch.id)

    assert second_result.matched_asset_ids == first_result.created_asset_ids
    assert second_result.created_asset_ids == []

    original_signal = db.get(AssetEvidenceSignal, first_signal_id)
    assert original_signal is not None
    assert original_signal.observation_type == TechnicalObservationType.HOST_REACHABLE.value

    all_signals = (
        db.query(AssetEvidenceSignal).filter(AssetEvidenceSignal.asset_id == first_result.created_asset_ids[0]).all()
    )
    assert len(all_signals) == 2
    assert any(signal.observation_type == TechnicalObservationType.VULNERABILITY_OBSERVED.value for signal in all_signals)


def test_normalize_batch_route_returns_summary(monkeypatch):
    batch = RiskIngestionBatch(
        id=21,
        organization_id=1,
        source_name="telia_full_report.json",
        collector_profile="subfinder_amass_nmap_nuclei",
        file_name="telia_full_report.json",
        content_type="application/json",
        payload_checksum="d" * 64,
        raw_payload=_batch_payload(),
        raw_payload_size_bytes=256,
        status=RiskIngestionBatchStatus.RECEIVED,
        received_at=datetime(2026, 5, 13, 8, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 5, 13, 8, 5, tzinfo=timezone.utc),
    )
    result = NormalizationResult(
        ingestion_batch_id=batch.id,
        organization_id=1,
        batch_status=RiskIngestionBatchStatus.NEEDS_REVIEW,
        normalized_at=datetime(2026, 5, 13, 8, 10, tzinfo=timezone.utc),
        technical_summary="Normalized 1 host observation.",
        human_decision_required=True,
        signal_count=1,
        finding_count=1,
        matched_asset_ids=[11],
        created_asset_ids=[],
        business_contexts=[
            NormalizedAssetContextSummary(
                asset_id=11,
                asset_name="api.example.com",
                matched_by="matched:api.example.com",
                created=False,
                linked_service_names=["Customer API"],
                linked_process_names=[],
                crown_jewel_candidate=True,
                blast_radius_service_count=1,
                blast_radius_mission_critical_count=1,
                has_financial_exposure=True,
            )
        ],
        findings=[
            NormalizedFindingSummary(
                finding_id=99,
                asset_id=11,
                severity="high",
                title="Outdated TLS configuration",
                status="needs_review",
                evidence_refs=["ingestion-batch:21"],
                risk_score=80.0,
            )
        ],
    )

    monkeypatch.setattr(ingestion_routes, "normalize_ingestion_batch", lambda *args, **kwargs: result)

    response = ingestion_routes.normalize_batch(batch_id=21, ctx=_ctx(), db=object())

    assert response.ingestionBatchId == 21
    assert response.batchStatus == RiskIngestionBatchStatus.NEEDS_REVIEW.value
    assert response.signalCount == 1
    assert response.findingCount == 1
    assert response.businessContexts[0].assetName == "api.example.com"
    assert response.findings[0].findingId == 99


def test_normalize_batch_route_propagates_missing_batch(monkeypatch):
    from src.core.exceptions import ResourceNotFoundError

    monkeypatch.setattr(
        ingestion_routes,
        "normalize_ingestion_batch",
        lambda *args, **kwargs: (_ for _ in ()).throw(ResourceNotFoundError("Ingestion batch not found")),
    )

    with pytest.raises(ResourceNotFoundError):
        ingestion_routes.normalize_batch(batch_id=999, ctx=_ctx(), db=object())


# ---------------------------------------------------------------------------
# CA-06.1 — repeated observation across runs, end to end through normalization
# ---------------------------------------------------------------------------


def _host_batch(db: Session, *, source_name: str, host: dict[str, object]) -> RiskIngestionBatch:
    return create_ingestion_batch(
        db,
        organization_id=1,
        actor_user_id=7,
        source_name=source_name,
        collector_profile="subfinder_amass_nmap_nuclei",
        raw_payload={"hosts": [host]},
        file_name=source_name,
    )


def test_a_rescan_after_the_ip_moved_updates_the_artefact_instead_of_duplicating_it(db: Session):
    """CA-06's own exit criterion: repeated scans update stable artefacts. The
    hostname is unchanged, so this is the same machine on a new lease."""
    first = _host_batch(
        db, source_name="run-1.json", host={"hostname": "api.example.com", "ip": "10.0.0.5"}
    )
    first_result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=first.id)

    second = _host_batch(
        db, source_name="run-2.json", host={"hostname": "api.example.com", "ip": "10.0.0.99"}
    )
    second_result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=second.id)

    assert second_result.created_asset_ids == []
    assert second_result.matched_asset_ids == first_result.created_asset_ids
    assert db.query(Asset).filter(Asset.organization_id == 1).count() == 1

    asset_id = first_result.created_asset_ids[0]
    addresses = {
        row.identifier_value
        for row in db.query(AssetIdentifier).filter(
            AssetIdentifier.asset_id == asset_id,
            AssetIdentifier.identifier_type == "ip_address",
        )
    }
    assert addresses == {"10.0.0.5", "10.0.0.99"}


def test_identifiers_record_which_source_observed_them(db: Session):
    batch = _host_batch(
        db, source_name="collector_bundle.json", host={"hostname": "api.example.com", "ip": "10.0.0.5"}
    )
    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    rows = db.query(AssetIdentifier).filter(AssetIdentifier.asset_id == result.created_asset_ids[0]).all()
    assert rows
    assert {row.observed_by_source for row in rows} == {"collector_bundle.json"}


def test_a_name_collision_alone_never_merges_two_artefacts(db: Session):
    """Regression: this used to merge. `resolve_identity` returns the record it
    is *unsure* about, and the caller treated any returned record as a match —
    so two unrelated things sharing a label silently became one artefact, with
    no trace that a judgement had been made."""
    existing = Asset(
        organization_id=1,
        type="Service",
        provider="internal",
        display_name="Checkout Service",
        layer="Application",
        environment=Environment.PROD,
        criticality=Criticality.MEDIUM,
        status=AssetStatus.PARTIALLY_OBSERVED,
        connectivity_status=ConnectivityStatus.PENDING_VERIFICATION,
        setup_confidence=SetupConfidence.LOW,
        scan_start_mode=ScanStartMode.AUDIT_ONLY,
        findings_count=0,
        risk_score=0.0,
        confidence=0.4,
        lifecycle_state=AssetLifecycleState.ACTIVE,
    )
    db.add(existing)
    db.flush()

    # No hostname, no IP — nothing but a label that happens to match.
    batch = _host_batch(db, source_name="run-1.json", host={"name": "Checkout Service"})
    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    assert result.created_asset_ids, "an uncertain match must not be absorbed into the existing row"
    created = db.get(Asset, result.created_asset_ids[0])
    assert created is not None
    assert created.id != existing.id
    # Flagged as needing a decision rather than presented as established fact.
    assert created.lifecycle_state == AssetLifecycleState.UNCONFIRMED
    assert created.intent["possibleDuplicateOfAssetIds"] == [existing.id]
    assert created.intent["possibleDuplicateReason"]


def test_a_hand_uploaded_batch_records_no_provenance_rather_than_inventing_it(db: Session):
    """CA-06.2: absent references read as absent. A batch someone uploaded by
    hand has no evidence package, no job and no Collector — and the row must
    still be perfectly readable."""
    batch = _create_batch(db, source_name="manual_upload.json")
    assert batch.evidence_package_id is None

    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    signal = (
        db.query(AssetEvidenceSignal)
        .filter(AssetEvidenceSignal.asset_id == result.created_asset_ids[0])
        .one()
    )
    assert signal.evidence_package_id is None
    assert signal.provider_execution_id is None
    assert signal.scanner_instance_id is None
    # Still a complete observation in every other respect.
    assert signal.observation_type is not None
    assert signal.payload_json["ingestionBatchId"] == batch.id


def test_a_replayed_batch_still_advances_the_ports_last_seen_date(db: Session):
    """A replay writes no new signal — but the ports it reports were observed
    again, and that is exactly what last_seen_at is for."""
    batch = _create_batch(db, source_name="collector_bundle.json")
    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)
    asset_id = result.created_asset_ids[0]

    port = db.query(AssetObservedPort).filter(AssetObservedPort.asset_id == asset_id).one()
    assert port.port == 443
    first_seen = port.first_seen_at
    original_last_seen = port.last_seen_at

    replay = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)
    assert replay.signal_count == 0

    db.refresh(port)
    assert port.first_seen_at == first_seen
    assert port.last_seen_at >= original_last_seen
    assert db.query(AssetObservedPort).filter(AssetObservedPort.asset_id == asset_id).count() == 1


# --- CA-07.1 / #249: identity is re-read on every re-observation -------------


def test_a_later_scan_that_finds_a_service_replaces_nothing_answered(db: Session):
    """The defect, from a real inventory (Søren, 2026-08-25): 192.168.1.20 had
    an open HTTP proxy port and its row still read "Nothing answered on this
    address, so there was nothing to identify it by." The artefact was created
    by a sweep that found nothing, and identity was written once at creation and
    never again — so the later scan updated the classification, the type and the
    layer, and left the identity frozen at the first run's verdict."""
    first = _host_batch(db, source_name="sweep.json", host={"hostname": "api.example.com", "ip": "10.0.0.5"})
    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=first.id)
    asset = db.query(Asset).filter(Asset.id == result.created_asset_ids[0]).one()
    assert asset.intent["identity"]["undeterminedReason"] == "nothing_listening"

    second = _host_batch(
        db,
        source_name="deep.json",
        host={
            "hostname": "api.example.com",
            "ip": "10.0.0.5",
            "services": [{"port": 443, "service": "https", "product": "nginx", "version": "1.24.0"}],
            "fingerprinting_ran": True,
        },
    )
    normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=second.id)

    db.refresh(asset)
    assert asset.intent["identity"]["name"] == "nginx 1.24.0"
    assert asset.intent["identity"]["basis"] == "service_product"
    assert asset.intent["identity"]["undeterminedReason"] is None


def test_a_shallower_rescan_does_not_take_away_a_name_already_determined(db: Session):
    """A safe-discovery sweep that skips version detection is not evidence that
    yesterday's deep scan was wrong. Only a run that determines something may
    overwrite something."""
    first = _host_batch(
        db,
        source_name="deep.json",
        host={
            "hostname": "api.example.com",
            "ip": "10.0.0.5",
            "services": [{"port": 443, "service": "https", "product": "nginx", "version": "1.24.0"}],
            "fingerprinting_ran": True,
        },
    )
    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=first.id)
    asset = db.query(Asset).filter(Asset.id == result.created_asset_ids[0]).one()

    second = _host_batch(db, source_name="sweep.json", host={"hostname": "api.example.com", "ip": "10.0.0.5"})
    normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=second.id)

    db.refresh(asset)
    assert asset.intent["identity"]["name"] == "nginx 1.24.0"


def test_a_row_named_from_a_rejected_title_recovers_on_the_next_scan(db: Session):
    """Two artefacts on the live inventory were *named* "Site doesn't have a
    title (text/html)" — nmap reporting the absence of a title, stored as the
    row's name. Fixing the filter stops it happening again; this is what lets
    the rows already carrying it recover rather than keeping it for ever."""
    junk = "Site doesn't have a title (text/html)"
    first = _host_batch(
        db,
        source_name="first.json",
        host={
            "ip": "10.0.0.7",
            "services": [{"port": 8080, "service": "http-proxy", "scripts": {"http-title": junk}}],
            "fingerprinting_ran": True,
        },
    )
    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=first.id)
    asset = db.query(Asset).filter(Asset.id == result.created_asset_ids[0]).one()
    # The filter already refuses it, so it never became the name in the first place.
    assert asset.display_name == "10.0.0.7"

    second = _host_batch(
        db,
        source_name="second.json",
        host={
            "ip": "10.0.0.7",
            "services": [{"port": 8080, "service": "http-proxy", "product": "Uvicorn"}],
            "fingerprinting_ran": True,
        },
    )
    normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=second.id)

    db.refresh(asset)
    assert asset.display_name == "Uvicorn"
    assert asset.intent["identity"]["name"] == "Uvicorn"


def test_a_bad_name_is_withdrawn_by_a_scan_that_looked_and_found_nothing(db: Session):
    """The hole in "never lose a name to a shallower look": it would also have
    protected the bad names this work exists to remove. A run that genuinely
    probed and determined nothing is evidence, and it clears the stale name."""
    junk = "Site doesn't have a title (text/html)"
    first = _host_batch(
        db,
        source_name="first.json",
        host={"hostname": "box.example.com", "ip": "10.0.0.8"},
    )
    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=first.id)
    asset = db.query(Asset).filter(Asset.id == result.created_asset_ids[0]).one()

    # Put the artefact into the exact state found on the live inventory: named
    # after nmap's report that there is no name.
    asset.display_name = junk
    asset.intent = {**asset.intent, "identity": {"name": junk, "basis": "http_title", "undeterminedReason": None}}
    db.add(asset)
    db.flush()

    second = _host_batch(
        db,
        source_name="second.json",
        host={
            "hostname": "box.example.com",
            "ip": "10.0.0.8",
            "services": [{"port": 8080, "service": "http-proxy", "method": "probed"}],
            "fingerprinting_ran": True,
        },
    )
    normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=second.id)

    db.refresh(asset)
    assert asset.intent["identity"]["name"] is None
    assert asset.intent["identity"]["undeterminedReason"] == "probed_nothing_identifying"
    # The row's title falls back down the ladder — to the name the organisation
    # already had for it, which outranks anything a scan concluded.
    assert asset.display_name == "box.example.com"


def test_a_port_nmap_only_looked_up_is_stored_as_a_lookup(db: Session):
    """#249. `observedServices` is a list of nmap's words with no way to tell a
    finding from a guess: `http-proxy` is nmap restating "port 8080" from its
    static table, and it reached the reviewer looking exactly like `https` on a
    port that answered and identified itself."""
    batch = _host_batch(
        db,
        source_name="deep.json",
        host={
            "ip": "10.0.0.9",
            "services": [
                {"port": 8080, "service": "http-proxy", "method": "table"},
                {"port": 443, "service": "https", "method": "probed"},
            ],
            "fingerprinting_ran": True,
        },
    )
    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)
    asset = db.query(Asset).filter(Asset.id == result.created_asset_ids[0]).one()

    assert asset.intent["observedServiceEvidence"] == [
        {"name": "http-proxy", "port": 8080, "probed": False},
        {"name": "https", "port": 443, "probed": True},
    ]
    # The de-duplicated name list is unchanged. Older rows carry only that, and
    # the reading side still falls back to it.
    assert asset.intent["observedServices"] == ["http-proxy", "https"]


def test_a_rescan_replaces_the_evidence_it_re_observed(db: Session):
    """A port that was only looked up last time and probed this time is a
    stronger claim than before, and the row must say the stronger thing."""
    first = _host_batch(
        db,
        source_name="sweep.json",
        host={
            "hostname": "api.example.com",
            "ip": "10.0.0.5",
            "services": [{"port": 443, "service": "https", "method": "table"}],
        },
    )
    created = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=first.id)
    asset = db.query(Asset).filter(Asset.id == created.created_asset_ids[0]).one()
    assert asset.intent["observedServiceEvidence"] == [
        {"name": "https", "port": 443, "probed": False}
    ]

    second = _host_batch(
        db,
        source_name="deep.json",
        host={
            "hostname": "api.example.com",
            "ip": "10.0.0.5",
            "services": [{"port": 443, "service": "https", "method": "probed"}],
            "fingerprinting_ran": True,
        },
    )
    normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=second.id)

    db.refresh(asset)
    assert asset.intent["observedServiceEvidence"] == [
        {"name": "https", "port": 443, "probed": True}
    ]


# ── #323 — an address field that held a hostname ────────────────────────────


def test_the_recorded_address_is_an_address_not_whatever_the_host_called_itself(db: Session):
    """The row that contradicted itself, from the live estate (2026-08-27).

    A device announcing `iPad` was stored with `display_name="iPad"` **and**
    `networkAddress="iPad"`, because this field was written from `_host_label`,
    which searches names before addresses — it is the better handle for identity
    matching, and the wrong answer to "where does this live?".

    The surfaces read `display_name == network_address` as *"the name is only
    the address wearing a name's clothes"* and fell through to the honest
    fallback, so the row was titled **"Unidentified device"** while showing
    `iPad` on a chip beside it. Two fields disagreeing made the page tell the
    reader the platform could not see what they could.
    """
    batch = _host_batch(
        db, source_name="scan.json", host={"hostname": "iPad", "ip": "192.168.50.129"}
    )
    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)
    asset = db.query(Asset).filter(Asset.id == result.created_asset_ids[0]).one()

    assert asset.intent["networkAddress"] == "192.168.50.129"
    assert asset.display_name == "iPad"
    # The pair the surfaces compare. Equal is what broke it.
    assert asset.display_name != asset.intent["networkAddress"]


def test_a_host_with_no_address_still_records_where_it_was_seen(db: Session):
    """Subfinder returns names without addresses. Falling back to the label is
    better than storing nothing: a reviewer still needs some answer to "where",
    and an empty field would send them looking for one that was never taken."""
    batch = _host_batch(db, source_name="subfinder.json", host={"hostname": "api.example.com"})
    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)
    asset = db.query(Asset).filter(Asset.id == result.created_asset_ids[0]).one()

    assert asset.intent["networkAddress"] == "api.example.com"


def test_a_rescan_corrects_an_address_recorded_before_the_field_meant_an_address(db: Session):
    """The half that makes the fix reach the estate. `networkAddress` was
    written once at creation and never again, so every artefact already carrying
    the hostname-as-address would have kept it forever, however many times it
    was rescanned.

    It is also simply true of addresses: they move. A value frozen at first
    sight becomes a claim about where something *used* to be."""
    first = _host_batch(db, source_name="a.json", host={"hostname": "iPad", "ip": "192.168.50.129"})
    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=first.id)
    asset = db.query(Asset).filter(Asset.id == result.created_asset_ids[0]).one()
    # Simulate the estate as it stands: the old value, written by the old rule.
    asset.intent = {**asset.intent, "networkAddress": "iPad"}
    db.add(asset)
    db.commit()

    second = _host_batch(db, source_name="b.json", host={"hostname": "iPad", "ip": "192.168.50.129"})
    normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=second.id)

    db.refresh(asset)
    assert asset.intent["networkAddress"] == "192.168.50.129"


# --- A vulnerability scan must not mint artefacts ----------------------------
#
# 🐞 Every nuclei run used to create a duplicate artefact and an identity
# conflict for each host it scanned. Søren resolved six by hand after one scan of
# one small network — and the merges then stranded 22 of 25 findings on the
# tombstones. On a 500-host estate that is unusable.
#
# Two causes: the parser wrote the address into the `hostname` slot, making it a
# strong identifier nothing carried; and normalisation created a row when
# resolution came back short. A vulnerability scan is pointed at hosts discovery
# already found, so it can say what is wrong with something on record — never
# that something exists.


def _vuln_payload(address: str = "192.168.50.152") -> dict[str, object]:
    """The shape `_parse_nuclei_jsonl` produces for an address target."""
    return {
        "hosts": [
            {
                "hostname": None,
                "ip": address,
                "services": [],
                "establishesIdentity": False,
                "findings": [
                    {
                        "id": "ssh-sha1-hmac",
                        "severity": "info",
                        "title": "SSH SHA-1 HMAC Algorithms Enabled",
                        "description": None,
                    }
                ],
            }
        ]
    }


def _vuln_batch(db: Session, address: str = "192.168.50.152") -> RiskIngestionBatch:
    return create_ingestion_batch(
        db,
        organization_id=1,
        actor_user_id=7,
        source_name="discovery_execution:nuclei",
        collector_profile="discovery_execution_pipeline",
        raw_payload=_vuln_payload(address),
        file_name=None,
    )


def _named_host(db: Session, *, display_name: str = "pi-local", address: str = "192.168.50.152") -> Asset:
    """What discovery already established: a host with a real name, seen at an
    address."""
    asset = Asset(
        organization_id=1,
        type="Service",
        provider="internal",
        display_name=display_name,
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
    )
    db.add(asset)
    db.flush()
    db.add(
        AssetIdentifier(
            organization_id=1,
            asset_id=asset.id,
            identifier_type="ip_address",
            identifier_value=address,
            observed_by_source="discovery_execution:nmap",
            first_seen_at=utcnow(),
            last_seen_at=utcnow(),
        )
    )
    db.commit()
    return asset


def test_a_scan_of_a_known_host_creates_no_second_artefact(db: Session):
    """The whole point. The address came *from* this artefact's own record —
    the scan went there because discovery had already found it — so matching
    back is a return to source, not a guess about two strangers."""
    known = _named_host(db)
    before = db.query(Asset).count()
    batch = _vuln_batch(db)

    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    assert db.query(Asset).count() == before, "a vulnerability scan must not mint an artefact"
    assert result.created_asset_ids == []
    assert result.matched_asset_ids == [known.id]


def test_the_finding_lands_on_the_host_that_was_already_on_record(db: Session):
    known = _named_host(db)
    batch = _vuln_batch(db)

    normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    findings = db.query(AssetFinding).filter(AssetFinding.asset_id == known.id).all()
    assert [f.title for f in findings] == ["SSH SHA-1 HMAC Algorithms Enabled"]


def test_scanning_the_same_host_twice_still_creates_no_artefact(db: Session):
    """The bug compounded on every run. Six conflicts came from one scan."""
    _named_host(db)
    before = db.query(Asset).count()

    for _ in range(2):
        batch = _vuln_batch(db)
        normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    assert db.query(Asset).count() == before


def test_a_finding_for_a_host_nobody_has_on_record_is_skipped_not_invented(db: Session):
    """Inventing inventory from a vulnerability match is the fabrication
    BUG-DISC-14 removed from two other paths. The scan was sent to an address
    the platform chose from its own artefacts, so not finding it again is a
    discrepancy — skipped and logged, never a new row."""
    before = db.query(Asset).count()
    batch = _vuln_batch(db, address="10.99.99.99")

    result = normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    assert db.query(Asset).count() == before
    assert result.created_asset_ids == []
    assert db.query(AssetFinding).count() == 0


def test_one_unknown_host_does_not_cost_the_batch_its_other_findings(db: Session):
    """Per-item isolation, the same rule the normalisation hand-off and the scan
    runner both keep."""
    known = _named_host(db)
    payload = _vuln_payload()
    payload["hosts"].append(
        {
            "hostname": None,
            "ip": "10.99.99.99",
            "services": [],
            "establishesIdentity": False,
            "findings": [{"id": "x", "severity": "info", "title": "Orphaned", "description": None}],
        }
    )
    batch = create_ingestion_batch(
        db,
        organization_id=1,
        actor_user_id=7,
        source_name="discovery_execution:nuclei",
        collector_profile="discovery_execution_pipeline",
        raw_payload=payload,
        file_name=None,
    )

    normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    titles = {f.title for f in db.query(AssetFinding).filter(AssetFinding.asset_id == known.id)}
    assert titles == {"SSH SHA-1 HMAC Algorithms Enabled"}
    assert db.query(AssetFinding).count() == 1


def test_a_discovery_observation_still_creates_the_artefact_it_found(db: Session):
    """The guard is about vulnerability evidence only. nmap and subfinder carry
    no `establishesIdentity` flag and must keep discovering — narrowing them
    would make discovery incapable of discovering."""
    before = db.query(Asset).count()
    batch = _create_batch(db)

    normalize_ingestion_batch(db, organization_id=1, actor_user_id=7, batch_id=batch.id)

    assert db.query(Asset).count() > before
