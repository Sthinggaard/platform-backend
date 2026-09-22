"""BUG-DISC-18 — retention for the evidence store.

The table had no policy and no cap and reached 14.5 million rows behind 84
assets. The rules that matter here are the ones that decide what is *not*
deleted: evidence outlives telemetry, and an artefact never outlives its own
justification.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.database import Base
from src.core.model_defs.assets_runtime import (
    Asset,
    AssetEvidenceSignal,
    AssetStatus,
    ConnectivityStatus,
    Criticality,
    Environment,
    ScanStartMode,
    SetupConfidence,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.tenant_org import Organization
from src.core.services.signal_retention_service import (
    EVIDENCE_BEARING_KINDS,
    SIMULATED_KINDS,
    prune_expired_signals,
    retention_days_for,
    summarise_signal_volume,
)

EVIDENCE_KIND = "risk_intelligence_ingestion"
SIMULATED_KIND = "health"


@pytest.fixture(scope="function")
def db():
    engine = create_engine("sqlite:///:memory:")
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine)
    session.add(Organization(id=1, name="Org One", slug="org-one"))
    session.commit()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


def _asset(db: Session, name: str = "192.168.1.1") -> Asset:
    asset = Asset(
        organization_id=1,
        type="Service",
        provider="collector",
        display_name=name,
        layer="L1",
        environment=Environment.PROD,
        criticality=Criticality.MEDIUM,
        status=AssetStatus.PARTIALLY_OBSERVED,
        connectivity_status=ConnectivityStatus.PENDING_VERIFICATION,
        setup_confidence=SetupConfidence.LOW,
        scan_start_mode=ScanStartMode.AUDIT_ONLY,
        findings_count=0,
        risk_score=0.0,
        confidence=0.4,
    )
    db.add(asset)
    db.flush()
    return asset


def _signal(db: Session, asset: Asset, *, kind: str, age_days: int) -> AssetEvidenceSignal:
    signal = AssetEvidenceSignal(
        organization_id=asset.organization_id,
        asset_id=asset.id,
        kind=kind,
        payload_json={"n": age_days},
        observed_at=utcnow() - timedelta(days=age_days),
        confidence=0.5,
        risk_score=1.0,
    )
    db.add(signal)
    db.flush()
    return signal


class TestPolicy:
    def test_telemetry_has_a_far_shorter_horizon_than_evidence(self):
        assert retention_days_for(SIMULATED_KIND) < retention_days_for(EVIDENCE_KIND)

    def test_an_unrecognised_kind_is_treated_as_evidence(self):
        # The safe default: an unknown kind is likelier to be new evidence than
        # new noise, and wrongly keeping data is recoverable while wrongly
        # deleting it is not.
        assert retention_days_for("something_new_next_year") == retention_days_for(EVIDENCE_KIND)

    def test_the_two_taxonomies_do_not_overlap(self):
        # A kind in both would be pruned on whichever horizon happened to win.
        assert not (EVIDENCE_BEARING_KINDS & SIMULATED_KINDS)


class TestPrune:
    def test_expired_telemetry_is_removed(self, db: Session):
        asset = _asset(db)
        _signal(db, asset, kind=SIMULATED_KIND, age_days=400)

        outcome = prune_expired_signals(db)

        assert outcome.total_deleted == 1
        assert db.query(AssetEvidenceSignal).count() == 0

    def test_recent_telemetry_is_left_alone(self, db: Session):
        asset = _asset(db)
        _signal(db, asset, kind=SIMULATED_KIND, age_days=1)

        prune_expired_signals(db)

        assert db.query(AssetEvidenceSignal).count() == 1

    def test_evidence_survives_the_telemetry_horizon(self, db: Session):
        # 400 days is long past the telemetry cutoff and well inside the
        # evidence one — the whole point of a per-kind policy.
        asset = _asset(db)
        _signal(db, asset, kind=EVIDENCE_KIND, age_days=400)

        prune_expired_signals(db)

        assert db.query(AssetEvidenceSignal).count() == 1

    def test_an_artefact_never_outlives_its_own_last_evidence(self, db: Session):
        # Even at an age far past every horizon. An artefact asserting something
        # with nothing on record behind it is worse than a larger table: an
        # auditor asking "on what basis?" would get silence.
        asset = _asset(db)
        _signal(db, asset, kind=EVIDENCE_KIND, age_days=5_000)

        outcome = prune_expired_signals(db)

        assert outcome.total_deleted == 0
        assert outcome.protected_as_last_evidence == 1
        assert db.query(AssetEvidenceSignal).count() == 1

    def test_only_the_last_evidence_is_protected_not_all_of_it(self, db: Session):
        asset = _asset(db)
        _signal(db, asset, kind=EVIDENCE_KIND, age_days=5_000)
        _signal(db, asset, kind=EVIDENCE_KIND, age_days=4_999)
        newest = _signal(db, asset, kind=EVIDENCE_KIND, age_days=4_998)

        prune_expired_signals(db)

        remaining = db.query(AssetEvidenceSignal).all()
        assert [s.id for s in remaining] == [newest.id]

    def test_every_asset_keeps_its_own_last_evidence(self, db: Session):
        # Protection is per artefact, not one row for the whole table.
        first, second = _asset(db, "10.0.0.1"), _asset(db, "10.0.0.2")
        _signal(db, first, kind=EVIDENCE_KIND, age_days=5_000)
        _signal(db, second, kind=EVIDENCE_KIND, age_days=5_000)

        outcome = prune_expired_signals(db)

        assert outcome.protected_as_last_evidence == 2
        assert db.query(AssetEvidenceSignal).count() == 2

    def test_protection_does_not_extend_to_telemetry(self, db: Session):
        # A heartbeat is not a justification, so the newest one is not sacred.
        asset = _asset(db)
        _signal(db, asset, kind=SIMULATED_KIND, age_days=400)

        prune_expired_signals(db)

        assert db.query(AssetEvidenceSignal).count() == 0

    def test_a_prune_larger_than_one_batch_removes_everything(self, db: Session):
        # The loop must keep going past the first page. A single pass would
        # leave most of a 14-million-row table behind and look like it worked.
        asset = _asset(db)
        for age in range(400, 412):
            _signal(db, asset, kind=SIMULATED_KIND, age_days=age)

        outcome = prune_expired_signals(db, batch_size=5)

        assert outcome.total_deleted == 12
        assert db.query(AssetEvidenceSignal).count() == 0

    def test_a_page_full_of_protected_rows_does_not_stop_the_prune(self, db: Session):
        # The bug this guards: filtering protected rows out *after* the LIMIT
        # returns an empty batch as soon as one page is entirely protected, and
        # the prune stops with expired rows still behind it. Here the protected
        # evidence sorts first by id, so a naive implementation deletes nothing.
        asset = _asset(db)
        _signal(db, asset, kind=EVIDENCE_KIND, age_days=5_000)
        for age in range(400, 405):
            _signal(db, asset, kind=SIMULATED_KIND, age_days=age)

        outcome = prune_expired_signals(db, batch_size=1)

        assert outcome.total_deleted == 5
        assert db.query(AssetEvidenceSignal).count() == 1

    def test_overrides_can_lengthen_a_horizon_for_a_stricter_regulator(self, db: Session):
        asset = _asset(db)
        _signal(db, asset, kind=SIMULATED_KIND, age_days=400)

        prune_expired_signals(db, overrides={SIMULATED_KIND: 3_650})

        assert db.query(AssetEvidenceSignal).count() == 1

    def test_an_empty_store_is_not_an_error(self, db: Session):
        outcome = prune_expired_signals(db)

        assert outcome.total_deleted == 0


class TestObservability:
    def test_volume_is_reported_per_kind_heaviest_first(self, db: Session):
        asset = _asset(db)
        _signal(db, asset, kind=EVIDENCE_KIND, age_days=1)
        for age in range(3):
            _signal(db, asset, kind=SIMULATED_KIND, age_days=age)

        volumes = summarise_signal_volume(db)

        assert [(v.kind, v.rows) for v in volumes] == [(SIMULATED_KIND, 3), (EVIDENCE_KIND, 1)]

    def test_volume_reports_the_age_span_so_growth_is_visible(self, db: Session):
        asset = _asset(db)
        _signal(db, asset, kind=SIMULATED_KIND, age_days=10)
        _signal(db, asset, kind=SIMULATED_KIND, age_days=1)

        volume = summarise_signal_volume(db)[0]

        assert volume.oldest is not None and volume.newest is not None
        assert volume.oldest < volume.newest


class TestSimulatorIsNotEvidence:
    """The root cause. 14.5M of the 14.5M rows were fabricated by
    ``AssetMonitoringEngine``, which defaulted to on and which nothing anywhere
    turned off."""

    def test_the_simulator_is_off_unless_someone_asks_for_it(self):
        from src.core.config import MonitoringSettings

        assert MonitoringSettings().enabled is False

    def test_production_can_never_run_the_simulator(self):
        # Belt and braces: configuration alone is not enough, because
        # configuration is exactly what was wrong. A deploy setting
        # MONITORING_ENABLED=true must still not put invented latency figures
        # in front of an auditor.
        from src.api.main import _SIMULATOR_PERMITTED_ENVIRONMENTS

        assert "production" not in _SIMULATOR_PERMITTED_ENVIRONMENTS
        assert "staging" not in _SIMULATOR_PERMITTED_ENVIRONMENTS
        assert "development" in _SIMULATOR_PERMITTED_ENVIRONMENTS

    def test_every_kind_the_simulator_writes_is_named_as_simulated(self):
        # So the purge script and the retention policy can both find them, and
        # so nothing ever reads one as evidence again.
        assert SIMULATED_KINDS == {"health", "network_scan", "identity_event"}
