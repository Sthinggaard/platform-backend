import pytest
import time

from sqlalchemy.orm import Session, sessionmaker

from src.asset_monitoring.engine import AssetMonitoringEngine
from src.asset_monitoring.service import (
    connect_asset,
    disconnect_asset,
    ensure_seed_org,
    evaluate_control_coverage,
    seed_assets,
    seed_controls,
)
from src.core.models import Asset, AssetStatus, ControlCoverageStatus


@pytest.mark.unreconciled
def test_connect_and_disconnect(db_session: Session, sample_organization) -> None:
    seed_assets(db_session, sample_organization.id)
    asset = db_session.query(Asset).filter(Asset.organization_id == sample_organization.id).first()
    assert asset

    connect_asset(db_session, asset.id, auth_type="mock", scopes=["read"], external_account_id="demo")
    db_session.refresh(asset)
    assert asset.status == AssetStatus.PARTIALLY_OBSERVED
    assert asset.connections[0].state == "CONNECTED"

    disconnect_asset(db_session, asset.id)
    db_session.refresh(asset)
    assert asset.status == AssetStatus.NOT_CONNECTED
    assert asset.findings_count == 0


@pytest.mark.unreconciled
def test_monitoring_engine_initial_probe(test_engine) -> None:
    session_factory = sessionmaker(bind=test_engine)
    with session_factory() as session:
        org = ensure_seed_org(session)
        assets = seed_assets(session, org.id)
        network_asset_id = next(a.id for a in assets if a.layer.lower() == "network")
        connect_asset(session, network_asset_id, auth_type="mock", scopes=None, external_account_id=None)
        session.commit()

    engine = AssetMonitoringEngine(session_factory, interval_seconds=0.2, seed=42)
    engine.enqueue_initial_observation(network_asset_id, delay_seconds=0.1)
    time.sleep(0.35)
    engine.stop()

    with session_factory() as session:
        refreshed = session.get(Asset, network_asset_id)
        assert refreshed.status in {AssetStatus.AT_RISK, AssetStatus.OPERATIONALLY_COMPLIANT}
        assert refreshed.last_observed_at is not None


@pytest.mark.unreconciled
def test_control_evidence_evaluates(db_session: Session, sample_organization) -> None:
    seed_assets(db_session, sample_organization.id)
    seed_controls(db_session)
    evidences = evaluate_control_coverage(db_session, sample_organization.id)
    assert evidences
    # Evidence statuses should be set to one of the coverage enums
    assert all(ev.status in ControlCoverageStatus for ev in evidences)
