"""CA-06.2 — what an observation records: the detail, and where it came from."""

from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.database import Base
from src.core.model_defs.assets_runtime import (
    Asset,
    AssetLifecycleState,
    AssetObservedPort,
    AssetStatus,
    ConnectivityStatus,
    Criticality,
    Environment,
    ScanStartMode,
    SetupConfidence,
)
from src.core.model_defs.tenant_org import Organization
from src.core.services.artefact_observation_service import (
    UNKNOWN_PROTOCOL,
    ObservedPort,
    extract_observed_ports,
    record_observed_ports,
)


@pytest.fixture(scope="function")
def db():
    engine = create_engine("sqlite:///:memory:")
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine)
    session.add_all(
        [
            Organization(
                id=org_id,
                name=f"Org {org_id}",
                slug=f"org-{org_id}",
                plan_tier="enterprise",
                subscription_status="active",
                onboarding_completed=False,
            )
            for org_id in (1, 2)
        ]
    )
    session.commit()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


def _make_asset(db: Session, *, organization_id: int = 1, display_name: str = "api.example.com") -> Asset:
    asset = Asset(
        organization_id=organization_id,
        type="Service",
        provider="collector",
        display_name=display_name,
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
    db.add(asset)
    db.flush()
    return asset


# --- reading the evidence ---------------------------------------------------


def test_ports_are_read_from_both_key_spellings_the_parsers_emit():
    """The Nmap parser writes `service`; the generic collector payload writes
    `name`. This story records what the pipeline already produces rather than
    changing what it emits."""
    from_nmap = extract_observed_ports(
        {"services": [{"port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.24"}]}
    )
    from_collector = extract_observed_ports({"services": [{"port": 443, "protocol": "tcp", "name": "https"}]})

    assert from_nmap[0].service_name == "https"
    assert from_nmap[0].product == "nginx"
    assert from_nmap[0].product_version == "1.24"
    assert from_collector[0].service_name == "https"


def test_a_protocol_the_scanner_did_not_state_is_recorded_as_unknown():
    """Assuming tcp would be inventing evidence — and a NULL would break the
    per-port uniqueness that stops rescans duplicating rows."""
    ports = extract_observed_ports({"services": [{"port": 161, "service": "snmp"}]})

    assert ports[0].protocol == UNKNOWN_PROTOCOL


@pytest.mark.parametrize(
    "service",
    [
        {"protocol": "tcp"},  # no port at all
        {"port": None, "protocol": "tcp"},
        {"port": "443", "protocol": "tcp"},  # a string is not a port number
        {"port": True, "protocol": "tcp"},  # bool is an int subclass in Python
        {"port": 0, "protocol": "tcp"},
        {"port": 70000, "protocol": "tcp"},
    ],
)
def test_a_record_without_a_usable_port_contributes_nothing(service):
    assert extract_observed_ports({"services": [service]}) == ()


def test_one_unusable_service_does_not_discard_the_rest_of_the_record():
    ports = extract_observed_ports(
        {"services": [{"port": "not-a-port"}, {"port": 22, "protocol": "tcp", "service": "ssh"}]}
    )

    assert [port.port for port in ports] == [22]


def test_the_same_port_listed_twice_in_one_record_is_one_fact():
    ports = extract_observed_ports(
        {
            "services": [
                {"port": 443, "protocol": "tcp", "service": "http"},
                {"port": 443, "protocol": "tcp", "service": "https"},
            ]
        }
    )

    assert len(ports) == 1


# --- recording it -----------------------------------------------------------


def test_repeated_scans_update_the_port_rather_than_accumulating_rows(db: Session):
    """Bounded by construction — the growth problem BUG-DISC-18 had to solve
    for signals cannot arise here."""
    asset = _make_asset(db)
    port = ObservedPort(port=443, protocol="tcp", service_name="https")
    first_run = datetime(2026, 8, 1, 9, 0, 0)
    second_run = datetime(2026, 8, 15, 9, 0, 0)

    record_observed_ports(db, asset=asset, ports=(port,), observed_at=first_run)
    record_observed_ports(db, asset=asset, ports=(port,), observed_at=second_run)
    db.flush()

    rows = db.query(AssetObservedPort).filter(AssetObservedPort.asset_id == asset.id).all()
    assert len(rows) == 1
    assert rows[0].first_seen_at == first_run
    assert rows[0].last_seen_at == second_run


def test_a_port_that_stops_answering_is_kept_so_closed_since_is_answerable(db: Session):
    asset = _make_asset(db)
    first_run = datetime(2026, 8, 1, 9, 0, 0)
    second_run = datetime(2026, 8, 15, 9, 0, 0)

    record_observed_ports(
        db,
        asset=asset,
        ports=(ObservedPort(22, "tcp", "ssh"), ObservedPort(443, "tcp", "https")),
        observed_at=first_run,
    )
    # The second scan sees only 443. SSH is gone.
    record_observed_ports(db, asset=asset, ports=(ObservedPort(443, "tcp", "https"),), observed_at=second_run)
    db.flush()

    rows = {row.port: row for row in db.query(AssetObservedPort).filter(AssetObservedPort.asset_id == asset.id)}
    assert set(rows) == {22, 443}, "the closed port must not be erased"
    assert rows[22].last_seen_at == first_run
    assert rows[443].last_seen_at == second_run
    # "Not seen in the most recent observation" is a comparison, not a guess.
    assert rows[22].last_seen_at < rows[443].last_seen_at


def test_a_scan_that_reports_no_service_name_does_not_erase_the_one_already_known(db: Session):
    asset = _make_asset(db)
    record_observed_ports(db, asset=asset, ports=(ObservedPort(443, "tcp", "https", "nginx", "1.24"),))
    record_observed_ports(db, asset=asset, ports=(ObservedPort(443, "tcp", None),))
    db.flush()

    row = db.query(AssetObservedPort).filter(AssetObservedPort.asset_id == asset.id).one()
    assert row.service_name == "https"
    assert row.product == "nginx"
    assert row.product_version == "1.24"


def test_later_evidence_supersedes_earlier_evidence_about_the_same_port(db: Session):
    asset = _make_asset(db)
    record_observed_ports(db, asset=asset, ports=(ObservedPort(443, "tcp", "http", "nginx", "1.24"),))
    record_observed_ports(db, asset=asset, ports=(ObservedPort(443, "tcp", "https", "nginx", "1.27"),))
    db.flush()

    row = db.query(AssetObservedPort).filter(AssetObservedPort.asset_id == asset.id).one()
    assert row.service_name == "https"
    assert row.product_version == "1.27"


def test_the_same_port_on_two_organisations_artefacts_stays_separate(db: Session):
    org_one_asset = _make_asset(db, organization_id=1)
    org_two_asset = _make_asset(db, organization_id=2)
    port = ObservedPort(443, "tcp", "https")

    record_observed_ports(db, asset=org_one_asset, ports=(port,))
    record_observed_ports(db, asset=org_two_asset, ports=(port,))
    db.flush()

    for organization_id, asset in ((1, org_one_asset), (2, org_two_asset)):
        rows = (
            db.query(AssetObservedPort)
            .filter(AssetObservedPort.organization_id == organization_id)
            .all()
        )
        assert [row.asset_id for row in rows] == [asset.id]


def test_the_same_port_number_on_two_protocols_is_two_facts(db: Session):
    asset = _make_asset(db)

    record_observed_ports(
        db, asset=asset, ports=(ObservedPort(53, "tcp", "domain"), ObservedPort(53, "udp", "domain"))
    )
    db.flush()

    assert db.query(AssetObservedPort).filter(AssetObservedPort.asset_id == asset.id).count() == 2
