"""CA-06.3 — artefacts can record how they relate to one another."""

from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.artefact_relationship_enums import (
    ArtefactRelationshipConfidence,
    ArtefactRelationshipOrigin,
    ArtefactRelationshipState,
    ArtefactRelationshipType,
)
from src.core.database import Base
from src.core.model_defs.artefact_relationships import ArtefactRelationship
from src.core.model_defs.assets_runtime import (
    Asset,
    AssetLifecycleState,
    AssetStatus,
    ConnectivityStatus,
    Criticality,
    Environment,
    ScanStartMode,
    SetupConfidence,
)
from src.core.model_defs.tenant_org import Organization
from src.core.services.artefact_relationship_service import (
    ArtefactRelationshipError,
    record_relationship,
    relationships_for_asset,
    repoint_relationships,
    withdraw_relationship,
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


def _make_asset(db: Session, display_name: str, *, organization_id: int = 1) -> Asset:
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


def _observe(db: Session, source: Asset, target: Asset, **overrides):
    params = dict(
        organization_id=source.organization_id,
        source_asset_id=source.id,
        target_asset_id=target.id,
        relationship_type=ArtefactRelationshipType.RUNS_ON,
        origin=ArtefactRelationshipOrigin.OBSERVED,
        confidence=ArtefactRelationshipConfidence.HIGH,
        observed_by_source="nmap",
    )
    params.update(overrides)
    return record_relationship(db, **params)


# --- recording --------------------------------------------------------------


def test_a_relationship_records_what_it_says_who_says_it_and_how_sure(db: Session):
    app = _make_asset(db, "checkout-api")
    host = _make_asset(db, "host-01.internal")

    edge = _observe(db, app, host, reason="Reported by the provider's own topology")

    assert edge.relationship_type == ArtefactRelationshipType.RUNS_ON.value
    assert edge.origin == ArtefactRelationshipOrigin.OBSERVED.value
    assert edge.confidence == ArtefactRelationshipConfidence.HIGH.value
    assert edge.state == ArtefactRelationshipState.ACTIVE.value
    assert edge.observed_by_source == "nmap"
    assert edge.reason


def test_direction_is_part_of_the_claim(db: Session):
    """"A runs on B" is not "B runs on A" — storing it symmetrically would lose
    which artefact is the host."""
    app = _make_asset(db, "checkout-api")
    host = _make_asset(db, "host-01.internal")

    _observe(db, app, host)
    reverse = _observe(db, host, app)

    assert db.query(ArtefactRelationship).count() == 2
    assert reverse.source_asset_id == host.id


def test_two_artefacts_can_be_related_in_more_than_one_way(db: Session):
    name = _make_asset(db, "api.example.com")
    address = _make_asset(db, "10.0.0.5")

    _observe(db, name, address, relationship_type=ArtefactRelationshipType.RESOLVES_TO)
    _observe(db, name, address, relationship_type=ArtefactRelationshipType.CONNECTS_TO)

    assert db.query(ArtefactRelationship).count() == 2


def test_an_artefact_cannot_be_related_to_itself(db: Session):
    asset = _make_asset(db, "host-01.internal")

    with pytest.raises(ArtefactRelationshipError):
        _observe(db, asset, asset)


def test_a_person_asserted_relationship_must_name_the_person(db: Session):
    app = _make_asset(db, "checkout-api")
    host = _make_asset(db, "host-01.internal")

    with pytest.raises(ArtefactRelationshipError):
        _observe(db, app, host, origin=ArtefactRelationshipOrigin.ASSERTED_BY_PERSON)


def test_a_relationship_cannot_span_two_organisations(db: Session):
    """The one place in this domain where two artefact ids meet, and so the one
    place a tenant boundary could be crossed by accident."""
    ours = _make_asset(db, "checkout-api", organization_id=1)
    theirs = _make_asset(db, "someone-elses-host", organization_id=2)

    with pytest.raises(ArtefactRelationshipError):
        _observe(db, ours, theirs)

    assert db.query(ArtefactRelationship).count() == 0


def test_relationships_are_not_visible_to_another_organisation(db: Session):
    app = _make_asset(db, "checkout-api", organization_id=1)
    host = _make_asset(db, "host-01.internal", organization_id=1)
    _observe(db, app, host)

    assert relationships_for_asset(db, organization_id=2, asset_id=app.id) == []
    assert len(relationships_for_asset(db, organization_id=1, asset_id=app.id)) == 1


# --- repeated scans ---------------------------------------------------------


def test_a_rescan_refreshes_the_relationship_rather_than_duplicating_it(db: Session):
    app = _make_asset(db, "checkout-api")
    host = _make_asset(db, "host-01.internal")
    first_run = datetime(2026, 8, 1, 9, 0, 0)
    second_run = datetime(2026, 8, 15, 9, 0, 0)

    _observe(db, app, host, observed_at=first_run)
    _observe(db, app, host, observed_at=second_run)

    edge = db.query(ArtefactRelationship).one()
    assert edge.first_seen_at == first_run
    assert edge.last_seen_at == second_run


def test_a_withdrawn_relationship_keeps_its_history(db: Session):
    app = _make_asset(db, "checkout-api")
    host = _make_asset(db, "host-01.internal")
    edge = _observe(db, app, host)

    withdraw_relationship(db, relationship=edge, reason="Not seen in the latest scan")

    assert edge.state == ArtefactRelationshipState.WITHDRAWN.value
    assert edge.withdrawn_at is not None
    assert db.query(ArtefactRelationship).count() == 1, "withdrawing must not delete the record"
    # And it is out of the way by default, without being gone.
    assert relationships_for_asset(db, organization_id=1, asset_id=app.id) == []
    assert len(relationships_for_asset(db, organization_id=1, asset_id=app.id, include_withdrawn=True)) == 1


def test_seeing_a_withdrawn_relationship_again_revives_it(db: Session):
    app = _make_asset(db, "checkout-api")
    host = _make_asset(db, "host-01.internal")
    edge = _observe(db, app, host)
    withdraw_relationship(db, relationship=edge)

    _observe(db, app, host)

    assert edge.state == ArtefactRelationshipState.ACTIVE.value
    assert edge.withdrawn_at is None


# --- a person outranks a scan ----------------------------------------------


def test_a_scan_does_not_downgrade_what_a_person_asserted(db: Session):
    app = _make_asset(db, "checkout-api")
    host = _make_asset(db, "host-01.internal")
    _observe(
        db,
        app,
        host,
        origin=ArtefactRelationshipOrigin.ASSERTED_BY_PERSON,
        confidence=ArtefactRelationshipConfidence.HIGH,
        asserted_by_user_id=7,
    )

    # A later scan sees the same thing, but only weakly.
    _observe(
        db,
        app,
        host,
        origin=ArtefactRelationshipOrigin.INFERRED,
        confidence=ArtefactRelationshipConfidence.LOW,
        observed_at=datetime(2026, 8, 20, 9, 0, 0),
    )

    edge = db.query(ArtefactRelationship).one()
    assert edge.origin == ArtefactRelationshipOrigin.ASSERTED_BY_PERSON.value
    assert edge.confidence == ArtefactRelationshipConfidence.HIGH.value
    assert edge.asserted_by_user_id == 7
    # The sighting is still recorded — it just does not restate the claim.
    assert edge.last_seen_at == datetime(2026, 8, 20, 9, 0, 0)


def test_a_person_can_overrule_what_the_platform_inferred(db: Session):
    app = _make_asset(db, "checkout-api")
    host = _make_asset(db, "host-01.internal")
    _observe(db, app, host, origin=ArtefactRelationshipOrigin.INFERRED, confidence=ArtefactRelationshipConfidence.LOW)

    _observe(
        db,
        app,
        host,
        origin=ArtefactRelationshipOrigin.ASSERTED_BY_PERSON,
        confidence=ArtefactRelationshipConfidence.HIGH,
        asserted_by_user_id=7,
    )

    edge = db.query(ArtefactRelationship).one()
    assert edge.origin == ArtefactRelationshipOrigin.ASSERTED_BY_PERSON.value
    assert edge.asserted_by_user_id == 7


def test_the_platform_cannot_withdraw_a_persons_assertion(db: Session):
    app = _make_asset(db, "checkout-api")
    host = _make_asset(db, "host-01.internal")
    edge = _observe(
        db, app, host, origin=ArtefactRelationshipOrigin.ASSERTED_BY_PERSON, asserted_by_user_id=7
    )

    with pytest.raises(ArtefactRelationshipError):
        withdraw_relationship(db, relationship=edge)

    assert edge.state == ArtefactRelationshipState.ACTIVE.value


def test_a_later_observation_fills_provenance_gaps_without_blanking_them(db: Session):
    app = _make_asset(db, "checkout-api")
    host = _make_asset(db, "host-01.internal")
    _observe(db, app, host, observed_by_source="nmap", scanner_instance_id="collector-1")

    _observe(db, app, host, observed_by_source=None, scanner_instance_id=None)

    edge = db.query(ArtefactRelationship).one()
    assert edge.observed_by_source == "nmap"
    assert edge.scanner_instance_id == "collector-1"


# --- surviving reconciliation (what CA-06.4 will call) ----------------------


def test_merging_moves_relationships_onto_the_survivor(db: Session):
    """Structure a person never agreed to lose must not disappear because two
    records turned out to be one thing."""
    duplicate = _make_asset(db, "host-01")
    survivor = _make_asset(db, "host-01.internal")
    app = _make_asset(db, "checkout-api")
    database = _make_asset(db, "postgres-primary")

    _observe(db, app, duplicate)  # something points at the duplicate
    _observe(db, duplicate, database, relationship_type=ArtefactRelationshipType.CONNECTS_TO)

    moved, collapsed = repoint_relationships(
        db, organization_id=1, from_asset_id=duplicate.id, into_asset_id=survivor.id
    )

    assert (moved, collapsed) == (2, 0)
    assert relationships_for_asset(db, organization_id=1, asset_id=duplicate.id) == []
    survivor_edges = relationships_for_asset(db, organization_id=1, asset_id=survivor.id)
    assert len(survivor_edges) == 2


def test_merging_collapses_an_edge_the_survivor_already_had(db: Session):
    duplicate = _make_asset(db, "host-01")
    survivor = _make_asset(db, "host-01.internal")
    app = _make_asset(db, "checkout-api")
    early = datetime(2026, 7, 1, 9, 0, 0)
    late = datetime(2026, 8, 15, 9, 0, 0)

    _observe(db, app, duplicate, observed_at=early)
    _observe(db, app, survivor, observed_at=late)

    moved, collapsed = repoint_relationships(
        db, organization_id=1, from_asset_id=duplicate.id, into_asset_id=survivor.id
    )

    assert (moved, collapsed) == (0, 1)
    edge = db.query(ArtefactRelationship).one()
    # Merging must never shorten a relationship's history.
    assert edge.first_seen_at == early
    assert edge.last_seen_at == late


def test_merging_keeps_the_human_claim_when_it_collapses_two_edges(db: Session):
    duplicate = _make_asset(db, "host-01")
    survivor = _make_asset(db, "host-01.internal")
    app = _make_asset(db, "checkout-api")

    _observe(
        db,
        app,
        duplicate,
        origin=ArtefactRelationshipOrigin.ASSERTED_BY_PERSON,
        confidence=ArtefactRelationshipConfidence.HIGH,
        asserted_by_user_id=7,
    )
    _observe(db, app, survivor, origin=ArtefactRelationshipOrigin.INFERRED, confidence=ArtefactRelationshipConfidence.LOW)

    repoint_relationships(db, organization_id=1, from_asset_id=duplicate.id, into_asset_id=survivor.id)

    edge = db.query(ArtefactRelationship).one()
    assert edge.origin == ArtefactRelationshipOrigin.ASSERTED_BY_PERSON.value
    assert edge.asserted_by_user_id == 7


def test_merging_drops_an_edge_that_would_point_an_artefact_at_itself(db: Session):
    """"A runs on B" where A and B turn out to be the same artefact was never
    real structure — it was a symptom of the duplicate."""
    duplicate = _make_asset(db, "host-01")
    survivor = _make_asset(db, "host-01.internal")
    _observe(db, duplicate, survivor, relationship_type=ArtefactRelationshipType.CONNECTS_TO)

    moved, collapsed = repoint_relationships(
        db, organization_id=1, from_asset_id=duplicate.id, into_asset_id=survivor.id
    )

    assert (moved, collapsed) == (0, 1)
    assert db.query(ArtefactRelationship).count() == 0


def test_repointing_cannot_cross_an_organisation_boundary(db: Session):
    ours = _make_asset(db, "host-01", organization_id=1)
    theirs = _make_asset(db, "their-host", organization_id=2)

    with pytest.raises(ArtefactRelationshipError):
        repoint_relationships(db, organization_id=1, from_asset_id=ours.id, into_asset_id=theirs.id)


def test_deleting_an_artefact_takes_its_relationships_with_it(db: Session):
    app = _make_asset(db, "checkout-api")
    host = _make_asset(db, "host-01.internal")
    _observe(db, app, host)

    db.delete(app)
    db.flush()

    assert db.query(ArtefactRelationship).count() == 0
