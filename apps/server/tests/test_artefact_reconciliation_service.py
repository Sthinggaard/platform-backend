"""CA-06.4 — a person resolves an uncertain match: same thing, or genuinely separate.

The acceptance criteria name the properties this file has to prove rather than
assume: a merge preserves everything, "keep separate" survives the next scan,
every decision is attributed, and one organisation cannot reconcile another's
records. Reversibility is tested the same way — by undoing a merge that
*collapsed* rows, since re-pointed ids alone would restore nothing.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.artefact_identity_enums import (
    ARTEFACT_AUDIT_KEPT_SEPARATE,
    ARTEFACT_AUDIT_MERGE_REVERSED,
    ARTEFACT_AUDIT_MERGED,
    ArtefactIdentityConflictState,
)
from src.core.database import Base
from src.core.model_defs.artefact_reconciliation import ArtefactIdentityConflict
from src.core.model_defs.artefact_relationships import ArtefactRelationship
from src.core.model_defs.common import utcnow
from src.core.model_defs.assets_runtime import (
    Asset,
    AssetFinding,
    AssetFindingStatus,
    AssetIdentifier,
    AssetLifecycleState,
    AssetObservedPort,
    AssetStatus,
    ConnectivityStatus,
    Criticality,
    Environment,
    ScanStartMode,
    SetupConfidence,
    SeverityLevel,
)
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.model_defs.tenant_org import Organization
from src.core.services.artefact_reconciliation_service import (
    ArtefactReconciliationError,
    keep_artefacts_separate,
    list_open_conflicts,
    merge_artefacts,
    raise_identity_conflict,
    reverse_merge,
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
            Organization(id=1, name="Org One", slug="org-one"),
            Organization(id=2, name="Org Two", slug="org-two"),
        ]
    )
    session.commit()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


def _asset(
    db: Session,
    *,
    organization_id: int = 1,
    display_name: str = "192.168.1.1",
    lifecycle_state: AssetLifecycleState = AssetLifecycleState.ACTIVE,
) -> Asset:
    asset = Asset(
        organization_id=organization_id,
        type="Observed host",
        provider="collector",
        display_name=display_name,
        layer="Infrastructure",
        environment=Environment.PROD,
        criticality=Criticality.MEDIUM,
        status=AssetStatus.PARTIALLY_OBSERVED,
        connectivity_status=ConnectivityStatus.PENDING_VERIFICATION,
        setup_confidence=SetupConfidence.LOW,
        scan_start_mode=ScanStartMode.AUDIT_ONLY,
        findings_count=0,
        risk_score=0.0,
        confidence=0.4,
        lifecycle_state=lifecycle_state,
    )
    db.add(asset)
    db.flush()
    return asset


def _identifier(db: Session, asset: Asset, *, identifier_type: str, value: str) -> AssetIdentifier:
    row = AssetIdentifier(
        organization_id=asset.organization_id,
        asset_id=asset.id,
        identifier_type=identifier_type,
        identifier_value=value,
        observed_by_source="collector",
    )
    db.add(row)
    db.flush()
    return row


def _port(db: Session, asset: Asset, *, port: int, protocol: str = "tcp") -> AssetObservedPort:
    row = AssetObservedPort(
        organization_id=asset.organization_id,
        asset_id=asset.id,
        port=port,
        protocol=protocol,
        service_name="http",
    )
    db.add(row)
    db.flush()
    return row


def _relationship(db: Session, *, source: Asset, target: Asset, relationship_type: str = "RUNS_ON"):
    edge = ArtefactRelationship(
        organization_id=source.organization_id,
        source_asset_id=source.id,
        target_asset_id=target.id,
        relationship_type=relationship_type,
        origin="observed",
        confidence="medium",
        state="ACTIVE",
    )
    db.add(edge)
    db.flush()
    return edge


def _audit(db: Session, event_type: str) -> AuditEvent | None:
    return db.query(AuditEvent).filter(AuditEvent.event_type == event_type).first()


# --- raising the question ----------------------------------------------------


def test_a_conflict_is_one_question_per_pair_whichever_way_round_it_is_raised(db: Session):
    """A-vs-B and B-vs-A are the same question. Stored unordered, a reviewer
    could dismiss one direction and be asked again in the other."""
    left = _asset(db, display_name="host-a")
    right = _asset(db, display_name="host-b")

    first = raise_identity_conflict(
        db, organization_id=1, left_asset_id=left.id, right_asset_id=right.id, reason="Shared address."
    )
    second = raise_identity_conflict(
        db, organization_id=1, left_asset_id=right.id, right_asset_id=left.id, reason="Shared address."
    )

    assert first is not None and second is not None
    assert first.id == second.id
    assert db.query(ArtefactIdentityConflict).count() == 1


def test_re_raising_an_open_conflict_refreshes_it_rather_than_stacking_another(db: Session):
    left = _asset(db, display_name="host-a")
    right = _asset(db, display_name="host-b")

    conflict = raise_identity_conflict(
        db, organization_id=1, left_asset_id=left.id, right_asset_id=right.id, reason="Shared address."
    )
    raised_at = conflict.raised_at
    conflict.last_raised_at = conflict.raised_at.replace(year=2000)
    db.flush()

    raise_identity_conflict(
        db, organization_id=1, left_asset_id=left.id, right_asset_id=right.id, reason="Shared address."
    )

    assert db.query(ArtefactIdentityConflict).count() == 1
    # The question is not new, but it is not stale either.
    assert conflict.raised_at == raised_at
    assert conflict.last_raised_at > conflict.raised_at.replace(year=2000)


def test_keeping_two_artefacts_separate_survives_the_next_scan(db: Session):
    """The acceptance criterion in its own words: "a later scan does not
    re-raise a conflict a person has already dismissed"."""
    left = _asset(db, display_name="host-a")
    right = _asset(db, display_name="host-b")
    conflict = raise_identity_conflict(
        db, organization_id=1, left_asset_id=left.id, right_asset_id=right.id, reason="Shared address."
    )

    keep_artefacts_separate(db, organization_id=1, conflict_id=conflict.id, actor_user_id=7, reason="Different racks.")

    # The next scan sees the same ambiguity and says so again.
    reraised = raise_identity_conflict(
        db, organization_id=1, left_asset_id=left.id, right_asset_id=right.id, reason="Shared address."
    )

    assert reraised is None
    assert conflict.state == ArtefactIdentityConflictState.RESOLVED_SEPARATE.value
    assert list_open_conflicts(db, organization_id=1) == []


def test_keeping_separate_is_recorded_as_a_decision_with_its_author(db: Session):
    """Neither record changes, which is exactly why it has to be written down —
    "nothing happened" and "a person decided" are otherwise identical."""
    left = _asset(db, display_name="host-a")
    right = _asset(db, display_name="host-b")
    conflict = raise_identity_conflict(
        db, organization_id=1, left_asset_id=left.id, right_asset_id=right.id, reason="Shared address."
    )

    keep_artefacts_separate(db, organization_id=1, conflict_id=conflict.id, actor_user_id=7, reason="Different racks.")

    event = _audit(db, ARTEFACT_AUDIT_KEPT_SEPARATE)
    assert event is not None
    assert event.actor_user_id == 7
    assert sorted(event.metadata_json["assetIds"]) == sorted([left.id, right.id])
    assert event.metadata_json["reason"] == "Different racks."


def test_the_conflict_surface_shows_both_sides_and_what_they_share(db: Session):
    """Never a bare "these might match": the reviewer needs each side's
    identifiers and the overlap, or they can only guess."""
    left = _asset(db, display_name="host-a")
    right = _asset(db, display_name="host-b")
    _identifier(db, left, identifier_type="ip_address", value="10.0.0.5")
    _identifier(db, left, identifier_type="hostname", value="a.internal")
    _identifier(db, right, identifier_type="ip_address", value="10.0.0.5")

    raise_identity_conflict(
        db,
        organization_id=1,
        left_asset_id=left.id,
        right_asset_id=right.id,
        reason="Another artefact has been observed at this address.",
    )

    views = list_open_conflicts(db, organization_id=1)
    assert len(views) == 1
    view = views[0]
    assert view.reason == "Another artefact has been observed at this address."
    assert {view.left.asset_id, view.right.asset_id} == {left.id, right.id}
    assert [row["identifierValue"] for row in view.shared_identifiers] == ["10.0.0.5"]


# --- merging -----------------------------------------------------------------


def test_a_merge_moves_every_identifier_port_and_relationship_to_the_survivor(db: Session):
    survivor = _asset(db, display_name="host-a")
    merged = _asset(db, display_name="host-b")
    other = _asset(db, display_name="db-1")

    _identifier(db, merged, identifier_type="hostname", value="b.internal")
    _port(db, merged, port=8080)
    _relationship(db, source=merged, target=other)

    merge_artefacts(
        db, organization_id=1, survivor_asset_id=survivor.id, merged_asset_id=merged.id, actor_user_id=7
    )

    assert [row.identifier_value for row in db.query(AssetIdentifier).filter(AssetIdentifier.asset_id == survivor.id)] == [
        "b.internal"
    ]
    assert db.query(AssetObservedPort).filter(AssetObservedPort.asset_id == survivor.id).count() == 1
    assert db.query(ArtefactRelationship).filter(ArtefactRelationship.source_asset_id == survivor.id).count() == 1
    assert merged.lifecycle_state == AssetLifecycleState.MERGED
    assert merged.merged_into_asset_id == survivor.id


def test_a_merge_never_deletes_the_record_it_merged(db: Session):
    """"Nothing is destroyed" is the acceptance criterion. The merged row stays,
    in MERGED, pointing at what superseded it."""
    survivor = _asset(db, display_name="host-a")
    merged = _asset(db, display_name="host-b")

    merge_artefacts(
        db, organization_id=1, survivor_asset_id=survivor.id, merged_asset_id=merged.id, actor_user_id=7
    )

    assert db.get(Asset, merged.id) is not None


def test_a_relationship_between_the_two_merged_records_is_collapsed_not_repointed(db: Session):
    """Re-pointing it would claim the survivor runs on itself — which the table's
    own check constraint forbids, and which is not a fact about the world but an
    artefact of the merge."""
    survivor = _asset(db, display_name="host-a")
    merged = _asset(db, display_name="host-b")
    _relationship(db, source=merged, target=survivor)

    record = merge_artefacts(
        db, organization_id=1, survivor_asset_id=survivor.id, merged_asset_id=merged.id, actor_user_id=7
    )

    assert db.query(ArtefactRelationship).count() == 0
    # Collapsed with its contents, not just its id — the row is gone, so an id
    # would restore nothing.
    assert record.moved["relationships"][0]["collapsed"]["sourceAssetId"] == merged.id


def test_a_duplicate_identifier_is_collapsed_and_keeps_the_widest_true_window(db: Session):
    survivor = _asset(db, display_name="host-a")
    merged = _asset(db, display_name="host-b")
    kept = _identifier(db, survivor, identifier_type="ip_address", value="10.0.0.5")
    duplicate = _identifier(db, merged, identifier_type="ip_address", value="10.0.0.5")
    duplicate.first_seen_at = duplicate.first_seen_at.replace(year=2020)
    db.flush()

    merge_artefacts(
        db, organization_id=1, survivor_asset_id=survivor.id, merged_asset_id=merged.id, actor_user_id=7
    )

    remaining = db.query(AssetIdentifier).filter(AssetIdentifier.identifier_value == "10.0.0.5").all()
    assert len(remaining) == 1
    # The identifier was genuinely first seen in 2020, whichever record held it.
    assert remaining[0].id == kept.id
    assert remaining[0].first_seen_at.year == 2020


def test_a_merge_is_attributed(db: Session):
    survivor = _asset(db, display_name="host-a")
    merged = _asset(db, display_name="host-b")

    merge_artefacts(
        db,
        organization_id=1,
        survivor_asset_id=survivor.id,
        merged_asset_id=merged.id,
        actor_user_id=7,
        reason="Same box, two collectors.",
    )

    event = _audit(db, ARTEFACT_AUDIT_MERGED)
    assert event is not None
    assert event.actor_user_id == 7
    assert event.metadata_json["survivorAssetId"] == survivor.id
    assert event.metadata_json["mergedAssetId"] == merged.id
    assert event.metadata_json["reason"] == "Same box, two collectors."


def test_merging_resolves_the_conflict_that_asked_the_question(db: Session):
    survivor = _asset(db, display_name="host-a")
    merged = _asset(db, display_name="host-b")
    conflict = raise_identity_conflict(
        db, organization_id=1, left_asset_id=survivor.id, right_asset_id=merged.id, reason="Shared address."
    )

    merge_artefacts(
        db,
        organization_id=1,
        survivor_asset_id=survivor.id,
        merged_asset_id=merged.id,
        actor_user_id=7,
        conflict_id=conflict.id,
    )

    assert conflict.state == ArtefactIdentityConflictState.RESOLVED_MERGED.value
    assert list_open_conflicts(db, organization_id=1) == []


def test_an_artefact_cannot_be_merged_twice(db: Session):
    survivor = _asset(db, display_name="host-a")
    merged = _asset(db, display_name="host-b")
    third = _asset(db, display_name="host-c")
    merge_artefacts(
        db, organization_id=1, survivor_asset_id=survivor.id, merged_asset_id=merged.id, actor_user_id=7
    )

    with pytest.raises(ArtefactReconciliationError):
        merge_artefacts(
            db, organization_id=1, survivor_asset_id=third.id, merged_asset_id=merged.id, actor_user_id=7
        )


def test_an_artefact_cannot_be_merged_into_itself(db: Session):
    asset = _asset(db, display_name="host-a")
    with pytest.raises(ArtefactReconciliationError):
        merge_artefacts(
            db, organization_id=1, survivor_asset_id=asset.id, merged_asset_id=asset.id, actor_user_id=7
        )


# --- reversing ---------------------------------------------------------------


def test_reversing_a_merge_restores_repointed_and_collapsed_rows_alike(db: Session):
    """The case that makes the snapshots necessary: a collapsed row was deleted,
    so its id restores nothing."""
    survivor = _asset(db, display_name="host-a")
    merged = _asset(db, display_name="host-b", lifecycle_state=AssetLifecycleState.UNCONFIRMED)
    other = _asset(db, display_name="db-1")

    _identifier(db, survivor, identifier_type="ip_address", value="10.0.0.5")
    _identifier(db, merged, identifier_type="ip_address", value="10.0.0.5")  # collapses
    _identifier(db, merged, identifier_type="hostname", value="b.internal")  # re-points
    _port(db, merged, port=8080)
    _relationship(db, source=merged, target=other)

    record = merge_artefacts(
        db, organization_id=1, survivor_asset_id=survivor.id, merged_asset_id=merged.id, actor_user_id=7
    )
    reverse_merge(db, organization_id=1, merge_record_id=record.id, actor_user_id=9, reason="Wrong call.")

    merged_identifiers = {
        row.identifier_value for row in db.query(AssetIdentifier).filter(AssetIdentifier.asset_id == merged.id)
    }
    assert merged_identifiers == {"10.0.0.5", "b.internal"}
    assert db.query(AssetObservedPort).filter(AssetObservedPort.asset_id == merged.id).count() == 1
    assert db.query(ArtefactRelationship).filter(ArtefactRelationship.source_asset_id == merged.id).count() == 1
    # Restored to what it was, not assumed ACTIVE.
    assert merged.lifecycle_state == AssetLifecycleState.UNCONFIRMED
    assert merged.merged_into_asset_id is None


def test_a_reversed_merge_keeps_its_record_and_reopens_the_question(db: Session):
    """"Merged on the 3rd, undone on the 5th" is what an audit asks about. And
    undoing an answer does not make the question certain."""
    survivor = _asset(db, display_name="host-a")
    merged = _asset(db, display_name="host-b")
    conflict = raise_identity_conflict(
        db, organization_id=1, left_asset_id=survivor.id, right_asset_id=merged.id, reason="Shared address."
    )
    record = merge_artefacts(
        db,
        organization_id=1,
        survivor_asset_id=survivor.id,
        merged_asset_id=merged.id,
        actor_user_id=7,
        conflict_id=conflict.id,
    )

    reverse_merge(db, organization_id=1, merge_record_id=record.id, actor_user_id=9, reason="Wrong call.")

    assert record.reversed_at is not None
    assert record.reversed_by_user_id == 9
    event = _audit(db, ARTEFACT_AUDIT_MERGE_REVERSED)
    assert event is not None and event.actor_user_id == 9
    assert conflict.state == ArtefactIdentityConflictState.OPEN.value
    assert len(list_open_conflicts(db, organization_id=1)) == 1


def test_a_merge_cannot_be_undone_twice(db: Session):
    survivor = _asset(db, display_name="host-a")
    merged = _asset(db, display_name="host-b")
    record = merge_artefacts(
        db, organization_id=1, survivor_asset_id=survivor.id, merged_asset_id=merged.id, actor_user_id=7
    )
    reverse_merge(db, organization_id=1, merge_record_id=record.id, actor_user_id=9)

    with pytest.raises(ArtefactReconciliationError):
        reverse_merge(db, organization_id=1, merge_record_id=record.id, actor_user_id=9)


# --- tenant isolation --------------------------------------------------------


def test_another_organisations_artefacts_cannot_be_merged(db: Session):
    ours = _asset(db, organization_id=1, display_name="host-a")
    theirs = _asset(db, organization_id=2, display_name="host-b")

    with pytest.raises(ArtefactReconciliationError):
        merge_artefacts(
            db, organization_id=1, survivor_asset_id=ours.id, merged_asset_id=theirs.id, actor_user_id=7
        )


def test_another_organisations_conflicts_are_neither_listed_nor_resolvable(db: Session):
    left = _asset(db, organization_id=2, display_name="host-a")
    right = _asset(db, organization_id=2, display_name="host-b")
    conflict = raise_identity_conflict(
        db, organization_id=2, left_asset_id=left.id, right_asset_id=right.id, reason="Shared address."
    )

    assert list_open_conflicts(db, organization_id=1) == []
    with pytest.raises(ArtefactReconciliationError):
        keep_artefacts_separate(db, organization_id=1, conflict_id=conflict.id, actor_user_id=7)


def test_another_organisations_merge_cannot_be_reversed(db: Session):
    survivor = _asset(db, organization_id=2, display_name="host-a")
    merged = _asset(db, organization_id=2, display_name="host-b")
    record = merge_artefacts(
        db, organization_id=2, survivor_asset_id=survivor.id, merged_asset_id=merged.id, actor_user_id=7
    )

    with pytest.raises(ArtefactReconciliationError):
        reverse_merge(db, organization_id=1, merge_record_id=record.id, actor_user_id=7)


# --- A merge has to carry the findings too -----------------------------------
#
# 🐞 It did not until 2026-09-07, and the merge's own docstring said "everything
# the merged record knew moves to the survivor" the whole time. On organisation
# 7 that stranded 22 of 25 findings on MERGED artefacts: 192.168.50.152 held 13,
# including SSH and RPC results, while `pi-local` — the surviving record for the
# same machine — showed zero. The tombstone rendered as "Unidentified device ·
# Nothing answered on this address · Nothing listening" next to a control
# offering 13 findings.


def _finding(db: Session, asset: Asset, *, title: str = "mDNS Enumeration") -> AssetFinding:
    finding = AssetFinding(
        organization_id=asset.organization_id,
        asset_id=asset.id,
        domain="risk_intelligence_ingestion",
        severity=SeverityLevel.LOW,
        title=title,
        description=None,
        evidence_refs=[],
        risk_score=25.0,
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
        status=AssetFindingStatus.OPEN,
    )
    db.add(finding)
    db.commit()
    return finding


def _findings_on(db: Session, asset: Asset) -> set[str]:
    return {
        row.title for row in db.query(AssetFinding).filter(AssetFinding.asset_id == asset.id)
    }


def test_a_merge_moves_the_findings_to_the_survivor(db: Session):
    """The one that matters most: a finding *is* the product's output, and on a
    tombstoned record it is evidence the platform holds and never shows."""
    survivor = _asset(db, display_name="pi-local")
    merged = _asset(db, display_name="192.168.50.152")
    _finding(db, merged, title="SSH SHA-1 HMAC Algorithms Enabled")
    _finding(db, merged, title="Rpcbind Portmapper - Detect")

    merge_artefacts(
        db, organization_id=1, survivor_asset_id=survivor.id, merged_asset_id=merged.id, actor_user_id=7
    )

    assert _findings_on(db, survivor) == {
        "SSH SHA-1 HMAC Algorithms Enabled",
        "Rpcbind Portmapper - Detect",
    }
    assert _findings_on(db, merged) == set()


def test_the_survivor_keeps_its_own_findings_as_well(db: Session):
    """Both records were observed. A merge adds to the survivor; it never
    replaces what the survivor already had."""
    survivor = _asset(db, display_name="pi-local")
    merged = _asset(db, display_name="192.168.50.152")
    _finding(db, survivor, title="Already on the survivor")
    _finding(db, merged, title="Came across in the merge")

    merge_artefacts(
        db, organization_id=1, survivor_asset_id=survivor.id, merged_asset_id=merged.id, actor_user_id=7
    )

    assert _findings_on(db, survivor) == {"Already on the survivor", "Came across in the merge"}


def test_the_same_finding_on_both_records_stays_two_rows(db: Session):
    """Deliberate. They were observed separately, and collapsing them here would
    be the merge deciding they are one finding — a judgement it is not entitled
    to make, and one that would destroy evidence to tidy a list."""
    survivor = _asset(db, display_name="pi-local")
    merged = _asset(db, display_name="192.168.50.152")
    _finding(db, survivor, title="mDNS Enumeration")
    _finding(db, merged, title="mDNS Enumeration")

    merge_artefacts(
        db, organization_id=1, survivor_asset_id=survivor.id, merged_asset_id=merged.id, actor_user_id=7
    )

    assert db.query(AssetFinding).filter(AssetFinding.asset_id == survivor.id).count() == 2


def test_a_merge_records_the_findings_it_moved(db: Session):
    """Written down so the merge can be undone — the same contract the other
    three movers keep."""
    survivor = _asset(db, display_name="pi-local")
    merged = _asset(db, display_name="192.168.50.152")
    finding = _finding(db, merged)

    record = merge_artefacts(
        db, organization_id=1, survivor_asset_id=survivor.id, merged_asset_id=merged.id, actor_user_id=7
    )

    assert record.moved["findings"] == [{"id": finding.id}]


def test_reversing_a_merge_gives_the_findings_back(db: Session):
    survivor = _asset(db, display_name="pi-local")
    merged = _asset(db, display_name="192.168.50.152")
    _finding(db, merged, title="SSH Password-based Authentication")

    record = merge_artefacts(
        db, organization_id=1, survivor_asset_id=survivor.id, merged_asset_id=merged.id, actor_user_id=7
    )
    reverse_merge(db, organization_id=1, merge_record_id=record.id, actor_user_id=9, reason="Wrong call.")

    assert _findings_on(db, merged) == {"SSH Password-based Authentication"}
    assert _findings_on(db, survivor) == set()


def test_reversing_a_merge_recorded_before_findings_moved_still_works(db: Session):
    """Every merge already on record has no `findings` key at all. Reversing one
    must not fail because a newer version of the code expects it."""
    survivor = _asset(db, display_name="pi-local")
    merged = _asset(db, display_name="192.168.50.152")

    record = merge_artefacts(
        db, organization_id=1, survivor_asset_id=survivor.id, merged_asset_id=merged.id, actor_user_id=7
    )
    record.moved = {key: value for key, value in record.moved.items() if key != "findings"}
    db.add(record)
    db.commit()

    reverse_merge(db, organization_id=1, merge_record_id=record.id, actor_user_id=9, reason="Wrong call.")

    assert merged.lifecycle_state != AssetLifecycleState.MERGED
