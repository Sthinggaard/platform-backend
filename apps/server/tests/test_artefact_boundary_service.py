"""CA-06.5 — an excluded target leaves the inventory, and says why.

The gap this closes: ``DiscoveryScopeProposal.exclusions`` bound the *next scan*
and nothing else, so approving an exclusion left every artefact already inside it
sitting in the inventory. The acceptance criteria name what has to be true, and
each is asserted here rather than argued for in a comment: withdrawn not deleted,
the withdrawal is explained, no resurrection, lifting an exclusion returns the
artefact to review, and none of it crosses a tenant boundary.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.artefact_identity_enums import (
    ARTEFACT_AUDIT_BOUNDARY_RESTORED,
    ARTEFACT_AUDIT_BOUNDARY_WITHDRAWN,
)
from src.core.database import Base
from src.core.model_defs.assets_runtime import (
    Asset,
    AssetIdentifier,
    AssetLifecycleState,
    AssetStatus,
    ConnectivityStatus,
    Criticality,
    Environment,
    ScanStartMode,
    SetupConfidence,
)
from src.core.model_defs.discovery_scope_proposal import DiscoveryScopeProposal
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.model_defs.tenant_org import Organization
from src.core.services.artefact_boundary_service import (
    apply_boundary_to_inventory,
    evaluate_boundary,
    restore_artefact_to_review,
    withdraw_artefact,
)

APPROVED = "approved"


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
    display_name: str = "10.0.0.15",
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


def _identifier(db: Session, asset: Asset, *, identifier_type: str, value: str) -> None:
    db.add(
        AssetIdentifier(
            organization_id=asset.organization_id,
            asset_id=asset.id,
            identifier_type=identifier_type,
            identifier_value=value,
            observed_by_source="collector",
        )
    )
    db.flush()


def _boundary(db: Session, *, organization_id: int = 1, exclusions: list[str]) -> DiscoveryScopeProposal:
    subject = PermissionSubject(organization_id=organization_id, subject_kind="discovery_scope_proposal")
    db.add(subject)
    db.flush()
    profile = PermissionProfile(
        organization_id=organization_id,
        subject_id=subject.id,
        name="Boundary test profile",
        capabilities=[],
        discovery_capabilities=[],
        status="active",
    )
    db.add(profile)
    db.flush()
    proposal = DiscoveryScopeProposal(
        organization_id=organization_id,
        evidence_source_id="source-1",
        status=APPROVED,
        inclusions=[],
        exclusions=exclusions,
        checks=[],
        permission_subject_id=subject.id,
        permission_profile_id=profile.id,
        rationale={},
    )
    db.add(proposal)
    db.flush()
    return proposal


def _audit(db: Session, event_type: str) -> AuditEvent | None:
    return db.query(AuditEvent).filter(AuditEvent.event_type == event_type).first()


# --- matching ----------------------------------------------------------------


def test_an_exclusion_catches_an_artefact_by_any_identifier_not_just_its_name(db: Session):
    """An exclusion is written as an address or a domain; a display name that has
    since become a hostname would otherwise slip past a boundary it plainly
    falls inside."""
    asset = _asset(db, display_name="build-01")
    _identifier(db, asset, identifier_type="ip_address", value="10.0.0.15")

    verdict = evaluate_boundary(db, asset=asset, exclusions=["10.0.0.0/24"])

    assert verdict.excluded is True
    assert verdict.matched_exclusion == "10.0.0.0/24"
    assert verdict.matched_value == "10.0.0.15"


def test_an_artefact_inside_the_boundary_is_left_alone(db: Session):
    asset = _asset(db, display_name="192.168.5.9")
    assert evaluate_boundary(db, asset=asset, exclusions=["10.0.0.0/24"]).excluded is False


# --- withdrawal --------------------------------------------------------------


def test_withdrawing_keeps_the_record_and_says_which_exclusion_did_it(db: Session):
    """Withdrawn, not deleted — and explainable. "It vanished" is not an answer
    to "why is this no longer in our inventory?"."""
    asset = _asset(db)
    verdict = evaluate_boundary(db, asset=asset, exclusions=["10.0.0.0/24"])

    withdraw_artefact(db, asset=asset, verdict=verdict, actor_user_id=7)

    assert db.get(Asset, asset.id) is not None
    assert asset.lifecycle_state == AssetLifecycleState.WITHDRAWN
    assert asset.withdrawn_by_exclusion == "10.0.0.0/24"
    assert asset.withdrawn_at is not None

    event = _audit(db, ARTEFACT_AUDIT_BOUNDARY_WITHDRAWN)
    assert event is not None
    assert event.actor_user_id == 7
    assert event.metadata_json["matchedExclusion"] == "10.0.0.0/24"


def test_re_seeing_a_withdrawn_artefact_does_not_move_the_date_it_left(db: Session):
    """Idempotent: a scan that keeps finding an excluded target must not keep
    re-stamping the withdrawal, or "since when" becomes unanswerable."""
    asset = _asset(db)
    verdict = evaluate_boundary(db, asset=asset, exclusions=["10.0.0.0/24"])
    withdraw_artefact(db, asset=asset, verdict=verdict, actor_user_id=7)
    first_withdrawn_at = asset.withdrawn_at

    withdraw_artefact(db, asset=asset, verdict=verdict, actor_user_id=7)

    assert asset.withdrawn_at == first_withdrawn_at
    assert db.query(AuditEvent).filter(AuditEvent.event_type == ARTEFACT_AUDIT_BOUNDARY_WITHDRAWN).count() == 1


# --- the boundary applied to the whole inventory -----------------------------


def test_approving_an_exclusion_withdraws_the_artefacts_already_inside_it(db: Session):
    inside = _asset(db, display_name="10.0.0.15")
    outside = _asset(db, display_name="192.168.5.9")
    _boundary(db, exclusions=["10.0.0.0/24"])

    withdrawn, restored = apply_boundary_to_inventory(
        db, organization_id=1, evidence_source_id="source-1", actor_user_id=7
    )

    assert (withdrawn, restored) == (1, 0)
    assert inside.lifecycle_state == AssetLifecycleState.WITHDRAWN
    assert outside.lifecycle_state == AssetLifecycleState.ACTIVE


def test_lifting_an_exclusion_returns_the_artefact_to_review_not_to_active(db: Session):
    """The acceptance criterion, and the reason it is worded that way: nobody
    ever said this artefact belongs in the inventory. A boundary stopped
    applying to it, which is a different statement."""
    asset = _asset(db)
    boundary = _boundary(db, exclusions=["10.0.0.0/24"])
    apply_boundary_to_inventory(db, organization_id=1, evidence_source_id="source-1", actor_user_id=7)
    assert asset.lifecycle_state == AssetLifecycleState.WITHDRAWN

    boundary.exclusions = []
    db.flush()
    withdrawn, restored = apply_boundary_to_inventory(
        db, organization_id=1, evidence_source_id="source-1", actor_user_id=7
    )

    assert (withdrawn, restored) == (0, 1)
    assert asset.lifecycle_state == AssetLifecycleState.UNCONFIRMED
    assert asset.withdrawn_by_exclusion is None
    assert _audit(db, ARTEFACT_AUDIT_BOUNDARY_RESTORED) is not None


def test_a_boundary_change_never_overwrites_a_persons_own_decision(db: Session):
    """REMOVED is someone saying "not ours". Letting an exclusion overwrite it
    would erase their decision — and lifting the exclusion would then hand back
    a record whose rejection no longer existed."""
    rejected = _asset(db, display_name="10.0.0.15", lifecycle_state=AssetLifecycleState.REMOVED)
    not_used = _asset(db, display_name="10.0.0.16", lifecycle_state=AssetLifecycleState.NOT_USED)
    _boundary(db, exclusions=["10.0.0.0/24"])

    withdrawn, _ = apply_boundary_to_inventory(
        db, organization_id=1, evidence_source_id="source-1", actor_user_id=7
    )

    assert withdrawn == 0
    assert rejected.lifecycle_state == AssetLifecycleState.REMOVED
    assert not_used.lifecycle_state == AssetLifecycleState.NOT_USED


def test_restoring_leaves_alone_an_artefact_that_was_never_withdrawn(db: Session):
    asset = _asset(db, lifecycle_state=AssetLifecycleState.ACTIVE)
    restore_artefact_to_review(db, asset=asset, actor_user_id=7)
    assert asset.lifecycle_state == AssetLifecycleState.ACTIVE
    assert _audit(db, ARTEFACT_AUDIT_BOUNDARY_RESTORED) is None


# --- tenant isolation --------------------------------------------------------


def test_a_boundary_only_reaches_its_own_organisations_inventory(db: Session):
    ours = _asset(db, organization_id=1, display_name="10.0.0.15")
    theirs = _asset(db, organization_id=2, display_name="10.0.0.15")
    _boundary(db, organization_id=1, exclusions=["10.0.0.0/24"])

    apply_boundary_to_inventory(db, organization_id=1, evidence_source_id="source-1", actor_user_id=7)

    assert ours.lifecycle_state == AssetLifecycleState.WITHDRAWN
    assert theirs.lifecycle_state == AssetLifecycleState.ACTIVE


def test_with_no_approved_boundary_nothing_is_withdrawn(db: Session):
    """Never on a guess: an organisation with no approved boundary has agreed to
    no exclusions, not to all of them."""
    asset = _asset(db)
    withdrawn, restored = apply_boundary_to_inventory(
        db, organization_id=1, evidence_source_id="source-1", actor_user_id=7
    )
    assert (withdrawn, restored) == (0, 0)
    assert asset.lifecycle_state == AssetLifecycleState.ACTIVE
