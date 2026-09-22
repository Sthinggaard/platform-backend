"""#150 — human decisions on a discovered artefact.

Before this service existed, nothing in the codebase could move an Asset out of
UNCONFIRMED and nothing could remove one that should never have been created, so
a screen asking the user to "review and confirm" pointed at an action that did
not exist.

The two properties that make these decisions worth anything — that a decision
survives the next scan, and that it is attributable — are asserted here against
the real identity-resolution path, not assumed from reading it.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.artefact_identity_enums import (
    ARTEFACT_AUDIT_CLASSIFICATION_CORRECTED,
    ARTEFACT_AUDIT_CONFIRMED,
    ARTEFACT_AUDIT_DEPENDENCY_CATEGORY_SET,
    ARTEFACT_AUDIT_NOT_USED,
    ARTEFACT_AUDIT_REJECTED,
    ArtefactIdentityMatchType,
)
from src.core.constants.dependency_category_enums import DependencyCategory
from src.core.database import Base
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
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.model_defs.tenant_org import Organization
from src.core.services.artefact_identity_service import (
    ArtefactIdentityCandidate,
    build_canonical_identity_key,
    resolve_identity,
)
from src.core.services.artefact_review_service import (
    ArtefactReviewError,
    confirm_artefact,
    correct_artefact_classification,
    mark_artefact_not_used,
    reject_artefact,
    set_dependency_category,
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
    asset_type: str = "Service",
    layer: str = "Application",
    canonical_identity_key: str | None = None,
    lifecycle_state: AssetLifecycleState = AssetLifecycleState.ACTIVE,
) -> Asset:
    asset = Asset(
        organization_id=organization_id,
        type=asset_type,
        provider="collector",
        display_name=display_name,
        layer=layer,
        environment=Environment.PROD,
        criticality=Criticality.MEDIUM,
        status=AssetStatus.PARTIALLY_OBSERVED,
        connectivity_status=ConnectivityStatus.PENDING_VERIFICATION,
        setup_confidence=SetupConfidence.LOW,
        scan_start_mode=ScanStartMode.AUDIT_ONLY,
        findings_count=0,
        risk_score=0.0,
        confidence=0.4,
        canonical_identity_key=canonical_identity_key,
        lifecycle_state=lifecycle_state,
    )
    db.add(asset)
    db.flush()
    return asset


def _audit(db: Session, event_type: str) -> AuditEvent | None:
    return db.query(AuditEvent).filter(AuditEvent.event_type == event_type).first()


# --- confirm ------------------------------------------------------------------------------


def test_confirming_an_unconfirmed_artefact_activates_it(db: Session):
    """The case that had no path at all: an ambiguous match left UNCONFIRMED
    rather than silently merged, which nothing could then resolve."""
    asset = _asset(db, lifecycle_state=AssetLifecycleState.UNCONFIRMED)

    confirm_artefact(db, organization_id=1, asset_id=asset.id, actor_user_id=7)

    assert asset.lifecycle_state == AssetLifecycleState.ACTIVE
    event = _audit(db, ARTEFACT_AUDIT_CONFIRMED)
    assert event is not None
    assert event.actor_user_id == 7
    assert event.metadata_json["previousLifecycleState"] == "UNCONFIRMED"


def test_confirming_an_already_active_artefact_still_records_the_decision(db: Session):
    """Most discovered rows are created ACTIVE, so confirmation is usually a
    human agreeing rather than a state change. The audit record is the point."""
    asset = _asset(db)

    confirm_artefact(db, organization_id=1, asset_id=asset.id, actor_user_id=7)

    assert asset.lifecycle_state == AssetLifecycleState.ACTIVE
    assert _audit(db, ARTEFACT_AUDIT_CONFIRMED) is not None


def test_a_confirmed_artefact_gets_a_human_library_category(db: Session):
    asset = _asset(db)
    confirm_artefact(db, organization_id=1, asset_id=asset.id, actor_user_id=7)

    set_dependency_category(
        db,
        organization_id=1,
        asset_id=asset.id,
        actor_user_id=7,
        category=DependencyCategory.INFRASTRUCTURE,
    )

    assert asset.dependency_category == "infrastructure"
    event = _audit(db, ARTEFACT_AUDIT_DEPENDENCY_CATEGORY_SET)
    assert event is not None
    assert event.actor_user_id == 7
    assert event.metadata_json["to"] == "infrastructure"


def test_an_unreviewed_artefact_cannot_be_given_a_dependency_category(db: Session):
    asset = _asset(db)

    with pytest.raises(ArtefactReviewError, match="Confirm this active artefact"):
        set_dependency_category(
            db,
            organization_id=1,
            asset_id=asset.id,
            actor_user_id=7,
            category=DependencyCategory.DATA,
        )


def test_a_merged_artefact_cannot_be_confirmed_on_its_own(db: Session):
    asset = _asset(db, lifecycle_state=AssetLifecycleState.MERGED)

    with pytest.raises(ArtefactReviewError):
        confirm_artefact(db, organization_id=1, asset_id=asset.id, actor_user_id=7)


# --- reject -------------------------------------------------------------------------------


def test_rejecting_an_artefact_removes_it_and_records_why(db: Session):
    """BUG-DISC-14's placeholder row is the motivating case: an asset that
    describes a scan rather than anything the organisation owns."""
    asset = _asset(db, display_name="subfinder-scan-a55ee57c")

    reject_artefact(
        db,
        organization_id=1,
        asset_id=asset.id,
        actor_user_id=7,
        reason="Not an asset — this is a scan record.",
    )

    assert asset.lifecycle_state == AssetLifecycleState.REMOVED
    event = _audit(db, ARTEFACT_AUDIT_REJECTED)
    assert event is not None
    assert event.metadata_json["reason"] == "Not an asset — this is a scan record."


def test_a_rejected_artefact_is_not_recreated_by_the_next_scan(db: Session):
    """The property that makes "not ours" mean anything. Asserted against the
    real resolve_identity path rather than inferred from reading it: a later run
    observing the same host must re-match this row — leaving it rejected —
    instead of creating a fresh ACTIVE duplicate."""
    candidate = ArtefactIdentityCandidate(
        organization_id=1,
        normalized_type="Service",
        hostname="scanner-noise.example.com",
    )
    key = build_canonical_identity_key(candidate)
    asset = _asset(db, display_name="scanner-noise.example.com", canonical_identity_key=key)

    reject_artefact(db, organization_id=1, asset_id=asset.id, actor_user_id=7)
    db.flush()

    resolution = resolve_identity(db, candidate)

    assert resolution.match_type == ArtefactIdentityMatchType.EXACT_MATCH
    assert resolution.matched_asset is not None
    assert resolution.matched_asset.id == asset.id
    assert resolution.matched_asset.lifecycle_state == AssetLifecycleState.REMOVED


# --- correct classification ---------------------------------------------------------------


def test_correcting_a_classification_records_both_values(db: Session):
    """BUG-DISC-15: a router classified Service · Application because it has
    open ports. A reviewer looking at their own network knows better."""
    asset = _asset(db, display_name="192.168.1.1", asset_type="Service", layer="Application")

    correct_artefact_classification(
        db,
        organization_id=1,
        asset_id=asset.id,
        actor_user_id=7,
        asset_type="Network device",
        layer="Network",
    )

    assert asset.type == "Network device"
    assert asset.layer == "Network"
    event = _audit(db, ARTEFACT_AUDIT_CLASSIFICATION_CORRECTED)
    assert event is not None
    assert event.metadata_json["changed"]["type"] == {"from": "Service", "to": "Network device"}
    assert event.metadata_json["changed"]["layer"] == {"from": "Application", "to": "Network"}


def test_one_field_can_be_corrected_without_restating_the_other(db: Session):
    asset = _asset(db, asset_type="Service", layer="Application")

    correct_artefact_classification(
        db, organization_id=1, asset_id=asset.id, actor_user_id=7, layer="Network"
    )

    assert asset.layer == "Network"
    assert asset.type == "Service"


def test_a_correction_that_changes_nothing_writes_no_audit_noise(db: Session):
    asset = _asset(db, asset_type="Service", layer="Application")

    correct_artefact_classification(
        db, organization_id=1, asset_id=asset.id, actor_user_id=7, asset_type="Service"
    )

    assert _audit(db, ARTEFACT_AUDIT_CLASSIFICATION_CORRECTED) is None


def test_a_correction_must_actually_change_something(db: Session):
    asset = _asset(db)

    with pytest.raises(ArtefactReviewError):
        correct_artefact_classification(
            db, organization_id=1, asset_id=asset.id, actor_user_id=7
        )


def test_a_correction_survives_the_next_scan(db: Session):
    """The other half of "decisions stick". The matched-asset path in
    normalisation only backfills canonical_identity_key and never rewrites
    type/layer, so a re-scan must not undo a human correction."""
    candidate = ArtefactIdentityCandidate(
        organization_id=1, normalized_type="Service", hostname="router.internal"
    )
    key = build_canonical_identity_key(candidate)
    asset = _asset(db, display_name="router.internal", canonical_identity_key=key)

    correct_artefact_classification(
        db,
        organization_id=1,
        asset_id=asset.id,
        actor_user_id=7,
        asset_type="Network device",
        layer="Network",
    )
    db.flush()

    resolution = resolve_identity(db, candidate)

    assert resolution.matched_asset is not None
    assert resolution.matched_asset.type == "Network device"
    assert resolution.matched_asset.layer == "Network"


# --- tenant isolation ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "decide",
    [
        lambda db, asset_id: confirm_artefact(
            db, organization_id=2, asset_id=asset_id, actor_user_id=9
        ),
        lambda db, asset_id: reject_artefact(
            db, organization_id=2, asset_id=asset_id, actor_user_id=9
        ),
        lambda db, asset_id: correct_artefact_classification(
            db, organization_id=2, asset_id=asset_id, actor_user_id=9, layer="Network"
        ),
    ],
)
def test_no_decision_crosses_an_organisation_boundary(db: Session, decide):
    """Org 2 must not be able to touch org 1's inventory, and the failure must
    read as "does not exist" rather than confirming the row is there."""
    asset = _asset(db, organization_id=1)

    with pytest.raises(ArtefactReviewError):
        decide(db, asset.id)

    assert asset.lifecycle_state == AssetLifecycleState.ACTIVE
    assert asset.layer == "Application"


# --- reviewer authority (regression) -------------------------------------------------------


def test_manager_and_above_may_review(db: Session):
    """The first version of the route hardcoded `role != "org_admin"`, silently
    excluding `admin` — a role with full access within an org. A real reviewer
    was refused with a 403, and because the client treated 403 like 401 it
    logged them out on every click.

    The floor is now manager (Søren's call): a manager can already manage
    assets, and saying what an asset *is* is the same kind of authority, not a
    governance decision. MANAGER_ROLES is inclusive upward by construction, so
    seniority needs no separate rule."""
    from src.core.roles import MANAGER_ROLES, UserRole

    assert UserRole.MANAGER in MANAGER_ROLES
    assert UserRole.ADMIN in MANAGER_ROLES
    assert UserRole.ORG_ADMIN in MANAGER_ROLES
    # Operational-view-only and time-boxed external access must not decide what
    # the organisation owns.
    assert UserRole.MEMBER not in MANAGER_ROLES
    assert UserRole.CONSULTANT not in MANAGER_ROLES


# --- the decision has to be visible on the record (Søren, 2026-08-13) ----------------------
# "When i click confirm nothing visually happens." Most discovered rows are
# created ACTIVE, so confirming changed no state at all — the decision existed
# only in the audit trail, which the screen cannot see.


def test_confirming_stamps_the_record_even_when_the_state_does_not_move(db: Session):
    asset = _asset(db, lifecycle_state=AssetLifecycleState.ACTIVE)
    assert asset.reviewed_at is None

    confirm_artefact(db, organization_id=1, asset_id=asset.id, actor_user_id=7)

    # State is unchanged — and that is exactly why the stamp is needed.
    assert asset.lifecycle_state == AssetLifecycleState.ACTIVE
    assert asset.reviewed_at is not None
    assert asset.reviewed_by_user_id == 7


def test_rejecting_also_records_who_decided_and_when(db: Session):
    asset = _asset(db)

    reject_artefact(db, organization_id=1, asset_id=asset.id, actor_user_id=7)

    assert asset.reviewed_at is not None
    assert asset.reviewed_by_user_id == 7


def test_review_state_distinguishes_confirmed_from_merely_discovered(db: Session):
    """What the list renders. Without reviewed_at, a confirmed row and an
    untouched one are both ACTIVE and indistinguishable."""
    from src.core.services.discovery_results_service import _review_state

    untouched = _asset(db, display_name="untouched")
    confirmed = _asset(db, display_name="confirmed")
    ambiguous = _asset(db, display_name="ambiguous", lifecycle_state=AssetLifecycleState.UNCONFIRMED)
    rejected = _asset(db, display_name="rejected")

    confirm_artefact(db, organization_id=1, asset_id=confirmed.id, actor_user_id=7)
    reject_artefact(db, organization_id=1, asset_id=rejected.id, actor_user_id=7)

    assert _review_state(untouched) == "undecided"
    assert _review_state(confirmed) == "confirmed"
    assert _review_state(ambiguous) == "needs_decision"
    assert _review_state(rejected) == "rejected"


def test_correcting_a_classification_also_records_that_a_human_looked(db: Session):
    """A correction is a decision about the artefact, same as confirming it is
    ours. Without the stamp, anything asking "has a human looked at this?" —
    including the migration that retires fabricated classifications — could not
    see a correction at all."""
    asset = _asset(db, asset_type="Service", layer="Application")
    assert asset.reviewed_at is None

    correct_artefact_classification(
        db,
        organization_id=1,
        asset_id=asset.id,
        actor_user_id=7,
        asset_type="Network device",
        layer="Network",
    )

    assert asset.reviewed_at is not None
    assert asset.reviewed_by_user_id == 7


def test_a_correction_that_changes_nothing_leaves_no_review_mark(db: Session):
    asset = _asset(db, asset_type="Service", layer="Application")

    correct_artefact_classification(
        db, organization_id=1, asset_id=asset.id, actor_user_id=7, asset_type="Service"
    )

    assert asset.reviewed_at is None


def test_a_correction_marks_the_classification_as_a_persons_answer(db: Session):
    """Distinct from reviewed_at on purpose. Confirming an artefact means "this
    is ours" and says nothing about the label, so a re-scan must still be free to
    improve a machine guess on a confirmed row — but must never overwrite a
    class a person actually chose."""
    asset = _asset(db, asset_type="Service", layer="Application")

    correct_artefact_classification(
        db, organization_id=1, asset_id=asset.id, actor_user_id=7, layer="L2"
    )

    assert asset.intent["classificationSetByHuman"] is True


def test_confirming_does_not_claim_the_classification_as_a_persons_answer(db: Session):
    asset = _asset(db)

    confirm_artefact(db, organization_id=1, asset_id=asset.id, actor_user_id=7)

    intent = asset.intent if isinstance(asset.intent, dict) else {}
    assert not intent.get("classificationSetByHuman")


def test_marking_not_used_records_ownership_without_the_dependency(db: Session):
    """The third disposition. A laptop on the office WiFi is genuinely theirs,
    so rejecting it as "not ours" would be false — but it will never appear in a
    dependency picture either."""
    asset = _asset(db)

    mark_artefact_not_used(db, organization_id=1, asset_id=asset.id, actor_user_id=7)

    assert asset.lifecycle_state is AssetLifecycleState.NOT_USED
    assert asset.reviewed_by_user_id == 7
    assert asset.reviewed_at is not None


def test_not_used_is_a_distinct_audit_event_from_rejection(db: Session):
    """An auditor asking "what is on your network that you chose not to model,
    and who decided?" must get a different answer from "what did you disown"."""
    asset = _asset(db)

    mark_artefact_not_used(db, organization_id=1, asset_id=asset.id, actor_user_id=7)

    events = [e.event_type for e in db.query(AuditEvent).all()]
    assert ARTEFACT_AUDIT_NOT_USED in events
    assert ARTEFACT_AUDIT_REJECTED not in events


def test_not_used_is_reversible_by_confirming(db: Session):
    asset = _asset(db)
    mark_artefact_not_used(db, organization_id=1, asset_id=asset.id, actor_user_id=7)

    confirm_artefact(db, organization_id=1, asset_id=asset.id, actor_user_id=7)

    assert asset.lifecycle_state is AssetLifecycleState.ACTIVE


def test_not_used_cannot_be_applied_to_another_organisations_artefact(db: Session):
    asset = _asset(db)

    with pytest.raises(ArtefactReviewError, match="does not exist"):
        mark_artefact_not_used(db, organization_id=999, asset_id=asset.id, actor_user_id=7)

    assert asset.lifecycle_state is not AssetLifecycleState.NOT_USED


def test_not_used_is_refused_on_a_merged_artefact(db: Session):
    asset = _asset(db)
    asset.lifecycle_state = AssetLifecycleState.MERGED
    db.flush()

    with pytest.raises(ArtefactReviewError, match="merged"):
        mark_artefact_not_used(db, organization_id=1, asset_id=asset.id, actor_user_id=7)
