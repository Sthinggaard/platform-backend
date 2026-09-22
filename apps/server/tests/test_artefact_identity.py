from __future__ import annotations

import hashlib
from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.artefact_identity_enums import ArtefactIdentityMatchType
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
from src.core.model_defs.tenant_org import Organization
from src.core.services.artefact_identity_service import (
    ArtefactIdentityCandidate,
    build_canonical_identity_key,
    build_identifier_set,
    record_observed_identifiers,
    resolve_identity,
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
            Organization(id=1, name="Org One", slug="org-one", plan_tier="enterprise", subscription_status="active", onboarding_completed=False),
            Organization(id=2, name="Org Two", slug="org-two", plan_tier="enterprise", subscription_status="active", onboarding_completed=False),
        ]
    )
    session.commit()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


def _make_asset(db: Session, *, organization_id: int, display_name: str, canonical_identity_key: str | None = None) -> Asset:
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
        canonical_identity_key=canonical_identity_key,
        lifecycle_state=AssetLifecycleState.ACTIVE,
    )
    db.add(asset)
    db.flush()
    return asset


def test_canonical_key_prefers_provider_resource_id_over_hostname():
    key_with_provider = build_canonical_identity_key(
        ArtefactIdentityCandidate(
            organization_id=1,
            normalized_type="Database",
            provider="aws",
            provider_resource_id="arn:aws:rds:eu-west-1:1234:db:prod",
            hostname="prod-db.internal",
        )
    )
    key_hostname_only = build_canonical_identity_key(
        ArtefactIdentityCandidate(organization_id=1, normalized_type="Database", hostname="prod-db.internal")
    )
    assert key_with_provider != key_hostname_only


def test_canonical_key_never_built_from_display_name_alone():
    key = build_canonical_identity_key(
        ArtefactIdentityCandidate(organization_id=1, normalized_type="Service", display_name="My Nice Service")
    )
    assert key is None


def test_canonical_key_is_deterministic_for_identical_input():
    candidate = ArtefactIdentityCandidate(organization_id=1, normalized_type="Service", hostname="api.example.com")
    assert build_canonical_identity_key(candidate) == build_canonical_identity_key(candidate)


def test_exact_match_when_canonical_key_already_stored(db: Session):
    candidate = ArtefactIdentityCandidate(organization_id=1, normalized_type="Service", hostname="api.example.com")
    key = build_canonical_identity_key(candidate)
    existing = _make_asset(db, organization_id=1, display_name="api.example.com", canonical_identity_key=key)

    resolution = resolve_identity(db, candidate)

    assert resolution.match_type == ArtefactIdentityMatchType.EXACT_MATCH
    assert resolution.matched_asset is not None
    assert resolution.matched_asset.id == existing.id


def test_strong_match_for_pre_existing_asset_with_no_identity_key_yet(db: Session):
    existing = _make_asset(db, organization_id=1, display_name="api.example.com", canonical_identity_key=None)
    candidate = ArtefactIdentityCandidate(organization_id=1, normalized_type="Service", hostname="api.example.com")

    resolution = resolve_identity(db, candidate)

    assert resolution.match_type == ArtefactIdentityMatchType.STRONG_MATCH
    assert resolution.matched_asset is not None
    assert resolution.matched_asset.id == existing.id


def test_possible_match_on_display_name_alone_never_auto_merges_but_is_flagged(db: Session):
    existing = _make_asset(db, organization_id=1, display_name="Checkout Service")
    candidate = ArtefactIdentityCandidate(organization_id=1, normalized_type="Service", display_name="Checkout Service")

    resolution = resolve_identity(db, candidate)

    assert resolution.match_type == ArtefactIdentityMatchType.POSSIBLE_MATCH
    # The caller decides what to do with a possible match — the service
    # itself never merges: it returns the candidate row for review, it
    # does not silently treat this as identity confirmation.
    assert resolution.matched_asset is not None
    assert resolution.matched_asset.id == existing.id
    assert resolution.canonical_identity_key is None


def test_distinct_when_nothing_matches(db: Session):
    _make_asset(db, organization_id=1, display_name="unrelated-host.example.com")
    candidate = ArtefactIdentityCandidate(organization_id=1, normalized_type="Service", hostname="new-host.example.com")

    resolution = resolve_identity(db, candidate)

    assert resolution.match_type == ArtefactIdentityMatchType.DISTINCT
    assert resolution.matched_asset is None
    assert resolution.canonical_identity_key is not None


def test_identical_external_identifier_stays_separate_across_organisations(db: Session):
    key = build_canonical_identity_key(
        ArtefactIdentityCandidate(organization_id=1, normalized_type="Service", hostname="shared-vendor-host.example.com")
    )
    _make_asset(db, organization_id=1, display_name="shared-vendor-host.example.com", canonical_identity_key=key)

    candidate_org_2 = ArtefactIdentityCandidate(
        organization_id=2, normalized_type="Service", hostname="shared-vendor-host.example.com"
    )
    resolution = resolve_identity(db, candidate_org_2)

    assert resolution.match_type == ArtefactIdentityMatchType.DISTINCT
    assert resolution.matched_asset is None


# ---------------------------------------------------------------------------
# CA-06.1 — identity is the set of identifiers an artefact has been seen under
# ---------------------------------------------------------------------------


def _observe(
    db: Session,
    asset: Asset,
    candidate: ArtefactIdentityCandidate,
    *,
    source: str = "nmap",
    at: datetime | None = None,
) -> None:
    """Record what one observation saw, the way normalization does."""
    record_observed_identifiers(
        db,
        asset=asset,
        identifiers=build_identifier_set(candidate),
        observed_by_source=source,
        observed_at=at,
    )
    db.flush()


def _identifiers(db: Session, asset: Asset) -> dict[str, set[str]]:
    rows = db.query(AssetIdentifier).filter(AssetIdentifier.asset_id == asset.id).all()
    grouped: dict[str, set[str]] = {}
    for row in rows:
        grouped.setdefault(row.identifier_type, set()).add(row.identifier_value)
    return grouped


def test_canonical_key_is_unchanged_by_the_move_to_identifier_sets():
    """The key form is frozen: it is already stored on live rows, so a change
    here silently orphans every artefact keyed under it."""
    candidate = ArtefactIdentityCandidate(
        organization_id=1, normalized_type="Service", hostname="api.example.com"
    )
    legacy = hashlib.sha256(b"org:1|type:service|hostname:api.example.com").hexdigest()

    assert build_canonical_identity_key(candidate) == legacy


def test_canonical_key_for_a_provider_resource_is_unchanged_too():
    candidate = ArtefactIdentityCandidate(
        organization_id=1,
        normalized_type="Database",
        provider="AWS",
        provider_resource_id="i-0ABC",
        hostname="prod-db.internal",
    )
    legacy = hashlib.sha256(b"org:1|type:database|provider:aws:i-0abc").hexdigest()

    assert build_canonical_identity_key(candidate) == legacy


def test_a_host_whose_ip_changes_stays_the_same_artefact(db: Session):
    """The story's own case: DHCP hands out a new lease, the hostname does not
    change, and the inventory must not grow a second row."""
    first_sighting = ArtefactIdentityCandidate(
        organization_id=1, normalized_type="Service", hostname="api.example.com", ip_address="10.0.0.5"
    )
    asset = _make_asset(
        db,
        organization_id=1,
        display_name="api.example.com",
        canonical_identity_key=build_canonical_identity_key(first_sighting),
    )
    _observe(db, asset, first_sighting)

    after_the_lease_moved = ArtefactIdentityCandidate(
        organization_id=1, normalized_type="Service", hostname="api.example.com", ip_address="10.0.0.99"
    )
    resolution = resolve_identity(db, after_the_lease_moved)

    assert resolution.match_type == ArtefactIdentityMatchType.EXACT_MATCH
    assert resolution.matched_asset is not None
    assert resolution.matched_asset.id == asset.id

    _observe(db, asset, after_the_lease_moved)
    # The address it used to answer on is history, not rubbish: without it,
    # "where was this in March" stops being answerable.
    assert _identifiers(db, asset)["ip_address"] == {"10.0.0.5", "10.0.0.99"}
    assert db.query(Asset).filter(Asset.organization_id == 1).count() == 1


def test_a_second_provider_finding_the_same_host_converges_on_one_artefact(db: Session):
    """nmap sees a hostname; AWS sees an instance id and the same hostname.
    Before CA-06.1 those produced two keys that could never converge."""
    seen_by_nmap = ArtefactIdentityCandidate(
        organization_id=1, normalized_type="Service", hostname="api.example.com"
    )
    asset = _make_asset(
        db,
        organization_id=1,
        display_name="api.example.com",
        canonical_identity_key=build_canonical_identity_key(seen_by_nmap),
    )
    _observe(db, asset, seen_by_nmap, source="nmap")

    seen_by_aws = ArtefactIdentityCandidate(
        organization_id=1,
        normalized_type="Service",
        provider="aws",
        provider_resource_id="i-0abc123",
        hostname="api.example.com",
    )
    resolution = resolve_identity(db, seen_by_aws)

    assert resolution.match_type == ArtefactIdentityMatchType.EXACT_MATCH
    assert resolution.matched_asset is not None
    assert resolution.matched_asset.id == asset.id

    _observe(db, asset, seen_by_aws, source="aws")
    identifiers = _identifiers(db, asset)
    assert identifiers["provider_resource"] == {"aws:i-0abc123"}
    assert identifiers["hostname"] == {"api.example.com"}


def test_the_artefacts_original_key_is_kept_when_a_stronger_identifier_appears(db: Session):
    """A key that moved would not be an identity. The provider id joins the
    set; it does not rewrite what the artefact is already known as."""
    seen_by_nmap = ArtefactIdentityCandidate(
        organization_id=1, normalized_type="Service", hostname="api.example.com"
    )
    original_key = build_canonical_identity_key(seen_by_nmap)
    asset = _make_asset(
        db, organization_id=1, display_name="api.example.com", canonical_identity_key=original_key
    )
    _observe(db, asset, seen_by_nmap)

    resolution = resolve_identity(
        db,
        ArtefactIdentityCandidate(
            organization_id=1,
            normalized_type="Service",
            provider="aws",
            provider_resource_id="i-0abc123",
            hostname="api.example.com",
        ),
    )

    assert resolution.canonical_identity_key == original_key


def test_sharing_only_an_address_raises_a_conflict_instead_of_merging(db: Session):
    """IP alone is not identity. An address can be reassigned, so this is a
    question for a person (CA-06.4), not a match."""
    previous_occupant = ArtefactIdentityCandidate(
        organization_id=1, normalized_type="Service", hostname="old-host.example.com", ip_address="10.0.0.5"
    )
    existing = _make_asset(
        db,
        organization_id=1,
        display_name="old-host.example.com",
        canonical_identity_key=build_canonical_identity_key(previous_occupant),
    )
    _observe(db, existing, previous_occupant)

    resolution = resolve_identity(
        db,
        ArtefactIdentityCandidate(
            organization_id=1,
            normalized_type="Service",
            hostname="new-host.example.com",
            ip_address="10.0.0.5",
        ),
    )

    assert resolution.match_type == ArtefactIdentityMatchType.POSSIBLE_MATCH
    assert resolution.conflicting_asset_ids == (existing.id,)


def test_one_candidate_spanning_two_artefacts_is_a_conflict_not_a_choice(db: Session):
    """Two artefacts each legitimately claim one of this observation's strong
    identifiers. Picking one would be guessing."""
    by_hostname = ArtefactIdentityCandidate(
        organization_id=1, normalized_type="Service", hostname="api.example.com"
    )
    by_domain = ArtefactIdentityCandidate(
        organization_id=1, normalized_type="Service", domain="example.com"
    )
    first = _make_asset(db, organization_id=1, display_name="api.example.com")
    second = _make_asset(db, organization_id=1, display_name="example.com")
    _observe(db, first, by_hostname)
    _observe(db, second, by_domain)

    resolution = resolve_identity(
        db,
        ArtefactIdentityCandidate(
            organization_id=1,
            normalized_type="Service",
            hostname="api.example.com",
            domain="example.com",
        ),
    )

    assert resolution.match_type == ArtefactIdentityMatchType.POSSIBLE_MATCH
    assert set(resolution.conflicting_asset_ids) == {first.id, second.id}


def test_re_observing_an_identifier_updates_it_rather_than_duplicating_it(db: Session):
    candidate = ArtefactIdentityCandidate(
        organization_id=1, normalized_type="Service", hostname="api.example.com", ip_address="10.0.0.5"
    )
    asset = _make_asset(db, organization_id=1, display_name="api.example.com")

    first_run = datetime(2026, 8, 1, 9, 0, 0)
    second_run = datetime(2026, 8, 15, 9, 0, 0)
    _observe(db, asset, candidate, at=first_run)
    _observe(db, asset, candidate, at=second_run)

    rows = db.query(AssetIdentifier).filter(AssetIdentifier.asset_id == asset.id).all()
    assert len(rows) == 2  # one hostname, one ip — not four
    for row in rows:
        assert row.first_seen_at == first_run
        assert row.last_seen_at == second_run


def test_identifiers_never_match_across_organisations(db: Session):
    """Two tenants can legitimately run hosts with the same name. Nothing in
    one organisation may resolve to an artefact in another."""
    shared = ArtefactIdentityCandidate(
        organization_id=1, normalized_type="Service", hostname="intranet.local"
    )
    org_one_asset = _make_asset(db, organization_id=1, display_name="intranet.local")
    _observe(db, org_one_asset, shared)

    resolution = resolve_identity(
        db,
        ArtefactIdentityCandidate(
            organization_id=2, normalized_type="Service", hostname="intranet.local"
        ),
    )

    assert resolution.match_type == ArtefactIdentityMatchType.DISTINCT
    assert resolution.matched_asset is None
    assert resolution.conflicting_asset_ids == ()


def test_an_already_merged_artefact_is_not_a_match_candidate(db: Session):
    """Resurrecting a merged record is CA-06.4's decision to reverse, not a
    side effect of the next scan."""
    candidate = ArtefactIdentityCandidate(
        organization_id=1, normalized_type="Service", hostname="api.example.com"
    )
    merged = _make_asset(db, organization_id=1, display_name="api.example.com")
    _observe(db, merged, candidate)
    merged.lifecycle_state = AssetLifecycleState.MERGED
    db.flush()

    resolution = resolve_identity(db, candidate)

    assert resolution.matched_asset is None
