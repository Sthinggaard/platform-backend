"""CA-05.A — environment detection: coverage classification, tenant isolation,
and the boundary rules the contract makes non-negotiable (an excluded candidate
is never proposed; a near-miss domain never falls inside an approved one)."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.discovery_environment_enums import (
    EnvironmentCandidateKind,
    EnvironmentCoverageState,
    EnvironmentDetectionSource,
)
from src.core.constants.evidence_scanner_enums import ScannerTargetStatus
from src.core.database import Base
from src.core.model_defs.assets_runtime import Asset
from src.core.model_defs.evidence_scanner import ScannerDomainTarget, ScannerNetworkTarget
from src.core.model_defs.organization_identity import OrganizationScope
from src.core.model_defs.tenant_org import Organization
from src.core.services.discovery_boundary_matching import is_scannable_identifier
from src.core.services.discovery_environment_detection_service import detect_environment

SOURCE_ID = "src-1"
OTHER_SOURCE_ID = "src-2"

_TABLES = (
    Organization.__table__,
    Asset.__table__,
    ScannerDomainTarget.__table__,
    ScannerNetworkTarget.__table__,
    OrganizationScope.__table__,
)


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in _TABLES:
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=list(_TABLES))
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org", country="DK"),
            Organization(id=2, name="Other", slug="other", country="DK"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _domain(db: Session, domain: str, status: str, *, org: int = 1, source: str = SOURCE_ID) -> None:
    db.add(
        ScannerDomainTarget(
            organization_id=org,
            evidence_source_id=source,
            domain=domain,
            source="manual",
            ownership_status="owned",
            status=status,
        )
    )
    db.commit()


def _network(db: Session, cidr: str, status: str, *, org: int = 1, source: str = SOURCE_ID) -> None:
    db.add(
        ScannerNetworkTarget(
            organization_id=org,
            evidence_source_id=source,
            cidr=cidr,
            name=f"net {cidr}",
            network_type="corporate",
            status=status,
        )
    )
    db.commit()


def _asset(db: Session, display_name: str, *, org: int = 1) -> None:
    db.add(
        Asset(
            organization_id=org,
            type="server",
            display_name=display_name,
            layer="infrastructure",
        )
    )
    db.commit()


def _detect(db: Session, *, org: int = 1, source: str = SOURCE_ID):
    return detect_environment(db, organization_id=org, evidence_source_id=source)


def _find(result, value: str):
    return next((c for c in result.candidates if c.value == value), None)


def test_approved_domain_target_is_covered(db: Session) -> None:
    _domain(db, "example.com", ScannerTargetStatus.APPROVED.value)

    candidate = _find(_detect(db), "example.com")

    assert candidate is not None
    assert candidate.kind == EnvironmentCandidateKind.DOMAIN.value
    assert candidate.coverage_state == EnvironmentCoverageState.COVERED.value
    assert candidate.detected_from == EnvironmentDetectionSource.SCANNER_DOMAIN_TARGET.value
    assert candidate.is_proposable is False


def test_draft_target_is_not_covered_and_proposable(db: Session) -> None:
    _domain(db, "draft.example.com", ScannerTargetStatus.DRAFT.value)

    candidate = _find(_detect(db), "draft.example.com")

    assert candidate.coverage_state == EnvironmentCoverageState.NOT_COVERED.value
    assert candidate.is_proposable is True


def test_disabled_target_is_not_a_candidate(db: Session) -> None:
    _domain(db, "dormant.example.com", ScannerTargetStatus.DISABLED.value)

    assert _find(_detect(db), "dormant.example.com") is None


def test_asset_inside_approved_domain_is_covered(db: Session) -> None:
    _domain(db, "example.com", ScannerTargetStatus.APPROVED.value)
    _asset(db, "api.example.com")

    assert _find(_detect(db), "api.example.com").coverage_state == (
        EnvironmentCoverageState.COVERED.value
    )


def test_lookalike_domain_is_not_pulled_into_approved_scope(db: Session) -> None:
    """`notexample.com` must never match an approval for `example.com` — a bare
    suffix check would silently scan a third party."""
    _domain(db, "example.com", ScannerTargetStatus.APPROVED.value)
    _asset(db, "notexample.com")

    assert _find(_detect(db), "notexample.com").coverage_state == (
        EnvironmentCoverageState.NOT_COVERED.value
    )


def test_asset_inside_approved_cidr_is_covered(db: Session) -> None:
    _network(db, "10.0.0.0/24", ScannerTargetStatus.APPROVED.value)
    _asset(db, "10.0.0.15")

    assert _find(_detect(db), "10.0.0.15").coverage_state == (
        EnvironmentCoverageState.COVERED.value
    )


def test_asset_outside_approved_cidr_is_not_covered(db: Session) -> None:
    _network(db, "10.0.0.0/24", ScannerTargetStatus.APPROVED.value)
    _asset(db, "10.9.9.9")

    assert _find(_detect(db), "10.9.9.9").coverage_state == (
        EnvironmentCoverageState.NOT_COVERED.value
    )


def test_malformed_stored_cidr_fails_closed(db: Session) -> None:
    """A broken CIDR must not widen coverage — the host stays NOT_COVERED
    rather than being treated as inside an approved range."""
    _network(db, "not-a-cidr", ScannerTargetStatus.APPROVED.value)
    _asset(db, "10.0.0.15")

    assert _find(_detect(db), "10.0.0.15").coverage_state == (
        EnvironmentCoverageState.NOT_COVERED.value
    )


def test_excluded_domain_beats_approval_and_is_never_proposable(db: Session) -> None:
    _domain(db, "example.com", ScannerTargetStatus.APPROVED.value)
    _domain(db, "secret.example.com", ScannerTargetStatus.EXCLUDED.value)
    _asset(db, "secret.example.com")

    candidate = _find(_detect(db), "secret.example.com")

    assert candidate.coverage_state == EnvironmentCoverageState.EXPLICITLY_EXCLUDED.value
    assert candidate.is_proposable is False
    assert candidate not in _detect(db).proposable


def test_organization_scope_exclusion_is_surfaced(db: Session) -> None:
    db.add(
        OrganizationScope(
            organization_id=1,
            scope_type="discovery",
            name="Out of scope",
            status="confirmed",
            excluded_entity_ids=["legacy.example.com"],
        )
    )
    db.commit()

    candidate = _find(_detect(db), "legacy.example.com")

    assert candidate.coverage_state == EnvironmentCoverageState.EXPLICITLY_EXCLUDED.value
    assert candidate.detected_from == EnvironmentDetectionSource.ORGANIZATION_SCOPE.value


def test_other_tenant_records_never_leak(db: Session) -> None:
    _domain(db, "tenant2.example.com", ScannerTargetStatus.APPROVED.value, org=2, source=SOURCE_ID)
    _asset(db, "tenant2-host", org=2)

    values = {c.value for c in _detect(db, org=1).candidates}

    assert "tenant2.example.com" not in values
    assert "tenant2-host" not in values


def test_other_evidence_source_targets_excluded(db: Session) -> None:
    _domain(db, "other-source.example.com", ScannerTargetStatus.APPROVED.value, source=OTHER_SOURCE_ID)

    assert _find(_detect(db), "other-source.example.com") is None


def test_detection_writes_nothing(db: Session) -> None:
    _domain(db, "example.com", ScannerTargetStatus.DRAFT.value)
    _asset(db, "host.example.com")
    before = (
        db.query(ScannerDomainTarget).count(),
        db.query(Asset).count(),
        db.query(OrganizationScope).count(),
    )

    _detect(db)

    assert (
        db.query(ScannerDomainTarget).count(),
        db.query(Asset).count(),
        db.query(OrganizationScope).count(),
    ) == before


def test_duplicate_candidates_collapse_to_one(db: Session) -> None:
    _domain(db, "example.com", ScannerTargetStatus.APPROVED.value)
    _asset(db, "example.com")

    matches = [c for c in _detect(db).candidates if c.value == "example.com"]

    assert len(matches) == 1


@pytest.mark.parametrize(
    "value,scannable",
    [
        ("api.example.com", True),
        ("db-01.corp.local", True),
        ("10.0.0.15", True),
        ("192.168.1.0/24", True),
        # Business names from the asset registry — Asset has no hostname/IP
        # column, so display_name is often prose. None of these can be scanned.
        ("main firewall", False),
        ("AWS production", False),
        ("core router edge", False),
        ("firewall", False),
        ("", False),
    ],
)
def test_is_scannable_identifier(value: str, scannable: bool) -> None:
    assert is_scannable_identifier(value) is scannable


def test_business_named_assets_are_not_proposed(db: Session) -> None:
    """Found in manual testing: a proposal offered 15 asset display names such
    as "main firewall" as discovery targets. Approving those would put
    unscannable entries inside a human-approved boundary."""
    _asset(db, "main firewall")
    _asset(db, "AWS production")
    _asset(db, "api.example.com")

    values = {c.value for c in _detect(db).candidates}

    assert "api.example.com" in values
    assert "main firewall" not in values
    assert "aws production" not in values
