"""CA-05.B — run creation honours the approved boundary.

An approved boundary is mandatory: every run must trace back to one a human
signed off, which is what the audit argument rests on. Covers both failure
modes — discovery running with no approved boundary, and a target the approver
explicitly excluded still being scanned.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.discovery_run_enums import (
    DISCOVERY_RUN_ERROR_BOUNDARY_APPROVAL_REQUIRED,
    DISCOVERY_RUN_ERROR_TARGET_EXCLUDED_BY_BOUNDARY,
)
from src.core.constants.discovery_scope_proposal_enums import DiscoveryScopeProposalStatus
from src.core.database import Base
from src.core.model_defs.discovery_scope_proposal import DiscoveryScopeProposal
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.model_defs.tenant_org import Organization
from src.core.services.discovery_run_service import _evaluate_approved_boundary

SOURCE_ID = "src-1"

_TABLES = (
    Organization.__table__,
    PermissionSubject.__table__,
    PermissionProfile.__table__,
    DiscoveryScopeProposal.__table__,
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
    session.add(Organization(id=1, name="Org", slug="org", country="DK"))
    session.commit()
    yield session
    session.close()


def _boundary(db: Session, exclusions: list[str], *, status: str | None = None) -> None:
    subject = PermissionSubject(organization_id=1, subject_kind="discovery_scope_proposal")
    db.add(subject)
    db.flush()
    profile = PermissionProfile(
        organization_id=1,
        subject_id=subject.id,
        name="Test discovery profile",
        capabilities=[],
        discovery_capabilities=[],
        status="active",
    )
    db.add(profile)
    db.flush()
    db.add(
        DiscoveryScopeProposal(
            organization_id=1,
            evidence_source_id=SOURCE_ID,
            status=status or DiscoveryScopeProposalStatus.APPROVED.value,
            inclusions=[],
            exclusions=exclusions,
            checks=[],
            permission_subject_id=subject.id,
            permission_profile_id=profile.id,
            rationale={},
        )
    )
    db.commit()


def _gate(db: Session, targets: list[str]) -> list[str]:
    return _evaluate_approved_boundary(
        db,
        organization_id=1,
        evidence_source_id=SOURCE_ID,
        target_snapshot=[{"approvedValue": value} for value in targets],
    )


def test_no_boundary_blocks_discovery(db: Session) -> None:
    """An approved boundary is mandatory: every run must trace back to one a
    human signed off. Surfaced as a readiness blocker, not a bare refusal."""
    assert _gate(db, ["example.com"]) == [DISCOVERY_RUN_ERROR_BOUNDARY_APPROVAL_REQUIRED]


def test_a_boundary_still_awaiting_approval_does_not_count(db: Session) -> None:
    """Proposing is not approving — an undecided boundary must not unlock
    discovery."""
    _boundary(db, ["secret.example.com"], status=DiscoveryScopeProposalStatus.AWAITING_APPROVAL.value)

    assert _gate(db, ["secret.example.com"]) == [DISCOVERY_RUN_ERROR_BOUNDARY_APPROVAL_REQUIRED]


def test_excluded_target_blocks_the_run(db: Session) -> None:
    _boundary(db, ["secret.example.com"])

    assert _gate(db, ["secret.example.com"]) == [DISCOVERY_RUN_ERROR_TARGET_EXCLUDED_BY_BOUNDARY]


def test_subdomain_of_an_excluded_domain_blocks_the_run(db: Session) -> None:
    _boundary(db, ["example.com"])

    assert _gate(db, ["api.example.com"]) == [DISCOVERY_RUN_ERROR_TARGET_EXCLUDED_BY_BOUNDARY]


def test_lookalike_domain_is_not_blocked(db: Session) -> None:
    """`notexample.com` is a different organisation — excluding `example.com`
    must not block it."""
    _boundary(db, ["example.com"])

    assert _gate(db, ["notexample.com"]) == []


def test_address_inside_an_excluded_cidr_blocks_the_run(db: Session) -> None:
    _boundary(db, ["10.0.0.0/24"])

    assert _gate(db, ["10.0.0.15"]) == [DISCOVERY_RUN_ERROR_TARGET_EXCLUDED_BY_BOUNDARY]


def test_address_outside_an_excluded_cidr_is_allowed(db: Session) -> None:
    _boundary(db, ["10.0.0.0/24"])

    assert _gate(db, ["10.9.9.9"]) == []


def test_one_excluded_target_among_many_blocks_the_run(db: Session) -> None:
    _boundary(db, ["secret.example.com"])

    assert _gate(db, ["ok.example.org", "secret.example.com"]) == [
        DISCOVERY_RUN_ERROR_TARGET_EXCLUDED_BY_BOUNDARY
    ]


def test_approved_boundary_with_no_exclusions_allows_discovery(db: Session) -> None:
    _boundary(db, [])

    assert _gate(db, ["example.com"]) == []


def test_another_tenants_boundary_does_not_satisfy_the_requirement(db: Session) -> None:
    db.add(Organization(id=2, name="Other", slug="other", country="DK"))
    subject = PermissionSubject(organization_id=2, subject_kind="discovery_scope_proposal")
    db.add(subject)
    db.flush()
    profile = PermissionProfile(
        organization_id=2,
        subject_id=subject.id,
        name="Other tenant profile",
        capabilities=[],
        discovery_capabilities=[],
        status="active",
    )
    db.add(profile)
    db.flush()
    db.add(
        DiscoveryScopeProposal(
            organization_id=2,
            evidence_source_id=SOURCE_ID,
            status=DiscoveryScopeProposalStatus.APPROVED.value,
            inclusions=[],
            exclusions=["secret.example.com"],
            checks=[],
            permission_subject_id=subject.id,
            permission_profile_id=profile.id,
            rationale={},
        )
    )
    db.commit()

    assert _gate(db, ["secret.example.com"]) == [DISCOVERY_RUN_ERROR_BOUNDARY_APPROVAL_REQUIRED]
