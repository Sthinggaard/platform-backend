"""CA-05.B — scope proposal: the three ways a boundary could silently widen
(an exclusion leaking into inclusions, a capability exceeding the scanner
profile, an unauthorised actor approving), plus who may sign off, immutability
of an approved boundary, and tenant isolation."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.discovery_scope_proposal_enums import (
    DiscoveryCapability,
    DiscoveryScopeProposalStatus,
)
from src.core.constants.evidence_scanner_enums import ScannerTargetStatus
from src.core.database import Base
from src.core.model_defs.assets_runtime import Asset
from src.core.model_defs.discovery_scope_proposal import DiscoveryScopeProposal
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.model_defs.evidence_scanner import ScannerDomainTarget, ScannerNetworkTarget
from src.core.model_defs.organization_identity import OrganizationScope
from src.core.model_defs.tenant_identity import AuditEvent, User
from src.core.model_defs.tenant_org import Organization
from src.core.services.discovery_scope_proposal_service import (
    ScopeProposalError,
    approve_scope_proposal,
    build_scope_proposal,
    get_approved_scope,
    reject_scope_proposal,
)

SOURCE_ID = "src-1"
TSO_USER_ID = 1
OTHER_USER_ID = 2

FULL_PROFILE = {
    "allowsExternalDiscovery": True,
    "allowsInternalDiscovery": True,
    "allowsFingerprinting": True,
    "allowsVulnerabilityChecks": True,
}
EXTERNAL_ONLY_PROFILE = {
    "allowsExternalDiscovery": True,
    "allowsInternalDiscovery": False,
    "allowsFingerprinting": False,
    "allowsVulnerabilityChecks": False,
}

_TABLES = (
    Organization.__table__,
    User.__table__,
    Asset.__table__,
    AuditEvent.__table__,
    ScannerDomainTarget.__table__,
    ScannerNetworkTarget.__table__,
    OrganizationScope.__table__,
    DiscoveryScopeProposal.__table__,
    PermissionSubject.__table__,
    PermissionProfile.__table__,
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
            Organization(id=1, name="Org", slug="org", country="DK", technical_setup_owner_user_id=TSO_USER_ID),
            Organization(id=2, name="Other", slug="other", country="DK"),
            User(id=TSO_USER_ID, organization_id=1, email="tso@example.com", role="org_admin"),
            User(id=OTHER_USER_ID, organization_id=1, email="member@example.com", role="member"),
            User(id=3, organization_id=1, email="manager@example.com", role="manager"),
            User(id=4, organization_id=1, email="admin@example.com", role="admin"),
            User(id=5, organization_id=1, email="consultant@example.com", role="consultant"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _domain(db: Session, domain: str, status: str, *, org: int = 1) -> None:
    db.add(
        ScannerDomainTarget(
            organization_id=org,
            evidence_source_id=SOURCE_ID,
            domain=domain,
            source="manual",
            ownership_status="owned",
            status=status,
        )
    )
    db.commit()


def _build(db: Session, *, profile: dict = FULL_PROFILE, requested=None, org: int = 1):
    return build_scope_proposal(
        db,
        organization_id=org,
        evidence_source_id=SOURCE_ID,
        profile_snapshot=profile,
        requested_capabilities=requested,
    )


def test_proposal_includes_only_uncovered_candidates(db: Session) -> None:
    _domain(db, "draft.example.com", ScannerTargetStatus.DRAFT.value)
    _domain(db, "approved.example.com", ScannerTargetStatus.APPROVED.value)

    proposal = _build(db)

    assert "draft.example.com" in proposal.inclusions
    assert "approved.example.com" not in proposal.inclusions


def test_excluded_value_never_appears_in_inclusions(db: Session) -> None:
    _domain(db, "secret.example.com", ScannerTargetStatus.EXCLUDED.value)

    proposal = _build(db)

    assert "secret.example.com" in proposal.exclusions
    assert "secret.example.com" not in proposal.inclusions


def test_capabilities_default_to_what_the_profile_permits(db: Session) -> None:
    proposal = _build(db, profile=EXTERNAL_ONLY_PROFILE)

    profile = db.get(PermissionProfile, proposal.permission_profile_id)
    assert profile is not None
    assert profile.discovery_capabilities == [
        DiscoveryCapability.EXTERNAL_DISCOVERY.value
    ]


def test_capability_beyond_the_profile_is_refused(db: Session) -> None:
    """Refused outright rather than silently dropped — silently narrowing would
    leave the reviewer approving a boundary different from the one shown."""
    with pytest.raises(ScopeProposalError, match="does not permit"):
        _build(
            db,
            profile=EXTERNAL_ONLY_PROFILE,
            requested=[DiscoveryCapability.VULNERABILITY_CHECKS.value],
        )


def test_unknown_capability_is_refused(db: Session) -> None:
    with pytest.raises(ScopeProposalError, match="Unknown"):
        _build(db, requested=["root_access"])


def test_member_cannot_approve(db: Session) -> None:
    """A plain member has no authority over what may be scanned."""
    proposal = _build(db)
    db.commit()

    with pytest.raises(ScopeProposalError, match="may decide"):
        approve_scope_proposal(
            db, organization_id=1, proposal_id=proposal.id, actor_user_id=OTHER_USER_ID
        )


@pytest.mark.parametrize("actor_user_id", [3, 4])
def test_manager_tier_may_approve(db: Session, actor_user_id: int) -> None:
    """Leadership (manager/admin/org_admin) can sign off too, so accountability
    is not a single point of failure when the Technical Setup Owner is away.
    The audit event still records who actually decided."""
    proposal = _build(db)
    db.commit()

    decision = approve_scope_proposal(
        db, organization_id=1, proposal_id=proposal.id, actor_user_id=actor_user_id
    )
    db.commit()

    assert decision.status == DiscoveryScopeProposalStatus.APPROVED.value
    assert decision.decided_by_user_id == actor_user_id


def test_consultant_cannot_approve(db: Session) -> None:
    """DISC-44 defines consultant as external, time-boxed and read-only. An
    external party approving what may be scanned would weaken the audit
    argument, not strengthen it."""
    proposal = _build(db)
    db.commit()

    with pytest.raises(ScopeProposalError, match="read-only"):
        approve_scope_proposal(db, organization_id=1, proposal_id=proposal.id, actor_user_id=5)


def test_technical_setup_owner_approves(db: Session) -> None:
    proposal = _build(db)
    db.commit()

    decision = approve_scope_proposal(
        db, organization_id=1, proposal_id=proposal.id, actor_user_id=TSO_USER_ID
    )
    db.commit()

    assert decision.status == DiscoveryScopeProposalStatus.APPROVED.value
    assert get_approved_scope(db, organization_id=1, evidence_source_id=SOURCE_ID).id == proposal.id


def test_approved_proposal_is_immutable(db: Session) -> None:
    proposal = _build(db)
    db.commit()
    approve_scope_proposal(
        db, organization_id=1, proposal_id=proposal.id, actor_user_id=TSO_USER_ID
    )
    db.commit()

    with pytest.raises(ScopeProposalError, match="Cannot move"):
        reject_scope_proposal(
            db, organization_id=1, proposal_id=proposal.id, actor_user_id=TSO_USER_ID
        )


def test_rejected_proposal_is_not_in_force(db: Session) -> None:
    proposal = _build(db)
    db.commit()
    reject_scope_proposal(
        db, organization_id=1, proposal_id=proposal.id, actor_user_id=TSO_USER_ID, note="too wide"
    )
    db.commit()

    assert get_approved_scope(db, organization_id=1, evidence_source_id=SOURCE_ID) is None


def test_new_proposal_supersedes_the_open_one(db: Session) -> None:
    first = _build(db)
    db.commit()
    _build(db)
    db.commit()

    db.refresh(first)
    assert first.status == DiscoveryScopeProposalStatus.SUPERSEDED.value


def test_approval_still_possible_when_no_owner_is_assigned(db: Session) -> None:
    """With no Technical Setup Owner assigned, the manager tier can still sign
    off — otherwise an unassigned owner would deadlock discovery entirely.
    (Assigning an owner remains a separate readiness blocker on the run.)"""
    organization = db.query(Organization).filter(Organization.id == 1).first()
    organization.technical_setup_owner_user_id = None
    db.commit()
    proposal = _build(db)
    db.commit()

    decision = approve_scope_proposal(
        db, organization_id=1, proposal_id=proposal.id, actor_user_id=4
    )

    assert decision.status == DiscoveryScopeProposalStatus.APPROVED.value


def test_proposal_from_another_tenant_is_not_decidable(db: Session) -> None:
    proposal = _build(db)
    db.commit()

    with pytest.raises(ScopeProposalError, match="not found"):
        approve_scope_proposal(
            db, organization_id=2, proposal_id=proposal.id, actor_user_id=TSO_USER_ID
        )


def test_proposing_writes_an_audit_event(db: Session) -> None:
    _domain(db, "draft.example.com", ScannerTargetStatus.DRAFT.value)
    _build(db)
    db.commit()

    events = db.query(AuditEvent).filter(
        AuditEvent.event_type == "discovery_scope_proposal.proposed"
    ).all()

    assert len(events) == 1
    assert events[0].metadata_json["inclusionCount"] == 1


def test_approval_writes_an_audit_event_naming_the_actor(db: Session) -> None:
    proposal = _build(db)
    db.commit()
    approve_scope_proposal(
        db, organization_id=1, proposal_id=proposal.id, actor_user_id=TSO_USER_ID, note="ok"
    )
    db.commit()

    event = db.query(AuditEvent).filter(
        AuditEvent.event_type == "discovery_scope_proposal.approved"
    ).first()

    assert event.actor_user_id == TSO_USER_ID
    assert event.metadata_json["note"] == "ok"


def test_rationale_explains_each_inclusion(db: Session) -> None:
    _domain(db, "draft.example.com", ScannerTargetStatus.DRAFT.value)

    proposal = _build(db)

    assert "draft.example.com" in proposal.rationale
    assert proposal.rationale["draft.example.com"]
