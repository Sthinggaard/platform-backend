"""CA-05.B routes — the authorisation boundary in particular: proposing is
admin-gated, while *deciding* belongs to the Technical Setup Owner or the
manager tier, so a plain member must still be refused at the route."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import discovery_run as routes
from src.core.constants.discovery_scope_proposal_enums import DiscoveryScopeProposalStatus
from src.core.constants.evidence_scanner_enums import ScannerTargetStatus
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ResourceNotFoundError
from src.core.model_defs.assets_runtime import Asset
from src.core.model_defs.discovery_scope_proposal import DiscoveryScopeProposal
from src.core.model_defs.evidence_scanner import ScannerDomainTarget, ScannerInstance, ScannerNetworkTarget
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.model_defs.organization_identity import OrganizationScope
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.model_defs.tenant_identity import AuditEvent, User
from src.core.model_defs.tenant_org import Organization

SOURCE_ID = "src-1"
TSO_USER_ID = 1
MEMBER_USER_ID = 2

_TABLES = (
    Organization.__table__,
    User.__table__,
    Asset.__table__,
    AuditEvent.__table__,
    EvidenceSource.__table__,
    ScannerInstance.__table__,
    ScannerDomainTarget.__table__,
    ScannerNetworkTarget.__table__,
    OrganizationScope.__table__,
    # Proposing writes a subject row and the profile that bounds it, and
    # `DiscoveryScopeProposal.permission_subject_id` is a real foreign key into
    # the supertable — so the sqlite schema this fixture builds by hand has to
    # carry both. They were left out when CA-07.3 introduced the supertable,
    # and every route test in this file failed on "no such table:
    # permission_subjects" — invisibly, because pushes to `dev` were embargoed
    # at the time.
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
    session.add_all(
        [
            Organization(
                id=1, name="Org", slug="org", country="DK", technical_setup_owner_user_id=TSO_USER_ID
            ),
            User(id=TSO_USER_ID, organization_id=1, email="tso@example.com", role="org_admin"),
            User(id=MEMBER_USER_ID, organization_id=1, email="member@example.com", role="member"),
            EvidenceSource(id=SOURCE_ID, organization_id=1, name="Scanner", type="scanner", mode="agent"),
            ScannerInstance(
                id="inst-1",
                organization_id=1,
                evidence_source_id=SOURCE_ID,
                name="Collector",
                installation_method="docker",
                activation_token_hash="hash",
                status="connected",
                scan_profile="external_attack_surface",
            ),
            ScannerDomainTarget(
                organization_id=1,
                evidence_source_id=SOURCE_ID,
                domain="draft.example.com",
                source="manual",
                ownership_status="owned",
                status=ScannerTargetStatus.DRAFT.value,
            ),
        ]
    )
    session.commit()
    yield session
    session.close()


def _ctx(user_id: int) -> TenantContext:
    return TenantContext(
        user_id=user_id,
        organization_id=1,
        email=f"user{user_id}@example.com",
        roles=["org_admin"],
        permissions=[],
    )


def _propose(db: Session, actor: int = TSO_USER_ID):
    return routes.create_scope_proposal_route(
        SOURCE_ID,
        payload=routes.CreateScopeProposalRequest(),
        ctx=_ctx(actor),
        db=db,
    )


def test_propose_returns_inclusions_with_rationale(db: Session) -> None:
    response = _propose(db)

    assert response.status == DiscoveryScopeProposalStatus.AWAITING_APPROVAL.value
    values = {item.value for item in response.inclusions}
    assert "draft.example.com" in values
    assert next(i for i in response.inclusions if i.value == "draft.example.com").rationale


def test_member_cannot_approve_through_the_route(db: Session) -> None:
    """The route itself is reachable by any admin; the approver check lives in
    the service and must still refuse a member here."""
    proposal = _propose(db)

    with pytest.raises(AuthorizationError, match="may decide"):
        routes.approve_scope_proposal_route(
            SOURCE_ID,
            proposal.id,
            payload=routes.ScopeDecisionRequest(),
            ctx=_ctx(MEMBER_USER_ID),
            db=db,
        )


def test_technical_setup_owner_approves(db: Session) -> None:
    proposal = _propose(db)

    response = routes.approve_scope_proposal_route(
        SOURCE_ID,
        proposal.id,
        payload=routes.ScopeDecisionRequest(note="ok"),
        ctx=_ctx(TSO_USER_ID),
        db=db,
    )

    assert response.status == DiscoveryScopeProposalStatus.APPROVED.value
    assert response.decided_by_user_id == TSO_USER_ID
    assert response.decision_note == "ok"


def test_get_returns_a_proposal_still_awaiting_decision(db: Session) -> None:
    """A pending proposal must be visible — otherwise nobody can approve it and
    discovery stays blocked forever with no way out in the UI."""
    proposal = _propose(db)

    current = routes.get_scope_proposal_route(SOURCE_ID, ctx=_ctx(TSO_USER_ID), db=db)

    assert current is not None
    assert current.id == proposal.id
    assert current.status == DiscoveryScopeProposalStatus.AWAITING_APPROVAL.value


def test_get_returns_none_when_nothing_has_been_proposed(db: Session) -> None:
    assert routes.get_scope_proposal_route(SOURCE_ID, ctx=_ctx(TSO_USER_ID), db=db) is None


def test_get_returns_the_approved_boundary(db: Session) -> None:
    proposal = _propose(db)
    routes.approve_scope_proposal_route(
        SOURCE_ID,
        proposal.id,
        payload=routes.ScopeDecisionRequest(),
        ctx=_ctx(TSO_USER_ID),
        db=db,
    )

    current = routes.get_scope_proposal_route(SOURCE_ID, ctx=_ctx(TSO_USER_ID), db=db)

    assert current is not None
    assert current.id == proposal.id


def test_rejected_proposal_is_not_resurfaced(db: Session) -> None:
    proposal = _propose(db)

    routes.reject_scope_proposal_route(
        SOURCE_ID,
        proposal.id,
        payload=routes.ScopeDecisionRequest(note="too wide"),
        ctx=_ctx(TSO_USER_ID),
        db=db,
    )

    assert routes.get_scope_proposal_route(SOURCE_ID, ctx=_ctx(TSO_USER_ID), db=db) is None


def test_unknown_proposal_is_not_found(db: Session) -> None:
    with pytest.raises(ResourceNotFoundError):
        routes.approve_scope_proposal_route(
            SOURCE_ID,
            "missing",
            payload=routes.ScopeDecisionRequest(),
            ctx=_ctx(TSO_USER_ID),
            db=db,
        )


def test_capability_beyond_profile_is_rejected_by_the_route(db: Session) -> None:
    from src.core.exceptions import ValidationError

    with pytest.raises(ValidationError, match="does not permit"):
        routes.create_scope_proposal_route(
            SOURCE_ID,
            payload=routes.CreateScopeProposalRequest(capabilities=["vulnerability_checks"]),
            ctx=_ctx(TSO_USER_ID),
            db=db,
        )
