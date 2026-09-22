"""CA-10 (#50) — ProcessScanScope routes: draft/submit/approve/mark-outdated
/revoke/effective, and the authorization gate (org MANAGER_ROLES or the
process's own accepted owner — matches scanner_management.py's
_require_process_link_access exactly, since a scan scope governs what a
ProcessScannerLink the same authority already granted may do).
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

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import process_ownership as process_ownership_routes
from src.api.routes import process_scan_scopes as routes
from src.api.schemas.process_ownership import ProcessOwnershipInvitationRequest
from src.api.schemas.process_scan_scope import (
    ApproveProcessScanScopeRequest,
    CreateProcessScanScopeRequest,
    MarkProcessScanScopeOutdatedRequest,
    SubmitProcessScanScopeRequest,
)
from src.core.constants.leadership_authorization_enums import LeadershipAuthorizationStatus
from src.core.constants.org_access_enums import CanonicalMandateRole, MandateAssignmentSubjectType, MandateScopeType
from src.core.constants.process_scan_scope_enums import ProcessScanScopeStatus
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.leadership_authorization import LeadershipAuthorization
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.model_defs.process_scan_scope import ProcessScanScope
from src.core.model_defs.process_scanner_link import ProcessScannerLink
from src.core.model_defs.value_streams import ValueStream
from src.core.models import AuditEvent, Organization, ProcessOwnerAcceptance, User


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    tables = [
        Organization.__table__,
        User.__table__,
        ValueStream.__table__,
        ProcessScanScope.__table__,
        ProcessScannerLink.__table__,
        AuditEvent.__table__,
        OrgMandateRoleAssignment.__table__,
        OrgMandateScopeBinding.__table__,
        ProcessOwnerAcceptance.__table__,
        LeadershipAuthorization.__table__,
    ]
    for table in tables:
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=tables)
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org", country="DK"),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
            User(id=2, organization_id=1, email="owner@example.com", role="member"),
            User(id=3, organization_id=1, email="stranger@example.com", role="member"),
            ValueStream(id="process-1", organization_id=1, name="Order to cash"),
            LeadershipAuthorization(
                id="leadership-authorization-1",
                organization_id=1,
                status=LeadershipAuthorizationStatus.ACTIVE.value,
                version=1,
                sponsor_user_id=1,
                approving_body="senior_management",
                authorized_scope="Full onboarding programme.",
                approved_by="1",
            ),
        ]
    )
    session.commit()
    yield session
    session.close()


def _ctx(user_id: int, role: str = "org_admin") -> TenantContext:
    return TenantContext(user_id=user_id, organization_id=1, email="x@example.com", roles=[role], permissions=[])


def _accept_process_ownership(db: Session, *, process_id: str, owner_user_id: int) -> None:
    """Same helper shape as test_scanner_management.py's own
    _accept_process_ownership — reaches ProcessOwnerAcceptance(ACCEPTED) via
    the real invite/accept routes rather than a hand-rolled row."""
    assignment = OrgMandateRoleAssignment(
        id=f"assignment-{owner_user_id}",
        organization_id=1,
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        subject_type=MandateAssignmentSubjectType.USER.value,
        user_id=owner_user_id,
    )
    db.add(assignment)
    db.flush()
    binding = OrgMandateScopeBinding(
        id=f"binding-{process_id}",
        organization_id=1,
        scope_type=MandateScopeType.BUSINESS_PROCESS.value,
        value_stream_id=process_id,
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        role_assignment_id=assignment.id,
    )
    db.add(binding)
    db.commit()
    process_ownership_routes.create_process_ownership_invitation(
        ProcessOwnershipInvitationRequest(scope_binding_id=binding.id), ctx=_ctx(1, "org_admin"), db=db
    )
    process_ownership_routes.accept_process_owner_invitation(process_id, ctx=_ctx(owner_user_id, "member"), db=db)


def _draft_scope(db: Session, *, ctx: TenantContext) -> ProcessScanScope:
    response = routes.create_process_scan_scope_route(
        "process-1", CreateProcessScanScopeRequest(checks=["nmap"]), ctx, db
    )
    return db.query(ProcessScanScope).filter(ProcessScanScope.id == response.id).one()


def test_create_route_allows_org_admin(db: Session):
    response = routes.create_process_scan_scope_route(
        "process-1", CreateProcessScanScopeRequest(checks=["nmap"]), _ctx(1), db
    )
    assert response.status == ProcessScanScopeStatus.DRAFT.value
    assert response.revision == 1


def test_create_route_rejects_a_stranger(db: Session):
    with pytest.raises(AuthorizationError):
        routes.create_process_scan_scope_route(
            "process-1", CreateProcessScanScopeRequest(checks=["nmap"]), _ctx(3, "member"), db
        )


def test_create_route_allows_the_accepted_process_owner(db: Session):
    _accept_process_ownership(db, process_id="process-1", owner_user_id=2)
    response = routes.create_process_scan_scope_route(
        "process-1", CreateProcessScanScopeRequest(checks=["nmap"]), _ctx(2, "member"), db
    )
    assert response.status == ProcessScanScopeStatus.DRAFT.value


def test_create_route_rejects_unknown_check_key(db: Session):
    with pytest.raises(ValidationError):
        routes.create_process_scan_scope_route(
            "process-1", CreateProcessScanScopeRequest(checks=["not_a_real_check"]), _ctx(1), db
        )


def test_submit_then_approve_route_activates_the_scope(db: Session):
    scope = _draft_scope(db, ctx=_ctx(1))
    routes.submit_process_scan_scope_route("process-1", scope.id, SubmitProcessScanScopeRequest(), _ctx(1), db)
    approved = routes.approve_process_scan_scope_route(
        "process-1", scope.id, ApproveProcessScanScopeRequest(), _ctx(1), db
    )
    assert approved.status == ProcessScanScopeStatus.ACTIVE.value
    assert approved.approved_by_user_id == 1


def test_approve_route_rejects_a_draft_that_was_never_submitted(db: Session):
    scope = _draft_scope(db, ctx=_ctx(1))
    with pytest.raises(ValidationError):
        routes.approve_process_scan_scope_route("process-1", scope.id, ApproveProcessScanScopeRequest(), _ctx(1), db)


def test_approve_route_404s_for_a_scope_belonging_to_a_different_process(db: Session):
    db.add(ValueStream(id="process-2", organization_id=1, name="Payroll"))
    db.commit()
    scope = _draft_scope(db, ctx=_ctx(1))
    with pytest.raises(ResourceNotFoundError):
        routes.approve_process_scan_scope_route(
            "process-2", scope.id, ApproveProcessScanScopeRequest(), _ctx(1), db
        )


def test_effective_route_404s_with_no_approved_scope(db: Session):
    with pytest.raises(ResourceNotFoundError):
        routes.get_effective_process_scan_scope_route("process-1", _ctx(1), db)


def test_effective_route_returns_the_active_scope(db: Session):
    scope = _draft_scope(db, ctx=_ctx(1))
    routes.submit_process_scan_scope_route("process-1", scope.id, SubmitProcessScanScopeRequest(), _ctx(1), db)
    routes.approve_process_scan_scope_route("process-1", scope.id, ApproveProcessScanScopeRequest(), _ctx(1), db)

    effective = routes.get_effective_process_scan_scope_route("process-1", _ctx(1), db)

    assert effective.id == scope.id


def test_mark_outdated_route_keeps_status_active(db: Session):
    scope = _draft_scope(db, ctx=_ctx(1))
    routes.submit_process_scan_scope_route("process-1", scope.id, SubmitProcessScanScopeRequest(), _ctx(1), db)
    routes.approve_process_scan_scope_route("process-1", scope.id, ApproveProcessScanScopeRequest(), _ctx(1), db)

    outdated = routes.mark_process_scan_scope_outdated_route(
        "process-1", scope.id, MarkProcessScanScopeOutdatedRequest(reason="dependency bundle republished"), _ctx(1), db
    )

    assert outdated.status == ProcessScanScopeStatus.ACTIVE.value
    assert outdated.outdated_reason == "dependency bundle republished"


def test_revoke_route_removes_effective_authorization(db: Session):
    scope = _draft_scope(db, ctx=_ctx(1))
    routes.submit_process_scan_scope_route("process-1", scope.id, SubmitProcessScanScopeRequest(), _ctx(1), db)
    routes.approve_process_scan_scope_route("process-1", scope.id, ApproveProcessScanScopeRequest(), _ctx(1), db)

    revoked = routes.revoke_process_scan_scope_route("process-1", scope.id, _ctx(1), db)

    assert revoked.status == ProcessScanScopeStatus.REVOKED.value
    with pytest.raises(ResourceNotFoundError):
        routes.get_effective_process_scan_scope_route("process-1", _ctx(1), db)


def test_every_write_route_writes_an_audit_event(db: Session):
    scope = _draft_scope(db, ctx=_ctx(1))
    routes.submit_process_scan_scope_route("process-1", scope.id, SubmitProcessScanScopeRequest(), _ctx(1), db)
    routes.approve_process_scan_scope_route("process-1", scope.id, ApproveProcessScanScopeRequest(), _ctx(1), db)
    routes.revoke_process_scan_scope_route("process-1", scope.id, _ctx(1), db)

    event_types = {row.event_type for row in db.query(AuditEvent).all()}
    assert {
        "process_scan_scope.draft_created",
        "process_scan_scope.submitted",
        "process_scan_scope.approved",
        "process_scan_scope.revoked",
    } <= event_types
