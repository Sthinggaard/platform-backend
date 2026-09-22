"""Leadership authorisation is tenant-scoped, human-approved, and gates owner invites."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import leadership_authorization as leadership_routes
from src.api.schemas.process_ownership import ProcessOwnershipInvitationRequest
from src.core.constants.leadership_authorization_enums import (
    LEADERSHIP_AUTHORIZATION_AUDIT_APPROVED,
    LEADERSHIP_AUTHORIZATION_AUDIT_DRAFT_CREATED,
    LEADERSHIP_AUTHORIZATION_AUDIT_SELF_AUTHORIZED,
    LEADERSHIP_AUTHORIZATION_AUDIT_SUBMITTED,
    LeadershipApprovingBody,
    LeadershipAuthorizationStatus,
)
from src.core.constants.org_access_enums import CanonicalMandateRole, MandateAssignmentSubjectType, MandateScopeType
from src.core.constants.process_ownership_enums import ProcessOwnershipStatus
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ValidationError
from src.core.model_defs.leadership_authorization import LeadershipAuthorization
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.models import AuditEvent, Organization, ProcessOwnerAcceptance, User, ValueStream
from src.core.repository import TenantRepository
from src.core.services.leadership_authorization_service import (
    backfill_leadership_authorization_for_legacy_org,
    get_active_leadership_authorization,
)
from src.api.routes import process_ownership


# --- Route-level lifecycle tests (fake, in-memory repository) --------------


class FakeQuery:
    def __init__(self, rows):
        self.rows = list(rows)

    def filter(self, *expressions, **_kwargs):
        for expression in expressions:
            left = getattr(expression, "left", None)
            right = getattr(expression, "right", None)
            field_name = getattr(left, "key", None)
            value = getattr(right, "value", None)
            if field_name is not None:
                self.rows = [row for row in self.rows if getattr(row, field_name, None) == value]
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def first(self):
        return self.rows[0] if self.rows else None


class FakeDB:
    def __init__(self, records):
        self.records = records
        self.added: list[object] = []

    def query(self, model):
        return FakeQuery(self.records.get(model, []))

    def add(self, record):
        self.added.append(record)
        self.records.setdefault(type(record), []).append(record)

    def flush(self):
        for record in self.added:
            if isinstance(record, LeadershipAuthorization) and record.id is None:
                record.id = str(uuid4())

    def commit(self):
        pass

    def refresh(self, _record):
        pass


class FakeTenantRepository:
    def __init__(self, db, model_class, organization_id):
        self.db = db
        self.model_class = model_class
        self.organization_id = organization_id

    def _records(self):
        return [
            record
            for record in self.db.records.get(self.model_class, [])
            if record.organization_id == self.organization_id
        ]

    def get_by_id(self, record_id):
        return next((record for record in self._records() if record.id == record_id), None)

    def filter_by(self, **kwargs):
        return [
            record
            for record in self._records()
            if all(getattr(record, key) == value for key, value in kwargs.items())
        ]


def _context(user_id: int) -> TenantContext:
    return TenantContext(
        user_id=user_id,
        organization_id=7,
        email=f"user-{user_id}@risklence.test",
        roles=["org_admin"],
        permissions=[],
    )


def _user(user_id: int, role: str = "org_admin") -> User:
    return User(
        id=user_id,
        organization_id=7,
        email=f"user-{user_id}@risklence.test",
        role=role,
        is_active=True,
    )


@pytest.fixture(autouse=True)
def tenant_repository(monkeypatch):
    monkeypatch.setattr(leadership_routes, "TenantRepository", FakeTenantRepository)


def test_leadership_authorization_requires_admin_draft_and_sponsor_self_approval():
    db = FakeDB(
        {
            User: [_user(1), _user(2)],
            LeadershipAuthorization: [],
        }
    )

    draft = leadership_routes.create_draft(
        leadership_routes.LeadershipAuthorizationDraftRequest(
            sponsor_user_id=2,
            approving_body=LeadershipApprovingBody.BOARD_RISK_COMMITTEE,
            authorized_scope="Authorise the organisation-wide onboarding programme.",
        ),
        ctx=_context(1),
        db=db,
    )
    assert draft.status == LeadershipAuthorizationStatus.DRAFT.value
    authorization = db.records[LeadershipAuthorization][0]
    assert any(
        event.event_type == LEADERSHIP_AUTHORIZATION_AUDIT_DRAFT_CREATED
        for event in db.added
        if isinstance(event, AuditEvent)
    )

    submitted = leadership_routes.submit_draft(authorization.id, ctx=_context(1), db=db)
    assert submitted.status == LeadershipAuthorizationStatus.LEADERSHIP_REVIEW.value
    assert any(
        event.event_type == LEADERSHIP_AUTHORIZATION_AUDIT_SUBMITTED
        for event in db.added
        if isinstance(event, AuditEvent)
    )

    # Only the named sponsor (user 2) may approve — not the admin who prepared it.
    with pytest.raises(AuthorizationError):
        leadership_routes.approve_draft(
            authorization.id,
            leadership_routes.LeadershipAuthorizationApprovalRequest(),
            ctx=_context(1),
            db=db,
        )

    approved = leadership_routes.approve_draft(
        authorization.id,
        leadership_routes.LeadershipAuthorizationApprovalRequest(
            approval_reference="board-minutes-2026-07"
        ),
        ctx=_context(2),
        db=db,
    )
    assert approved.status == LeadershipAuthorizationStatus.ACTIVE.value
    assert approved.approved_by == "2"
    assert approved.sponsor_user_id == 2
    assert approved.backfilled is False
    assert any(
        event.event_type == LEADERSHIP_AUTHORIZATION_AUDIT_APPROVED
        for event in db.added
        if isinstance(event, AuditEvent)
    )


def test_self_authorize_creates_an_immediately_active_authorization_naming_the_actor_as_sponsor():
    db = FakeDB({User: [_user(1)], LeadershipAuthorization: []})

    authorization = leadership_routes.self_authorize(
        leadership_routes.LeadershipAuthorizationSelfAuthorizeRequest(
            sponsor_user_id=1,
            approving_body=LeadershipApprovingBody.CRO,
            authorized_scope="Authorise the onboarding programme.",
        ),
        ctx=_context(1),
        db=db,
    )

    assert authorization.status == LeadershipAuthorizationStatus.ACTIVE.value
    assert authorization.sponsor_user_id == 1
    assert authorization.approved_by == "1"
    assert authorization.prepared_by == "1"
    assert authorization.submitted_by == "1"
    assert authorization.effective_from is not None
    assert any(
        event.event_type == LEADERSHIP_AUTHORIZATION_AUDIT_SELF_AUTHORIZED
        for event in db.added
        if isinstance(event, AuditEvent)
    )
    # Never recorded as a delegated approval — it's the same human, one step.
    assert not any(
        event.event_type == LEADERSHIP_AUTHORIZATION_AUDIT_APPROVED
        for event in db.added
        if isinstance(event, AuditEvent)
    )


def test_self_authorize_allows_naming_a_different_person_as_sponsor():
    # The person running onboarding (an admin) isn't always the accountable
    # leader — e.g. an IT admin onboarding on behalf of the actual CEO.
    db = FakeDB({User: [_user(1), _user(2)], LeadershipAuthorization: []})

    authorization = leadership_routes.self_authorize(
        leadership_routes.LeadershipAuthorizationSelfAuthorizeRequest(
            sponsor_user_id=2,
            approving_body=LeadershipApprovingBody.CRO,
            authorized_scope="Authorise the onboarding programme.",
        ),
        ctx=_context(1),
        db=db,
    )

    assert authorization.status == LeadershipAuthorizationStatus.ACTIVE.value
    assert authorization.sponsor_user_id == 2
    # The actor performed the action; the named sponsor is who's accountable.
    assert authorization.approved_by == "1"
    assert authorization.prepared_by == "1"


def test_self_authorize_requires_admin_access():
    db = FakeDB({User: [_user(1, role="member")], LeadershipAuthorization: []})

    with pytest.raises(AuthorizationError):
        leadership_routes.self_authorize(
            leadership_routes.LeadershipAuthorizationSelfAuthorizeRequest(
                sponsor_user_id=1,
                approving_body=LeadershipApprovingBody.CRO,
                authorized_scope="Authorise the onboarding programme.",
            ),
            ctx=_context(1),
            db=db,
        )


def test_self_authorize_supersedes_an_existing_active_authorization():
    existing = LeadershipAuthorization(
        id="authorization-existing",
        organization_id=7,
        status=LeadershipAuthorizationStatus.ACTIVE.value,
        version=1,
        sponsor_user_id=1,
        approving_body=LeadershipApprovingBody.CISO.value,
        authorized_scope="Prior authorisation.",
    )
    db = FakeDB({User: [_user(1)], LeadershipAuthorization: [existing]})

    authorization = leadership_routes.self_authorize(
        leadership_routes.LeadershipAuthorizationSelfAuthorizeRequest(
            sponsor_user_id=1,
            approving_body=LeadershipApprovingBody.CRO,
            authorized_scope="Renewed authorisation.",
        ),
        ctx=_context(1),
        db=db,
    )

    assert authorization.version == 2
    assert existing.status == LeadershipAuthorizationStatus.SUPERSEDED.value
    assert existing.superseded_by_id == authorization.id


def test_leadership_authorization_rejects_approval_by_anyone_other_than_the_named_sponsor():
    authorization = LeadershipAuthorization(
        id="authorization-1",
        organization_id=7,
        status=LeadershipAuthorizationStatus.LEADERSHIP_REVIEW.value,
        version=1,
        sponsor_user_id=1,
        approving_body=LeadershipApprovingBody.CISO.value,
        authorized_scope="Authorise the onboarding programme.",
    )
    db = FakeDB({User: [_user(1), _user(2)], LeadershipAuthorization: [authorization]})

    with pytest.raises(AuthorizationError):
        leadership_routes.approve_draft(
            authorization.id,
            leadership_routes.LeadershipAuthorizationApprovalRequest(),
            ctx=_context(2),
            db=db,
        )


def test_non_admin_cannot_prepare_a_leadership_authorization_draft():
    db = FakeDB({User: [_user(1, role="member")], LeadershipAuthorization: []})

    with pytest.raises(AuthorizationError):
        leadership_routes.create_draft(
            leadership_routes.LeadershipAuthorizationDraftRequest(
                sponsor_user_id=1,
                approving_body=LeadershipApprovingBody.SENIOR_MANAGEMENT,
                authorized_scope="Authorise the onboarding programme.",
            ),
            ctx=_context(1),
            db=db,
        )


# --- Service-level backfill and owner-invite gating (real sqlite db) -------


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            User.__table__,
            ValueStream.__table__,
            OrgMandateRoleAssignment.__table__,
            OrgMandateScopeBinding.__table__,
            ProcessOwnerAcceptance.__table__,
            LeadershipAuthorization.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org"),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
            User(id=2, organization_id=1, email="owner@example.com", role="member"),
            ValueStream(id="process-1", organization_id=1, name="Order to cash"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _binding(db: Session) -> OrgMandateScopeBinding:
    assignment = OrgMandateRoleAssignment(
        id="assignment-1",
        organization_id=1,
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        subject_type=MandateAssignmentSubjectType.USER.value,
        user_id=2,
    )
    binding = OrgMandateScopeBinding(
        id="binding-1",
        organization_id=1,
        scope_type=MandateScopeType.BUSINESS_PROCESS.value,
        value_stream_id="process-1",
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        role_assignment_id=assignment.id,
    )
    db.add_all([assignment, binding])
    db.commit()
    return binding


def test_owner_invite_is_blocked_until_leadership_authorises_the_programme(db: Session):
    binding = _binding(db)

    with pytest.raises(ValidationError, match="Leadership must authorise"):
        process_ownership.create_process_ownership_invitation(
            ProcessOwnershipInvitationRequest(scope_binding_id=binding.id),
            ctx=TenantContext(
                user_id=1, organization_id=1, email="admin@example.com", roles=["org_admin"], permissions=[]
            ),
            db=db,
        )


def test_owner_invite_succeeds_once_leadership_authorization_is_active(db: Session):
    binding = _binding(db)
    db.add(
        LeadershipAuthorization(
            id="authorization-1",
            organization_id=1,
            status=LeadershipAuthorizationStatus.ACTIVE.value,
            version=1,
            sponsor_user_id=1,
            approving_body=LeadershipApprovingBody.BOARD_RISK_COMMITTEE.value,
            authorized_scope="Authorise the onboarding programme.",
            approved_by="1",
        )
    )
    db.commit()

    invited = process_ownership.create_process_ownership_invitation(
        ProcessOwnershipInvitationRequest(scope_binding_id=binding.id),
        ctx=TenantContext(
            user_id=1, organization_id=1, email="admin@example.com", roles=["org_admin"], permissions=[]
        ),
        db=db,
    )
    assert invited.status is ProcessOwnershipStatus.INVITATION_SENT


def test_backfill_is_a_noop_for_a_genuinely_new_org_with_no_prior_ownership(db: Session):
    assert backfill_leadership_authorization_for_legacy_org(db, 1) is None
    assert get_active_leadership_authorization(db, 1) is None


def test_backfill_creates_a_flagged_active_authorization_for_a_legacy_org(db: Session):
    binding = _binding(db)
    acceptance = ProcessOwnerAcceptance(
        id="acceptance-1",
        organization_id=1,
        process_id="process-1",
        scope_binding_id=binding.id,
        role_assignment_id="assignment-1",
        owner_user_id=2,
        status=ProcessOwnershipStatus.ACCEPTED.value,
    )
    db.add(acceptance)
    db.commit()

    backfilled = backfill_leadership_authorization_for_legacy_org(db, 1)
    db.commit()

    assert backfilled is not None
    assert backfilled.backfilled is True
    assert backfilled.status == LeadershipAuthorizationStatus.ACTIVE.value
    assert backfilled.sponsor_user_id is None  # never invent a sponsor for a legacy baseline
    assert get_active_leadership_authorization(db, 1).id == backfilled.id

    # Idempotent: a second call is a no-op once an active row exists.
    assert backfill_leadership_authorization_for_legacy_org(db, 1) is None


def test_status_route_reports_active_pending_and_history(db: Session, monkeypatch):
    # The module-level autouse fixture above swaps in FakeTenantRepository for
    # the fake-in-memory route tests; this test exercises the real lifecycle
    # against a real sqlite session, so it needs the real repository back.
    monkeypatch.setattr(leadership_routes, "TenantRepository", TenantRepository)

    draft = leadership_routes.create_draft(
        leadership_routes.LeadershipAuthorizationDraftRequest(
            sponsor_user_id=2,
            approving_body=LeadershipApprovingBody.BOARD_RISK_COMMITTEE,
            authorized_scope="Authorise the organisation-wide onboarding programme.",
        ),
        ctx=TenantContext(
            user_id=1, organization_id=1, email="admin@example.com", roles=["org_admin"], permissions=[]
        ),
        db=db,
    )
    leadership_routes.submit_draft(
        draft.id,
        ctx=TenantContext(
            user_id=1, organization_id=1, email="admin@example.com", roles=["org_admin"], permissions=[]
        ),
        db=db,
    )

    status = leadership_routes.get_status(
        ctx=TenantContext(
            user_id=1, organization_id=1, email="admin@example.com", roles=["org_admin"], permissions=[]
        ),
        db=db,
    )
    assert status.active is None
    assert status.pending is not None and status.pending.id == draft.id
    assert status.pending.status == LeadershipAuthorizationStatus.LEADERSHIP_REVIEW.value
    assert len(status.history) == 1

    leadership_routes.approve_draft(
        draft.id,
        leadership_routes.LeadershipAuthorizationApprovalRequest(),
        ctx=TenantContext(
            user_id=2, organization_id=1, email="owner@example.com", roles=["member"], permissions=[]
        ),
        db=db,
    )

    status_after_approval = leadership_routes.get_status(
        ctx=TenantContext(
            user_id=1, organization_id=1, email="admin@example.com", roles=["org_admin"], permissions=[]
        ),
        db=db,
    )
    assert status_after_approval.active is not None and status_after_approval.active.id == draft.id
    assert status_after_approval.pending is None
