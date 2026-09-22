"""Organisation appetite governance is tenant-scoped and human-approved."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import risk_appetite_policies as appetite
from src.core.constants.leadership_authorization_enums import LeadershipAuthorizationStatus
from src.core.exceptions import AuthorizationError
from src.core.model_defs.leadership_authorization import LeadershipAuthorization
from src.core.model_defs.risk_appetite_policy import (
    APPETITE_AUDIT_APPROVED,
    APPETITE_AUDIT_DRAFT_CREATED,
    APPETITE_AUDIT_SUBMITTED,
    APPETITE_POLICY_ACTIVE,
    APPETITE_POLICY_DRAFT,
    APPETITE_POLICY_LEADERSHIP_REVIEW,
    RiskAppetitePolicy,
)
from src.core.models import AuditEvent, User


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

    def all(self):
        return list(self.rows)


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
            if isinstance(record, RiskAppetitePolicy) and record.id is None:
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


def _user(user_id: int) -> User:
    return User(
        id=user_id,
        organization_id=7,
        email=f"user-{user_id}@risklence.test",
        role="org_admin",
        is_active=True,
    )


@pytest.fixture(autouse=True)
def tenant_repository(monkeypatch):
    monkeypatch.setattr(appetite, "TenantRepository", FakeTenantRepository)


def test_organisation_appetite_requires_admin_submission_and_leadership_sponsor_approval():
    leadership_authorization = LeadershipAuthorization(
        id="leadership-authorization-1",
        organization_id=7,
        status=LeadershipAuthorizationStatus.ACTIVE.value,
        version=1,
        sponsor_user_id=2,
        approving_body="senior_management",
        authorized_scope="Organisation-wide onboarding",
    )
    db = FakeDB(
        {
            User: [_user(1), _user(2)],
            LeadershipAuthorization: [leadership_authorization],
            RiskAppetitePolicy: [],
        }
    )
    draft = appetite.create_organisation_appetite_draft(
        appetite.AppetiteDraftRequest(
            answers={"downtime": 2, "data_loss": 1},
            review_at=datetime.now(timezone.utc) + timedelta(days=90),
            note="Prepared for leadership review.",
        ),
        ctx=_context(1),
        db=db,
    )

    assert draft.status == APPETITE_POLICY_DRAFT
    policy = db.records[RiskAppetitePolicy][0]
    assert any(
        event.event_type == APPETITE_AUDIT_DRAFT_CREATED
        for event in db.added
        if isinstance(event, AuditEvent)
    )

    submitted = appetite.submit_organisation_appetite_draft(policy.id, ctx=_context(1), db=db)
    assert submitted.status == APPETITE_POLICY_LEADERSHIP_REVIEW
    assert any(
        event.event_type == APPETITE_AUDIT_SUBMITTED
        for event in db.added
        if isinstance(event, AuditEvent)
    )

    approved = appetite.approve_organisation_appetite_draft(
        policy.id,
        appetite.AppetiteApprovalRequest(
            approval_reference="leadership-meeting-2026-07",
        ),
        ctx=_context(2),
        db=db,
    )
    assert approved.status == APPETITE_POLICY_ACTIVE
    assert approved.approved_by == "2"
    assert any(
        event.event_type == APPETITE_AUDIT_APPROVED
        for event in db.added
        if isinstance(event, AuditEvent)
    )


def test_organisation_appetite_status_reports_active_pending_and_history():
    active = RiskAppetitePolicy(
        id="policy-1",
        organization_id=7,
        scope="organisation",
        answers={"downtime": 2},
        status=APPETITE_POLICY_ACTIVE,
        version=1,
        approved_by="1",
    )
    pending = RiskAppetitePolicy(
        id="policy-2",
        organization_id=7,
        scope="organisation",
        answers={"downtime": 3},
        status=APPETITE_POLICY_LEADERSHIP_REVIEW,
        version=2,
        prepared_by="1",
        submitted_by="1",
    )
    db = FakeDB({RiskAppetitePolicy: [active, pending]})

    status = appetite.get_organisation_appetite_status(ctx=_context(1), db=db)

    assert status.active is not None and status.active.policy_id == "policy-1"
    assert status.pending is not None and status.pending.policy_id == "policy-2"
    assert {item.policy_id for item in status.history} == {"policy-1", "policy-2"}


def test_organisation_appetite_status_is_empty_before_any_draft():
    db = FakeDB({RiskAppetitePolicy: []})

    status = appetite.get_organisation_appetite_status(ctx=_context(1), db=db)

    assert status.active is None
    assert status.pending is None
    assert status.history == []


def test_organisation_appetite_rejects_approval_without_an_active_leadership_authorization():
    policy = RiskAppetitePolicy(
        id="policy-1",
        organization_id=7,
        scope="organisation",
        answers={"downtime": 2},
        status=APPETITE_POLICY_LEADERSHIP_REVIEW,
        version=1,
        review_at=datetime.now(timezone.utc) + timedelta(days=90),
    )
    db = FakeDB({User: [_user(2)], RiskAppetitePolicy: [policy]})

    with pytest.raises(AuthorizationError):
        appetite.approve_organisation_appetite_draft(
            policy.id,
            appetite.AppetiteApprovalRequest(),
            ctx=_context(2),
            db=db,
        )


def test_organisation_appetite_rejects_approval_by_a_user_who_is_not_the_named_sponsor():
    leadership_authorization = LeadershipAuthorization(
        id="leadership-authorization-1",
        organization_id=7,
        status=LeadershipAuthorizationStatus.ACTIVE.value,
        version=1,
        sponsor_user_id=1,  # the named sponsor is user 1, not the caller below (user 2)
        approving_body="senior_management",
        authorized_scope="Organisation-wide onboarding",
    )
    policy = RiskAppetitePolicy(
        id="policy-1",
        organization_id=7,
        scope="organisation",
        answers={"downtime": 2},
        status=APPETITE_POLICY_LEADERSHIP_REVIEW,
        version=1,
        review_at=datetime.now(timezone.utc) + timedelta(days=90),
    )
    db = FakeDB(
        {
            User: [_user(1), _user(2)],
            LeadershipAuthorization: [leadership_authorization],
            RiskAppetitePolicy: [policy],
        }
    )

    with pytest.raises(AuthorizationError):
        appetite.approve_organisation_appetite_draft(
            policy.id,
            appetite.AppetiteApprovalRequest(),
            ctx=_context(2),
            db=db,
        )
