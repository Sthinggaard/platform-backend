"""DISC-44 — consultant-assisted access: invite-time validation.

A consultant invite must always set access_expires_at (in the future, and
never further out than CONSULTANT_MAX_ACCESS_DAYS); every other role must
never set it. Calls the route function directly, matching this codebase's
own convention (test_discovery_run.py) rather than standing up a full
HTTP client — this repo has no prior route-level test file for auth.py at
all, so this is scoped narrowly to the new consultant-specific validation,
not the full login/invite/MFA/SSO surface."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.rate_limit import auth_rate_limiter
from src.api.middleware.tenant_context import TenantContext
from src.api.routes import auth as auth_routes
from src.api.schemas.auth import InviteCreateRequest
from src.core.database import Base
from src.core.exceptions import ValidationError
from src.core.model_defs.tenant_identity import AuditEvent, InviteToken, User
from src.core.model_defs.tenant_org import AuthTenantSettings, Organization
from src.core.roles import CONSULTANT_MAX_ACCESS_DAYS


class _FakeClient:
    host = "127.0.0.1"


class _FakeState:
    pass


class _FakeRequest:
    def __init__(self, ctx: TenantContext):
        self.state = _FakeState()
        self.state.tenant_context = ctx
        self.client = _FakeClient()
        self.headers: dict[str, str] = {}


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    tables = [
        Organization.__table__,
        AuthTenantSettings.__table__,
        User.__table__,
        InviteToken.__table__,
        AuditEvent.__table__,
    ]
    for table in tables:
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=tables)
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Org", slug="org", country="DK", technical_setup_owner_user_id=1))
    session.add(AuthTenantSettings(organization_id=1, domain_allowlist=[]))
    session.add(
        User(id=1, organization_id=1, email="admin@example.com", role="org_admin", is_active=True)
    )
    session.commit()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def _clear_rate_limiter():
    auth_rate_limiter.store.clear()
    yield
    auth_rate_limiter.store.clear()


def _ctx() -> TenantContext:
    return TenantContext(user_id=1, organization_id=1, email="admin@example.com", roles=["org_admin"], permissions=[])


def test_consultant_invite_requires_access_expires_at(db: Session):
    payload = InviteCreateRequest(email="consultant@example.com", role="consultant")

    with pytest.raises(ValidationError):
        auth_routes.create_invite(payload, _FakeRequest(_ctx()), db)


def test_consultant_invite_rejects_an_expiry_in_the_past(db: Session):
    payload = InviteCreateRequest(
        email="consultant@example.com", role="consultant", access_expires_at=datetime.now(timezone.utc) - timedelta(days=1)
    )

    with pytest.raises(ValidationError):
        auth_routes.create_invite(payload, _FakeRequest(_ctx()), db)


def test_consultant_invite_rejects_an_expiry_beyond_the_max_days(db: Session):
    payload = InviteCreateRequest(
        email="consultant@example.com",
        role="consultant",
        access_expires_at=datetime.now(timezone.utc) + timedelta(days=CONSULTANT_MAX_ACCESS_DAYS + 1),
    )

    with pytest.raises(ValidationError):
        auth_routes.create_invite(payload, _FakeRequest(_ctx()), db)


def test_consultant_invite_succeeds_within_the_allowed_window(db: Session):
    expires_at = datetime.now(timezone.utc) + timedelta(days=30)
    payload = InviteCreateRequest(email="consultant@example.com", role="consultant", access_expires_at=expires_at)

    auth_routes.create_invite(payload, _FakeRequest(_ctx()), db)

    created = db.query(User).filter(User.email == "consultant@example.com").first()
    assert created is not None
    assert created.role == "consultant"
    assert created.access_expires_at is not None


def test_non_consultant_invite_rejects_an_access_expires_at(db: Session):
    payload = InviteCreateRequest(
        email="member@example.com", role="member", access_expires_at=datetime.now(timezone.utc) + timedelta(days=1)
    )

    with pytest.raises(ValidationError):
        auth_routes.create_invite(payload, _FakeRequest(_ctx()), db)


def test_plain_member_invite_still_works_unchanged(db: Session):
    payload = InviteCreateRequest(email="member@example.com", role="member")

    auth_routes.create_invite(payload, _FakeRequest(_ctx()), db)

    created = db.query(User).filter(User.email == "member@example.com").first()
    assert created is not None
    assert created.role == "member"
    assert created.access_expires_at is None


def test_reinviting_an_existing_consultant_without_role_still_requires_expiry(db: Session):
    """The effective-role fallback: a re-invite call that omits role= must
    still be evaluated against the existing user's current role, not
    silently treated as role=member (which would wrongly reject any
    access_expires_at, or worse, wrongly allow dropping it to None)."""
    first_expiry = datetime.now(timezone.utc) + timedelta(days=10)
    auth_routes.create_invite(
        InviteCreateRequest(email="consultant@example.com", role="consultant", access_expires_at=first_expiry),
        _FakeRequest(_ctx()),
        db,
    )
    auth_rate_limiter.store.clear()

    with pytest.raises(ValidationError):
        auth_routes.create_invite(InviteCreateRequest(email="consultant@example.com"), _FakeRequest(_ctx()), db)
