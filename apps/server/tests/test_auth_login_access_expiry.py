"""DISC-44 — consultant-assisted access: login rejects an expired grant.

Complements test_auth_access_expiry.py (which covers the refresh path) —
this is the route-level check that stops an expired consultant from even
starting a new session, not just from refreshing an existing one."""

from __future__ import annotations

import json
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
from src.api.routes import auth as auth_routes
from src.api.schemas.auth import LoginRequest
from src.core.database import Base
from src.core.exceptions import AuthenticationError
from src.core.model_defs.tenant_identity import AuditEvent, User, UserSession
from src.core.model_defs.tenant_org import AuthTenantSettings, Organization
from src.core.services.auth_service import hash_password


class _FakeClient:
    host = "127.0.0.1"


class _FakeRequest:
    def __init__(self):
        self.client = _FakeClient()
        self.headers: dict[str, str] = {"user-agent": "pytest"}


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    tables = [Organization.__table__, AuthTenantSettings.__table__, User.__table__, UserSession.__table__, AuditEvent.__table__]
    for table in tables:
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=tables)
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Org", slug="org", country="DK", technical_setup_owner_user_id=1))
    session.add(AuthTenantSettings(organization_id=1, domain_allowlist=[]))
    session.commit()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def _clear_rate_limiter():
    auth_rate_limiter.store.clear()
    yield
    auth_rate_limiter.store.clear()


def _consultant(db: Session, *, access_expires_at: datetime | None) -> User:
    user = User(
        organization_id=1,
        email="consultant@example.com",
        email_verified=True,
        password_hash=hash_password("correct-horse-battery-staple"),
        role="consultant",
        is_active=True,
        status="active",
        access_expires_at=access_expires_at,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_login_rejected_once_a_consultants_access_has_expired(db: Session):
    _consultant(db, access_expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))
    payload = LoginRequest(email="consultant@example.com", password="correct-horse-battery-staple", tenant_id=1)

    with pytest.raises(AuthenticationError):
        auth_routes.login(payload, _FakeRequest(), db)


def test_login_still_works_for_a_non_expired_consultant(db: Session):
    _consultant(db, access_expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    payload = LoginRequest(email="consultant@example.com", password="correct-horse-battery-staple", tenant_id=1)

    response = auth_routes.login(payload, _FakeRequest(), db)

    assert response.status_code == 200


def test_login_still_works_for_a_consultant_with_no_expiry_set(db: Session):
    """Defence in depth only — the invite route itself never allows this
    combination to be created, but the login gate must not assume that
    invariant always held (e.g. a row created before this feature, or
    directly in the database)."""
    _consultant(db, access_expires_at=None)
    payload = LoginRequest(email="consultant@example.com", password="correct-horse-battery-staple", tenant_id=1)

    response = auth_routes.login(payload, _FakeRequest(), db)

    assert response.status_code == 200


def test_login_response_carries_the_consultants_own_expiry(db: Session):
    """DISC-53 — the Consultant Presence Indicator's own data source: the
    frontend session must be able to see the grant's expiry without a
    second round trip."""
    expires_at = datetime.now(timezone.utc) + timedelta(days=1)
    _consultant(db, access_expires_at=expires_at)
    payload = LoginRequest(email="consultant@example.com", password="correct-horse-battery-staple", tenant_id=1)

    response = auth_routes.login(payload, _FakeRequest(), db)

    body = json.loads(response.body)
    assert body["user"]["access_expires_at"] is not None


def test_login_response_omits_expiry_for_a_non_consultant(db: Session):
    org_admin = User(
        organization_id=1,
        email="admin@example.com",
        email_verified=True,
        password_hash=hash_password("correct-horse-battery-staple"),
        role="org_admin",
        is_active=True,
        status="active",
    )
    db.add(org_admin)
    db.commit()
    payload = LoginRequest(email="admin@example.com", password="correct-horse-battery-staple", tenant_id=1)

    response = auth_routes.login(payload, _FakeRequest(), db)

    body = json.loads(response.body)
    assert body["user"]["access_expires_at"] is None
