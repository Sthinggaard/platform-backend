"""DISC-44 — consultant-assisted access: expiry enforcement at the session
layer (auth_service.is_access_expired, consulted again at refresh so an
already-issued access token can't outlive its grant)."""

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

from src.core.database import Base
from src.core.exceptions import AuthenticationError
from src.core.model_defs.tenant_identity import User, UserSession
from src.core.model_defs.tenant_org import Organization
from src.core.services.auth_service import create_refresh_session, is_access_expired, rotate_refresh_token


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    tables = [Organization.__table__, User.__table__, UserSession.__table__]
    for table in tables:
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=tables)
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Org", slug="org", country="DK", technical_setup_owner_user_id=1))
    session.commit()
    yield session
    session.close()


def _user(db: Session, *, access_expires_at: datetime | None) -> User:
    user = User(
        organization_id=1,
        email="consultant@example.com",
        email_verified=True,
        password_hash="hash",
        role="consultant",
        is_active=True,
        access_expires_at=access_expires_at,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# --- is_access_expired -------------------------------------------------------


def test_no_expiry_never_expires(db: Session):
    user = _user(db, access_expires_at=None)
    assert is_access_expired(user) is False


def test_future_expiry_not_yet_expired(db: Session):
    user = _user(db, access_expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    assert is_access_expired(user) is False


def test_past_expiry_is_expired(db: Session):
    user = _user(db, access_expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))
    assert is_access_expired(user) is True


def test_naive_datetime_is_treated_as_utc(db: Session):
    """SQLite round-trips DateTime columns as naive — the comparison must
    not blow up or silently misjudge expiry because of that."""
    naive_past = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
    user = _user(db, access_expires_at=naive_past)
    db.refresh(user)
    assert is_access_expired(user) is True


# --- rotate_refresh_token -----------------------------------------------------


def test_refresh_rejected_once_a_consultants_access_has_expired(db: Session):
    user = _user(db, access_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
    refresh_token, _session = create_refresh_session(db, user=user, organization_id=1, ip=None, user_agent=None)

    # Access expires between issuance and the refresh attempt.
    user.access_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.add(user)
    db.commit()

    with pytest.raises(AuthenticationError):
        rotate_refresh_token(db, refresh_token=refresh_token, ip=None, user_agent=None)


def test_refresh_still_works_for_a_non_expired_consultant(db: Session):
    user = _user(db, access_expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    refresh_token, _session = create_refresh_session(db, user=user, organization_id=1, ip=None, user_agent=None)

    result = rotate_refresh_token(db, refresh_token=refresh_token, ip=None, user_agent=None)

    assert result.access_token
    assert result.refresh_token != refresh_token
