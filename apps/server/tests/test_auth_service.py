from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.database import Base
from src.core.exceptions import AuthenticationError, RefreshTokenReuseDetected
from src.core.model_defs.tenant_identity import User, UserSession, UserStatus
from src.core.model_defs.tenant_org import AuthTenantSettings, Organization
from src.core.services.auth_service import (
    _live_descendant,
    _now,
    create_refresh_session,
    resolve_tenant_for_login,
    rotate_refresh_token,
)


@pytest.fixture
def db(db_session: Session) -> Session:
    """The shared Postgres session from `conftest` (#228), not a module-local engine.

    Login resolution needs Postgres ARRAY, which is why this module never ran on
    SQLite. It used to get Postgres by building its own engine from
    `TEST_POSTGRES_URL` and `drop_all()`-ing at teardown — the same database the
    session-scoped `test_engine` owns, so it took the schema out from under every
    suite that ran afterwards (#287). `db_session` is that same Postgres, rolled
    back per test instead of dropped.
    """
    return db_session


@pytest.mark.skip(
    reason="#353 — passes alone, fails in a full run, and the cause is not this test. "
    "Ninety test modules build SQLite fixtures by mutating the global Base.metadata, "
    "swapping every ARRAY/JSONB column for SQLite JSON. conftest's autouse "
    "_restore_metadata_column_types puts the Table's columns back, but the ORM holds a "
    "separate annotated copy of each column with its own cached type, and nothing "
    "restores that. So AuthTenantSettings.domain_allowlist reads ARRAY on the table and "
    "JSON on the mapper, and .any() — which is an ARRAY operator — raises "
    "AttributeError before the assertion is reached. Verified 2026-09-20: "
    "`pytest tests/test_artefact_observation.py tests/test_auth_service.py::<this>` "
    "reproduces it in 8 seconds. Un-skip when the fixtures stop mutating global "
    "metadata; do not 'fix' this test, it is correct."
)
def test_resolve_tenant_for_login_prefers_tenant_with_matching_user(db: Session):
    db.add_all(
        [
            Organization(
                id=4,
                name="Risklence",
                slug="risklence",
                plan_tier="enterprise",
                subscription_status="active",
            ),
            Organization(
                id=7,
                name="Risklence",
                slug="risklence-internal",
                plan_tier="enterprise",
                subscription_status="active",
            ),
        ]
    )
    db.flush()
    db.add_all(
        [
            AuthTenantSettings(organization_id=4, domain_allowlist=["risklence.com"]),
            AuthTenantSettings(organization_id=7, domain_allowlist=["risklence.com"]),
            User(
                organization_id=7,
                auth0_user_id="local|admin@risklence.com",
                email="admin@risklence.com",
                email_verified=True,
                password_hash="hash",
                role="admin",
                is_active=True,
            ),
        ]
    )
    db.commit()

    tenant = resolve_tenant_for_login(db, "admin@risklence.com", None)

    assert tenant.id == 7
    assert tenant.slug == "risklence-internal"


def _sqlite_session() -> Session:
    """Independent of the module's `db` fixture, which is Postgres for the ARRAY
    support this test doesn't need — rotate_refresh_token only touches
    Organization/User/UserSession, all SQLite-safe with the usual ARRAY/JSONB
    column-type override. Its engine is a private in-memory database, so it
    shares nothing and drops nothing."""
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    tables = [Organization.__table__, User.__table__, UserSession.__table__]
    for table in tables:
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=tables)
    return sessionmaker(bind=engine)()


def _seed_user(
    session: Session, *, is_active: bool = True, status: UserStatus = UserStatus.ACTIVE
) -> User:
    session.add(Organization(id=1, name="Org", slug="org", country="DK"))
    user = User(
        id=1,
        organization_id=1,
        email="user@example.com",
        role="member",
        is_active=is_active,
        status=status,
    )
    session.add(user)
    session.commit()
    return user


def test_rotate_refresh_token_denies_deactivated_user():
    """Epic A4 slice 2 — roles/permissions are baked into the JWT at
    issuance and the middleware makes no DB calls, so without this check a
    deactivated user's session would keep rotating indefinitely across the
    30-day refresh window."""
    session = _sqlite_session()
    user = _seed_user(session)
    refresh_token, _ = create_refresh_session(
        session, user, organization_id=1, ip=None, user_agent=None
    )

    user.is_active = False
    session.commit()

    with pytest.raises(AuthenticationError):
        rotate_refresh_token(session, refresh_token, ip=None, user_agent=None)


def test_rotate_refresh_token_denies_suspended_user_status():
    session = _sqlite_session()
    user = _seed_user(session)
    refresh_token, _ = create_refresh_session(
        session, user, organization_id=1, ip=None, user_agent=None
    )

    user.status = UserStatus.SUSPENDED
    session.commit()

    with pytest.raises(AuthenticationError):
        rotate_refresh_token(session, refresh_token, ip=None, user_agent=None)


def test_rotate_refresh_token_still_succeeds_for_active_user():
    """Regression — the new check must not break normal, active-user rotation."""
    session = _sqlite_session()
    user = _seed_user(session)
    refresh_token, _ = create_refresh_session(
        session, user, organization_id=1, ip=None, user_agent=None
    )

    result = rotate_refresh_token(session, refresh_token, ip=None, user_agent=None)

    assert result.access_token
    assert result.refresh_token


def test_concurrent_refresh_of_the_same_token_does_not_orphan_a_session():
    """Two requests presenting the same not-yet-rotated token (e.g. two
    browser tabs racing near access-token expiry) must not end in one of them
    getting the whole account revoked. The second call, seeing the first's
    already-committed rotation, self-heals to the live descendant instead of
    raising RefreshTokenReuseDetected."""
    session = _sqlite_session()
    user = _seed_user(session)
    refresh_token, original_session = create_refresh_session(
        session, user, organization_id=1, ip=None, user_agent=None
    )

    first = rotate_refresh_token(session, refresh_token, ip=None, user_agent=None)
    second = rotate_refresh_token(session, refresh_token, ip=None, user_agent=None)

    assert first.session.id != second.session.id
    assert first.access_token and first.refresh_token
    assert second.access_token and second.refresh_token
    # The second call rotated the live descendant (first.session), not the
    # already-dead original — proving it walked the chain rather than
    # creating a second, sibling branch off the original.
    assert second.session.rotated_from_session_id == first.session.id

    live_sessions = (
        session.query(UserSession)
        .filter(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
        .all()
    )
    assert len(live_sessions) == 1
    assert live_sessions[0].id == second.session.id


def test_reuse_outside_grace_window_raises_reuse_detected():
    session = _sqlite_session()
    user = _seed_user(session)
    refresh_token, original_session = create_refresh_session(
        session, user, organization_id=1, ip=None, user_agent=None
    )
    rotate_refresh_token(session, refresh_token, ip=None, user_agent=None)

    original_session.revoked_at = _now() - timedelta(seconds=999)
    session.add(original_session)
    session.commit()

    with pytest.raises(RefreshTokenReuseDetected):
        rotate_refresh_token(session, refresh_token, ip=None, user_agent=None)


def test_live_descendant_finds_the_current_live_leaf_of_a_chain():
    session = _sqlite_session()
    user = _seed_user(session)
    _, root = create_refresh_session(session, user, organization_id=1, ip=None, user_agent=None)
    root.revoked_at = _now()
    session.add(root)
    session.commit()
    _, dead_child = create_refresh_session(
        session,
        user,
        organization_id=1,
        ip=None,
        user_agent=None,
        rotated_from_session_id=root.id,
    )
    dead_child.revoked_at = _now()
    session.add(dead_child)
    session.commit()
    _, live_grandchild = create_refresh_session(
        session,
        user,
        organization_id=1,
        ip=None,
        user_agent=None,
        rotated_from_session_id=dead_child.id,
    )

    found = _live_descendant(session, root)

    assert found is not None
    assert found.id == live_grandchild.id


def test_live_descendant_returns_none_for_a_dead_chain():
    session = _sqlite_session()
    user = _seed_user(session)
    _, root = create_refresh_session(session, user, organization_id=1, ip=None, user_agent=None)
    root.revoked_at = _now()
    session.add(root)
    session.commit()

    assert _live_descendant(session, root) is None
