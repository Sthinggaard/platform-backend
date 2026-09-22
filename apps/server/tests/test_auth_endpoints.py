from datetime import datetime, timedelta, timezone
from time import time

import pytest
from fastapi import HTTPException, Response
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select

from src.api.main import app
from src.api.routes import auth as auth_route
from src.api.routes.auth import _set_state_cookie
from src.core.config import settings
from src.core.database import get_db
from src.core.models import (
    AuditEvent,
    AuthMsTenantAllowlist,
    AuthTenantSettings,
    Organization,
    User,
    UserSession,
    UserStatus,
)
from src.core.services.auth_service import (
    create_access_token,
    create_invite_token,
    create_password_reset_token,
    hash_password,
    hash_refresh_token,
    sign_state_payload,
)
from src.pretenant import store as pretenant_store


def _prepare_locked_draft(store: pretenant_store.PreTenantStore, session_id: str) -> None:
    store.update_draft_org(
        session_id,
        status="LOCKED",
        cvr="12345678",
        legal_name="Signup Ready A/S",
        country="DK",
        industry_code="62010",
        city="Copenhagen",
        baseline_snapshot={
            "overallRiskScore": 55,
            "riskLevel": "medium",
            "focusAreas": ["identity_access"],
            "hypotheses": [],
            "profileFingerprint": "signupphase2",
        },
        baseline_model_version="risk-intel-baseline-v1",
        baseline_generated_at=datetime.now(timezone.utc),
    )


def _create_user(db_session, organization: Organization, email: str, password: str) -> User:
    user = User(
        organization_id=organization.id,
        auth0_user_id=None,
        email=email,
        email_verified=True,
        password_hash=hash_password(password),
        role="member",
        permissions=[],
        is_active=True,
        status=UserStatus.ACTIVE,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _create_invited_user(db_session, organization: Organization, email: str) -> User:
    user = User(
        organization_id=organization.id,
        auth0_user_id=None,
        email=email,
        email_verified=False,
        password_hash=None,
        role="member",
        permissions=[],
        is_active=False,
        status=UserStatus.INVITED,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _cookie_header(response) -> str:
    return response.headers.get("set-cookie", "")


@pytest.mark.unreconciled
def test_login_refresh_and_reuse_detection(db_session):
    """Replaying the just-rotated cookie immediately is a benign same-client
    race (well within the grace window) and now self-heals instead of 401ing.
    See test_refresh_reuse_outside_grace_window_revokes_everything for the
    genuine-reuse case this test used to (mis)represent.
    """
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "lax"

    organization = Organization(
        name="Auth Org",
        slug="auth-org",
    )
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    db_session.add(
        AuthTenantSettings(
            organization_id=organization.id,
            domain_allowlist=["example.com"],
            local_login_enabled=True,
            sso_google_enabled=False,
            sso_ms_enabled=False,
            sso_required=False,
        )
    )
    db_session.commit()

    _create_user(db_session, organization, "user@example.com", "password123")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "password123"},
    )
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()
    refresh_cookie = client.cookies.get(settings.auth.refresh_cookie_name)
    assert refresh_cookie

    refresh_response = client.post("/api/v1/auth/refresh")
    assert refresh_response.status_code == 200
    assert "access_token" in refresh_response.json()
    rotated_cookie = client.cookies.get(settings.auth.refresh_cookie_name)
    assert rotated_cookie and rotated_cookie != refresh_cookie

    # Immediately replaying the pre-rotation cookie (a sibling request racing
    # the one above, e.g. a second browser tab) is within the grace window:
    # self-heals to the live descendant instead of revoking every session.
    reuse_response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_cookie},
    )
    assert reuse_response.status_code == 200
    assert "access_token" in reuse_response.json()
    self_healed_cookie = client.cookies.get(settings.auth.refresh_cookie_name)
    assert self_healed_cookie and self_healed_cookie not in (refresh_cookie, rotated_cookie)

    audit_event_types = [
        e.event_type for e in db_session.query(AuditEvent).order_by(AuditEvent.id).all()
    ]
    assert "REFRESH_REUSED_TOKEN_DETECTED" not in audit_event_types

    app.dependency_overrides.clear()


def test_refresh_reuse_outside_grace_window_revokes_everything(db_session):
    """A cookie replayed well after its own rotation — the genuine-reuse
    case — still hard-fails and revokes every session for the user.
    """
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "lax"

    organization = Organization(name="Auth Org 2", slug="auth-org-2")
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    db_session.add(
        AuthTenantSettings(
            organization_id=organization.id,
            domain_allowlist=["example.com"],
            local_login_enabled=True,
            sso_google_enabled=False,
            sso_ms_enabled=False,
            sso_required=False,
        )
    )
    db_session.commit()

    _create_user(db_session, organization, "user2@example.com", "password123")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "user2@example.com", "password": "password123"},
    )
    assert login_response.status_code == 200
    refresh_cookie = client.cookies.get(settings.auth.refresh_cookie_name)
    assert refresh_cookie

    refresh_response = client.post("/api/v1/auth/refresh")
    assert refresh_response.status_code == 200

    # Push the rotated-away session's revocation outside the grace window,
    # simulating real elapsed time rather than a same-tick race.
    rotated_away = (
        db_session.query(UserSession)
        .filter(UserSession.refresh_token_hash == hash_refresh_token(refresh_cookie))
        .one()
    )
    assert rotated_away.revoked_at is not None
    grace = settings.auth.refresh_token_reuse_grace_seconds
    rotated_away.revoked_at = datetime.now(timezone.utc) - timedelta(seconds=grace + 50)
    db_session.add(rotated_away)
    db_session.commit()

    reuse_response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_cookie},
    )
    assert reuse_response.status_code == 401

    remaining_live = (
        db_session.query(UserSession)
        .filter(
            UserSession.user_id == rotated_away.user_id,
            UserSession.revoked_at.is_(None),
        )
        .count()
    )
    assert remaining_live == 0

    audit_event_types = [
        e.event_type for e in db_session.query(AuditEvent).order_by(AuditEvent.id).all()
    ]
    assert "REFRESH_REUSED_TOKEN_DETECTED" in audit_event_types

    app.dependency_overrides.clear()


def test_direct_signup_is_blocked_without_onboarding_activation_flow(db_session):
    settings.auth.jwt_secret = SecretStr("test-secret")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.post(
        "/api/v1/auth/signup",
        json={"email": "new-user@example.com", "password": "password123"},
    )

    assert response.status_code == 403
    payload = response.json()
    assert payload["error_type"] == "authorization_error"
    assert payload["detail"] == "Complete onboarding first, then use the activation signup flow."

    app.dependency_overrides.clear()


def test_onboarding_gated_signup_start_issues_verification_challenge(db_session, monkeypatch):
    settings.auth.jwt_secret = SecretStr("test-secret")
    auth_route.auth_rate_limiter.store.clear()
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None

    sent = {}

    def _fake_send_signup_verification_email(email: str, verification_code: str) -> None:
        sent["email"] = email
        sent["code"] = verification_code

    monkeypatch.setattr(auth_route, "PRETENANT_STORE", store)
    monkeypatch.setattr(
        auth_route, "send_signup_verification_email", _fake_send_signup_verification_email
    )

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.post(
        "/api/v1/auth/signup/start",
        json={
            "activation_token": activation.token,
            "email": "new-user@example.com",
            "password": "password123",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["verification_method"] == "email_code"
    assert payload["challenge_id"]
    assert payload["masked_destination"].endswith("@example.com")
    assert "message" in payload
    assert sent["email"] == "new-user@example.com"
    assert len(sent["code"]) == 6
    challenge = store.get_signup_challenge(payload["challenge_id"])
    assert challenge is not None
    assert challenge.session_id == session.id
    assert challenge.activation_token_hash == store.hash_activation_token(activation.token)
    assert challenge.email == "new-user@example.com"
    assert challenge.password_hash != "password123"
    assert challenge.code_hash
    assert challenge.code_salt
    events = store.get_audit_events(
        session_id=session.id, event_type="signup_activation_challenge_issued"
    )
    assert len(events) == 1

    app.dependency_overrides.clear()


def test_onboarding_gated_signup_start_rejects_invalid_activation_token(db_session, monkeypatch):
    settings.auth.jwt_secret = SecretStr("test-secret")
    auth_route.auth_rate_limiter.store.clear()
    monkeypatch.setattr(
        auth_route, "PRETENANT_STORE", pretenant_store.PreTenantStore(ttl_minutes=5)
    )

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.post(
        "/api/v1/auth/signup/start",
        json={
            "activation_token": "opaque-activation-token-12345",
            "email": "new-user@example.com",
            "password": "password123",
        },
    )

    assert response.status_code == 400
    payload = response.json()
    assert payload["detail"]["error_type"] == "invalid_token"

    app.dependency_overrides.clear()


def test_onboarding_gated_signup_start_rejects_expired_activation_token(db_session, monkeypatch):
    settings.auth.jwt_secret = SecretStr("test-secret")
    auth_route.auth_rate_limiter.store.clear()
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=-1)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None
    monkeypatch.setattr(auth_route, "PRETENANT_STORE", store)

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.post(
        "/api/v1/auth/signup/start",
        json={
            "activation_token": activation.token,
            "email": "new-user@example.com",
            "password": "password123",
        },
    )

    assert response.status_code == 410
    payload = response.json()
    assert payload["detail"]["error_type"] == "token_expired"

    app.dependency_overrides.clear()


@pytest.mark.unreconciled
def test_onboarding_gated_signup_start_rejects_existing_email(db_session, monkeypatch):
    settings.auth.jwt_secret = SecretStr("test-secret")
    auth_route.auth_rate_limiter.store.clear()
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None
    monkeypatch.setattr(auth_route, "PRETENANT_STORE", store)

    organization = Organization(name="Existing Email Org", slug=f"existing-email-org-{int(time())}")
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    _create_user(db_session, organization, "existing@example.com", "password123")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.post(
        "/api/v1/auth/signup/start",
        json={
            "activation_token": activation.token,
            "email": "existing@example.com",
            "password": "password123",
        },
    )

    assert response.status_code == 409
    payload = response.json()
    assert payload["detail"]["error_type"] == "email_already_in_use"

    app.dependency_overrides.clear()


@pytest.mark.unreconciled
def test_onboarding_gated_signup_verify_completes_signup_and_activation(db_session, monkeypatch):
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    auth_route.auth_rate_limiter.store.clear()
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None

    sent: dict[str, str] = {}

    def _fake_send_signup_verification_email(email: str, verification_code: str) -> None:
        sent["email"] = email
        sent["code"] = verification_code

    monkeypatch.setattr(auth_route, "PRETENANT_STORE", store)
    monkeypatch.setattr(
        auth_route, "send_signup_verification_email", _fake_send_signup_verification_email
    )

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    start_response = client.post(
        "/api/v1/auth/signup/start",
        json={
            "activation_token": activation.token,
            "email": "founder@example.com",
            "password": "password123",
        },
    )
    assert start_response.status_code == 200
    challenge_id = start_response.json()["challenge_id"]
    assert sent["code"]

    response = client.post(
        "/api/v1/auth/signup/verify",
        json={
            "activation_token": activation.token,
            "challenge_id": challenge_id,
            "code": sent["code"],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["access_token"]
    assert payload["workspace_url"] == "/dashboard"
    assert payload["tenant"]["name"] == "Signup Ready A/S"
    assert payload["user"]["email"] == "founder@example.com"
    assert payload["user"]["role"] == "org_admin"
    assert store.get_activation_token_status(activation.token) == "redeemed"
    assert store.get_signup_challenge_status(challenge_id) in {"used", "revoked"}
    pretenant_events = store.get_audit_events(
        session_id=session.id, event_type="signup_activation_completed"
    )
    assert len(pretenant_events) == 1
    set_cookie = _cookie_header(response).lower()
    assert f"{settings.auth.refresh_cookie_name}=" in set_cookie

    created_user = db_session.execute(
        select(User).where(User.email == "founder@example.com")
    ).scalar_one_or_none()
    assert created_user is not None
    created_org = db_session.execute(
        select(Organization).where(Organization.id == created_user.organization_id)
    ).scalar_one_or_none()
    assert created_org is not None
    assert created_org.onboarding_completed is True
    assert isinstance(created_org.onboarding_data, dict)
    assert created_org.onboarding_data.get("source") == "public_onboarding"

    app.dependency_overrides.clear()


def test_onboarding_gated_signup_verify_rejects_invalid_code_without_burning_token(
    db_session, monkeypatch
):
    settings.auth.jwt_secret = SecretStr("test-secret")
    auth_route.auth_rate_limiter.store.clear()
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None

    def _fake_send_signup_verification_email(email: str, verification_code: str) -> None:
        return None

    monkeypatch.setattr(auth_route, "PRETENANT_STORE", store)
    monkeypatch.setattr(
        auth_route, "send_signup_verification_email", _fake_send_signup_verification_email
    )

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    start_response = client.post(
        "/api/v1/auth/signup/start",
        json={
            "activation_token": activation.token,
            "email": "founder2@example.com",
            "password": "password123",
        },
    )
    assert start_response.status_code == 200
    challenge_id = start_response.json()["challenge_id"]

    response = client.post(
        "/api/v1/auth/signup/verify",
        json={
            "activation_token": activation.token,
            "challenge_id": challenge_id,
            "code": "000000",
        },
    )

    assert response.status_code == 401
    payload = response.json()
    assert payload["detail"]["error_type"] == "invalid_verification_code"
    assert store.get_activation_token_status(activation.token) == "active"
    challenge = store.get_signup_challenge(challenge_id)
    assert challenge is not None
    assert challenge.attempt_count == 1
    assert challenge.used_at is None

    app.dependency_overrides.clear()


def test_onboarding_gated_signup_resend_rotates_challenge_and_preserves_verify_step_state(
    db_session, monkeypatch
):
    settings.auth.jwt_secret = SecretStr("test-secret")
    auth_route.auth_rate_limiter.store.clear()
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None

    sent_codes: list[str] = []

    def _fake_send_signup_verification_email(email: str, verification_code: str) -> None:
        sent_codes.append(verification_code)

    monkeypatch.setattr(auth_route, "PRETENANT_STORE", store)
    monkeypatch.setattr(
        auth_route, "send_signup_verification_email", _fake_send_signup_verification_email
    )

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    start_response = client.post(
        "/api/v1/auth/signup/start",
        json={
            "activation_token": activation.token,
            "email": "resend@example.com",
            "password": "password123",
        },
    )
    assert start_response.status_code == 200
    first = start_response.json()
    assert first["challenge_id"]

    resend_response = client.post(
        "/api/v1/auth/signup/resend",
        json={
            "activation_token": activation.token,
            "challenge_id": first["challenge_id"],
        },
    )
    assert resend_response.status_code == 200
    second = resend_response.json()
    assert second["challenge_id"] != first["challenge_id"]
    assert second["masked_destination"] == first["masked_destination"]
    assert len(sent_codes) == 2
    assert sent_codes[0] != sent_codes[1]
    assert store.get_signup_challenge_status(first["challenge_id"]) == "revoked"
    assert store.get_signup_challenge_status(second["challenge_id"]) == "active"

    app.dependency_overrides.clear()


def test_onboarding_gated_signup_resend_rejects_mismatched_activation_token(
    db_session, monkeypatch
):
    settings.auth.jwt_secret = SecretStr("test-secret")
    auth_route.auth_rate_limiter.store.clear()
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session1, _ = store.create_session()
    session2, _ = store.create_session()
    _prepare_locked_draft(store, session1.id)
    _prepare_locked_draft(store, session2.id)
    activation1 = store.create_activation_token(session1.id)
    activation2 = store.create_activation_token(session2.id)
    assert activation1 is not None and activation2 is not None

    monkeypatch.setattr(auth_route, "PRETENANT_STORE", store)
    monkeypatch.setattr(
        auth_route, "send_signup_verification_email", lambda *_args, **_kwargs: None
    )

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    start_response = client.post(
        "/api/v1/auth/signup/start",
        json={
            "activation_token": activation1.token,
            "email": "mismatch@example.com",
            "password": "password123",
        },
    )
    assert start_response.status_code == 200
    challenge_id = start_response.json()["challenge_id"]

    resend_response = client.post(
        "/api/v1/auth/signup/resend",
        json={
            "activation_token": activation2.token,
            "challenge_id": challenge_id,
        },
    )
    assert resend_response.status_code == 400
    payload = resend_response.json()
    assert payload["detail"]["error_type"] == "invalid_verification_challenge"

    app.dependency_overrides.clear()


@pytest.mark.unreconciled
def test_login_sets_refresh_cookie_strict_and_host_only(db_session):
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "strict"
    settings.auth.refresh_cookie_domain = None

    organization = Organization(name="Cookie Org", slug=f"cookie-org-{int(time())}")
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    db_session.add(
        AuthTenantSettings(
            organization_id=organization.id,
            domain_allowlist=["example.com"],
            local_login_enabled=True,
            sso_google_enabled=False,
            sso_ms_enabled=False,
            sso_required=False,
        )
    )
    db_session.commit()
    _create_user(db_session, organization, "cookie@example.com", "password123")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.post(
        "/api/v1/auth/login",
        json={"email": "cookie@example.com", "password": "password123"},
    )

    assert response.status_code == 200
    set_cookie = _cookie_header(response)
    set_cookie_lower = set_cookie.lower()
    assert f"{settings.auth.refresh_cookie_name}=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "samesite=strict" in set_cookie_lower
    assert "domain=" not in set_cookie_lower

    app.dependency_overrides.clear()


def test_sso_state_cookie_uses_lax_for_oauth_callback():
    settings.auth.refresh_cookie_domain = None
    settings.auth.refresh_cookie_secure = False
    response = Response()

    _set_state_cookie(response, "state-token")

    set_cookie = _cookie_header(response)
    set_cookie_lower = set_cookie.lower()
    assert f"{settings.auth.sso_state_cookie_name}=state-token" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "samesite=lax" in set_cookie_lower
    assert "domain=" not in set_cookie_lower


@pytest.mark.unreconciled
def test_password_reset_request_non_enumerating(db_session):
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "lax"

    organization = Organization(
        name="Reset Org",
        slug="reset-org",
    )
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    db_session.add(
        AuthTenantSettings(
            organization_id=organization.id,
            domain_allowlist=["example.com"],
            local_login_enabled=True,
            sso_google_enabled=False,
            sso_ms_enabled=False,
            sso_required=False,
        )
    )
    db_session.commit()

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.post(
        "/api/v1/auth/password/reset/request",
        json={"email": "missing@example.com"},
    )
    assert response.status_code == 200
    assert "message" in response.json()

    app.dependency_overrides.clear()


def test_password_reset_confirm_invalid_token(db_session):
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "lax"

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.post(
        "/api/v1/auth/password/reset/confirm",
        json={"token": "invalid-token", "new_password": "password123"},
    )
    assert response.status_code == 401

    app.dependency_overrides.clear()


@pytest.mark.unreconciled
def test_invite_create_and_accept_local(db_session):
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "lax"

    organization = Organization(name="Invite Org", slug="invite-org")
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    db_session.add(
        AuthTenantSettings(
            organization_id=organization.id,
            domain_allowlist=["example.com"],
            local_login_enabled=True,
            sso_google_enabled=False,
            sso_ms_enabled=False,
            sso_required=False,
        )
    )
    db_session.commit()

    admin = _create_user(db_session, organization, "admin@example.com", "password123")
    admin.role = "admin"
    db_session.add(admin)
    db_session.commit()

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    token = create_access_token(admin, organization.id)
    client.headers.update({"Authorization": f"Bearer {token}"})

    response = client.post(
        "/api/v1/auth/invite/create",
        json={"email": "invitee@example.com", "role": "member"},
    )
    assert response.status_code == 200
    invitee = db_session.execute(
        select(User).where(
            User.organization_id == organization.id, User.email == "invitee@example.com"
        )
    ).scalar_one()
    assert invitee.status == UserStatus.INVITED

    invite_token = create_invite_token(db_session, invitee, organization.id, admin.id)
    accept_response = client.post(
        "/api/v1/auth/invite/accept",
        json={"token": invite_token, "password": "password123"},
    )
    assert accept_response.status_code == 200
    data = accept_response.json()
    assert data.get("access_token")
    assert data.get("user", {}).get("status") == "active"

    app.dependency_overrides.clear()


@pytest.mark.unreconciled
def test_invite_accept_sso_only(db_session):
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "lax"

    organization = Organization(name="Invite SSO Org", slug="invite-sso-org")
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    db_session.add(
        AuthTenantSettings(
            organization_id=organization.id,
            domain_allowlist=["example.com"],
            local_login_enabled=False,
            sso_google_enabled=True,
            sso_ms_enabled=False,
            sso_required=True,
        )
    )
    db_session.commit()

    invitee = _create_invited_user(db_session, organization, "sso@example.com")
    invite_token = create_invite_token(db_session, invitee, organization.id, None)

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.post(
        "/api/v1/auth/invite/accept",
        json={"token": invite_token},
    )
    assert response.status_code == 200
    data = response.json()
    assert data.get("sso_required") is True
    assert data.get("sso_google_enabled") is True
    assert data.get("access_token") is None

    app.dependency_overrides.clear()


@pytest.mark.unreconciled
def test_invite_create_requires_admin_role(db_session):
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "strict"

    organization = Organization(name="Invite RBAC Org", slug=f"invite-rbac-org-{int(time())}")
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    db_session.add(
        AuthTenantSettings(
            organization_id=organization.id,
            domain_allowlist=["example.com"],
            local_login_enabled=True,
            sso_google_enabled=False,
            sso_ms_enabled=False,
            sso_required=False,
        )
    )
    db_session.commit()

    member = _create_user(db_session, organization, "member@example.com", "password123")
    member.role = "member"
    db_session.add(member)
    db_session.commit()

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    token = create_access_token(member, organization.id)
    client.headers.update({"Authorization": f"Bearer {token}"})

    response = client.post(
        "/api/v1/auth/invite/create",
        json={"email": "invitee@example.com", "role": "member"},
    )

    assert response.status_code == 403
    payload = response.json()
    assert payload["error_type"] == "authorization_error"
    assert payload["detail"] == "Admin access required"

    app.dependency_overrides.clear()


def test_sso_state_mismatch_rejected(db_session):
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "lax"

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    payload = {
        "state": "expected",
        "nonce": "nonce",
        "code_verifier": "verifier",
        "provider": "google",
        "created_at": 0,
    }
    state_token = sign_state_payload(payload)
    client.cookies.set(settings.auth.sso_state_cookie_name, state_token)

    response = client.get(
        "/api/v1/auth/sso/google/callback",
        params={"code": "dummy", "state": "wrong"},
    )
    assert response.status_code == 401

    app.dependency_overrides.clear()


def test_sso_google_cancel_redirect(db_session):
    settings.auth.frontend_base_url = "http://localhost:3000"

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.get(
        "/api/v1/auth/sso/google/callback",
        params={"error": "access_denied"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "sso=cancelled" in response.headers["location"]

    app.dependency_overrides.clear()


def test_sso_google_domain_not_allowed(db_session, monkeypatch):
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "lax"
    settings.auth.frontend_base_url = "http://localhost:3000"
    settings.auth.sso_callback_url = None

    organization = Organization(name="SSO Org", slug="sso-org")
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    db_session.add(
        AuthTenantSettings(
            organization_id=organization.id,
            domain_allowlist=["allowed.com"],
            local_login_enabled=False,
            sso_google_enabled=True,
            sso_ms_enabled=False,
            sso_required=True,
        )
    )
    db_session.commit()

    def override_get_db():
        yield db_session

    def fake_exchange_code(_provider, _code, _verifier):
        return {"id_token": "token"}

    def fake_verify_id_token(_provider, _token, _nonce):
        return {
            "sub": "sub-123",
            "email": "user@example.com",
            "email_verified": True,
        }

    monkeypatch.setattr("src.api.routes.auth.exchange_code", fake_exchange_code)
    monkeypatch.setattr("src.api.routes.auth.verify_id_token", fake_verify_id_token)

    payload = {
        "state": "state",
        "nonce": "nonce",
        "code_verifier": "verifier",
        "provider": "google",
        "tenant_id": organization.id,
        "created_at": int(time()),
    }
    state_token = sign_state_payload(payload)

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    client.cookies.set(settings.auth.sso_state_cookie_name, state_token)

    response = client.get(
        "/api/v1/auth/sso/google/callback",
        params={"code": "code", "state": "state"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "code=NOT_ALLOWED" in response.headers["location"]

    app.dependency_overrides.clear()


def test_sso_microsoft_action_required_redirect(db_session):
    settings.auth.frontend_base_url = "http://localhost:3000"

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.get(
        "/api/v1/auth/sso/microsoft/callback",
        params={"error": "interaction_required"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "sso=action_required" in response.headers["location"]

    app.dependency_overrides.clear()


def test_sso_microsoft_tenant_not_allowed(db_session, monkeypatch):
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "lax"
    settings.auth.frontend_base_url = "http://localhost:3000"
    settings.auth.sso_callback_url = None

    organization = Organization(name="MS Org", slug="ms-org")
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    auth_settings = AuthTenantSettings(
        organization_id=organization.id,
        domain_allowlist=["allowed.com"],
        local_login_enabled=False,
        sso_google_enabled=False,
        sso_ms_enabled=True,
        sso_required=True,
    )
    db_session.add(auth_settings)
    db_session.commit()
    db_session.refresh(auth_settings)
    db_session.add(
        AuthMsTenantAllowlist(
            auth_settings_id=auth_settings.id,
            tenant_id="allowed-tenant",
        )
    )
    db_session.commit()

    def override_get_db():
        yield db_session

    def fake_exchange_code(_provider, _code, _verifier):
        return {"id_token": "token"}

    def fake_verify_id_token(_provider, _token, _nonce):
        return {
            "sub": "sub-123",
            "email": "user@allowed.com",
            "email_verified": True,
            "tid": "other-tenant",
            "iss": "https://login.microsoftonline.com/other-tenant/v2.0",
        }

    monkeypatch.setattr("src.api.routes.auth.exchange_code", fake_exchange_code)
    monkeypatch.setattr("src.api.routes.auth.verify_id_token", fake_verify_id_token)

    payload = {
        "state": "state",
        "nonce": "nonce",
        "code_verifier": "verifier",
        "provider": "microsoft",
        "tenant_id": organization.id,
        "created_at": int(time()),
    }
    state_token = sign_state_payload(payload)

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    client.cookies.set(settings.auth.sso_state_cookie_name, state_token)

    response = client.get(
        "/api/v1/auth/sso/microsoft/callback",
        params={"code": "code", "state": "state"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "code=TENANT_NOT_ALLOWED" in response.headers["location"]

    app.dependency_overrides.clear()


def test_password_reset_rate_limit_still_returns_generic(db_session, monkeypatch):
    settings.auth.jwt_secret = SecretStr("test-secret")

    def override_get_db():
        yield db_session

    def fake_check(_key, _limit=None, limit=None):
        raise HTTPException(status_code=429, detail="Too many requests.")

    monkeypatch.setattr("src.api.routes.auth.auth_rate_limiter.check", fake_check)

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.post(
        "/api/v1/auth/password/reset/request",
        json={"email": "user@example.com"},
    )
    assert response.status_code == 200
    assert "message" in response.json()

    app.dependency_overrides.clear()


@pytest.mark.unreconciled
def test_password_reset_confirm_weak_password(db_session):
    settings.auth.jwt_secret = SecretStr("test-secret")

    organization = Organization(name="Weak Org", slug="weak-org")
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    db_session.add(
        AuthTenantSettings(
            organization_id=organization.id,
            domain_allowlist=["example.com"],
            local_login_enabled=True,
            sso_google_enabled=False,
            sso_ms_enabled=False,
            sso_required=False,
        )
    )
    db_session.commit()

    user = User(
        organization_id=organization.id,
        auth0_user_id=None,
        email="weak@example.com",
        email_verified=True,
        password_hash=hash_password("initial-strong-pass"),
        role="member",
        permissions=[],
        is_active=True,
        status=UserStatus.ACTIVE,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_password_reset_token(db_session, user, organization.id, None)

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.post(
        "/api/v1/auth/password/reset/confirm",
        json={"token": token, "new_password": "short"},
    )
    assert response.status_code == 422

    app.dependency_overrides.clear()


@pytest.mark.unreconciled
def test_logout_revokes_refresh_token(db_session):
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "lax"

    organization = Organization(name="Logout Org", slug="logout-org")
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    db_session.add(
        AuthTenantSettings(
            organization_id=organization.id,
            domain_allowlist=["example.com"],
            local_login_enabled=True,
            sso_google_enabled=False,
            sso_ms_enabled=False,
            sso_required=False,
        )
    )
    db_session.commit()

    _create_user(db_session, organization, "user@example.com", "password123")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "password123"},
    )
    assert login_response.status_code == 200
    refresh_cookie = client.cookies.get(settings.auth.refresh_cookie_name)
    assert refresh_cookie

    logout_response = client.post("/api/v1/auth/logout")
    assert logout_response.status_code == 200

    refresh_response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_cookie},
    )
    assert refresh_response.status_code == 401

    app.dependency_overrides.clear()


@pytest.mark.unreconciled
def test_login_requires_mfa_returns_challenge(db_session, monkeypatch):
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "lax"

    organization = Organization(name="MFA Org", slug="mfa-org")
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    db_session.add(
        AuthTenantSettings(
            organization_id=organization.id,
            domain_allowlist=["example.com"],
            local_login_enabled=True,
            sso_google_enabled=False,
            sso_ms_enabled=False,
            sso_required=False,
            mfa_sms_enabled=True,
            mfa_required_for_all=False,
            mfa_required_for_admins=False,
        )
    )
    db_session.commit()

    user = _create_user(db_session, organization, "mfa@example.com", "password123")
    user.mfa_enabled = True
    user.mfa_phone_e164 = "+4511122233"
    db_session.add(user)
    db_session.commit()

    monkeypatch.setattr("src.core.services.mfa_service.generate_otp", lambda: "123456")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa@example.com", "password": "password123"},
    )
    assert response.status_code == 202
    payload = response.json()
    assert payload["mfa_required"] is True
    assert payload["challenge_id"]

    app.dependency_overrides.clear()


@pytest.mark.unreconciled
def test_mfa_login_verify_issues_tokens(db_session, monkeypatch):
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "lax"

    organization = Organization(name="MFA Verify Org", slug="mfa-verify-org")
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    db_session.add(
        AuthTenantSettings(
            organization_id=organization.id,
            domain_allowlist=["example.com"],
            local_login_enabled=True,
            sso_google_enabled=False,
            sso_ms_enabled=False,
            sso_required=False,
            mfa_sms_enabled=True,
            mfa_required_for_all=False,
            mfa_required_for_admins=False,
        )
    )
    db_session.commit()

    user = _create_user(db_session, organization, "verify@example.com", "password123")
    user.mfa_enabled = True
    user.mfa_phone_e164 = "+4511122233"
    db_session.add(user)
    db_session.commit()

    monkeypatch.setattr("src.core.services.mfa_service.generate_otp", lambda: "123456")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "verify@example.com", "password": "password123"},
    )
    challenge_id = login_response.json()["challenge_id"]

    verify_response = client.post(
        "/api/v1/auth/mfa/login/verify",
        json={"challenge_id": challenge_id, "code": "123456"},
    )
    assert verify_response.status_code == 200
    assert "access_token" in verify_response.json()

    app.dependency_overrides.clear()


@pytest.mark.unreconciled
def test_mfa_enroll_start_and_verify(db_session, monkeypatch):
    settings.auth.jwt_secret = SecretStr("test-secret")
    settings.auth.refresh_cookie_secure = False
    settings.auth.refresh_cookie_samesite = "lax"

    organization = Organization(name="MFA Enroll Org", slug="mfa-enroll-org")
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)
    db_session.add(
        AuthTenantSettings(
            organization_id=organization.id,
            domain_allowlist=["example.com"],
            local_login_enabled=True,
            sso_google_enabled=False,
            sso_ms_enabled=False,
            sso_required=False,
            mfa_sms_enabled=True,
            mfa_required_for_all=False,
            mfa_required_for_admins=False,
        )
    )
    db_session.commit()

    user = _create_user(db_session, organization, "enroll@example.com", "password123")

    monkeypatch.setattr("src.core.services.mfa_service.generate_otp", lambda: "123456")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    token = create_access_token(user, organization.id)
    client.headers.update({"Authorization": f"Bearer {token}"})

    start_response = client.post(
        "/api/v1/auth/mfa/enroll/start",
        json={"phone_e164": "+4511122233"},
    )
    assert start_response.status_code == 200
    challenge_id = start_response.json()["challenge_id"]

    verify_response = client.post(
        "/api/v1/auth/mfa/enroll/verify",
        json={"challenge_id": challenge_id, "code": "123456"},
    )
    assert verify_response.status_code == 200

    refreshed = db_session.get(User, user.id)
    assert refreshed.mfa_enabled is True

    app.dependency_overrides.clear()
