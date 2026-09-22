from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from pydantic import SecretStr

from src.api.main import app
from src.api.routes import activation as activation_route
from src.core.config import settings
from src.core.database import get_db
from src.core.models import ActivationAuditOutbox, AuditEvent, Organization, User
from src.core.utils.jwt_secrets import get_jwt_secret_bytes
from src.pretenant import store as pretenant_store

settings.auth.jwt_secret = SecretStr("test-secret")


def _build_token(org_id: int, email: str) -> str:
    namespace = "https://risklence.com/"
    payload = {
        "sub": "999",
        "email": email,
        f"{namespace}organization_id": org_id,
        f"{namespace}roles": ["admin"],
        f"{namespace}permissions": [],
    }
    return jwt.encode(payload, get_jwt_secret_bytes(), algorithm="HS256")


def _auth_header(org_id: int, email: str = "owner@example.com") -> dict[str, str]:
    return {"Authorization": f"Bearer {_build_token(org_id, email)}"}


def _prepare_locked_draft(store: pretenant_store.PreTenantStore, session_id: str) -> None:
    store.update_draft_org(
        session_id,
        status="LOCKED",
        cvr="12345678",
        legal_name="Risklence Promoted A/S",
        country="DK",
        industry_code="62010",
        city="Copenhagen",
        baseline_snapshot={
            "overallRiskScore": 62,
            "riskLevel": "medium",
            "focusAreas": ["identity_access"],
            "hypotheses": [],
            "profileFingerprint": "abc123def4567890",
        },
        baseline_model_version="risk-intel-baseline-v1",
        baseline_generated_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.unreconciled
def test_redeem_activation_token_happy_path(client, db_session, sample_organization, monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None
    monkeypatch.setattr(activation_route, "PRETENANT_STORE", store)

    response = client.post(
        "/app/activate/redeem",
        headers=_auth_header(sample_organization.id, "founder@example.com"),
        json={"token": activation.token},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["workspaceUrl"] == "/dashboard"
    assert payload["organizationName"] == "Risklence Promoted A/S"
    assert payload["organizationSlug"]
    assert payload["userEmail"] == "founder@example.com"
    assert payload["modelVersion"] == "risk-intel-baseline-v1"

    org = db_session.query(Organization).filter(Organization.id == payload["organizationId"]).one()
    assert org.subscription_status == "active"
    assert org.onboarding_completed is True
    assert org.onboarding_data is not None
    assert org.onboarding_data["baseline"]["model_version"] == "risk-intel-baseline-v1"

    user = db_session.query(User).filter(User.id == payload["userId"]).one()
    assert user.organization_id == org.id
    assert user.email == "founder@example.com"
    assert user.role == "org_admin"

    event_types = {
        row.event_type
        for row in db_session.query(AuditEvent).filter(AuditEvent.organization_id == org.id).all()
    }
    assert "ACTIVATION_TOKEN_REDEEMED" in event_types
    assert "ACTIVATION_TOKEN_REDEEM_SUCCEEDED" in event_types
    assert "DRAFT_PROMOTED" in event_types

    redeem_succeeded = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.organization_id == org.id,
            AuditEvent.event_type == "ACTIVATION_TOKEN_REDEEM_SUCCEEDED",
        )
        .one()
    )
    assert redeem_succeeded.metadata_json is not None
    assert "token_hash_prefix" in redeem_succeeded.metadata_json
    assert len(redeem_succeeded.metadata_json["token_hash_prefix"]) == 16
    assert "baseline_snapshot_hash" in redeem_succeeded.metadata_json
    assert len(redeem_succeeded.metadata_json["baseline_snapshot_hash"]) == 64
    assert "token_fingerprint" not in redeem_succeeded.metadata_json

    draft_promoted = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.organization_id == org.id,
            AuditEvent.event_type == "DRAFT_PROMOTED",
        )
        .one()
    )
    assert draft_promoted.metadata_json is not None
    assert "baseline_snapshot_hash" in draft_promoted.metadata_json
    assert "token_hash_prefix" in draft_promoted.metadata_json
    assert "token_fingerprint" not in draft_promoted.metadata_json

    assert store.get_activation_token_status(activation.token) == "redeemed"
    pretenant_events = store.get_audit_events(session_id=session.id, event_type="activation_token_redeemed")
    assert len(pretenant_events) == 1
    assert pretenant_events[0].details is not None
    assert pretenant_events[0].details["model_version"] == "risk-intel-baseline-v1"
    assert "token_hash_prefix" in pretenant_events[0].details
    assert "token_fingerprint" not in pretenant_events[0].details
    assert len(pretenant_events[0].details["draft_hash"]) == 64


def test_redeem_activation_token_invalid_token_returns_400(client, sample_organization, monkeypatch):
    monkeypatch.setattr(activation_route, "PRETENANT_STORE", pretenant_store.PreTenantStore(ttl_minutes=5))
    response = client.post(
        "/app/activate/redeem",
        headers=_auth_header(sample_organization.id),
        json={"token": "not-a-real-token"},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error_type"] == "invalid_token"


def test_redeem_activation_token_expired_returns_410(client, sample_organization, monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=-1)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None
    monkeypatch.setattr(activation_route, "PRETENANT_STORE", store)

    response = client.post(
        "/app/activate/redeem",
        headers=_auth_header(sample_organization.id),
        json={"token": activation.token},
    )
    assert response.status_code == 410
    assert response.json()["detail"]["error_type"] == "token_expired"


@pytest.mark.unreconciled
def test_redeem_activation_token_redeemed_returns_repeat_success_for_same_user(
    client, db_session, sample_organization, monkeypatch
):
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None
    monkeypatch.setattr(activation_route, "PRETENANT_STORE", store)

    first = client.post(
        "/app/activate/redeem",
        headers=_auth_header(sample_organization.id, "founder@example.com"),
        json={"token": activation.token},
    )
    assert first.status_code == 200
    first_payload = first.json()

    second = client.post(
        "/app/activate/redeem",
        headers=_auth_header(sample_organization.id, "founder@example.com"),
        json={"token": activation.token},
    )
    assert second.status_code == 200
    second_payload = second.json()
    assert second_payload["organizationId"] == first_payload["organizationId"]
    assert second_payload["userId"] == first_payload["userId"]
    assert second_payload["organizationSlug"] == first_payload["organizationSlug"]

    assert db_session.query(Organization).count() == 2  # sample org + promoted org
    assert db_session.query(User).count() == 1


@pytest.mark.unreconciled
def test_redeem_activation_token_redeemed_by_different_user_returns_409(client, sample_organization, monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None
    monkeypatch.setattr(activation_route, "PRETENANT_STORE", store)

    first = client.post(
        "/app/activate/redeem",
        headers=_auth_header(sample_organization.id, "founder@example.com"),
        json={"token": activation.token},
    )
    assert first.status_code == 200

    second = client.post(
        "/app/activate/redeem",
        headers=_auth_header(sample_organization.id, "another.user@example.com"),
        json={"token": activation.token},
    )
    assert second.status_code == 409
    assert second.json()["detail"]["error_type"] == "token_redeemed"


def test_redeem_activation_token_rolls_back_consumption_on_failure(client, sample_organization, monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None
    monkeypatch.setattr(activation_route, "PRETENANT_STORE", store)

    def _raise_slug(*_args, **_kwargs):
        raise RuntimeError("forced-failure")

    monkeypatch.setattr(activation_route, "_unique_org_slug", _raise_slug)

    response = client.post(
        "/app/activate/redeem",
        headers=_auth_header(sample_organization.id),
        json={"token": activation.token},
    )
    assert response.status_code == 500
    assert response.json()["detail"]["error_type"] == "activation_failed"
    assert store.get_activation_token_status(activation.token) == "active"


@pytest.mark.unreconciled
def test_redeem_activation_token_commit_failure_fails_closed(client, db_session, sample_organization, monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None
    monkeypatch.setattr(activation_route, "PRETENANT_STORE", store)

    original_commit = db_session.commit
    call_count = {"count": 0}

    def _commit_failure():
        call_count["count"] += 1
        raise RuntimeError("forced-commit-failure")

    monkeypatch.setattr(db_session, "commit", _commit_failure)

    response = client.post(
        "/app/activate/redeem",
        headers=_auth_header(sample_organization.id, "founder@example.com"),
        json={"token": activation.token},
    )

    monkeypatch.setattr(db_session, "commit", original_commit)

    assert response.status_code == 500
    assert response.json()["detail"]["error_type"] == "activation_failed"
    assert call_count["count"] == 1
    assert store.get_activation_token_status(activation.token) == "active"

    assert (
        db_session.query(Organization)
        .filter(Organization.name == "Risklence Promoted A/S")
        .one_or_none()
        is None
    )
    assert (
        db_session.query(User)
        .filter(User.email == "founder@example.com")
        .one_or_none()
        is None
    )


@pytest.mark.unreconciled
def test_redeem_activation_token_duplicate_cvr_returns_safe_outcome_and_no_new_org(
    client, db_session, sample_organization, monkeypatch
):
    sample_organization.subscription_status = "active"
    sample_organization.onboarding_data = {"cvr": "12345678"}
    db_session.add(sample_organization)
    db_session.commit()

    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None
    monkeypatch.setattr(activation_route, "PRETENANT_STORE", store)

    before_org_ids = {org.id for org in db_session.query(Organization).all()}

    response = client.post(
        "/app/activate/redeem",
        headers=_auth_header(sample_organization.id, "founder@example.com"),
        json={"token": activation.token},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["outcome"] == "ALREADY_REGISTERED"
    assert payload["message"] == "Organisation already registered. Please contact your administrator."
    assert "organizationId" not in payload

    after_org_ids = {org.id for org in db_session.query(Organization).all()}
    assert after_org_ids == before_org_ids
    assert db_session.query(User).count() == 0
    assert store.get_activation_token_status(activation.token) == "redeemed"

    event_types = {
        row.event_type
        for row in db_session.query(AuditEvent).filter(AuditEvent.organization_id == sample_organization.id).all()
    }
    assert "ACTIVATION_TOKEN_REDEEM_ATTEMPTED" in event_types
    assert "ACTIVATION_TOKEN_REDEEM_FAILED" in event_types

    pretenant_events = store.get_audit_events(session_id=session.id, event_type="activation_token_redeem_failed")
    assert len(pretenant_events) == 1
    assert pretenant_events[0].details is not None
    assert pretenant_events[0].details["reason"] == "duplicate_cvr"
    assert "token_hash_prefix" in pretenant_events[0].details


@pytest.mark.unreconciled
def test_redeem_activation_token_duplicate_cvr_audit_commit_failure_fails_closed(
    client, db_session, sample_organization, monkeypatch
):
    sample_organization.subscription_status = "active"
    sample_organization.onboarding_data = {"cvr": "12345678"}
    db_session.add(sample_organization)
    db_session.commit()
    sample_org_id = sample_organization.id

    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None
    monkeypatch.setattr(activation_route, "PRETENANT_STORE", store)

    original_commit = db_session.commit
    call_count = {"count": 0}

    def _commit_with_duplicate_branch_failure():
        call_count["count"] += 1
        # Route duplicate branch should hit db.commit exactly once inside request.
        raise RuntimeError("forced-audit-commit-failure")

    monkeypatch.setattr(db_session, "commit", _commit_with_duplicate_branch_failure)

    response = client.post(
        "/app/activate/redeem",
        headers=_auth_header(sample_org_id, "founder@example.com"),
        json={"token": activation.token},
    )

    # Restore commit so fixture/session cleanup and follow-up checks behave normally.
    monkeypatch.setattr(db_session, "commit", original_commit)

    assert response.status_code == 500
    assert response.json()["detail"]["error_type"] == "activation_failed"
    assert call_count["count"] == 1
    assert store.get_activation_token_status(activation.token) == "active"

    # No duplicate-branch tenant audit events should persist after rollback.
    duplicate_events = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.organization_id == sample_org_id,
            AuditEvent.event_type.in_(
                ["ACTIVATION_TOKEN_REDEEM_ATTEMPTED", "ACTIVATION_TOKEN_REDEEM_FAILED"]
            ),
        )
        .all()
    )
    assert duplicate_events == []


def test_activation_audit_durability_mode_defaults_to_fail_closed(monkeypatch):
    monkeypatch.delenv("ACTIVATION_AUDIT_DURABILITY_MODE", raising=False)
    assert activation_route._activation_audit_durability_mode() == "fail_closed"


@pytest.mark.unreconciled
def test_redeem_activation_token_transactional_outbox_mode_succeeds(
    client, db_session, sample_organization, monkeypatch
):
    monkeypatch.setenv("ACTIVATION_AUDIT_DURABILITY_MODE", "transactional_outbox")

    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None
    monkeypatch.setattr(activation_route, "PRETENANT_STORE", store)

    response = client.post(
        "/app/activate/redeem",
        headers=_auth_header(sample_organization.id, "founder@example.com"),
        json={"token": activation.token},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["outcome"] == "ACTIVATED"
    assert store.get_activation_token_status(activation.token) == "redeemed"

    outbox_rows = db_session.query(ActivationAuditOutbox).all()
    assert outbox_rows
    assert all(row.status == "sent" for row in outbox_rows)
    assert all(row.processed_at is not None for row in outbox_rows)

    event_types = {
        row.event_type
        for row in db_session.query(AuditEvent).filter(AuditEvent.organization_id == payload["organizationId"]).all()
    }
    assert "ACTIVATION_TOKEN_REDEEM_SUCCEEDED" in event_types


@pytest.mark.unreconciled
def test_redeem_activation_token_transactional_outbox_flush_failure_keeps_pending_rows(
    client, db_session, sample_organization, monkeypatch
):
    monkeypatch.setenv("ACTIVATION_AUDIT_DURABILITY_MODE", "transactional_outbox")

    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_locked_draft(store, session.id)
    activation = store.create_activation_token(session.id)
    assert activation is not None
    monkeypatch.setattr(activation_route, "PRETENANT_STORE", store)

    original_flush = activation_route._flush_activation_audit_outbox_best_effort

    def _flush_failure(_db):
        raise RuntimeError("forced-outbox-flush-failure")

    monkeypatch.setattr(activation_route, "_flush_activation_audit_outbox_best_effort", _flush_failure)

    response = client.post(
        "/app/activate/redeem",
        headers=_auth_header(sample_organization.id, "founder@example.com"),
        json={"token": activation.token},
    )

    monkeypatch.setattr(activation_route, "_flush_activation_audit_outbox_best_effort", original_flush)

    assert response.status_code == 200
    payload = response.json()
    assert payload["outcome"] == "ACTIVATED"
    assert store.get_activation_token_status(activation.token) == "redeemed"

    outbox_rows = db_session.query(ActivationAuditOutbox).all()
    assert outbox_rows
    assert all(row.status == "pending" for row in outbox_rows)
    assert all(row.processed_at is None for row in outbox_rows)

    # No tenant audit rows persisted yet because the flush failed post-commit.
    tenant_events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.organization_id == payload["organizationId"])
        .all()
    )
    assert tenant_events == []

    flushed = activation_route.process_activation_audit_outbox(db_session)
    assert flushed == len(outbox_rows)

    db_session.expire_all()
    outbox_rows_after = db_session.query(ActivationAuditOutbox).all()
    assert outbox_rows_after
    assert all(row.status == "sent" for row in outbox_rows_after)
    assert all(row.processed_at is not None for row in outbox_rows_after)

    tenant_event_types = {
        row.event_type
        for row in db_session.query(AuditEvent).filter(AuditEvent.organization_id == payload["organizationId"]).all()
    }
    assert "ACTIVATION_TOKEN_REDEEM_SUCCEEDED" in tenant_event_types
