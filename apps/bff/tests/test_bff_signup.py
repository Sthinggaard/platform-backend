from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
import pytest

from bff import app as bff_module


class _DummyResponse:
    def __init__(self, status_code: int, payload: Any):
        self.status_code = status_code
        self._payload = payload
        self.headers: dict[str, str] = {}
        self.text = str(payload)

    def json(self):
        return self._payload


def test_bff_signup_start_proxies_to_upstream(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, Any] = {}
    upstream_payload = {
        "challengeId": "signup-challenge-1",
        "maskedDestination": "n***@example.com",
        "expiresAt": "2026-02-22T13:00:00Z",
        "verificationMethod": "email_code",
        "message": "Verification code sent",
    }

    async def fake_upstream_request(**kwargs):
        captured.clear()
        captured.update(kwargs)
        return _DummyResponse(status_code=200, payload=upstream_payload)

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    with TestClient(bff_module.app) as client:
        response = client.post(
            "/app/auth/signup/start",
            json={
                "activationToken": "opaque-activation-token-12345",
                "email": "new-user@example.com",
                "password": "password123",
            },
        )

    assert response.status_code == 200
    assert response.json()["challengeId"] == "signup-challenge-1"
    assert captured["method"] == "POST"
    assert captured["path"] == "/api/v1/auth/signup/start"
    assert captured["require_auth"] is False
    assert captured["json_payload"] == {
        "activation_token": "opaque-activation-token-12345",
        "email": "new-user@example.com",
        "password": "password123",
    }


def test_bff_signup_verify_propagates_upstream_error(monkeypatch: pytest.MonkeyPatch):
    async def fake_upstream_request(**kwargs):
        return _DummyResponse(
            status_code=410,
            payload={
                "error_type": "activation_token_expired",
                "message": "Activation token expired",
            },
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    with TestClient(bff_module.app) as client:
        response = client.post(
            "/app/auth/signup/verify",
            json={
                "activationToken": "opaque-activation-token-12345",
                "challengeId": "signup-challenge-1",
                "code": "123456",
            },
        )

    assert response.status_code == 410
    assert response.json()["detail"]["error_type"] == "activation_token_expired"


def test_bff_signup_resend_proxies_to_upstream(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, Any] = {}
    upstream_payload = {
        "challengeId": "signup-challenge-2",
        "maskedDestination": "n***@example.com",
        "expiresAt": "2026-02-22T13:05:00Z",
        "verificationMethod": "email_code",
        "message": "Verification code sent",
    }

    async def fake_upstream_request(**kwargs):
        captured.clear()
        captured.update(kwargs)
        return _DummyResponse(status_code=200, payload=upstream_payload)

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    with TestClient(bff_module.app) as client:
        response = client.post(
            "/app/auth/signup/resend",
            json={
                "activationToken": "opaque-activation-token-12345",
                "challengeId": "signup-challenge-1",
            },
        )

    assert response.status_code == 200
    assert response.json()["challengeId"] == "signup-challenge-2"
    assert captured["method"] == "POST"
    assert captured["path"] == "/api/v1/auth/signup/resend"
    assert captured["require_auth"] is False
    assert captured["json_payload"] == {
        "activation_token": "opaque-activation-token-12345",
        "challenge_id": "signup-challenge-1",
    }


def test_bff_signup_verify_accepts_snake_case_upstream_payload(monkeypatch: pytest.MonkeyPatch):
    """A successful verify must survive serialisation.

    Regression for the staging UAT blocker found 2026-08-17: the API completed
    the signup and returned 200, but the BFF raised ResponseValidationError on
    the nested `tenant` object and answered 500. The user was created and told
    it had failed — the worst possible pair.

    The payload below is the real upstream shape, copied from the traceback:
    the API emits this object in **snake_case**. Every other test in this file
    uses camelCase fixtures, which is exactly why the bug survived them.
    """

    upstream_payload = {
        "access_token": "upstream-access-token",
        "token_type": "bearer",
        "user": {
            "id": 1,
            "organization_id": 1,
            "email": "new-user@example.com",
            "email_verified": True,
            "status": "active",
            "role": "owner",
            "permissions": ["read"],
        },
        "tenant": {
            "id": 1,
            "name": "NOVO NORDISK A/S",
            "sso_required": False,
            "local_login_enabled": True,
        },
        "workspace_url": "/dashboard",
        "activated_at": "2026-08-17T19:06:18Z",
    }

    async def fake_upstream_request(**kwargs):
        return _DummyResponse(status_code=200, payload=upstream_payload)

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    with TestClient(bff_module.app) as client:
        response = client.post(
            "/app/auth/signup/verify",
            json={
                "activationToken": "opaque-activation-token-12345",
                "challengeId": "signup-challenge-1",
                "code": "123456",
            },
        )

    assert response.status_code == 200, response.text
    body = response.json()
    # The client is served camelCase even though the upstream spoke snake_case.
    assert body["tenant"]["ssoRequired"] is False
    assert body["tenant"]["localLoginEnabled"] is True
    assert body["user"]["organizationId"] == 1
    assert body["accessToken"] == "upstream-access-token"
