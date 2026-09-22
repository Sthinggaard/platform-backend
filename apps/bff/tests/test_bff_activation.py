from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from jose import jwt
from pydantic import SecretStr
import pytest

from bff import app as bff_module
from src.core.config import settings
from src.core.utils.jwt_secrets import get_jwt_secret_bytes

settings.auth.jwt_secret = SecretStr("test-secret")


class _DummyResponse:
    def __init__(self, status_code: int, payload: Any):
        self.status_code = status_code
        self._payload = payload
        self.headers: dict[str, str] = {}
        self.text = str(payload)

    def json(self):
        return self._payload


def _auth_header(org_id: int = 1, email: str = "owner@example.com") -> dict[str, str]:
    namespace = "https://risklence.com/"
    payload = {
        "sub": "1",
        "email": email,
        f"{namespace}organization_id": org_id,
        f"{namespace}roles": ["admin"],
        f"{namespace}permissions": [],
    }
    token = jwt.encode(payload, get_jwt_secret_bytes(), algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def test_bff_activation_redeem_proxies_to_upstream(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, Any] = {}
    upstream_payload = {
        "organizationId": 42,
        "organizationName": "Risklence Promoted A/S",
        "organizationSlug": "risklence-promoted-as",
        "userId": 777,
        "userEmail": "owner@example.com",
        "workspaceUrl": "/dashboard",
        "activatedAt": "2026-02-21T17:10:00Z",
        "modelVersion": "risk-intel-baseline-v1",
    }

    async def fake_upstream_request(**kwargs):
        captured.clear()
        captured.update(kwargs)
        return _DummyResponse(status_code=200, payload=upstream_payload)

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    with TestClient(bff_module.app) as client:
        response = client.post(
            "/app/activate/redeem",
            headers=_auth_header(),
            json={"token": "opaque-activation-token"},
        )

    assert response.status_code == 200
    assert response.json()["organizationId"] == 42
    assert captured["method"] == "POST"
    assert captured["path"] == "/app/activate/redeem"
    assert captured["require_auth"] is True
    assert captured["json_payload"] == {"token": "opaque-activation-token"}


def test_bff_activation_redeem_accepts_duplicate_cvr_safe_outcome(monkeypatch: pytest.MonkeyPatch):
    async def fake_upstream_request(**kwargs):
        return _DummyResponse(
            status_code=200,
            payload={
                "outcome": "ALREADY_REGISTERED",
                "message": "Organisation already registered. Please contact your administrator.",
            },
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._app_activation_counters.clear()
    with TestClient(bff_module.app) as client:
        response = client.post(
            "/app/activate/redeem",
            headers=_auth_header(),
            json={"token": "opaque-activation-token"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["outcome"] == "ALREADY_REGISTERED"
    assert "organizationId" not in payload


def test_bff_activation_redeem_propagates_upstream_error(monkeypatch: pytest.MonkeyPatch):
    async def fake_upstream_request(**kwargs):
        return _DummyResponse(
            status_code=409,
            payload={
                "error_type": "token_redeemed",
                "message": "Activation token already redeemed",
            },
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    with TestClient(bff_module.app) as client:
        response = client.post(
            "/app/activate/redeem",
            headers=_auth_header(),
            json={"token": "opaque-activation-token"},
        )

    assert response.status_code == 409
    assert response.json()["detail"]["error_type"] == "token_redeemed"


def test_bff_activation_redeem_rate_limit_applies_before_upstream(monkeypatch: pytest.MonkeyPatch):
    calls = {"count": 0}

    async def fake_upstream_request(**kwargs):
        calls["count"] += 1
        return _DummyResponse(
            status_code=200,
            payload={
                "outcome": "ACTIVATED",
                "organizationId": 42,
                "organizationName": "Risklence Promoted A/S",
                "organizationSlug": "risklence-promoted-as",
                "userId": 777,
                "userEmail": "owner@example.com",
                "workspaceUrl": "/dashboard",
                "activatedAt": "2026-02-21T17:10:00Z",
                "modelVersion": "risk-intel-baseline-v1",
            },
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    monkeypatch.setattr(bff_module, "APP_ACTIVATION_REDEEM_RATE_LIMIT_PER_MINUTE", 1)
    bff_module._app_activation_counters.clear()

    with TestClient(bff_module.app) as client:
        first = client.post(
            "/app/activate/redeem",
            headers=_auth_header(email="one@example.com"),
            json={"token": "opaque-activation-token"},
        )
        second = client.post(
            "/app/activate/redeem",
            headers=_auth_header(email="one@example.com"),
            json={"token": "opaque-activation-token"},
        )

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["Retry-After"] == "60"
    assert calls["count"] == 1
