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
        f"{namespace}roles": ["org_admin"],
        f"{namespace}permissions": [],
    }
    token = jwt.encode(payload, get_jwt_secret_bytes(), algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def test_bff_workspace_bootstrap_proxies_to_upstream(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, Any] = {}
    upstream_payload = {
        "workspace": {
            "organizationId": 42,
            "organizationName": "Risklence Promoted A/S",
            "organizationSlug": "risklence-promoted-as",
            "userId": 777,
            "userEmail": "owner@example.com",
        },
        "baselineSummary": {
            "modelVersion": "risk-intel-baseline-v1",
            "generatedAt": "2026-02-22T10:00:00Z",
            "overallRiskScore": 62,
            "riskLevel": "medium",
            "focusAreas": ["identity_access"],
            "hypothesesCount": 2,
        },
        "nextSteps": [
            {"code": "review_baseline", "title": "Review baseline", "description": "Review promoted baseline"}
        ],
        "autoMonitoringEnabled": False,
    }

    async def fake_upstream_request(**kwargs):
        captured.clear()
        captured.update(kwargs)
        return _DummyResponse(status_code=200, payload=upstream_payload)

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    with TestClient(bff_module.app) as client:
        response = client.get("/app/workspace/bootstrap", headers=_auth_header())

    assert response.status_code == 200
    assert response.json()["workspace"]["organizationId"] == 42
    assert captured["method"] == "GET"
    assert captured["path"] == "/app/workspace/bootstrap"
    assert captured["require_auth"] is True


def test_bff_workspace_bootstrap_propagates_upstream_error(monkeypatch: pytest.MonkeyPatch):
    async def fake_upstream_request(**kwargs):
        return _DummyResponse(
            status_code=404,
            payload={"error_type": "organization_not_found", "message": "Organization not found"},
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    with TestClient(bff_module.app) as client:
        response = client.get("/app/workspace/bootstrap", headers=_auth_header())

    assert response.status_code == 404
    assert response.json()["detail"]["error_type"] == "organization_not_found"
