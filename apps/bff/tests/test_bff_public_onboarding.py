from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from bff import app as bff_module

#: #228 — what `/cvr/lookup` genuinely returns. The fixtures below omitted it
#: entirely, so the BFF's `CvrLookupResponse` (which requires `assumptionPreview`)
#: rejected its own upstream. Kept in one place because four fixtures need the same
#: shape, and four hand-copied versions are how one of them drifts later.
#:
#: Mirrors `CvrAssumptionPreviewResponse` in
#: `apps/server/src/api/routes/public_onboarding.py:268` — the server builds this
#: dict at line 1486 under the camelCase key.
_ASSUMPTION_PREVIEW: dict[str, Any] = {
    "archetypeKey": "professional_services",
    "archetypeLabel": "Professional services",
    "summary": "A Danish professional-services company.",
    "headline": "Professional services, Denmark",
    "source": {"provider": "cvr", "confidence": "high"},
    "businessContext": {},
    "confidence": {"overall": "high"},
    "completeness": {"score": 0.8},
}


class _DummyResponse:
    def __init__(self, status_code: int, payload: Any):
        self.status_code = status_code
        self._payload = payload
        self.headers: dict[str, str] = {}
        self.text = str(payload)

    def json(self):
        return self._payload


def _invoke(client: TestClient, method: str, path: str, payload: dict[str, Any] | None):
    if method == "GET":
        return client.get(path)
    if method == "PATCH":
        return client.patch(path, json=payload)
    return client.post(path, json=payload)


@pytest.mark.parametrize(
    ("method", "path", "payload", "upstream_payload"),
    [
        (
            "POST",
            "/public/onboarding/sessions",
            {},
            {"sessionId": "s_1", "expiresAt": "2026-02-21T12:00:00Z", "nextStep": "/onboarding"},
        ),
        (
            "GET",
            "/public/onboarding/sessions/s_1",
            None,
            {
                "sessionId": "s_1",
                "expiresAt": "2026-02-21T12:00:00Z",
                "currentStep": "CVR_ENTRY",
                "draftSnapshot": {
                    "cvr": None,
                    "companyDetails": None,
                    "riskAppetite": None,
                    "selectedAssetCategories": None,
                    "baselineComputed": False,
                },
                "nextStep": "/onboarding",
            },
        ),
        (
            "PATCH",
            "/public/onboarding/sessions/s_1",
            {"city": "Aarhus"},
            {
                "sessionId": "s_1",
                "expiresAt": "2026-02-21T12:00:00Z",
                "currentStep": "CONTEXT_CONFIRM",
                "city": "Aarhus",
                "baselineStatus": "STALE",
                "draftOrganisation": {
                    "city": "Aarhus",
                    "baselineStatus": "STALE",
                },
            },
        ),
        (
            "POST",
            "/public/onboarding/sessions/s_1/cvr",
            {"cvr": "12345678"},
            {"cvr": "12345678", "legalName": "Risklence A/S", "country": "DK"},
        ),
        (
            "POST",
            "/public/onboarding/sessions/s_1/cvr/lookup",
            {"cvr": "12345678"},
            {
                "sessionId": "s_1",
                "expiresAt": "2026-02-21T12:00:00Z",
                "nextStep": "CONFIRM_CONTEXT",
                "draftOrganisation": {
                    "cvr": "12345678",
                    "legalName": "Risklence A/S",
                    "industry": "62010",
                    "sizeBracket": None,
                    "geography": "DK",
                },
                "assumptionPreview": _ASSUMPTION_PREVIEW,
            },
        ),
        (
            "POST",
            "/public/onboarding/org-lookup",
            {"vat": "12345678"},
            {
                "vat": "12345678",
                "name": "Risklence A/S",
                "legalForm": "Anpartsselskab",
                "industry": "Computer programming activities",
                "orgSizeBand": "Small",
                "employeeCount": 24,
                "siteCount": 2,
                "multiSite": True,
                "lifecycleStage": "Mature",
            },
        ),
        (
            "POST",
            "/public/onboarding/org-confirm",
            {"vat": "12345678", "confirmed": True, "sessionId": "s_1"},
            {
                "vat": "12345678",
                "name": "Risklence A/S",
                "industryCluster": "Information",
                "orgSizeBand": "Small",
                "legalFormBand": "ApS",
                "siteCount": 2,
                "multiSite": True,
                "lifecycleStage": "Mature",
                "confirmationTimestamp": "2026-02-21T12:00:00Z",
                "sessionId": "s_1",
            },
        ),
        (
            "POST",
            "/public/onboarding/sessions/s_1/baseline",
            {},
            {
                "modelVersion": "risk-intel-baseline-v1",
                "baselineStatus": "FRESH",
                "baselineComputedAt": "2026-02-21T12:00:00Z",
                # #227 — required on the API's BaselineRiskResponse. The BFF used to
                # omit both from its own copy, so `response_model` stripped them and
                # no client ever saw that a human still had to review the baseline.
                "assumptionStatus": "assumed",
                "requiresHumanReview": True,
                "baselineRiskLandscape": {
                    "overallRiskScore": 62,
                    "riskLevel": "medium",
                    "focusAreas": [],
                    "hypotheses": [],
                    "profileFingerprint": "abc123def4567890",
                },
            },
        ),
        (
            "GET",
            "/public/onboarding/sessions/s_1/baseline",
            None,
            {
                "modelVersion": "risk-intel-baseline-v1",
                "baselineStatus": "STALE",
                "baselineComputedAt": "2026-02-21T12:00:00Z",
                # #227 — required on the API's BaselineRiskResponse. The BFF used to
                # omit both from its own copy, so `response_model` stripped them and
                # no client ever saw that a human still had to review the baseline.
                "assumptionStatus": "assumed",
                "requiresHumanReview": True,
                "baselineRiskLandscape": {
                    "overallRiskScore": 62,
                    "riskLevel": "medium",
                    "focusAreas": [],
                    "hypotheses": [],
                    "profileFingerprint": "abc123def4567890",
                },
            },
        ),
        (
            "POST",
            "/public/onboarding/sessions/s_1/finalize",
            {},
            {
                "sessionId": "s_1",
                "draftStatus": "LOCKED",
                "redirectUrl": "/login?activationToken=opaque-token",
                "tokenExpiresAt": "2026-02-21T12:10:00Z",
            },
        ),
    ],
)
def test_public_onboarding_routes_proxy_to_upstream(
    method: str,
    path: str,
    payload: dict[str, Any] | None,
    upstream_payload: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
):
    captured: dict[str, Any] = {}

    async def fake_upstream_request(**kwargs):
        captured.clear()
        captured.update(kwargs)
        status_code = 201 if path == "/public/onboarding/sessions" else 200
        return _DummyResponse(status_code=status_code, payload=upstream_payload)

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._public_onboarding_counters.clear()
    with TestClient(bff_module.app) as client:
        response = _invoke(client, method, path, payload)

    assert response.status_code in {200, 201}
    response_body = response.json()
    for key, value in upstream_payload.items():
        if isinstance(value, dict):
            assert isinstance(response_body[key], dict)
            for nested_key, nested_value in value.items():
                assert response_body[key][nested_key] == nested_value
            continue
        assert response_body[key] == value
    assert captured["method"] == method
    assert captured["path"] == path
    assert captured["require_auth"] is False
    if path.endswith("/baseline") and method == "POST" and payload == {}:
        assert captured.get("json_payload") == {"forceRecompute": False}
        return
    assert captured.get("json_payload") == payload


def test_public_onboarding_cvr_lookup_normalizes_cvr_before_upstream(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, Any] = {}

    async def fake_upstream_request(**kwargs):
        captured.clear()
        captured.update(kwargs)
        return _DummyResponse(
            status_code=200,
            payload={
                "sessionId": "s_1",
                "expiresAt": "2026-02-21T12:00:00Z",
                "nextStep": "CONFIRM_CONTEXT",
                "draftOrganisation": {
                    "cvr": "12345678",
                    "legalName": "Risklence A/S",
                    "industry": "62010",
                    "sizeBracket": None,
                    "geography": "DK",
                },
                "assumptionPreview": _ASSUMPTION_PREVIEW,
            },
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._public_onboarding_counters.clear()
    with TestClient(bff_module.app) as client:
        response = client.post("/public/onboarding/sessions/s_1/cvr/lookup", json={"cvr": "12 34 56 78"})

    assert response.status_code == 200
    assert captured["json_payload"] == {"cvr": "12345678"}


def test_public_onboarding_cvr_lookup_normalizes_cvr_with_symbols_before_upstream(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, Any] = {}

    async def fake_upstream_request(**kwargs):
        captured.clear()
        captured.update(kwargs)
        return _DummyResponse(
            status_code=200,
            payload={
                "sessionId": "s_1",
                "expiresAt": "2026-02-21T12:00:00Z",
                "nextStep": "CONFIRM_CONTEXT",
                "draftOrganisation": {
                    "cvr": "12345678",
                    "legalName": "Risklence A/S",
                    "industry": "62010",
                    "sizeBracket": None,
                    "geography": "DK",
                },
                "assumptionPreview": _ASSUMPTION_PREVIEW,
            },
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._public_onboarding_counters.clear()
    with TestClient(bff_module.app) as client:
        response = client.post("/public/onboarding/sessions/s_1/cvr/lookup", json={"cvr": "12-34-56-78"})

    assert response.status_code == 200
    assert captured["json_payload"] == {"cvr": "12345678"}


def test_public_onboarding_org_lookup_normalizes_vat_before_upstream(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, Any] = {}

    async def fake_upstream_request(**kwargs):
        captured.clear()
        captured.update(kwargs)
        return _DummyResponse(
            status_code=200,
            payload={
                "vat": "12345678",
                "name": "Risklence A/S",
                "legalForm": "Anpartsselskab",
                "industry": "Computer programming activities",
                "orgSizeBand": "Small",
                "employeeCount": 24,
                "siteCount": 2,
                "multiSite": True,
                "lifecycleStage": "Mature",
            },
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._public_onboarding_counters.clear()
    with TestClient(bff_module.app) as client:
        response = client.post("/public/onboarding/org-lookup", json={"vat": "12-34-56-78"})

    assert response.status_code == 200
    assert captured["json_payload"] == {"vat": "12345678"}


def test_public_onboarding_org_confirm_normalizes_vat_before_upstream(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, Any] = {}

    async def fake_upstream_request(**kwargs):
        captured.clear()
        captured.update(kwargs)
        return _DummyResponse(
            status_code=200,
            payload={
                "vat": "12345678",
                "name": "Risklence A/S",
                "industryCluster": "Information",
                "orgSizeBand": "Small",
                "legalFormBand": "ApS",
                "siteCount": 2,
                "multiSite": True,
                "lifecycleStage": "Mature",
                "confirmationTimestamp": "2026-02-21T12:00:00Z",
                "sessionId": "s_1",
            },
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._public_onboarding_counters.clear()
    with TestClient(bff_module.app) as client:
        response = client.post(
            "/public/onboarding/org-confirm",
            json={"vat": "12 34 56 78", "confirmed": True, "sessionId": "s_1"},
        )

    assert response.status_code == 200
    assert captured["json_payload"] == {"vat": "12345678", "confirmed": True, "sessionId": "s_1"}


def test_public_onboarding_org_confirm_rejects_invalid_vat_before_upstream(monkeypatch: pytest.MonkeyPatch):
    called = {"value": False}

    async def fake_upstream_request(**kwargs):
        called["value"] = True
        return _DummyResponse(status_code=200, payload={})

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._public_onboarding_counters.clear()
    with TestClient(bff_module.app) as client:
        response = client.post(
            "/public/onboarding/org-confirm",
            json={"vat": "1234", "confirmed": True, "sessionId": "s_1"},
        )

    assert response.status_code == 422
    assert called["value"] is False


def test_public_onboarding_org_confirm_rejects_missing_session_id_before_upstream(monkeypatch: pytest.MonkeyPatch):
    called = {"value": False}

    async def fake_upstream_request(**kwargs):
        called["value"] = True
        return _DummyResponse(status_code=200, payload={})

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._public_onboarding_counters.clear()
    with TestClient(bff_module.app) as client:
        response = client.post(
            "/public/onboarding/org-confirm",
            json={"vat": "12345678", "confirmed": True},
        )

    assert response.status_code == 422
    assert called["value"] is False


def test_public_onboarding_finalize_propagates_upstream_error(monkeypatch: pytest.MonkeyPatch):
    async def fake_upstream_request(**kwargs):
        return _DummyResponse(
            status_code=409,
            payload={
                "error_type": "incomplete_draft",
                "message": "Draft is incomplete",
            },
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._public_onboarding_counters.clear()
    with TestClient(bff_module.app) as client:
        response = client.post("/public/onboarding/sessions/s_1/finalize", json={})

    assert response.status_code == 409
    assert response.json()["detail"]["error_type"] == "incomplete_draft"


def test_public_onboarding_cvr_lookup_flattens_nested_detail_from_upstream(monkeypatch: pytest.MonkeyPatch):
    async def fake_upstream_request(**kwargs):
        return _DummyResponse(
            status_code=404,
            payload={
                "detail": {
                    "error_type": "cvr_not_found",
                    "message": "Company information unavailable",
                }
            },
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._public_onboarding_counters.clear()
    with TestClient(bff_module.app) as client:
        response = client.post("/public/onboarding/sessions/s_1/cvr/lookup", json={"cvr": "12345678"})

    assert response.status_code == 404
    assert response.json()["detail"]["error_type"] == "cvr_not_found"
    assert "detail" not in response.json()["detail"]


def test_public_onboarding_baseline_review_not_found_preserves_next_action(monkeypatch: pytest.MonkeyPatch):
    async def fake_upstream_request(**kwargs):
        return _DummyResponse(
            status_code=404,
            payload={
                "error_type": "baseline_not_found",
                "message": "Baseline preview is not available yet",
                "nextAction": "generate_baseline",
            },
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._public_onboarding_counters.clear()
    with TestClient(bff_module.app) as client:
        response = client.get("/public/onboarding/sessions/s_1/baseline")

    assert response.status_code == 404
    assert response.json()["detail"]["error_type"] == "baseline_not_found"
    assert response.json()["detail"]["nextAction"] == "generate_baseline"


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/public/onboarding/sessions/s_1/baseline"),
        ("GET", "/public/onboarding/sessions/s_1/baseline"),
    ],
)
def test_public_onboarding_baseline_routes_accept_contract_only_payload_without_legacy_field(
    method: str,
    path: str,
    monkeypatch: pytest.MonkeyPatch,
):
    async def fake_upstream_request(**kwargs):
        return _DummyResponse(
            status_code=200,
            payload={
                "sessionId": "s_1",
                "expiresAt": "2026-02-21T12:00:00Z",
                "baselineStatus": "FRESH",
                "baselineComputedAt": "2026-02-21T12:00:00Z",
                # #227 — required on the API's BaselineRiskResponse. The BFF used to
                # omit both from its own copy, so `response_model` stripped them and
                # no client ever saw that a human still had to review the baseline.
                "assumptionStatus": "assumed",
                "requiresHumanReview": True,
                "modelVersion": "risk-intel-baseline-v1",
                "baseline": {
                    "odmList": [],
                    "kriList": [],
                    "assumptions": [],
                    "confidence": {"score": 0.7, "band": "medium"},
                    "explainabilityVersion": "exp-v1",
                },
            },
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._public_onboarding_counters.clear()

    with TestClient(bff_module.app) as client:
        response = _invoke(client, method, path, {} if method == "POST" else None)

    assert response.status_code == 200
    data = response.json()
    assert data["baseline"]["explainabilityVersion"] == "exp-v1"
    assert "baselineRiskLandscape" not in data


def test_public_onboarding_cvr_lookup_propagates_generic_not_found_wording(monkeypatch: pytest.MonkeyPatch):
    async def fake_upstream_request(**kwargs):
        return _DummyResponse(
            status_code=404,
            payload={
                "error_type": "cvr_not_found",
                "message": "Company information unavailable",
            },
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._public_onboarding_counters.clear()
    with TestClient(bff_module.app) as client:
        response = client.post("/public/onboarding/sessions/s_1/cvr/lookup", json={"cvr": "12345678"})

    assert response.status_code == 404
    assert response.json()["detail"]["error_type"] == "cvr_not_found"
    assert response.json()["detail"]["message"] == "Company information unavailable"


def test_public_onboarding_start_rejects_invalid_schema_before_upstream(monkeypatch: pytest.MonkeyPatch):
    called = {"value": False}

    async def fake_upstream_request(**kwargs):
        called["value"] = True
        return _DummyResponse(status_code=201, payload={})

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._public_onboarding_counters.clear()
    with TestClient(bff_module.app) as client:
        response = client.post("/public/onboarding/sessions", json={"unexpected": "value"})

    assert response.status_code == 400
    assert response.json()["detail"]["error_type"] == "invalid_schema"
    assert called["value"] is False


def test_public_onboarding_start_rate_limit_uses_device_fingerprint(monkeypatch: pytest.MonkeyPatch):
    calls = {"count": 0}

    async def fake_upstream_request(**kwargs):
        calls["count"] += 1
        return _DummyResponse(
            status_code=201,
            payload={"sessionId": f"s_{calls['count']}", "expiresAt": "2026-02-21T12:00:00Z", "nextStep": "/onboarding"},
        )

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    monkeypatch.setattr(bff_module, "PUBLIC_ONBOARDING_RATE_LIMIT_PER_MINUTE", 1)
    bff_module._public_onboarding_counters.clear()

    with TestClient(bff_module.app) as client:
        first = client.post("/public/onboarding/sessions", json={}, headers={"x-device-fingerprint": "device-alpha"})
        second = client.post("/public/onboarding/sessions", json={}, headers={"x-device-fingerprint": "device-beta"})

    assert first.status_code == 201
    assert second.status_code == 201
    assert calls["count"] == 2


def test_public_onboarding_resume_logs_masked_session_identifier(monkeypatch: pytest.MonkeyPatch):
    log_messages: list[str] = []

    async def fake_upstream_request(**kwargs):
        return _DummyResponse(
            status_code=200,
            payload={
                "sessionId": "s_1",
                "expiresAt": "2026-02-21T12:00:00Z",
                "currentStep": "CVR_ENTRY",
                "draftSnapshot": {"baselineComputed": False},
                "nextStep": "/onboarding",
            },
        )

    def fake_logger_info(message: str):
        log_messages.append(message)

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    monkeypatch.setattr(bff_module.logger, "info", fake_logger_info)
    bff_module._public_onboarding_counters.clear()

    with TestClient(bff_module.app) as client:
        response = client.get("/public/onboarding/sessions/s_sensitive_token")

    assert response.status_code == 200
    parsed = [json.loads(msg) for msg in log_messages if msg.startswith("{")]
    explicit = next(item for item in parsed if item.get("event") == "public_onboarding_session_checked")
    assert "session_id" not in explicit
    assert explicit["session_id_masked"].startswith("id_")
    assert explicit["session_id_masked"] != "s_sensitive_token"

    edge = next(item for item in parsed if item.get("event") == "bff_request")
    assert "/public/onboarding/sessions/s_sensitive_token" not in edge["path"]
    assert "/public/onboarding/sessions/id_" in edge["path"]


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("GET", "/public/onboarding/sessions/bad.id", None),
        ("PATCH", "/public/onboarding/sessions/bad.id", {"city": "Aarhus"}),
        ("POST", "/public/onboarding/sessions/bad.id/cvr", {"cvr": "12345678"}),
        ("POST", "/public/onboarding/sessions/bad.id/cvr/lookup", {"cvr": "12345678"}),
        ("POST", "/public/onboarding/sessions/bad.id/baseline", {}),
        ("GET", "/public/onboarding/sessions/bad.id/baseline", None),
        ("POST", "/public/onboarding/sessions/bad.id/finalize", {}),
    ],
)
def test_public_onboarding_session_routes_reject_invalid_session_id_before_upstream(
    method: str,
    path: str,
    payload: dict[str, Any] | None,
    monkeypatch: pytest.MonkeyPatch,
):
    called = {"value": False}

    async def fake_upstream_request(**kwargs):
        called["value"] = True
        return _DummyResponse(status_code=200, payload={})

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    bff_module._public_onboarding_counters.clear()

    with TestClient(bff_module.app) as client:
        response = _invoke(client, method, path, payload)

    assert response.status_code == 400
    assert response.json()["detail"]["error_type"] == "invalid_session_id"
    assert called["value"] is False


@pytest.mark.parametrize(
    ("method", "path", "payload", "limit_attr", "upstream_payload"),
    [
        (
            "GET",
            "/public/onboarding/sessions/s_1",
            None,
            "PUBLIC_ONBOARDING_RESUME_RATE_LIMIT_PER_MINUTE",
            {
                "sessionId": "s_1",
                "expiresAt": "2026-02-21T12:00:00Z",
                "currentStep": "CVR_ENTRY",
                "draftSnapshot": {"baselineComputed": False},
                "nextStep": "/onboarding",
            },
        ),
        (
            "PATCH",
            "/public/onboarding/sessions/s_1",
            {"city": "Aarhus"},
            "PUBLIC_ONBOARDING_PATCH_RATE_LIMIT_PER_MINUTE",
            {
                "sessionId": "s_1",
                "expiresAt": "2026-02-21T12:00:00Z",
                "city": "Aarhus",
            },
        ),
        (
            "POST",
            "/public/onboarding/sessions/s_1/cvr/lookup",
            {"cvr": "12345678"},
            "PUBLIC_ONBOARDING_CVR_RATE_LIMIT_PER_MINUTE",
            {
                "sessionId": "s_1",
                "expiresAt": "2026-02-21T12:00:00Z",
                "nextStep": "CONFIRM_CONTEXT",
                "draftOrganisation": {
                    "cvr": "12345678",
                    "legalName": "Risklence A/S",
                    "industry": "62010",
                    "sizeBracket": None,
                    "geography": "DK",
                },
                "assumptionPreview": _ASSUMPTION_PREVIEW,
            },
        ),
        (
            "POST",
            "/public/onboarding/org-lookup",
            {"vat": "12345678"},
            "PUBLIC_ONBOARDING_ORG_LOOKUP_RATE_LIMIT_PER_MINUTE",
            {
                "vat": "12345678",
                "name": "Risklence A/S",
                "legalForm": "Anpartsselskab",
                "industry": "Computer programming activities",
                "orgSizeBand": "Small",
                "employeeCount": 24,
                "siteCount": 2,
                "multiSite": True,
                "lifecycleStage": "Mature",
            },
        ),
        (
            "POST",
            "/public/onboarding/org-confirm",
            {"vat": "12345678", "confirmed": True, "sessionId": "s_1"},
            "PUBLIC_ONBOARDING_ORG_CONFIRM_RATE_LIMIT_PER_MINUTE",
            {
                "vat": "12345678",
                "name": "Risklence A/S",
                "industryCluster": "Information",
                "orgSizeBand": "Small",
                "legalFormBand": "ApS",
                "siteCount": 2,
                "multiSite": True,
                "lifecycleStage": "Mature",
                "confirmationTimestamp": "2026-02-21T12:00:00Z",
                "sessionId": "s_1",
            },
        ),
        (
            "POST",
            "/public/onboarding/sessions/s_1/baseline",
            {},
            "PUBLIC_ONBOARDING_BASELINE_POST_RATE_LIMIT_PER_MINUTE",
            {
                "modelVersion": "risk-intel-baseline-v1",
                "baselineStatus": "FRESH",
                "baselineComputedAt": "2026-02-21T12:00:00Z",
                # #227 — required on the API's BaselineRiskResponse. The BFF used to
                # omit both from its own copy, so `response_model` stripped them and
                # no client ever saw that a human still had to review the baseline.
                "assumptionStatus": "assumed",
                "requiresHumanReview": True,
                "baselineRiskLandscape": {"overallRiskScore": 62, "riskLevel": "medium"},
            },
        ),
        (
            "GET",
            "/public/onboarding/sessions/s_1/baseline",
            None,
            "PUBLIC_ONBOARDING_BASELINE_GET_RATE_LIMIT_PER_MINUTE",
            {
                "modelVersion": "risk-intel-baseline-v1",
                "baselineStatus": "STALE",
                "baselineComputedAt": "2026-02-21T12:00:00Z",
                # #227 — required on the API's BaselineRiskResponse. The BFF used to
                # omit both from its own copy, so `response_model` stripped them and
                # no client ever saw that a human still had to review the baseline.
                "assumptionStatus": "assumed",
                "requiresHumanReview": True,
                "baselineRiskLandscape": {"overallRiskScore": 62, "riskLevel": "medium"},
            },
        ),
        (
            "POST",
            "/public/onboarding/sessions/s_1/finalize",
            {},
            "PUBLIC_ONBOARDING_FINALIZE_RATE_LIMIT_PER_MINUTE",
            {
                "sessionId": "s_1",
                "draftStatus": "LOCKED",
                "redirectUrl": "/login?activationToken=opaque-token",
                "tokenExpiresAt": "2026-02-21T12:10:00Z",
            },
        ),
    ],
)
def test_public_onboarding_endpoint_specific_rate_limits(
    method: str,
    path: str,
    payload: dict[str, Any] | None,
    limit_attr: str,
    upstream_payload: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
):
    calls = {"count": 0}

    async def fake_upstream_request(**kwargs):
        calls["count"] += 1
        return _DummyResponse(status_code=200, payload=upstream_payload)

    monkeypatch.setattr(bff_module, "_upstream_request", fake_upstream_request)
    monkeypatch.setattr(bff_module, limit_attr, 1)
    bff_module._public_onboarding_counters.clear()

    with TestClient(bff_module.app) as client:
        first = _invoke(client, method, path, payload)
        second = _invoke(client, method, path, payload)

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["detail"] == "Rate limit exceeded"
    assert calls["count"] == 1
