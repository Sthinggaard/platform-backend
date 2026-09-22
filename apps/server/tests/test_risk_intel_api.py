import httpx
import pytest
from fastapi import FastAPI

from src.api.routes import risk_intel

app = FastAPI()
app.include_router(risk_intel.router)


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _payload() -> dict:
    return {
        "organisationProfile": {
            "industryCode": "62010",
            "sizeBracket": "smb",
            "geography": "DK",
            "locations": 2,
            "itDependency": "medium",
            "riskAppetite": "balanced",
            "selectedAssetCategories": ["email", "identity"],
            "regulatoryFlags": ["GDPR"],
        }
    }


@pytest.mark.anyio
async def test_risk_intel_baseline_contract_happy_path():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/risk-intel/baseline", json=_payload())
    assert resp.status_code == 200
    data = resp.json()
    assert data["modelVersion"]
    baseline = data["baselineRiskLandscape"]
    assert "odmList" in baseline
    assert "kriList" in baseline
    assert "assumptions" in baseline
    assert "confidence" in baseline
    assert "explainabilityVersion" in baseline


@pytest.mark.anyio
async def test_risk_intel_baseline_is_deterministic_for_same_input_and_model_version():
    transport = httpx.ASGITransport(app=app)
    payload = _payload()
    payload["modelVersion"] = "current"
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        first = await client.post("/risk-intel/baseline", json=payload)
        second = await client.post("/risk-intel/baseline", json=payload)
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()


@pytest.mark.anyio
async def test_risk_intel_baseline_response_excludes_forbidden_internal_fields():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/risk-intel/baseline", json=_payload())
    assert resp.status_code == 200
    body = resp.text
    for forbidden in ("weights", "trainingData", "scoreFormula", "coefficients"):
        assert forbidden not in body


@pytest.mark.anyio
async def test_risk_intel_baseline_rejects_unsupported_model_version():
    transport = httpx.ASGITransport(app=app)
    payload = _payload()
    payload["modelVersion"] = "risk-intel-baseline-v999"
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/risk-intel/baseline", json=payload)
    assert resp.status_code == 422
    assert resp.json()["detail"]["error_type"] == "unsupported_model_version"


@pytest.mark.anyio
async def test_risk_intel_baseline_rejects_invalid_asset_category():
    transport = httpx.ASGITransport(app=app)
    payload = _payload()
    payload["organisationProfile"]["selectedAssetCategories"] = ["email", "free_text"]
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/risk-intel/baseline", json=payload)
    assert resp.status_code == 422
    assert resp.json()["detail"]["error_type"] == "validation_failed"
    assert "free_text" in resp.json()["detail"]["invalidValues"]
