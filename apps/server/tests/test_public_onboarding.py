import json
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi import FastAPI

from src.api.routes import public_onboarding
from src.core import database
from src.core.exceptions import AuthorizationError
from src.pretenant import enrichment as pretenant_enrichment
from src.pretenant import risk_intelligence as pretenant_risk_intelligence
from src.pretenant import store as pretenant_store
from src.pretenant.risk_intel_client import RiskIntelligenceClient
from src.pretenant.workspace_contracts import (
    BusinessServiceAssetLink,
    CriticalityProfile,
    WorkspaceAsset,
)
from src.pretenant.workspace_service import load_workspace

app = FastAPI()
app.include_router(public_onboarding.router)


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _prepare_complete_draft(store: pretenant_store.PreTenantStore, session_id: str) -> None:
    store.update_draft_org(
        session_id,
        cvr="12345678",
        legal_name="Risklence A/S",
        country="DK",
        industry_code="62010",
        city="Copenhagen",
        baseline_snapshot={
            "overallRiskScore": 62,
            "riskLevel": "medium",
            "focusAreas": ["identity_access", "vendor_risk", "backup_resilience"],
            "hypotheses": [
                {
                    "riskCode": "R-IA-01",
                    "title": "Identity controls may be inconsistently enforced",
                    "rationale": "Initial profile indicates potential variance in IAM maturity.",
                    "likelihood": "medium",
                    "impact": "significant",
                }
            ],
            "profileFingerprint": "abc123def4567890",
        },
        baseline_model_version=pretenant_risk_intelligence.MODEL_VERSION,
        baseline_generated_at=datetime.now(timezone.utc),
    )


def _seed_baseline_ready_workspace(store: pretenant_store.PreTenantStore, session_id: str) -> None:
    draft = store.get_draft_org(session_id)
    assert draft is not None

    workspace = load_workspace(session_id, draft)
    primary_service = workspace.business_services[0]
    primary_asset = WorkspaceAsset(
        id="asset_identity_platform",
        name="Identity Platform",
        assetType="identity",
        source="manual",
        critical=True,
    )
    workspace = workspace.model_copy(
        update={
            "assets": [primary_asset],
            "service_asset_links": [
                BusinessServiceAssetLink(
                    id="link_service_identity_platform",
                    businessServiceId=primary_service.id,
                    assetId=primary_asset.id,
                    relationshipType="supports",
                    critical=True,
                )
            ],
            "criticality_profiles": [
                CriticalityProfile(
                    id="criticality_primary_service",
                    targetRef=primary_service.id,
                    targetType="business_service",
                    criticality="high",
                    rationale="Baseline tests require a confirmed critical service dependency map.",
                )
            ],
        }
    )
    store.update_draft_org(session_id, workspace_snapshot=workspace.model_dump(by_alias=True))


def _extract_activation_token(redirect_url: str) -> str:
    parsed = urlparse(redirect_url)
    token_values = parse_qs(parsed.query).get("activationToken", [])
    assert token_values
    return token_values[0]


@pytest.mark.anyio
async def test_public_onboarding_session_happy_path():
    transport = httpx.ASGITransport(app=app)
    public_onboarding._rate_limit_counters.clear()
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/public/onboarding/sessions", json={})
        assert resp.status_code == 201
        data = resp.json()
        assert data["sessionId"]
        assert data["expiresAt"]
        assert data["nextStep"] == "/onboarding"
        expires_at = datetime.fromisoformat(data["expiresAt"].replace("Z", "+00:00"))
        assert expires_at > datetime.now(timezone.utc)


@pytest.mark.anyio
async def test_public_onboarding_rate_limit(monkeypatch):
    transport = httpx.ASGITransport(app=app)
    monkeypatch.setattr(public_onboarding, "_RATE_LIMIT_PER_MINUTE", 1)
    public_onboarding._rate_limit_counters.clear()
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        assert (await client.post("/public/onboarding/sessions", json={})).status_code == 201
        resp = await client.post("/public/onboarding/sessions", json={})
        assert resp.status_code == 429


@pytest.mark.anyio
async def test_public_onboarding_expired_session(monkeypatch):
    transport = httpx.ASGITransport(app=app)
    public_onboarding._rate_limit_counters.clear()
    original_ttl = public_onboarding.PRETENANT_STORE.ttl_minutes
    monkeypatch.setattr(public_onboarding.PRETENANT_STORE, "ttl_minutes", -1)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/public/onboarding/sessions", json={})
        assert resp.status_code == 201
        session_id = resp.json()["sessionId"]
        status_resp = await client.get(f"/public/onboarding/sessions/{session_id}")
        assert status_resp.status_code == 410
    monkeypatch.setattr(public_onboarding.PRETENANT_STORE, "ttl_minutes", original_ttl)


@pytest.mark.anyio
async def test_public_onboarding_resume_returns_safe_snapshot(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(
        session.id,
        cvr="12345678",
        legal_name="Risklence A/S",
        country="DK",
        industry_code="62010",
    )
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get(f"/public/onboarding/sessions/{session.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["sessionId"] == session.id
        assert data["currentStep"] == "CONTEXT_CONFIRM"
        assert data["nextStep"] == "/onboarding"
        assert data["draftSnapshot"]["cvr"] == "12345678"
        assert data["draftSnapshot"]["baselineComputed"] is False
        assert data["draftSnapshot"]["companyDetails"]["legalName"] == "Risklence A/S"
        assert data["draftSnapshot"]["companyDetails"]["industryCode"] == "62010"
        assert data["draftSnapshot"]["companyDetails"]["geography"] == "DK"


@pytest.mark.anyio
async def test_public_onboarding_resume_locked_draft_returns_generic_unavailable(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(session.id, status="LOCKED")
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get(f"/public/onboarding/sessions/{session.id}")
        assert resp.status_code == 409
        detail = resp.json()["detail"]
        assert detail["error_type"] == "session_unavailable"


@pytest.mark.anyio
async def test_public_onboarding_invalid_schema():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/public/onboarding/sessions", json={"unexpected": "value"})
        assert resp.status_code == 400
        assert resp.json()["detail"]["error_type"] == "invalid_schema"


def test_pretenant_session_id_collision(monkeypatch):
    values = iter(["dup_session", "draft_a", "unique_session", "draft_b"])

    def fake_token(_size):
        return next(values)

    monkeypatch.setattr(pretenant_store.secrets, "token_urlsafe", fake_token)
    store = pretenant_store.PreTenantStore(ttl_minutes=1)
    existing_session, existing_org = store.create_session()
    assert existing_session.id == "dup_session"
    assert existing_org.id == "draft_a"

    new_session, new_org = store.create_session()
    assert new_session.id == "unique_session"
    assert new_org.id == "draft_b"


def test_pretenant_db_guard_blocks_access():
    token = database.set_pretenant_request(True)
    try:
        with pytest.raises(AuthorizationError):
            next(database.get_db())
    finally:
        database.reset_pretenant_request(token)


def test_pretenant_store_persistence_roundtrip(tmp_path):
    store_path = tmp_path / "pretenant-store.json"
    first = pretenant_store.PreTenantStore(
        ttl_minutes=5,
        activation_token_ttl_minutes=10,
        persistence_path=str(store_path),
    )
    session, _ = first.create_session()
    first.update_draft_org(
        session.id,
        cvr="12345678",
        legal_name="Risklence A/S",
        country="DK",
        city="Copenhagen",
    )
    token = first.create_activation_token(session.id)
    assert token is not None
    first.record_audit_event("draft_finalized", session.id, {"draft_status": "LOCKED"})
    persisted = json.loads(store_path.read_text(encoding="utf-8"))
    activation_tokens = persisted.get("activation_tokens") or {}
    assert token.token not in activation_tokens
    assert all("token" not in payload for payload in activation_tokens.values())
    assert any("token_hash" in payload for payload in activation_tokens.values())

    second = pretenant_store.PreTenantStore(persistence_path=str(store_path))
    assert second.get_session_status(session.id) == "active"
    draft = second.get_draft_org(session.id)
    assert draft is not None
    assert draft.legal_name == "Risklence A/S"
    assert draft.city == "Copenhagen"
    assert second.get_activation_token_status(token.token) == "active"
    events = second.get_audit_events(session_id=session.id, event_type="draft_finalized")
    assert len(events) == 1


def test_pretenant_store_persists_revoked_token_state(tmp_path):
    store_path = tmp_path / "pretenant-store.json"
    first = pretenant_store.PreTenantStore(
        ttl_minutes=5,
        activation_token_ttl_minutes=10,
        persistence_path=str(store_path),
    )
    session, _ = first.create_session()
    token = first.create_activation_token(session.id)
    assert token is not None
    first.revoke_activation_tokens_for_session(session.id, "manual_revoke")

    second = pretenant_store.PreTenantStore(persistence_path=str(store_path))
    assert second.get_activation_token_status(token.token) == "revoked"
    restored = second.get_activation_token(token.token)
    assert restored is not None
    assert restored.revocation_reason == "manual_revoke"

@pytest.mark.anyio
async def test_public_onboarding_cvr_timeout(monkeypatch):
    class TimeoutClient:
        def enrich(self, cvr: str):
            raise pretenant_enrichment.CvrTimeoutError("timeout")

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_enrichment_client", TimeoutClient())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/cvr", json={"cvr": "12345678"})
        assert resp.status_code == 503


@pytest.mark.anyio
async def test_public_onboarding_cvr_not_found(monkeypatch):
    class NotFoundClient:
        def enrich(self, cvr: str):
            raise pretenant_enrichment.CvrNotFoundError("not found")

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_enrichment_client", NotFoundClient())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/cvr", json={"cvr": "12345678"})
        assert resp.status_code == 404
        body = resp.json()
        assert body["detail"]["error_type"] == "cvr_not_found"
        assert body["detail"]["message"] == "Company information unavailable"


@pytest.mark.anyio
async def test_public_onboarding_cvr_happy_path(monkeypatch):
    class OkClient:
        def enrich(self, cvr: str):
            return pretenant_enrichment.CvrEnrichmentResult(
                cvr=cvr,
                legal_name="Risklence A/S",
                trade_name="Risklence",
                address="Street 1",
                postal_code="1000",
                city="Copenhagen",
                country="DK",
                industry_code="62010",
            )

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_enrichment_client", OkClient())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/cvr", json={"cvr": "12345678"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["cvr"] == "12345678"
        assert data["legalName"] == "Risklence A/S"


@pytest.mark.anyio
async def test_public_onboarding_cvr_lookup_happy_path_wrapped_response(monkeypatch):
    class OkClient:
        def enrich(self, cvr: str):
            return pretenant_enrichment.CvrEnrichmentResult(
                cvr=cvr,
                legal_name="Risklence A/S",
                country="DK",
                industry_code="62010",
                industry_desc="Computer programming activities",
            )

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_enrichment_client", OkClient())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(
            f"/public/onboarding/sessions/{session.id}/cvr/lookup",
            json={"cvr": "12 34 56 78"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["sessionId"] == session.id
        assert data["nextStep"] == "CONFIRM_CONTEXT"
        assert data["draftOrganisation"]["cvr"] == "12345678"
        assert data["draftOrganisation"]["legalName"] == "Risklence A/S"
        assert data["draftOrganisation"]["tradeName"] is None
        assert data["draftOrganisation"]["address"] is None
        assert data["draftOrganisation"]["postalCode"] is None
        assert data["draftOrganisation"]["city"] is None
        assert data["draftOrganisation"]["country"] == "DK"
        assert data["draftOrganisation"]["industryCode"] == "62010"
        assert data["draftOrganisation"]["industry"] == "Computer programming activities"
        assert data["draftOrganisation"]["geography"] == "DK"
        assert data["assumptionPreview"]["archetypeKey"] == "software"
        assert data["assumptionPreview"]["continuityAssumption"]["status"] == "assumed"
        assert data["assumptionPreview"]["continuityAssumption"]["label"] == "Very low — availability supports delivery"
        assert [item["key"] for item in data["assumptionPreview"]["suggestedProcesses"]] == [
            "software_delivery",
            "platform_operations",
            "quote_to_cash",
            "customer_service",
            "contract_to_renewal",
        ]
        flagship = data["assumptionPreview"]["flagshipProcess"]
        assert flagship["templateKey"] == "software_delivery"
        assert flagship["source"] == "risk_intelligence_engine"
        assert flagship["processMap"]["nodes"][1]["confidence"] == "assumed"
        assert flagship["processMap"]["flows"][0]["kind"] == "sequence"
        assert data["assumptionPreview"]["completeness"]["status"] == "partial"
        assert data["assumptionPreview"]["focusAreas"][0]["source"] == "industry_archetype"
        assert data["assumptionPreview"]["source"]["retrievedAt"]
        assert set(data.keys()) == {"sessionId", "expiresAt", "nextStep", "draftOrganisation", "assumptionPreview"}
        assert set(data["draftOrganisation"].keys()) == {
            "cvr",
            "legalName",
            "tradeName",
            "address",
            "postalCode",
            "city",
            "country",
            "industryCode",
            "industry",
            "sizeBracket",
            "geography",
        }


@pytest.mark.anyio
async def test_public_onboarding_business_context_refines_the_flagship_process(monkeypatch):
    class OkClient:
        def enrich(self, cvr: str):
            return pretenant_enrichment.CvrEnrichmentResult(
                cvr=cvr,
                legal_name="Risklence A/S",
                country="DK",
                industry_code="62010",
                industry_desc="Computer programming activities",
            )

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_enrichment_client", OkClient())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        lookup = await client.post(
            f"/public/onboarding/sessions/{session.id}/cvr/lookup",
            json={"cvr": "12345678"},
        )
        assert lookup.status_code == 200

        response = await client.post(
            f"/public/onboarding/sessions/{session.id}/business-context",
            json={
                "primaryBusinessActivity": "physical_products",
                "criticalBusinessActivity": "plan_and_make",
                "customerVisibleImpact": ["product_or_service_stops_working", "late_or_missed_deliveries"],
                "timeSensitivity": "same_day",
                "hardToReplaceQuickly": ["key_people_or_expertise"],
                "operationalReach": "single_location",
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert data["assumptionPreview"]["businessContext"]["criticalBusinessActivity"] == "plan_and_make"
    assert data["assumptionPreview"]["businessContext"]["customerVisibleImpact"] == [
        "product_or_service_stops_working",
        "late_or_missed_deliveries",
    ]
    assert data["assumptionPreview"]["flagshipProcess"]["templateKey"] == "plan_to_produce"
    assert data["assumptionPreview"]["flagshipProcess"]["source"] == "company_context_suggestion"
    assert data["draftOrganisation"]["industry"] == "Computer programming activities"
    assert data["assumptionPreview"]["source"]["industry"] == "Computer programming activities"
    assert store.get_draft_org(session.id).business_context == {
        "primaryBusinessActivity": "physical_products",
        "criticalBusinessActivity": "plan_and_make",
        "customerVisibleImpact": ["product_or_service_stops_working", "late_or_missed_deliveries"],
        "timeSensitivity": "same_day",
        "hardToReplaceQuickly": ["key_people_or_expertise"],
        "operationalReach": "single_location",
    }


@pytest.mark.anyio
async def test_public_onboarding_business_context_rejects_unknown_multi_select_value(monkeypatch):
    class OkClient:
        def enrich(self, cvr: str):
            return pretenant_enrichment.CvrEnrichmentResult(
                cvr=cvr,
                legal_name="Risklence A/S",
                country="DK",
                industry_code="62010",
                industry_desc="Computer programming activities",
            )

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_enrichment_client", OkClient())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        lookup = await client.post(
            f"/public/onboarding/sessions/{session.id}/cvr/lookup",
            json={"cvr": "12345678"},
        )
        assert lookup.status_code == 200

        response = await client.post(
            f"/public/onboarding/sessions/{session.id}/business-context",
            json={"customerVisibleImpact": ["not_a_real_value"]},
        )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_public_onboarding_business_context_expired_session(monkeypatch):
    transport = httpx.ASGITransport(app=app)
    public_onboarding._rate_limit_counters.clear()
    original_ttl = public_onboarding.PRETENANT_STORE.ttl_minutes
    monkeypatch.setattr(public_onboarding.PRETENANT_STORE, "ttl_minutes", -1)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/public/onboarding/sessions", json={})
        session_id = resp.json()["sessionId"]
        response = await client.post(
            f"/public/onboarding/sessions/{session_id}/business-context",
            json={"primaryBusinessActivity": "digital_products"},
        )
    monkeypatch.setattr(public_onboarding.PRETENANT_STORE, "ttl_minutes", original_ttl)

    assert response.status_code == 410
    assert response.json()["detail"]["error_type"] == "session_expired"


@pytest.mark.anyio
async def test_public_onboarding_business_context_locked_draft(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(session.id, cvr="12345678", legal_name="Risklence A/S", status="LOCKED")
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            f"/public/onboarding/sessions/{session.id}/business-context",
            json={"primaryBusinessActivity": "digital_products"},
        )

    assert response.status_code == 409
    assert response.json()["detail"]["error_type"] == "draft_locked"


@pytest.mark.anyio
async def test_public_onboarding_business_context_requires_cvr_first(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            f"/public/onboarding/sessions/{session.id}/business-context",
            json={"primaryBusinessActivity": "digital_products"},
        )

    assert response.status_code == 409
    assert response.json()["detail"]["error_type"] == "cvr_required"


@pytest.mark.anyio
async def test_public_onboarding_business_context_skip_preserves_cvr_only_picture(monkeypatch):
    class OkClient:
        def enrich(self, cvr: str):
            return pretenant_enrichment.CvrEnrichmentResult(
                cvr=cvr,
                legal_name="Risklence A/S",
                country="DK",
                industry_code="62010",
                industry_desc="Computer programming activities",
            )

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_enrichment_client", OkClient())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        lookup = await client.post(
            f"/public/onboarding/sessions/{session.id}/cvr/lookup",
            json={"cvr": "12345678"},
        )
        cvr_only_preview = lookup.json()["assumptionPreview"]

        response = await client.post(
            f"/public/onboarding/sessions/{session.id}/business-context",
            json={},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["assumptionPreview"]["businessContext"] == {}
    assert data["assumptionPreview"]["archetypeKey"] == cvr_only_preview["archetypeKey"]
    assert data["assumptionPreview"]["flagshipProcess"]["templateKey"] == cvr_only_preview["flagshipProcess"]["templateKey"]
    assert data["assumptionPreview"]["flagshipProcess"]["source"] != "company_context_suggestion"


@pytest.mark.anyio
async def test_public_onboarding_cvr_lookup_normalizes_non_digit_input(monkeypatch):
    class OkClient:
        def enrich(self, cvr: str):
            return pretenant_enrichment.CvrEnrichmentResult(
                cvr=cvr,
                legal_name="Risklence A/S",
                country="DK",
                industry_code="62010",
            )

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_enrichment_client", OkClient())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(
            f"/public/onboarding/sessions/{session.id}/cvr/lookup",
            json={"cvr": "12-34-56-78"},
        )

    assert resp.status_code == 200
    assert resp.json()["draftOrganisation"]["cvr"] == "12345678"


@pytest.mark.anyio
async def test_public_onboarding_cvr_lookup_not_found_uses_generic_wording(monkeypatch):
    class NotFoundClient:
        def enrich(self, cvr: str):
            raise pretenant_enrichment.CvrNotFoundError("not found")

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_enrichment_client", NotFoundClient())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(
            f"/public/onboarding/sessions/{session.id}/cvr/lookup",
            json={"cvr": "12345678"},
        )
        assert resp.status_code == 404
        body = resp.json()
        assert body["detail"]["error_type"] == "cvr_not_found"
        assert body["detail"]["message"] == "Company information unavailable"


@pytest.mark.anyio
async def test_public_onboarding_org_lookup_happy_path(monkeypatch):
    class LookupClient:
        def lookup_verified_organisation(self, vat: str):
            return pretenant_enrichment.CvrOrganisationLookupResult(
                vat=vat,
                name="Risklence Demo A/S",
                legal_form="Anpartsselskab",
                industry="Computer programming activities",
                employee_count=25,
                industry_cluster="Information",
                org_size_band="Small",
                legal_form_band="ApS",
                site_count=2,
                multi_site=True,
                lifecycle_stage="Mature",
                employee_uncertain=False,
            )

    monkeypatch.setattr(public_onboarding, "_enrichment_client", LookupClient())
    public_onboarding._rate_limit_counters.clear()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/public/onboarding/org-lookup", json={"vat": "12-34-56-78"})

    assert resp.status_code == 200
    assert resp.json() == {
        "vat": "12345678",
        "name": "Risklence Demo A/S",
        "legalForm": "Anpartsselskab",
        "industry": "Computer programming activities",
        "orgSizeBand": "Small",
        "employeeCount": 25,
        "siteCount": 2,
        "multiSite": True,
        "lifecycleStage": "Mature",
    }


@pytest.mark.anyio
async def test_public_onboarding_org_lookup_rate_limit(monkeypatch):
    class LookupClient:
        def lookup_verified_organisation(self, vat: str):
            return pretenant_enrichment.CvrOrganisationLookupResult(
                vat=vat,
                name="Risklence Demo A/S",
                legal_form="Anpartsselskab",
                industry="Computer programming activities",
                employee_count=25,
                industry_cluster="Information",
                org_size_band="Small",
                legal_form_band="ApS",
                site_count=2,
                multi_site=True,
                lifecycle_stage="Mature",
                employee_uncertain=False,
            )

    monkeypatch.setattr(public_onboarding, "_enrichment_client", LookupClient())
    monkeypatch.setattr(public_onboarding, "_ORG_LOOKUP_RATE_LIMIT_PER_MINUTE", 1)
    public_onboarding._rate_limit_counters.clear()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        first = await client.post("/public/onboarding/org-lookup", json={"vat": "12345678"})
        second = await client.post("/public/onboarding/org-lookup", json={"vat": "12345678"})

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["detail"]["error_type"] == "rate_limit"


@pytest.mark.anyio
async def test_public_onboarding_org_confirm_requires_valid_session_id(monkeypatch):
    class LookupClient:
        def lookup_verified_organisation(self, vat: str):
            return pretenant_enrichment.CvrOrganisationLookupResult(
                vat=vat,
                name="Risklence Demo A/S",
                legal_form="Anpartsselskab",
                industry="Computer programming activities",
                employee_count=25,
                industry_cluster="Information",
                org_size_band="Small",
                legal_form_band="ApS",
                site_count=2,
                multi_site=True,
                lifecycle_stage="Mature",
                employee_uncertain=False,
            )

    monkeypatch.setattr(public_onboarding, "_enrichment_client", LookupClient())
    public_onboarding._rate_limit_counters.clear()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(
            "/public/onboarding/org-confirm",
            json={"vat": "12345678", "confirmed": True, "sessionId": "bad.id"},
        )

    assert resp.status_code == 422
    errors = resp.json()["detail"]
    assert isinstance(errors, list)
    assert any(error.get("loc") == ["body", "sessionId"] for error in errors)


@pytest.mark.anyio
async def test_public_onboarding_org_confirm_persists_verified_profile(monkeypatch):
    class LookupClient:
        def lookup_verified_organisation(self, vat: str):
            return pretenant_enrichment.CvrOrganisationLookupResult(
                vat=vat,
                name="Risklence Demo A/S",
                legal_form="Anpartsselskab",
                industry="Computer programming activities",
                employee_count=25,
                industry_cluster="Information",
                org_size_band="Small",
                legal_form_band="ApS",
                site_count=2,
                multi_site=True,
                lifecycle_stage="Mature",
                employee_uncertain=False,
            )

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_enrichment_client", LookupClient())
    public_onboarding._rate_limit_counters.clear()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(
            "/public/onboarding/org-confirm",
            json={"vat": "12 34 56 78", "confirmed": True, "sessionId": session.id},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["vat"] == "12345678"
    assert body["sessionId"] == session.id
    assert body["industryCluster"] == "Information"
    stored_profile = store.get_verified_org_profile(session.id)
    assert stored_profile is not None
    assert stored_profile.vat == "12345678"
    assert stored_profile.name == "Risklence Demo A/S"
    assert stored_profile.org_size_band == "Small"
    assert stored_profile.session_id == session.id


@pytest.mark.anyio
async def test_public_onboarding_org_confirm_requires_confirmed_true(monkeypatch):
    class LookupClient:
        def lookup_verified_organisation(self, vat: str):
            raise AssertionError("lookup should not run when confirmed=false")

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_enrichment_client", LookupClient())
    public_onboarding._rate_limit_counters.clear()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(
            "/public/onboarding/org-confirm",
            json={"vat": "12345678", "confirmed": False, "sessionId": session.id},
        )

    assert resp.status_code == 400
    assert resp.json()["detail"]["error_type"] == "invalid_confirmation"


@pytest.mark.anyio
async def test_public_onboarding_cvr_lookup_locked_draft(monkeypatch):
    class OkClient:
        def enrich(self, cvr: str):
            raise AssertionError("enrich must not be called for locked draft")

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(session.id, status="LOCKED")
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_enrichment_client", OkClient())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(
            f"/public/onboarding/sessions/{session.id}/cvr/lookup",
            json={"cvr": "12345678"},
        )
        assert resp.status_code == 409
        assert resp.json()["detail"]["error_type"] == "draft_locked"


@pytest.mark.anyio
async def test_public_onboarding_cvr_timing_guard(monkeypatch):
    class OkClient:
        def enrich(self, cvr: str):
            return pretenant_enrichment.CvrEnrichmentResult(cvr=cvr, legal_name="Risklence A/S")

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_enrichment_client", OkClient())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        start = time.monotonic()
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/cvr", json={"cvr": "12345678"})
        elapsed_ms = (time.monotonic() - start) * 1000
        assert resp.status_code == 200
        assert elapsed_ms >= 200


@pytest.mark.anyio
async def test_public_onboarding_baseline_happy_path(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(
        session.id,
        cvr="12345678",
        legal_name="Risklence A/S",
        country="DK",
        industry_code="62010",
        city="Copenhagen",
        size_bracket="smb",
        geography="DK",
        locations=1,
        it_dependency="medium",
        risk_appetite="balanced",
        selected_asset_categories=["identity", "email"],
    )
    _seed_baseline_ready_workspace(store, session.id)
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_risk_intelligence_engine", pretenant_risk_intelligence.RiskIntelligenceEngine())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/baseline", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["modelVersion"] == pretenant_risk_intelligence.MODEL_VERSION
        assert data["sessionId"] == session.id
        assert data["expiresAt"]
        assert "baseline" in data
        assert data["assumptionStatus"] == public_onboarding.PUBLIC_BASELINE_ASSUMPTION_STATUS
        assert data["requiresHumanReview"] is True
        assert "_legacy" not in data["baseline"]
        assert "weights" not in data["baseline"]
        assert "baselineRiskLandscape" in data
        assert "overallRiskScore" in data["baselineRiskLandscape"]
        assert "sessionId" not in data["baselineRiskLandscape"]
        assert data["baselineStatus"] == "FRESH"
        assert data["baselineComputedAt"]
        draft = store.get_draft_org(session.id)
        assert draft is not None
        assert draft.baseline_model_version == data["modelVersion"]
        assert draft.baseline_snapshot is not None
        assert draft.baseline_snapshot.get("_legacy") == data["baselineRiskLandscape"]
        assert {k: v for k, v in draft.baseline_snapshot.items() if k != "_legacy"} == data["baseline"]
        assert draft.baseline_stale is False
        assert draft.baseline_input_hash


@pytest.mark.anyio
async def test_public_onboarding_baseline_happy_path_omits_legacy_field_when_flag_disabled(monkeypatch):
    monkeypatch.setenv("FEATURE_FLAG_PUBLIC_BASELINE_LEGACY_FIELD", "false")
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(
        session.id,
        cvr="12345678",
        legal_name="Risklence A/S",
        country="DK",
        industry_code="62010",
        size_bracket="smb",
        geography="DK",
        locations=1,
        it_dependency="medium",
        risk_appetite="balanced",
        selected_asset_categories=["identity"],
    )
    _seed_baseline_ready_workspace(store, session.id)
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_risk_intelligence_engine", pretenant_risk_intelligence.RiskIntelligenceEngine())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/baseline", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert "baseline" in data
        assert "baselineRiskLandscape" not in data
        assert data["baselineStatus"] == "FRESH"


@pytest.mark.anyio
async def test_public_onboarding_baseline_insufficient_data(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/baseline", json={})
        assert resp.status_code == 422
        assert resp.json()["detail"]["error_type"] == "draft_incomplete"
        assert "missingFields" in resp.json()["detail"]


@pytest.mark.anyio
async def test_public_onboarding_baseline_allows_missing_size_bracket(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(
        session.id,
        cvr="12345678",
        legal_name="Risklence A/S",
        country="DK",
        industry_code="62010",
        geography="DK",
        locations=1,
        it_dependency="medium",
        risk_appetite="balanced",
        selected_asset_categories=["identity"],
        size_bracket=None,
    )
    _seed_baseline_ready_workspace(store, session.id)
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_risk_intelligence_engine", pretenant_risk_intelligence.RiskIntelligenceEngine())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/baseline", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["modelVersion"] == pretenant_risk_intelligence.MODEL_VERSION
        assert data["baselineStatus"] == "FRESH"


@pytest.mark.anyio
async def test_public_onboarding_baseline_model_unavailable(monkeypatch):
    class UnavailableEngine:
        def generate_baseline(self, profile: pretenant_risk_intelligence.OrganisationProfile):
            raise pretenant_risk_intelligence.RiskModelUnavailableError("down")

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(
        session.id,
        cvr="12345678",
        legal_name="Risklence A/S",
        country="DK",
        industry_code="62010",
        size_bracket="smb",
        geography="DK",
        locations=1,
        it_dependency="medium",
        risk_appetite="balanced",
        selected_asset_categories=["identity"],
    )
    _seed_baseline_ready_workspace(store, session.id)
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_risk_intelligence_engine", UnavailableEngine())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/baseline", json={})
        assert resp.status_code == 503
        detail = resp.json()["detail"]
        assert detail["error_type"] == "modeling_unavailable"
        assert "tenant" not in detail["message"].lower()
        assert "customer" not in detail["message"].lower()


@pytest.mark.anyio
async def test_public_onboarding_baseline_is_deterministic(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(
        session.id,
        cvr="12345678",
        legal_name="Risklence A/S",
        country="DK",
        industry_code="62010",
        city="Copenhagen",
        size_bracket="smb",
        geography="DK",
        locations=2,
        it_dependency="high",
        risk_appetite="balanced",
        selected_asset_categories=["identity", "endpoint"],
    )
    _seed_baseline_ready_workspace(store, session.id)
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_risk_intelligence_engine", pretenant_risk_intelligence.RiskIntelligenceEngine())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        first = await client.post(f"/public/onboarding/sessions/{session.id}/baseline", json={})
        second = await client.post(f"/public/onboarding/sessions/{session.id}/baseline", json={})
        assert first.status_code == 200
        assert second.status_code == 200
        assert first.json() == second.json()


@pytest.mark.anyio
async def test_public_onboarding_baseline_happy_path_internal_contract_mode(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(
        session.id,
        cvr="12345678",
        legal_name="Risklence A/S",
        country="DK",
        industry_code="62010",
        city="Copenhagen",
        size_bracket="smb",
        geography="DK",
        locations=1,
        it_dependency="medium",
        risk_appetite="balanced",
        selected_asset_categories=["identity", "email"],
    )
    _seed_baseline_ready_workspace(store, session.id)
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_risk_intelligence_client", RiskIntelligenceClient(mode="internal_contract"))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/baseline", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert data["modelVersion"] == pretenant_risk_intelligence.MODEL_VERSION
    assert "kriList" in data["baseline"]


@pytest.mark.anyio
async def test_public_onboarding_baseline_review_happy_path(monkeypatch):
    class PanicEngine:
        def generate_baseline(self, profile: pretenant_risk_intelligence.OrganisationProfile):
            raise AssertionError("GET baseline must not recompute")

    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    baseline_snapshot = {
        "overallRiskScore": 62,
        "riskLevel": "medium",
        "focusAreas": ["identity_access", "backup_resilience", "vendor_risk"],
        "hypotheses": [
            {
                "riskCode": "R-IA-01",
                "title": "Identity controls may be inconsistently enforced",
                "rationale": "Initial profile indicates potential variance in IAM maturity.",
                "likelihood": "medium",
                "impact": "significant",
            }
        ],
        "profileFingerprint": "abc123def4567890",
    }
    store.update_draft_org(
        session.id,
        baseline_snapshot=baseline_snapshot,
        baseline_model_version="risk-intel-baseline-v1",
        baseline_generated_at=datetime.now(timezone.utc),
        baseline_stale=False,
    )
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_risk_intelligence_engine", PanicEngine())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get(f"/public/onboarding/sessions/{session.id}/baseline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["modelVersion"] == "risk-intel-baseline-v1"
        assert data["baselineRiskLandscape"] == baseline_snapshot
        assert data["baseline"] == baseline_snapshot
        assert "_legacy" not in data["baseline"]
        assert "weights" not in data["baseline"]
        assert data["baselineStatus"] == "FRESH"
        assert data["baselineComputedAt"]


@pytest.mark.anyio
async def test_public_onboarding_baseline_review_omits_legacy_field_when_flag_disabled(monkeypatch):
    monkeypatch.setenv("FEATURE_FLAG_PUBLIC_BASELINE_LEGACY_FIELD", "false")
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(
        session.id,
        baseline_snapshot={
            "odmList": [],
            "kriList": [],
            "assumptions": [],
            "confidence": {"score": 0.7, "band": "medium"},
            "explainabilityVersion": "exp-v1",
        },
        baseline_model_version="risk-intel-baseline-v1",
        baseline_generated_at=datetime.now(timezone.utc),
        baseline_stale=False,
    )
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get(f"/public/onboarding/sessions/{session.id}/baseline")
        assert resp.status_code == 200
        data = resp.json()
        assert "baseline" in data
        assert "baselineRiskLandscape" not in data
        assert data["baseline"]["explainabilityVersion"] == "exp-v1"


@pytest.mark.anyio
async def test_public_onboarding_baseline_review_not_found(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get(f"/public/onboarding/sessions/{session.id}/baseline")
        assert resp.status_code == 404
        detail = resp.json()["detail"]
        assert detail["error_type"] == "baseline_not_found"
        assert detail["nextAction"] == "generate_baseline"
        assert "tenant" not in detail["message"].lower()
        assert "customer" not in detail["message"].lower()


@pytest.mark.anyio
async def test_public_onboarding_baseline_review_stale_status(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(
        session.id,
        baseline_snapshot={"overallRiskScore": 55},
        baseline_model_version="risk-intel-baseline-v1",
        baseline_generated_at=datetime.now(timezone.utc),
        baseline_stale=True,
    )
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get(f"/public/onboarding/sessions/{session.id}/baseline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["baselineStatus"] == "STALE"
        assert data["baselineComputedAt"]


@pytest.mark.anyio
async def test_public_onboarding_baseline_review_expired_session(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=-1)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get(f"/public/onboarding/sessions/{session.id}/baseline")
        assert resp.status_code == 410
        detail = resp.json()["detail"]
        assert detail["error_type"] == "session_expired"
        assert "tenant" not in detail["message"].lower()
        assert "customer" not in detail["message"].lower()


@pytest.mark.anyio
async def test_public_onboarding_baseline_generate_locked_draft_is_generic_unavailable(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(
        session.id,
        cvr="12345678",
        legal_name="Risklence A/S",
        industry_code="62010",
        size_bracket="smb",
        geography="DK",
        locations=1,
        it_dependency="medium",
        risk_appetite="balanced",
        selected_asset_categories=["identity"],
        status="LOCKED",
    )
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/baseline", json={})
        assert resp.status_code == 409
        detail = resp.json()["detail"]
        assert detail["error_type"] == "draft_unavailable"
        assert "tenant" not in detail["message"].lower()
        assert "customer" not in detail["message"].lower()


@pytest.mark.anyio
async def test_public_onboarding_patch_answers_happy_path(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.patch(
            f"/public/onboarding/sessions/{session.id}",
            json={
                "legalName": "Risklence A/S",
                "tradeName": "Risklence",
                "city": "Aarhus",
                "country": "dk",
                "industryCode": "62010",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["legalName"] == "Risklence A/S"
        assert data["tradeName"] == "Risklence"
        assert data["city"] == "Aarhus"
        assert data["country"] == "DK"
        assert data["draftOrganisation"]["legalName"] == "Risklence A/S"
        assert data["draftOrganisation"]["tradeName"] == "Risklence"
        assert data["draftOrganisation"]["city"] == "Aarhus"
        assert data["draftOrganisation"]["country"] == "DK"
        draft = store.get_draft_org(session.id)
        assert draft is not None
        assert draft.legal_name == "Risklence A/S"
        assert draft.trade_name == "Risklence"
        assert draft.city == "Aarhus"
        assert draft.country == "DK"


@pytest.mark.anyio
async def test_public_onboarding_patch_answers_invalid_fields(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.patch(
            f"/public/onboarding/sessions/{session.id}",
            json={"unexpectedField": "value"},
        )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error_type"] == "invalid_fields"


@pytest.mark.anyio
async def test_public_onboarding_patch_answers_locked_draft(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(session.id, status="LOCKED")
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.patch(
            f"/public/onboarding/sessions/{session.id}",
            json={"city": "Aarhus"},
        )
        assert resp.status_code == 409
        assert resp.json()["detail"]["error_type"] == "draft_locked"


@pytest.mark.anyio
async def test_public_onboarding_record_event_happy_path(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(
            f"/public/onboarding/sessions/{session.id}/events",
            json={
                "event_type": "value_stream_confirmed",
                "details": {"selected": ["order_to_cash"]},
            },
        )
        assert resp.status_code == 204

    events = store.get_audit_events(session_id=session.id, event_type="value_stream_confirmed")
    assert len(events) == 1
    assert events[0].details == {"selected": ["order_to_cash"]}


@pytest.mark.anyio
async def test_public_onboarding_record_event_locked_draft(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(session.id, status="LOCKED")
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(
            f"/public/onboarding/sessions/{session.id}/events",
            json={"event_type": "value_stream_confirmed"},
        )
        assert resp.status_code == 409
        assert resp.json()["detail"]["error_type"] == "draft_locked"


@pytest.mark.anyio
async def test_public_onboarding_patch_answers_rerun_baseline(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(
        session.id,
        cvr="12345678",
        legal_name="Risklence A/S",
        country="DK",
        industry_code="62010",
        city="Copenhagen",
        size_bracket="smb",
        geography="DK",
        locations=1,
        it_dependency="medium",
        risk_appetite="balanced",
        selected_asset_categories=["identity"],
    )
    _seed_baseline_ready_workspace(store, session.id)
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_risk_intelligence_engine", pretenant_risk_intelligence.RiskIntelligenceEngine())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.patch(
            f"/public/onboarding/sessions/{session.id}",
            json={"city": "Aarhus", "rerunBaseline": True},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["modelVersion"] == pretenant_risk_intelligence.MODEL_VERSION
        assert "baselineRiskLandscape" in data
        assert data["baselineStatus"] == "FRESH"
        draft = store.get_draft_org(session.id)
        assert draft is not None
        assert draft.baseline_snapshot == data["baselineRiskLandscape"]
        assert draft.baseline_model_version == data["modelVersion"]
        assert draft.baseline_stale is False


@pytest.mark.anyio
async def test_public_onboarding_patch_answers_expired_session(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=-1)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.patch(
            f"/public/onboarding/sessions/{session.id}",
            json={"city": "Aarhus"},
        )
        assert resp.status_code == 410
        assert resp.json()["detail"]["error_type"] == "session_expired"


@pytest.mark.anyio
async def test_public_onboarding_patch_answers_typed_fields_happy_path(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.patch(
            f"/public/onboarding/sessions/{session.id}",
            json={
                "locations": 3,
                "itDependency": "high",
                "riskAppetite": "balanced",
                "selectedAssetCategories": ["email", "endpoint", "email"],
                "regulatoryFlags": ["gdpr", "NIS2"],
                "geography": "dk",
                "sizeBracket": "SMB",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["locations"] == 3
        assert data["itDependency"] == "high"
        assert data["riskAppetite"] == "balanced"
        assert data["selectedAssetCategories"] == ["email", "endpoint"]
        assert data["regulatoryFlags"] == ["GDPR", "NIS2"]
        assert data["geography"] == "DK"
        assert data["sizeBracket"] == "smb"
        assert data["currentStep"] == "CVR_ENTRY"
        assert data["draftOrganisation"]["locations"] == 3
        assert data["draftOrganisation"]["itDependency"] == "high"
        assert data["draftOrganisation"]["riskAppetite"] == "balanced"
        assert data["draftOrganisation"]["selectedAssetCategories"] == ["email", "endpoint"]
        assert data["draftOrganisation"]["regulatoryFlags"] == ["GDPR", "NIS2"]
        assert data["draftOrganisation"]["geography"] == "DK"
        assert data["draftOrganisation"]["sizeBracket"] == "smb"

        draft = store.get_draft_org(session.id)
        assert draft is not None
        assert draft.locations == 3
        assert draft.it_dependency == "high"
        assert draft.risk_appetite == "balanced"
        assert draft.selected_asset_categories == ["email", "endpoint"]
        assert draft.regulatory_flags == ["GDPR", "NIS2"]
        assert draft.geography == "DK"
        assert draft.size_bracket == "smb"


@pytest.mark.anyio
async def test_public_onboarding_patch_answers_invalid_enum_returns_422(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.patch(
            f"/public/onboarding/sessions/{session.id}",
            json={"itDependency": "extreme"},
        )
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert detail["error_type"] == "validation_failed"
        assert detail["field"] == "itDependency"


@pytest.mark.anyio
async def test_public_onboarding_patch_answers_invalid_category_returns_422(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.patch(
            f"/public/onboarding/sessions/{session.id}",
            json={"selectedAssetCategories": ["email", "free-text"]},
        )
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert detail["error_type"] == "validation_failed"
        assert detail["field"] == "selectedAssetCategories"


@pytest.mark.anyio
async def test_public_onboarding_patch_material_change_marks_baseline_stale(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(
        session.id,
        cvr="12345678",
        legal_name="Risklence A/S",
        country="DK",
        baseline_snapshot={"overallRiskScore": 50},
        baseline_model_version="risk-intel-baseline-v1",
        baseline_stale=False,
    )
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.patch(
            f"/public/onboarding/sessions/{session.id}",
            json={"riskAppetite": "balanced"},
        )
        assert resp.status_code == 200
        assert resp.json()["baselineStatus"] == "STALE"

        draft = store.get_draft_org(session.id)
        assert draft is not None
        assert draft.baseline_stale is True


@pytest.mark.anyio
async def test_public_onboarding_patch_non_material_change_keeps_baseline_fresh(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(
        session.id,
        cvr="12345678",
        legal_name="Risklence A/S",
        country="DK",
        baseline_snapshot={"overallRiskScore": 50},
        baseline_model_version="risk-intel-baseline-v1",
        baseline_stale=False,
    )
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.patch(
            f"/public/onboarding/sessions/{session.id}",
            json={"tradeName": "Risklence"},
        )
        assert resp.status_code == 200
        assert resp.json()["baselineStatus"] == "FRESH"

        draft = store.get_draft_org(session.id)
        assert draft is not None
        assert draft.baseline_stale is False


@pytest.mark.anyio
async def test_public_onboarding_patch_rerun_baseline_clears_stale(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5)
    session, _ = store.create_session()
    store.update_draft_org(
        session.id,
        cvr="12345678",
        legal_name="Risklence A/S",
        industry_code="62010",
        size_bracket="smb",
        geography="DK",
        locations=1,
        it_dependency="medium",
        risk_appetite="balanced",
        selected_asset_categories=["identity", "email"],
        baseline_snapshot={"overallRiskScore": 50},
        baseline_model_version="risk-intel-baseline-v1",
        baseline_stale=True,
    )
    _seed_baseline_ready_workspace(store, session.id)
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    monkeypatch.setattr(public_onboarding, "_risk_intelligence_engine", pretenant_risk_intelligence.RiskIntelligenceEngine())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.patch(
            f"/public/onboarding/sessions/{session.id}",
            json={"rerunBaseline": True},
        )
        assert resp.status_code == 200
        assert resp.json()["baselineStatus"] == "FRESH"

        draft = store.get_draft_org(session.id)
        assert draft is not None
        assert draft.baseline_stale is False
        assert draft.baseline_input_hash


@pytest.mark.anyio
async def test_public_onboarding_finalize_happy_path(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_complete_draft(store, session.id)
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/finalize", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["sessionId"] == session.id
        assert data["draftStatus"] == "LOCKED"
        assert data["redirectUrl"].startswith("/signup?")
        parsed_redirect = urlparse(data["redirectUrl"])
        assert parsed_redirect.path == "/signup"
        assert parse_qs(parsed_redirect.query).get("activationToken")
        assert data["tokenExpiresAt"]

        token = _extract_activation_token(data["redirectUrl"])
        assert store.get_activation_token_status(token) == "active"

        draft = store.get_draft_org(session.id)
        assert draft is not None
        assert draft.status == "LOCKED"

        events = store.get_audit_events(session_id=session.id, event_type="draft_finalized")
        assert len(events) == 1
        issued = store.get_audit_events(session_id=session.id, event_type="activation_token_issued")
        assert len(issued) == 1
        issued_details = issued[0].details or {}
        assert len(issued_details.get("token_hash_prefix", "")) == 16
        assert "token_fingerprint" not in issued_details
        assert len(issued_details.get("draft_hash", "")) == 64
        assert issued_details.get("model_version") == pretenant_risk_intelligence.MODEL_VERSION


@pytest.mark.anyio
async def test_public_onboarding_finalize_incomplete_draft(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/finalize", json={})
        assert resp.status_code == 409
        detail = resp.json()["detail"]
        assert detail["error_type"] == "incomplete_draft"
        assert "missing_fields" in detail
        assert "cvr" in detail["missing_fields"]


@pytest.mark.anyio
async def test_public_onboarding_finalize_expired_session(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=-1, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_complete_draft(store, session.id)
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/finalize", json={})
        assert resp.status_code == 410
        assert resp.json()["detail"]["error_type"] == "session_expired"


@pytest.mark.anyio
async def test_public_onboarding_activation_token_single_use(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=10)
    session, _ = store.create_session()
    _prepare_complete_draft(store, session.id)
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/finalize", json={})
        assert resp.status_code == 200
        token = _extract_activation_token(resp.json()["redirectUrl"])

        first, first_status = store.consume_activation_token(token)
        assert first_status == "consumed"
        assert first is not None

        second, second_status = store.consume_activation_token(token)
        assert second is None
        assert second_status == "redeemed"


@pytest.mark.anyio
async def test_public_onboarding_activation_token_ttl_expiration(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=-1)
    session, _ = store.create_session()
    _prepare_complete_draft(store, session.id)
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/finalize", json={})
        assert resp.status_code == 200
        token = _extract_activation_token(resp.json()["redirectUrl"])

        consumed, consume_status = store.consume_activation_token(token)
        assert consumed is None
        assert consume_status == "revoked"

        token_obj = store.get_activation_token(token)
        assert token_obj is not None
        assert token_obj.revocation_reason == "token_expired"


@pytest.mark.anyio
async def test_public_onboarding_session_expiry_revokes_unredeemed_tokens(monkeypatch):
    store = pretenant_store.PreTenantStore(ttl_minutes=5, activation_token_ttl_minutes=30)
    session, _ = store.create_session()
    _prepare_complete_draft(store, session.id)
    monkeypatch.setattr(public_onboarding, "PRETENANT_STORE", store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(f"/public/onboarding/sessions/{session.id}/finalize", json={})
        assert resp.status_code == 200
        token = _extract_activation_token(resp.json()["redirectUrl"])

    session_obj = store.get_session(session.id)
    assert session_obj is not None
    with store._lock:  # noqa: SLF001 - explicit test hook for deterministic expiry simulation
        store._sessions[session.id] = pretenant_store.OnboardingSession(
            id=session_obj.id,
            draft_org_id=session_obj.draft_org_id,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            created_at=session_obj.created_at,
        )

    assert store.get_session_status(session.id) == "expired"
    assert store.get_activation_token_status(token) == "revoked"
    token_obj = store.get_activation_token(token)
    assert token_obj is not None
    assert token_obj.revocation_reason == "session_expired"
    expiry_events = store.get_audit_events(session_id=session.id, event_type="pretenant_session_expired")
    assert len(expiry_events) == 1
    details = expiry_events[0].details or {}
    assert details.get("reason") == "ttl_expired"
    assert details.get("revoked_activation_tokens") == 1


def test_pretenant_activation_token_hash_secret_required_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("PRETENANT_ACTIVATION_TOKEN_HASH_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="PRETENANT_ACTIVATION_TOKEN_HASH_SECRET is required in production"):
        pretenant_store._resolve_activation_token_hash_secret()


def test_pretenant_store_file_required_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("PRETENANT_STORE_FILE", raising=False)

    with pytest.raises(RuntimeError, match="PRETENANT_STORE_FILE is required in production"):
        pretenant_store._resolve_persistence_path()


def test_pretenant_activation_token_ttl_env_defaults_and_validates(monkeypatch):
    monkeypatch.delenv("PRETENANT_ACTIVATION_TOKEN_TTL_MINUTES", raising=False)
    assert pretenant_store._resolve_activation_token_ttl_minutes() == 30

    monkeypatch.setenv("PRETENANT_ACTIVATION_TOKEN_TTL_MINUTES", "45")
    assert pretenant_store._resolve_activation_token_ttl_minutes() == 45

    monkeypatch.setenv("PRETENANT_ACTIVATION_TOKEN_TTL_MINUTES", "0")
    with pytest.raises(RuntimeError, match="PRETENANT_ACTIVATION_TOKEN_TTL_MINUTES must be between"):
        pretenant_store._resolve_activation_token_ttl_minutes()

    monkeypatch.setenv("PRETENANT_ACTIVATION_TOKEN_TTL_MINUTES", "abc")
    with pytest.raises(RuntimeError, match="must be an integer"):
        pretenant_store._resolve_activation_token_ttl_minutes()
