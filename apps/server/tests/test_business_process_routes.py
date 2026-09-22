from __future__ import annotations

from collections.abc import Generator

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.routes import business_processes
from src.core.models import Base


def _make_session() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            business_processes.Organization.__table__,
            business_processes.BusinessProcessRecommendation.__table__,
            business_processes.BusinessProcessDecisionLog.__table__,
        ],
    )
    return sessionmaker(bind=engine)()


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _override_db(session: Session) -> Generator[Session, None, None]:
    yield session


def _app(session: Session, organization_id: int = 42) -> FastAPI:
    app = FastAPI()
    app.include_router(business_processes.router)

    def override_get_db() -> Generator[Session, None, None]:
        yield from _override_db(session)

    def override_get_tenant_context() -> TenantContext:
        return TenantContext(
            user_id=1, organization_id=organization_id, email="operator@example.com", roles=["org_admin"], permissions=[]
        )

    app.dependency_overrides[business_processes._get_db] = override_get_db
    app.dependency_overrides[get_tenant_context] = override_get_tenant_context
    return app


def _profile_payload() -> dict[str, object]:
    return {
        "organisationProfile": {
            "cvr": "12345678",
            "legalName": "Example ApS",
            "industryCode": "62010",
            "sizeBracket": "enterprise",
            "geography": "DK",
            "locations": 2,
            "itDependency": "critical",
            "riskAppetite": "balanced",
            "selectedAssetCategories": ["identity", "cloud", "email"],
            "regulatoryFlags": ["GDPR", "NIS2"],
            "businessModelTags": ["subscription", "b2b"],
        }
    }


def _seed_organization(session: Session) -> None:
    session.add(
        business_processes.Organization(
            id=42,
            name="Example ApS",
            slug="example",
            industry="62010",
            company_size="enterprise",
            country="DK",
            cvr_number="12345678",
            nace_code="62010",
            onboarding_data={
                "cvr": "12345678",
                "workspace": {
                    "version": "workspace.v1",
                    "sessionId": "workspace-session",
                    "currentStep": "synthesis",
                    "organization": {
                        "cvr": "12345678",
                        "legalName": "Example ApS",
                        "industryCode": "62010",
                        "geography": "DK",
                        "country": "DK",
                        "locations": 2,
                        "confirmed": True,
                    },
                    "businessServices": [],
                    "assets": [
                        {"id": "asset-identity", "name": "Identity", "assetType": "identity", "source": "manual"},
                        {"id": "asset-cloud", "name": "Cloud", "assetType": "cloud", "source": "manual"},
                        {"id": "asset-email", "name": "Email", "assetType": "email", "source": "manual"},
                    ],
                    "serviceAssetLinks": [],
                    "dependencyEdges": [],
                    "criticalityProfiles": [],
                    "riskAppetiteProfile": {"profile": "balanced"},
                    "valueStreamProfile": None,
                    "starterKris": [],
                    "initialStructuralInsight": None,
                },
            },
        )
    )
    session.commit()


@pytest.mark.anyio
async def test_business_process_routes_support_generate_decide_and_confirm_flow():
    session = _make_session()
    _seed_organization(session)
    transport = httpx.ASGITransport(app=_app(session))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        generate = await client.post(
            "/api/v1/organizations/42/business-processes/recommendations/generate",
            json=_profile_payload(),
        )
        assert generate.status_code == 200
        generated = generate.json()
        assert generated["action"] == "generate"
        assert len(generated["recommendations"]) == 5
        assert len(generated["generatedRecommendationIds"]) == 5
        first_recommendation = generated["recommendations"][0]
        accepted_template_id = first_recommendation["processTemplateId"]
        assert first_recommendation["score"] > 0
        assert first_recommendation["matchedInputs"]
        assert first_recommendation["userReasoning"]["plainName"]
        assert first_recommendation["userReasoning"]["businessOwnerSummary"]
        assert first_recommendation["userReasoning"]["whyThisMatters"]
        assert first_recommendation["userReasoning"]["whatCanGoWrong"]
        assert first_recommendation["userReasoning"]["whenToAccept"]
        assert first_recommendation["userReasoning"]["relevanceLabel"] in {"High", "Medium", "Low"}
        assert first_recommendation["userReasoning"]["technicalDetails"]["templateId"]
        assert first_recommendation["userReasoning"]["technicalDetails"]["originalTemplateName"]
        assert first_recommendation["userReasoning"]["technicalDetails"]["oldReason"]
        assert first_recommendation["sourceRule"]
        assert first_recommendation["confidence"] >= 0

        first_id = generated["recommendations"][0]["id"]
        second_id = generated["recommendations"][1]["id"]

        current = await client.get("/api/v1/organizations/42/business-processes/recommendations")
        assert current.status_code == 200
        current_payload = current.json()
        assert len(current_payload["recommendations"]) == 5
        assert all(item["userReasoning"]["plainName"] for item in current_payload["recommendations"])
        assert current_payload["recommendations"][0]["userReasoning"]["plainName"]

        accepted = await client.post(
            f"/api/v1/organizations/42/business-processes/recommendations/{first_id}/accept",
            json={"reason": {"summary": "Approved by operator", "details": {"reviewed": True}}},
        )
        assert accepted.status_code == 200
        assert accepted.json()["affectedRecommendationId"] == first_id
        assert accepted.json()["recommendations"][0]["status"] == "accepted"

        regenerated = await client.post(
            "/api/v1/organizations/42/business-processes/recommendations/generate",
            json=_profile_payload(),
        )
        assert regenerated.status_code == 200
        regenerated_payload = regenerated.json()
        accepted_rows = [
            item for item in regenerated_payload["recommendations"] if item["processTemplateId"] == accepted_template_id
        ]
        assert len(accepted_rows) == 1
        assert accepted_rows[0]["id"] == first_id
        assert accepted_rows[0]["status"] == "accepted"

        removed = await client.post(
            f"/api/v1/organizations/42/business-processes/recommendations/{second_id}/remove",
            json={"reason": {"summary": "Not relevant for current operating model", "details": {"scope": "pilot"}}},
        )
        assert removed.status_code == 200
        assert removed.json()["affectedRecommendationId"] == second_id
        assert removed.json()["recommendations"][1]["status"] == "removed"

        added = await client.post(
            "/api/v1/organizations/42/business-processes/library/add",
            json={
                "templateId": "customer-lifecycle",
                "confidence": 0.62,
                "reason": {"summary": "Add customer lifecycle support", "details": {"manual": True}},
            },
        )
        assert added.status_code == 200
        assert added.json()["action"] == "add"
        assert added.json()["affectedRecommendationId"]
        assert any(item["status"] == "added" for item in added.json()["recommendations"])

        confirmed = await client.post(
            "/api/v1/organizations/42/business-processes/confirm",
            json={"reason": {"summary": "Business process model confirmed"}},
        )
        assert confirmed.status_code == 200
        assert confirmed.json()["action"] == "confirm"
        assert len(confirmed.json()["confirmedRecommendationIds"]) >= 1
        assert all(item["status"] != "suggested" for item in confirmed.json()["recommendations"])

        crown_decision = await client.post(
            "/api/v1/organizations/42/business-processes/crown-jewel",
            json={
                "processId": "process-42",
                "processName": "Example ApS Core Process",
                "serviceId": "svc-billing",
                "serviceName": "Billing",
                "decision": "confirm",
                "reason": {
                    "summary": "Crown jewel confirmed for billing",
                    "details": {"reviewedBy": "operator", "severity": "high"},
                    "source": "manual_review",
                },
            },
        )
        assert crown_decision.status_code == 200
        crown_payload = crown_decision.json()
        assert crown_payload["action"] == "crown_confirm"
        crown_log = next(log for log in crown_payload["decisionLogs"] if log["action"] == "crown_confirm")
        assert crown_log["reasonDetails"]["serviceId"] == "svc-billing"
        assert crown_log["reasonDetails"]["processName"] == "Example ApS Core Process"
        assert crown_log["reasonDetails"]["decision"] == "confirm"
        assert crown_log["reason"]["source"] == "manual_review"


@pytest.mark.anyio
async def test_business_process_generate_accepts_missing_body_when_org_context_is_available():
    session = _make_session()
    _seed_organization(session)
    transport = httpx.ASGITransport(app=_app(session))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/api/v1/organizations/42/business-processes/recommendations/generate")

    assert response.status_code == 200
    payload = response.json()
    assert payload["action"] == "generate"
    assert len(payload["recommendations"]) == 5
    assert len(payload["generatedRecommendationIds"]) == 5


@pytest.mark.anyio
async def test_business_process_confirm_returns_conflict_when_no_suggestions_exist():
    session = _make_session()
    transport = httpx.ASGITransport(app=_app(session, organization_id=7))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/api/v1/organizations/7/business-processes/confirm",
            json={"reason": {"summary": "Confirm empty model"}},
        )

    assert response.status_code == 409
    assert response.json()["detail"]["error_type"] == "no_suggested_recommendations"


@pytest.mark.anyio
async def test_business_process_routes_reject_organization_id_mismatch():
    """Epic A4 / L2 fix — the path organization_id must match the caller's
    own JWT-verified TenantContext; a mismatch is a 403, never a silent
    fall-through to the URL's value (the fail-open shape this replaced)."""
    session = _make_session()
    _seed_organization(session)
    # ctx claims org 42 (the seeded org); the URL asks for a different org.
    transport = httpx.ASGITransport(app=_app(session, organization_id=42))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/v1/organizations/99/business-processes/recommendations")

    assert response.status_code == 403
    assert response.json()["detail"]["error_type"] == "organization_mismatch"
