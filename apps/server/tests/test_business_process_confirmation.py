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
async def test_business_process_confirmation_persists_model_snapshot_and_audit_trail():
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

        accepted_id = generated["recommendations"][0]["id"]
        removed_id = generated["recommendations"][1]["id"]

        accepted = await client.post(
            f"/api/v1/organizations/42/business-processes/recommendations/{accepted_id}/accept",
            json={"reason": {"summary": "Keep the primary operating structure"}},
        )
        assert accepted.status_code == 200

        removed = await client.post(
            f"/api/v1/organizations/42/business-processes/recommendations/{removed_id}/remove",
            json={"reason": {"summary": "Not needed for this business"}},
        )
        assert removed.status_code == 200

        added = await client.post(
            "/api/v1/organizations/42/business-processes/library/add",
            json={
                "templateId": "billing-subscription",
                "confidence": 0.62,
                "reason": {"summary": "Add billing support"},
            },
        )
        assert added.status_code == 200
        added_id = added.json()["affectedRecommendationId"]

        confirmed = await client.post(
            "/api/v1/organizations/42/business-processes/confirm",
            json={"reason": {"summary": "Confirmed business structure"}},
        )
        assert confirmed.status_code == 200
        confirmed_payload = confirmed.json()
        assert confirmed_payload["action"] == "confirm"
        assert accepted_id in confirmed_payload["confirmedRecommendationIds"]
        assert added_id in confirmed_payload["confirmedRecommendationIds"]
        assert removed_id not in confirmed_payload["confirmedRecommendationIds"]
        assert all(item["status"] != "suggested" for item in confirmed_payload["recommendations"])

    org = session.get(business_processes.Organization, 42)
    assert org is not None
    business_model = org.onboarding_data["business_process_model"]
    assert business_model["version"]
    assert business_model["confirmedAt"]
    assert set(business_model["activeRecommendationIds"]) == set(confirmed_payload["confirmedRecommendationIds"])
    assert any(item["status"] == "added" for item in business_model["activeProcesses"])
    assert all(item["status"] in {"accepted", "added"} for item in business_model["activeProcesses"])

    logs = session.query(business_processes.BusinessProcessDecisionLog).filter(
        business_processes.BusinessProcessDecisionLog.organization_id == 42
    ).all()
    actions = [log.action for log in logs]
    assert "accept" in actions
    assert "remove" in actions
    assert "add" in actions
    assert "confirm" in actions
    assert any(log.action == "confirm" and log.recommendation_id is None for log in logs)


@pytest.mark.anyio
async def test_business_process_confirmation_conflicts_when_nothing_can_be_confirmed():
    session = _make_session()
    _seed_organization(session)
    transport = httpx.ASGITransport(app=_app(session))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/api/v1/organizations/42/business-processes/confirm",
            json={"reason": {"summary": "Confirm empty model"}},
        )

    assert response.status_code == 409
    assert response.json()["detail"]["error_type"] == "no_suggested_recommendations"
