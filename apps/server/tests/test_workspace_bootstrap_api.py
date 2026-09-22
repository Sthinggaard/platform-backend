from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from jose import jwt
from pydantic import SecretStr
import pytest

from src.api.main import app
from src.core.config import settings
from src.core.database import get_db
from src.core.models import Organization
from src.core.utils.jwt_secrets import get_jwt_secret_bytes

settings.auth.jwt_secret = SecretStr("test-secret")


def _build_token(org_id: int, *, user_id: int = 101, email: str = "owner@example.com") -> str:
    namespace = "https://risklence.com/"
    payload = {
        "sub": str(user_id),
        "email": email,
        f"{namespace}organization_id": org_id,
        f"{namespace}roles": ["org_admin"],
        f"{namespace}permissions": [],
    }
    return jwt.encode(payload, get_jwt_secret_bytes(), algorithm="HS256")


def _auth_header(org_id: int, *, user_id: int = 101, email: str = "owner@example.com") -> dict[str, str]:
    return {"Authorization": f"Bearer {_build_token(org_id, user_id=user_id, email=email)}"}


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.unreconciled
def test_workspace_bootstrap_returns_baseline_summary_and_next_steps(client, db_session, sample_organization):
    sample_organization.onboarding_data = {
        "source": "public_onboarding",
        "baseline": {
            "model_version": "risk-intel-baseline-v1",
            "generated_at": datetime(2026, 2, 22, 9, 0, tzinfo=timezone.utc).isoformat(),
            "landscape": {
                "overallRiskScore": 62,
                "riskLevel": "medium",
                "focusAreas": ["identity_access", "backup_resilience"],
                "hypotheses": [{"riskCode": "R-IA-01"}, {"riskCode": "R-DP-02"}],
            },
        },
    }
    db_session.add(sample_organization)
    db_session.commit()

    response = client.get(
        "/app/workspace/bootstrap",
        headers=_auth_header(sample_organization.id, user_id=777, email="founder@example.com"),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["workspace"]["organizationId"] == sample_organization.id
    assert payload["workspace"]["userId"] == 777
    assert payload["workspace"]["userEmail"] == "founder@example.com"
    assert payload["autoMonitoringEnabled"] is False

    baseline = payload["baselineSummary"]
    assert baseline["modelVersion"] == "risk-intel-baseline-v1"
    assert baseline["overallRiskScore"] == 62
    assert baseline["riskLevel"] == "medium"
    assert baseline["focusAreas"] == ["identity_access", "backup_resilience"]
    assert baseline["hypothesesCount"] == 2

    next_steps = payload["nextSteps"]
    assert next_steps
    assert next_steps[0]["code"] == "review_baseline"


@pytest.mark.unreconciled
def test_workspace_bootstrap_returns_null_baseline_when_not_promoted(client, sample_organization):
    response = client.get(
        "/app/workspace/bootstrap",
        headers=_auth_header(sample_organization.id),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["workspace"]["organizationId"] == sample_organization.id
    assert payload["baselineSummary"] is None
    assert payload["autoMonitoringEnabled"] is False
    assert [step["code"] for step in payload["nextSteps"]] == [
        "connect_first_asset",
        "review_tenant_security",
    ]


def test_workspace_bootstrap_requires_authentication(client, sample_organization):
    with TestClient(app, raise_server_exceptions=False) as unauth_client:
        response = unauth_client.get("/app/workspace/bootstrap")
    assert response.status_code in {401, 403, 500}


def test_workspace_bootstrap_is_scoped_to_tenant_context_org(client, db_session, sample_organization):
    other_org = Organization(name="Other Org", slug="other-org-epic4")
    other_org.onboarding_data = {
        "baseline": {
            "model_version": "other-model",
            "landscape": {"overallRiskScore": 10, "riskLevel": "low", "focusAreas": [], "hypotheses": []},
        }
    }
    db_session.add(other_org)
    db_session.commit()
    db_session.refresh(other_org)

    response = client.get(
        "/app/workspace/bootstrap?organizationId=%d" % other_org.id,
        headers=_auth_header(sample_organization.id, email="tenant-a@example.com"),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["workspace"]["organizationId"] == sample_organization.id
