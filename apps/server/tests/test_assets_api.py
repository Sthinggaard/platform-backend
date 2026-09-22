from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from pydantic import SecretStr
from sqlalchemy.orm import Session

from src.api.main import app
from src.core.config import settings
from src.core.database import get_db
from src.core.models import AssetStatus, Organization
from src.core.utils.jwt_secrets import get_jwt_secret_bytes


def build_token(org_id: int) -> str:
    namespace = "https://risklence.com/"
    payload = {
        "sub": "1",
        "email": "admin@example.com",
        f"{namespace}organization_id": org_id,
        f"{namespace}roles": ["admin"],
        f"{namespace}permissions": [],
    }
    return jwt.encode(payload, get_jwt_secret_bytes(), algorithm="HS256")


settings.auth.jwt_secret = SecretStr("test-secret")


@pytest.fixture
def client(db_session, sample_organization):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.pop(get_db, None)


def auth_header(org_id: int) -> dict:
    return {"Authorization": f"Bearer {build_token(org_id)}"}


def create_org(db_session: Session, *, name: str = "Other Org") -> Organization:
    org = Organization(name=name, slug=f"{name.lower().replace(' ', '-')}-{uuid4().hex[:8]}")
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)
    return org


@pytest.mark.unreconciled
def test_list_and_connect_assets(client, sample_organization):
    listing = client.get("/api/assets", headers=auth_header(sample_organization.id))
    assert listing.status_code == 200
    assets = listing.json()
    assert assets
    target = assets[0]

    connect = client.post(
        f"/api/assets/{target['id']}/connect",
        headers=auth_header(sample_organization.id),
        json={"auth_type": "mock", "scopes": ["read"]},
    )
    assert connect.status_code == 200
    data = connect.json()
    assert data["status"] in [AssetStatus.PARTIALLY_OBSERVED.value, AssetStatus.AT_RISK.value, AssetStatus.OPERATIONALLY_COMPLIANT.value]

    history = client.get(
        f"/api/assets/{target['id']}/status-history", headers=auth_header(sample_organization.id)
    )
    assert history.status_code == 200
    assert len(history.json()) >= 1


def test_findings_feed(client, sample_organization):
    resp = client.get("/api/findings", headers=auth_header(sample_organization.id))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.unreconciled
def test_audit_endpoints(client, sample_organization):
    # Seed assets/controls
    client.get("/api/assets", headers=auth_header(sample_organization.id))

    overview = client.get("/api/audit/overview", headers=auth_header(sample_organization.id))
    assert overview.status_code == 200
    controls = client.get("/api/audit/controls", headers=auth_header(sample_organization.id))
    assert controls.status_code == 200
    control_rows = controls.json()
    if control_rows:
        control_id = control_rows[0]["control_id"]
        detail = client.get(f"/api/audit/controls/{control_id}", headers=auth_header(sample_organization.id))
        assert detail.status_code == 200

    share = client.post("/api/audit/share-link", headers=auth_header(sample_organization.id), json={})
    assert share.status_code == 200
    token = share.json()["token"]
    shared_view = client.get(
        f"/api/audit/shared/{token}", headers=auth_header(sample_organization.id)
    )
    assert shared_view.status_code == 200


@pytest.mark.parametrize(
    ("method", "path", "json_payload"),
    [
        ("get", "/api/assets", None),
        ("get", "/api/findings", None),
        ("get", "/api/audit/overview", None),
        ("get", "/api/audit/controls", None),
        ("post", "/api/audit/share-link", {}),
    ],
)
def test_optional_org_query_rejects_cross_tenant_override(
    client,
    db_session: Session,
    sample_organization,
    method: str,
    path: str,
    json_payload: dict | None,
):
    other_org = create_org(db_session)
    request = getattr(client, method)
    kwargs = {
        "headers": auth_header(sample_organization.id),
        "params": {"org_id": other_org.id},
    }
    if json_payload is not None:
        kwargs["json"] = json_payload

    response = request(path, **kwargs)

    assert response.status_code == 403
    assert response.json()["detail"] == "Organization mismatch"
