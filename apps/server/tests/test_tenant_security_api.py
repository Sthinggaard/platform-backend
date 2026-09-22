from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from pydantic import SecretStr
from sqlalchemy.orm import Session

from src.api.main import app
from src.core.config import settings
from src.core.database import get_db
from src.core.models import AuthTenantSettings, Organization, User
from src.core.services.auth_service import get_auth_settings
from src.core.utils.jwt_secrets import get_jwt_secret_bytes

settings.auth.jwt_secret = SecretStr("test-secret")


def build_token(org_id: int, *, role: str = "org_admin", user_id: int = 1) -> str:
    namespace = "https://risklence.com/"
    payload = {
        "sub": str(user_id),
        "email": "admin@example.com",
        f"{namespace}organization_id": org_id,
        f"{namespace}roles": [role],
        f"{namespace}permissions": [],
    }
    return jwt.encode(payload, get_jwt_secret_bytes(), algorithm="HS256")


def auth_header(org_id: int, *, role: str = "org_admin", user_id: int = 1) -> dict[str, str]:
    return {"Authorization": f"Bearer {build_token(org_id, role=role, user_id=user_id)}"}


def create_org(db_session: Session, *, name: str) -> Organization:
    org = Organization(name=name, slug=f"{name.lower().replace(' ', '-')}-{uuid4().hex[:8]}")
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)
    return org


def create_auth_settings(db_session: Session, organization_id: int) -> AuthTenantSettings:
    settings_row = AuthTenantSettings(organization_id=organization_id)
    db_session.add(settings_row)
    db_session.commit()
    db_session.refresh(settings_row)
    return settings_row


def create_user(db_session: Session, *, organization_id: int, role: str, email: str) -> User:
    user = User(
        organization_id=organization_id,
        email=email,
        role=role,
        email_verified=True,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def client(db_session, sample_organization):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.pop(get_db, None)


def test_get_mfa_policy_requires_admin_role(client, sample_organization):
    response = client.get(
        "/api/v1/tenant/security/mfa",
        headers=auth_header(sample_organization.id, role="member"),
    )

    assert response.status_code == 403
    payload = response.json()
    assert payload["error_type"] == "authorization_error"
    assert payload["detail"] == "Admin role required"


def test_update_mfa_policy_requires_admin_role(client, sample_organization):
    response = client.patch(
        "/api/v1/tenant/security/mfa",
        headers=auth_header(sample_organization.id, role="member"),
        json={"mfa_required_for_all": True},
    )

    assert response.status_code == 403
    payload = response.json()
    assert payload["error_type"] == "authorization_error"
    assert payload["detail"] == "Admin role required"


@pytest.mark.unreconciled
def test_update_mfa_policy_is_scoped_to_session_org(
    client,
    db_session: Session,
    sample_organization,
):
    other_org = create_org(db_session, name="Other Tenant")
    create_auth_settings(db_session, sample_organization.id)
    create_auth_settings(db_session, other_org.id)
    admin_user = create_user(
        db_session,
        organization_id=sample_organization.id,
        role="org_admin",
        email="org-admin@example.com",
    )
    primary_settings = get_auth_settings(db_session, sample_organization.id)
    other_settings = get_auth_settings(db_session, other_org.id)

    assert primary_settings.mfa_required_for_all is False
    assert other_settings.mfa_required_for_all is False

    response = client.patch(
        "/api/v1/tenant/security/mfa",
        headers=auth_header(sample_organization.id, role="org_admin", user_id=admin_user.id),
        json={"mfa_required_for_all": True},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["mfa_required_for_all"] is True

    refreshed_primary = get_auth_settings(db_session, sample_organization.id)
    refreshed_other = get_auth_settings(db_session, other_org.id)
    assert refreshed_primary.mfa_required_for_all is True
    assert refreshed_other.mfa_required_for_all is False
