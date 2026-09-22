"""An error downstream is not an authentication failure.

2026-08-31: the tenant middleware's try block wrapped `call_next`, so any
exception raised anywhere in an authenticated request was caught and re-raised
as AuthenticationError("Failed to process authentication token"). A duplicate
response model (#373) broke onboarding's Organisation Structure step and the
user was told their token could not be processed.

The re-raise also happened inside the handler that converts AuthenticationError
into a 401, so it escaped as an unhandled 500 — an auth message with a server
status, describing neither the cause nor the category correctly.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.middleware.tenant_context import TenantContextMiddleware


class _Boom(RuntimeError):
    """Stands in for any downstream fault — a schema mismatch, a bad query."""


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(TenantContextMiddleware)

    @app.get("/health")
    def health():  # a public path, so it bypasses authentication
        return {"ok": True}

    @app.get("/api/v1/health")
    def api_health():
        return {"ok": True}

    return app


def test_a_missing_token_is_still_a_401():
    """The genuine case must keep working."""
    client = TestClient(_app())
    response = client.get("/api/v1/anything")
    assert response.status_code == 401
    assert response.json()["error_type"] == "authentication_error"


def test_a_public_path_needs_no_token():
    client = TestClient(_app())
    assert client.get("/health").status_code == 200


def test_a_downstream_failure_is_not_reported_as_an_auth_problem():
    """The regression: a route that raises must not become an auth error.

    Uses a public path so the request actually reaches the route. Before the
    fix the middleware's try block wrapped `call_next`, so this fault surfaced
    as "Failed to process authentication token" with a 500.
    """
    app = FastAPI()
    app.add_middleware(TenantContextMiddleware)

    @app.get("/health")
    def boom():
        raise _Boom("a schema mismatch, say")

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/health")

    assert response.status_code != 401, (
        "a downstream fault was reported as an authentication failure"
    )
    body = response.text.lower()
    assert "authentication" not in body, body
    assert "failed to process authentication token" not in body, body


def test_an_authenticated_route_that_fails_is_not_disguised_either():
    """The same, with a real token — the path the onboarding defect took."""
    import jwt as pyjwt
    from src.api.middleware import tenant_context as tc

    app = FastAPI()
    app.add_middleware(TenantContextMiddleware)

    @app.get("/api/v1/boom")
    def boom():
        raise _Boom("a duplicate response model, say")

    client = TestClient(app, raise_server_exceptions=False)
    # Build a token the middleware will accept, using its own secret.
    instance = TenantContextMiddleware(app)
    token = pyjwt.encode(
        {"sub": "1", "user_id": 1, "organization_id": 1, "email": "a@b.test",
         "roles": ["admin"], "permissions": []},
        instance._jwt_secret(), algorithm="HS256",
    )
    response = client.get("/api/v1/boom", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code != 401, response.text
    assert "failed to process authentication token" not in response.text.lower()
