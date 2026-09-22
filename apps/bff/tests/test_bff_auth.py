"""#228 — the BFF forwards identity and request correlation upstream.

Rewritten to the architecture the BFF actually has. The original was written
against a synchronous `requests.Session` exported as `bff.app.session` and a
synchronous `_upstream_request`; both are gone — the client is now an
`httpx.AsyncClient` held on `app.state.http_client`, and `_upstream_request` is a
coroutine. The test could not even import, which is what running in no workflow
permits.

What it guards is unchanged and still worth guarding: a request arriving at the
BFF with a bearer token must reach the API with that token, and every forwarded
request must carry an `x-request-id` so one user action can be followed across
two services.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from bff.app import _require_auth, _upstream_request


class _StubAsyncClient:
    """Stands in for `app.state.http_client`, capturing what was forwarded."""

    def __init__(self) -> None:
        self.captured: dict[str, Any] = {}

    async def request(self, **kwargs: Any):
        self.captured.update(kwargs)

        class _Response:
            status_code = 200
            headers: dict[str, str] = {}

            def json(self) -> dict[str, bool]:
                return {"ok": True}

        return _Response()


def make_request(headers: dict[str, str] | None = None, *, client: Any = None) -> Request:
    """A Starlette request whose `app.state.http_client` is the stub.

    `_upstream_request` reads the client off `request.app.state`, so the app has
    to be reachable from the scope — a bare scope with no "app" key raises before
    the assertions are reached.
    """

    scope: dict[str, Any] = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/test",
        "headers": [],
        "client": ("testclient", 1234),
    }
    if headers:
        scope["headers"] = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    if client is not None:
        class _State:
            http_client = client

        class _App:
            state = _State()

        scope["app"] = _App()
    return Request(scope)


def test_require_auth_raises_without_header() -> None:
    with pytest.raises(HTTPException):
        _require_auth(make_request({}))


@pytest.mark.anyio
async def test_upstream_request_propagates_auth_and_request_id() -> None:
    stub = _StubAsyncClient()
    request = make_request({"authorization": "Bearer test-token"}, client=stub)

    response = await _upstream_request(method="GET", path="/api/v1/test", request=request)

    assert response.status_code == 200
    assert stub.captured["headers"]["authorization"] == "Bearer test-token"
    assert "x-request-id" in stub.captured["headers"]


@pytest.mark.anyio
async def test_upstream_request_reuses_an_inbound_request_id() -> None:
    """A correlation id that changes at the BFF boundary correlates nothing —
    the point is to follow one user action across both services."""
    stub = _StubAsyncClient()
    request = make_request(
        {"authorization": "Bearer test-token", "x-request-id": "known-correlation-id"},
        client=stub,
    )

    await _upstream_request(method="GET", path="/api/v1/test", request=request)

    assert stub.captured["headers"]["x-request-id"] == "known-correlation-id"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
