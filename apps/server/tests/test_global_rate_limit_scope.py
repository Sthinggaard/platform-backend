"""The global rate limiter must isolate tenants, not merely throttle.

Søren hit a 429 doing nothing unusual: opening pages in the tenant app. The
limit was not too low — it was being applied to the wrong thing. Risklence runs
``tenant Worker -> BFF -> API``, so every request arriving at this middleware
carries the BFF's address, and keying on ``request.client.host`` collapsed a
"per IP" limit into one platform-wide bucket. 120 requests/minute, shared by
every user of every tenant.

That is a cross-tenant availability failure: one organisation's traffic denies
service to all the others, and a single busy session locks out the platform.

These tests are written against the *scope function* rather than through a live
app, because the defect was never in the sliding window (which was correct and
already covered) — it was in the identity the window was keyed on.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.api.middleware.global_rate_limit import _get_client_ip, _rate_limit_scope
from src.api.middleware.rate_limit import RateLimiter
from src.api.middleware.tenant_context import TenantContext


def _context(*, user_id: int, organization_id: int) -> TenantContext:
    return TenantContext(
        user_id=user_id,
        organization_id=organization_id,
        email=f"user{user_id}@example.com",
        roles=["user"],
        permissions=["read"],
    )


def _request(*, client_host: str | None = "172.19.0.6", context: TenantContext | None = None):
    """A request as this middleware actually sees it.

    ``client_host`` defaults to the BFF's container address on purpose: that is
    what every real request looks like here, and a test using distinct
    per-caller IPs would pass against the broken code.
    """
    state = SimpleNamespace()
    if context is not None:
        state.tenant_context = context
    return SimpleNamespace(
        state=state,
        client=SimpleNamespace(host=client_host) if client_host else None,
        url=SimpleNamespace(path="/api/v1/organization-identity/prepared"),
        method="GET",
        headers={},
    )


class TestTenantsCannotExhaustEachOther:
    def test_two_organisations_behind_the_proxy_get_separate_buckets(self):
        # The regression. Both requests carry the BFF's address; before the fix
        # both produced "global:172.19.0.6" and shared one budget.
        a = _rate_limit_scope(_request(context=_context(user_id=5, organization_id=1)))
        b = _rate_limit_scope(_request(context=_context(user_id=9, organization_id=2)))

        assert a != b

    def test_two_users_in_one_organisation_get_separate_buckets(self):
        # Per user, not per org: one runaway tab must not deny its own
        # colleagues either.
        a = _rate_limit_scope(_request(context=_context(user_id=5, organization_id=1)))
        b = _rate_limit_scope(_request(context=_context(user_id=6, organization_id=1)))

        assert a != b

    def test_the_same_user_is_counted_consistently(self):
        # The limiter must still actually limit — separate buckets are useless
        # if a single caller gets a fresh one per request.
        first = _rate_limit_scope(_request(context=_context(user_id=5, organization_id=1)))
        second = _rate_limit_scope(_request(context=_context(user_id=5, organization_id=1)))

        assert first == second

    def test_identity_does_not_come_from_the_source_address(self):
        # The principal is resolved from the verified JWT, so the same user
        # keeps one bucket across addresses — and, critically, cannot mint a
        # new one by changing where the request appears to come from.
        via_bff = _rate_limit_scope(
            _request(client_host="172.19.0.6", context=_context(user_id=5, organization_id=1))
        )
        via_elsewhere = _rate_limit_scope(
            _request(client_host="203.0.113.9", context=_context(user_id=5, organization_id=1))
        )

        assert via_bff == via_elsewhere


class TestTheLimitStillBites:
    def test_one_principal_is_throttled_without_affecting_another(self):
        from fastapi import HTTPException

        limiter = RateLimiter(window_seconds=60)
        noisy = _rate_limit_scope(_request(context=_context(user_id=5, organization_id=1)))
        quiet = _rate_limit_scope(_request(context=_context(user_id=9, organization_id=2)))

        for _ in range(3):
            limiter.check(noisy, limit=3)
        with pytest.raises(HTTPException) as excinfo:
            limiter.check(noisy, limit=3)
        assert excinfo.value.status_code == 429

        # The other tenant is untouched — the whole point.
        limiter.check(quiet, limit=3)


class TestUnauthenticatedRequests:
    def test_anonymous_requests_still_fall_back_to_the_address(self):
        scope = _rate_limit_scope(_request(context=None))

        assert scope.startswith("ip:")

    def test_a_request_with_no_client_at_all_is_still_keyed(self):
        # ASGI does not guarantee a client tuple. A None here must not raise
        # inside middleware and turn a rate-limit check into a 500.
        assert _rate_limit_scope(_request(client_host=None, context=None)) == "ip:unknown"

    def test_the_address_is_never_taken_from_a_client_supplied_header(self):
        # Trusting X-Forwarded-For would let any caller mint a fresh bucket per
        # request and bypass the limit completely.
        request = _request(client_host="172.19.0.6", context=None)
        request.headers = {"X-Forwarded-For": "1.2.3.4, 5.6.7.8"}

        assert _get_client_ip(request) == "172.19.0.6"
        assert "1.2.3.4" not in _rate_limit_scope(request)
