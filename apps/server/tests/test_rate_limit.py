"""DISC-50 — the RateLimiter class had zero direct test coverage before
this ticket (every existing usage, auth_rate_limiter, only ever tests
around it via ``store.clear()`` fixtures, never the limiter's own
behaviour). Covers the sliding-window logic itself, independent of any
route."""

from __future__ import annotations

import time

import pytest
from fastapi import HTTPException

from src.api.middleware.rate_limit import RateLimiter, discovery_execution_rate_limiter


@pytest.fixture(autouse=True)
def _clear_discovery_rate_limiter():
    discovery_execution_rate_limiter.store.clear()
    yield
    discovery_execution_rate_limiter.store.clear()


def test_allows_requests_under_the_limit():
    limiter = RateLimiter(window_seconds=60)
    for _ in range(5):
        limiter.check("key", limit=5)  # must not raise


def test_blocks_the_request_that_exceeds_the_limit():
    limiter = RateLimiter(window_seconds=60)
    for _ in range(5):
        limiter.check("key", limit=5)
    with pytest.raises(HTTPException) as exc_info:
        limiter.check("key", limit=5)
    assert exc_info.value.status_code == 429


def test_different_keys_are_independent():
    limiter = RateLimiter(window_seconds=60)
    for _ in range(5):
        limiter.check("key-a", limit=5)
    limiter.check("key-b", limit=5)  # a different key's own budget, untouched


def test_the_window_slides_once_old_timestamps_age_out():
    limiter = RateLimiter(window_seconds=60)
    now = time.time()
    # Seed the store directly with timestamps already outside the window,
    # rather than sleeping 60s in a test.
    limiter.store["key"] = [now - 61, now - 61, now - 61, now - 61, now - 61]
    limiter.check("key", limit=5)  # the aged-out timestamps don't count


def test_discovery_execution_rate_limiter_is_its_own_store_not_shared_with_auth():
    from src.api.middleware.rate_limit import auth_rate_limiter

    assert discovery_execution_rate_limiter is not auth_rate_limiter
    assert discovery_execution_rate_limiter.store is not auth_rate_limiter.store
