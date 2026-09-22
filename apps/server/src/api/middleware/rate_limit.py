"""Simple in-memory sliding-window rate limiter, shared across route files.

In-memory, per-process — matches this codebase's existing convention for
this specific auth_rate_limiter instance (predates this module's reuse by
DISC-50). Per CLAUDE.md, rate limiters should use Redis in production;
this is a disclosed, pre-existing gap, not something a single ticket
extending the existing pattern should silently "fix" into a bigger
change (a real multi-process deployment would need a shared store, or
each process enforces its own independent limit rather than a true
org-wide one — acceptable for this repo's current single-process-per-
environment deployment, not for a horizontally-scaled one).

One instance per domain (auth_rate_limiter, discovery_execution_rate_limiter
below) rather than one instance per bucket — each instance's own key
prefixes (e.g. "login_ip", "discovery_run_create") distinguish buckets
within it, same convention auth.py's own multiple ``.check()`` call sites
already established.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List

from fastapi import HTTPException, status


@dataclass
class RateLimiter:
    window_seconds: int = 60
    store: Dict[str, List[float]] = field(default_factory=dict)

    def check(self, key: str, limit: int) -> None:
        now = time.time()
        window_start = now - self.window_seconds
        timestamps = [ts for ts in self.store.get(key, []) if ts >= window_start]
        if len(timestamps) >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
            )
        timestamps.append(now)
        self.store[key] = timestamps


auth_rate_limiter = RateLimiter(window_seconds=60)

# DISC-50 — a separate store, not a shared one: an org spamming discovery
# requests must never be able to also exhaust the auth rate limiter's
# budget (or vice versa) just by key volume in the same dict.
discovery_execution_rate_limiter = RateLimiter(window_seconds=60)
