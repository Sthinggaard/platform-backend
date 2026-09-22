"""Global rate limiting middleware (opt-in)."""

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from src.api.middleware.rate_limit import RateLimiter
from src.api.middleware.tenant_context import is_public_path
from src.core.logging_config import get_logger

logger = get_logger(__name__)


def _get_client_ip(request: Request) -> str:
    # Deliberately NOT read from X-Forwarded-For: the leftmost entry is
    # attacker-controlled, so trusting it would let a client mint a fresh
    # identity per request and bypass the limit entirely. request.client.host
    # cannot be spoofed.
    #
    # The cost is that behind a reverse proxy this is the *proxy's* address,
    # identical for every caller — see _rate_limit_scope for why that is no
    # longer the primary key, and BUG-PLATFORM (#176) for the unauthenticated
    # case, which still shares one bucket and needs a trusted-proxy allowlist
    # to fix properly.
    return request.client.host if request.client else "unknown"


def _rate_limit_scope(request: Request) -> str:
    """The bucket this request is counted against.

    **Why not the client IP.** Risklence runs
    ``tenant Worker -> BFF -> API``, so every request reaching this middleware
    carries the BFF's address. Keying on it collapsed a per-client limit into a
    single platform-wide bucket: 120 requests/minute shared by every user of
    every tenant, where one active session locked out everybody else. That is a
    cross-tenant availability failure, not a tuning problem — the exact class of
    isolation breach this codebase treats as non-negotiable.

    So an authenticated request is counted against **the principal it is
    actually made by**, which is both unspoofable (it comes from the verified
    JWT, not a header) and correctly isolated: one organisation exhausting its
    budget cannot affect another. This works because ``TenantContextMiddleware``
    is registered *outside* this one and has already resolved the context by the
    time this runs — verified against the real app's middleware stack, not
    assumed from registration order.

    Unauthenticated requests keep the IP bucket. Behind the BFF that is still
    one shared bucket, which is a genuine remaining weakness for login
    brute-force limiting; it is left explicitly unchanged here rather than
    silently "fixed" by trusting a spoofable header, because deciding which
    proxies to trust is a security decision, not a refactor.
    """
    context = getattr(request.state, "tenant_context", None)
    if context is not None:
        # Per user rather than per organisation: one runaway client must not
        # deny its own colleagues, and an org-wide bucket would make a single
        # polling tab everyone else's problem inside that tenant.
        return f"org:{context.organization_id}:user:{context.user_id}"
    return f"ip:{_get_client_ip(request)}"


class GlobalRateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory global rate limiter (per IP)."""

    def __init__(self, app, requests_per_minute: int = 120):
        super().__init__(app)
        self.limiter = RateLimiter(window_seconds=60)
        self.requests_per_minute = requests_per_minute

    async def dispatch(self, request: Request, call_next):
        if self.requests_per_minute <= 0:
            return await call_next(request)
        if request.method == "OPTIONS":
            return await call_next(request)
        if is_public_path(request.url.path):
            return await call_next(request)

        scope = _rate_limit_scope(request)
        key = f"global:{scope}"
        try:
            self.limiter.check(key, limit=self.requests_per_minute)
        except Exception as exc:  # pragma: no cover - defensive guard
            status_code = getattr(exc, "status_code", 429)
            detail = getattr(exc, "detail", "Too many requests. Please try again later.")
            logger.warning(
                "rate_limit_exceeded",
                # The bucket, not the source address — with the BFF in front,
                # logging the IP made every 429 look identical and hid the fact
                # that unrelated tenants were exhausting each other's budget.
                scope=scope,
                path=request.url.path,
            )
            return JSONResponse(
                status_code=status_code,
                content={"detail": detail, "error_type": "rate_limit"},
            )

        return await call_next(request)
