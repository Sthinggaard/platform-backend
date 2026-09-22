"""
Guard tenant DB access for pre-tenant public onboarding routes.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request

from src.core.database import reset_pretenant_request, set_pretenant_request


class PreTenantGuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = None
        if request.url.path.startswith("/public/onboarding"):
            token = set_pretenant_request(True)
        try:
            return await call_next(request)
        finally:
            if token is not None:
                reset_pretenant_request(token)
