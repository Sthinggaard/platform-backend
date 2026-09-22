"""
Tenant context middleware for multi-tenant isolation.

Extracts tenant (organization) information from JWT tokens and adds it to request state.
All API endpoints can access the current tenant via request.state.tenant_context.
"""

import hashlib
import time
from dataclasses import dataclass
from typing import Callable, Optional

from fastapi import Request, Response, status
import requests
from jose import JWTError, jwt
from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.config import Environment, settings
from src.core.constants.internal_routes import (
    LEARNING_LOOP_SCHEDULED_RUN_PATH,
    SCANNER_AGENT_PATH_PREFIX,
    TEMPLATE_GOVERNANCE_SCHEDULED_RUN_PATH,
)
from src.core.exceptions import AuthenticationError, AuthorizationError, ConfigurationError
from src.core.utils.jwt_secrets import get_jwt_secret_bytes
from src.core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class TenantContext:
    """
    Tenant context containing user and organization information.
    
    This is attached to request.state.tenant_context for all authenticated requests.
    """
    
    user_id: int
    organization_id: int
    email: str
    roles: list[str]
    permissions: list[str]
    
    def has_role(self, role: str) -> bool:
        """Check if user has a specific role."""
        return role in self.roles
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        return permission in self.permissions
    
    def is_admin(self) -> bool:
        """Check if user is an organization admin."""
        return "admin" in self.roles or "org_admin" in self.roles


class TenantContextMiddleware(BaseHTTPMiddleware):
    """
    Middleware that extracts tenant context from JWT tokens.
    
    For every authenticated request:
    1. Extracts JWT from Authorization header
    2. Validates JWT signature using Auth0's public keys
    3. Extracts user_id, organization_id, and roles from claims
    4. Creates TenantContext and attaches to request.state
    
    Public endpoints (health checks and auth flows) are allowed without authentication.
    Documentation endpoints are only public in non-production.
    """
    
    # Public endpoints that don't require authentication
    PUBLIC_PATHS = {
        "/health",
        "/healthz",
        "/readyz",
        "/api/v1/health",
        "/",
        "/favicon.ico",
        "/robots.txt",
        "/api/v1/auth/login",
        "/api/v1/auth/signup",
        "/api/v1/auth/signup/start",
        "/api/v1/auth/signup/verify",
        "/api/v1/auth/signup/resend",
        "/app/auth/signup/start",
        "/app/auth/signup/verify",
        "/app/auth/signup/resend",
        "/api/v1/auth/refresh",
        "/api/v1/auth/logout",
        "/api/v1/auth/password/reset/request",
        "/api/v1/auth/password/reset/confirm",
        "/api/v1/auth/mfa/login/verify",
        "/api/v1/auth/mfa/challenge/resend",
        "/api/v1/auth/sso/google/start",
        "/api/v1/auth/sso/google/callback",
        "/api/v1/auth/sso/microsoft/start",
        "/api/v1/auth/sso/microsoft/callback",
        "/api/v1/auth/invite/accept",
        "/risk-intel/baseline",
        TEMPLATE_GOVERNANCE_SCHEDULED_RUN_PATH,
        LEARNING_LOOP_SCHEDULED_RUN_PATH,
    }
    
    def __init__(self, app):
        super().__init__(app)
        self.auth0_domain = settings.auth0.auth0_domain
        self.auth0_audience = settings.auth0.auth0_api_audience
        self.algorithms = ["RS256"]
        self.jwks_url = (
            settings.auth0.auth0_jwks_url
            or (f"https://{self.auth0_domain}/.well-known/jwks.json" if self.auth0_domain else None)
        )
        self._jwks_cache: list[dict] | None = None
        self._jwks_expires_at: float = 0
        try:
            self._jwt_secret_bytes = get_jwt_secret_bytes()
        except ConfigurationError as exc:
            logger.error("jwt_secret_missing", error=str(exc))
            raise AuthenticationError(str(exc))
        self._jwt_secret_fingerprint = hashlib.sha256(self._jwt_secret_bytes).hexdigest()[:8]
        logger.info(
            "jwt_secret_loaded",
            fingerprint=self._jwt_secret_fingerprint,
        )

    def _jwt_secret(self) -> bytes:
        return self._jwt_secret_bytes

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process each request and extract tenant context."""
        
        # Let CORS middleware handle preflight while skipping auth
        if request.method == "OPTIONS":
            return await call_next(request)

        # Skip authentication for public endpoints
        if self._is_public_path(request.url.path):
            return await call_next(request)
        
        # This guard covers **authentication only**. It used to wrap
        # `call_next` as well, so every error raised anywhere downstream — in a
        # route, a service, or response validation — was caught here and
        # re-raised as AuthenticationError("Failed to process authentication
        # token"). Two things followed, and both cost real diagnosis time on
        # 2026-08-31:
        #
        #   * The message was untrue. A duplicate response model in
        #     organization_structure.py (#373) broke onboarding's Organisation
        #     Structure step, and the user was told their token could not be
        #     processed — sending anyone who investigated to the wrong end of
        #     the system entirely.
        #   * The status was wrong. The re-raise happened *inside* the handler
        #     that turns AuthenticationError into a 401, so it escaped as an
        #     unhandled 500.
        #
        # A failure downstream is not an authentication failure and must not be
        # described as one.
        try:
            token = self._extract_token(request)

            if not token:
                logger.warning(
                    "missing_auth_token",
                    path=request.url.path,
                    origin=request.headers.get("origin"),
                    has_auth_header=bool(request.headers.get("authorization")),
                )
                raise AuthenticationError("Missing authorization token")

            payload = self._decode_token(token)
            tenant_context = self._extract_tenant_context(payload)

        except AuthenticationError as e:
            logger.warning(
                "authentication_failed",
                path=request.url.path,
                error=str(e),
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": str(e), "error_type": "authentication_error"},
            )

        except Exception:
            # Something in authentication itself broke — a server fault, not a
            # credential problem. Logged with its traceback and re-raised as
            # itself, so the error that is reported is the error that happened.
            logger.error(
                "tenant_authentication_error",
                path=request.url.path,
                exc_info=True,
            )
            raise

        request.state.tenant_context = tenant_context

        logger.debug(
            "tenant_context_attached",
            user_id=tenant_context.user_id,
            organization_id=tenant_context.organization_id,
            path=request.url.path,
        )

        return await call_next(request)
    
    def _is_public_path(self, path: str) -> bool:
        """Check if path is a public endpoint."""
        return is_public_path(path)
    
    def _extract_token(self, request: Request) -> Optional[str]:
        """Extract JWT token from Authorization header."""
        auth_header = request.headers.get("Authorization")
        
        if not auth_header:
            return None
        
        # Expected format: "Bearer <token>"
        parts = auth_header.split()
        
        if len(parts) != 2:
            raise AuthenticationError("Invalid authorization header format")
        
        scheme, token = parts
        
        if scheme.lower() != "bearer":
            raise AuthenticationError("Invalid authorization scheme. Expected 'Bearer'")
        
        return token

    def _fetch_jwks(self) -> list[dict]:
        """Fetch JWKS with simple caching."""
        if self._jwks_cache and time.time() < self._jwks_expires_at:
            return self._jwks_cache
        if not self.jwks_url:
            raise AuthenticationError("JWKS URL is not configured")
        resp = requests.get(self.jwks_url, timeout=5)
        if resp.status_code != 200:
            raise AuthenticationError("Failed to fetch JWKS keys")
        data = resp.json()
        self._jwks_cache = data.get("keys", [])
        self._jwks_expires_at = time.time() + 300
        return self._jwks_cache

    def _get_rsa_key(self, kid: str | None) -> dict | None:
        if not kid:
            return None
        for key in self._fetch_jwks():
            if key.get("kid") == kid:
                return {
                    "kty": key.get("kty"),
                    "kid": key.get("kid"),
                    "use": key.get("use"),
                    "n": key.get("n"),
                    "e": key.get("e"),
                }
        return None
    
    def _decode_token(self, token: str) -> dict:
        """Decode and validate JWT token using HS256 or JWKS (Auth0)."""
        try:
            unverified_header = jwt.get_unverified_header(token)
            alg = unverified_header.get("alg")
            if alg == "HS256":
                secret = self._jwt_secret()
                return jwt.decode(
                    token,
                    secret,
                    algorithms=["HS256"],
                    audience=settings.auth.jwt_audience,
                    issuer=settings.auth.jwt_issuer,
                    options={
                        "verify_aud": bool(settings.auth.jwt_audience),
                        "verify_iss": bool(settings.auth.jwt_issuer),
                    },
                )

            # Default: Validate signature using JWKS
            if not settings.auth0.rs256_enabled:
                raise AuthenticationError("Unsupported JWT algorithm (only HS256 is allowed)")
            if not self.auth0_domain:
                raise AuthenticationError("Auth0 domain is not configured")
            if unverified_header.get("alg") != "RS256":
                raise AuthenticationError("Invalid algorithm. Expected RS256")

            rsa_key = self._get_rsa_key(unverified_header.get("kid"))
            if not rsa_key:
                raise AuthenticationError("Unable to find appropriate key")

            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=self.algorithms,
                audience=self.auth0_audience,
                issuer=f"https://{self.auth0_domain}/" if self.auth0_domain else None,
                options={"verify_aud": bool(self.auth0_audience), "verify_iss": bool(self.auth0_domain)},
            )
            return payload

        except JWTError as e:
            logger.warning("jwt_decode_failed", error=str(e))
            raise AuthenticationError(f"Invalid token: {str(e)}")
    
    def _extract_tenant_context(self, payload: dict) -> TenantContext:
        """Extract tenant context from JWT claims."""
        
        # Extract standard claims
        user_id = payload.get("sub")  # Subject (user ID)
        email = payload.get("email")
        
        # Extract custom claims (namespace depends on Auth0 configuration)
        # Typical Auth0 custom claims use a namespace like: https://yourapp.com/
        namespace = settings.auth0.auth0_custom_claims_namespace or "https://risklence.com/"

        organization_id = (
            payload.get("tid")
            or payload.get("organization_id")
            or payload.get(f"{namespace}organization_id")
        )
        roles = payload.get("roles") or payload.get(f"{namespace}roles", [])
        permissions = payload.get("permissions") or payload.get(f"{namespace}permissions", [])
        
        # Validate required claims
        if not user_id:
            raise AuthenticationError("Missing 'sub' claim in token")
        
        if not organization_id:
            raise AuthenticationError("Missing organization_id in token claims")
        
        # Convert IDs to integers if they're strings
        try:
            user_id_int = int(user_id) if isinstance(user_id, str) else user_id
            org_id_int = int(organization_id) if isinstance(organization_id, str) else organization_id
        except (ValueError, TypeError):
            raise AuthenticationError("Invalid user_id or organization_id format")
        
        return TenantContext(
            user_id=user_id_int,
            organization_id=org_id_int,
            email=email or "",
            roles=roles if isinstance(roles, list) else [],
            permissions=permissions if isinstance(permissions, list) else [],
        )


def is_public_path(path: str) -> bool:
    """Check if a path is public (no auth required)."""
    if path in TenantContextMiddleware.PUBLIC_PATHS:
        return True

    if path.startswith("/public/onboarding/") or path == "/public/onboarding":
        return True

    if path.startswith(SCANNER_AGENT_PATH_PREFIX):
        return True

    # Documentation endpoints are only public in non-production.
    if settings.environment != Environment.PRODUCTION:
        if path == "/openapi.json":
            return True
        public_prefixes = ["/api/docs", "/api/redoc"]
        if any(path.startswith(prefix) for prefix in public_prefixes):
            return True

    return False


def get_tenant_context(request: Request) -> TenantContext:
    """
    Helper function to get tenant context from request.
    
    Usage in API endpoints:
        @app.get("/api/v1/assets")
        def list_assets(request: Request):
            tenant = get_tenant_context(request)
            # Now you have tenant.organization_id, tenant.user_id, etc.
    
    Raises:
        AuthorizationError: If tenant context is not available
    """
    if not hasattr(request.state, "tenant_context"):
        raise AuthorizationError("Tenant context not available. Authentication required.")
    
    return request.state.tenant_context


def require_authenticated(request: Request) -> None:
    """Global auth dependency that enforces tenant context on private endpoints."""
    if is_public_path(request.url.path):
        return
    get_tenant_context(request)


def require_role(request: Request, role: str) -> None:
    """
    Helper function to require a specific role.
    
    Usage:
        require_role(request, "admin")
    
    Raises:
        AuthorizationError: If user doesn't have the required role
    """
    tenant = get_tenant_context(request)
    
    if not tenant.has_role(role):
        raise AuthorizationError(f"Required role '{role}' not found")


def require_permission(request: Request, permission: str) -> None:
    """
    Helper function to require a specific permission.
    
    Usage:
        require_permission(request, "scans:write")
    
    Raises:
        AuthorizationError: If user doesn't have the required permission
    """
    tenant = get_tenant_context(request)
    
    if not tenant.has_permission(permission):
        raise AuthorizationError(f"Required permission '{permission}' not found")
