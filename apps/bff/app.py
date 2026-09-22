import hashlib
import json
import logging
import os
import re
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
import requests
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Ensure server/src is on path for shared middleware/routes
ROOT = Path(__file__).resolve().parents[1]
SERVER_BASE = ROOT / "server"
if SERVER_BASE.exists():
    sys.path.insert(0, str(SERVER_BASE))

from src.api.middleware.tenant_context import TenantContextMiddleware
from src.pretenant.enrichment import normalize_vat

# #227 — the API's own vocabulary for business context, imported rather than
# retyped. These six fields were `str`/`list[str]` here while the API typed them
# as StrEnums, so the BFF's published OpenAPI advertised free-form strings: a
# client generated from it sent an invalid value, the BFF accepted and forwarded
# it, and the *API* answered 422 naming constraints the client's own contract
# never mentioned.
#
# `company_context_enums` is a leaf module — its only import is `enum.StrEnum` —
# so this costs nothing at startup. The route module that declares
# `BusinessContextRequest` itself is not imported on purpose: it pulls in
# enrichment, a risk-intelligence client and a stateful pretenant store, and the
# BFF has no business constructing those. The values are what drifted; they are
# what is now shared.
from src.pretenant.company_context_enums import (
    CriticalBusinessActivity,
    CustomerVisibleImpact,
    HardToReplaceQuickly,
    OperationalReach,
    PrimaryBusinessActivity,
    TimeSensitivity,
)

# Upstream base API (the existing FastAPI app)
UPSTREAM_BASE = os.getenv("BFF_UPSTREAM_BASE", "http://localhost:8000").rstrip("/")
UPSTREAM_TIMEOUT_SECONDS = int(os.getenv("BFF_UPSTREAM_TIMEOUT_SECONDS", "15"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("BFF_RATE_LIMIT_PER_MINUTE", "120"))
PUBLIC_ONBOARDING_RATE_LIMIT_PER_MINUTE = int(os.getenv("BFF_PUBLIC_ONBOARDING_RATE_LIMIT_PER_MINUTE", "30"))
# CORS — set BFF_ALLOWED_ORIGINS as a comma-separated list in production
_raw_origins = os.getenv("BFF_ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS: list[str] = (
    [o.strip() for o in _raw_origins.split(",") if o.strip()]
    if _raw_origins
    else [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:3002",
    ]
)
# Metrics endpoint protection — set BFF_METRICS_TOKEN to a strong random secret
METRICS_TOKEN: str | None = os.getenv("BFF_METRICS_TOKEN") or None

logger = logging.getLogger("bff")
logging.basicConfig(level=logging.INFO)


from contextlib import asynccontextmanager

@asynccontextmanager
async def _lifespan(application: "FastAPI"):
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(UPSTREAM_TIMEOUT_SECONDS),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    ) as client:
        application.state.http_client = client
        yield


app = FastAPI(title="BFF", version="0.1.0", lifespan=_lifespan)

# Basic Prometheus instrumentation
REQUEST_COUNT = Counter("bff_requests_total", "Total requests seen by the BFF", ["method", "path", "status"])
REQUEST_LATENCY = Histogram(
    "bff_request_latency_seconds",
    "Request latency observed at the BFF edge",
    ["method", "path", "status"],
)
UPSTREAM_ERRORS = Counter(
    "bff_upstream_errors_total",
    "Upstream failures observed by the BFF",
    ["method", "path", "kind"],
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_per_minute: int):
        super().__init__(app)
        self.max_per_minute = max_per_minute
        self.counters: Dict[str, Dict[str, float]] = {}

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window = int(now // 60)
        key = f"{client_ip}:{window}"

        count = self.counters.get(key, {"count": 0, "ts": window})
        count["count"] += 1
        self.counters[key] = count

        # Simple cleanup for previous windows
        stale_windows = [k for k in self.counters if k.endswith(f":{window-2}")]
        for k in stale_windows:
            self.counters.pop(k, None)

        if count["count"] > self.max_per_minute:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={"Retry-After": "60"},
            )

        start = time.time()
        response = await call_next(request)
        duration_ms = int((time.time() - start) * 1000)

        tenant_ctx = getattr(request.state, "tenant_context", None)
        tenant_org = getattr(tenant_ctx, "organization_id", None)
        tenant_user = getattr(tenant_ctx, "user_id", None)
        _raw_email = getattr(tenant_ctx, "email", None)
        tenant_email_hash = _masked_identifier(_raw_email)
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        log_record = {
            "event": "bff_request",
            "request_id": request_id,
            "method": request.method,
            "path": _sanitize_log_path(request.url.path),
            "status": response.status_code,
            "duration_ms": duration_ms,
            "client_ip": client_ip,
            "tenant_org": tenant_org,
            "tenant_user": tenant_user,
            "tenant_email_hash": tenant_email_hash,
        }
        logger.info(json.dumps(log_record))
        return response


# Enforce auth/tenant at the edge using the same middleware as the upstream API.
app.add_middleware(TenantContextMiddleware)
app.add_middleware(RateLimitMiddleware, max_per_minute=RATE_LIMIT_PER_MINUTE)

# Lightweight metrics middleware to observe latency and status codes.


class MetricsMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/metrics":
            return await call_next(request)
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start
        labels = {
            "method": request.method,
            "path": request.url.path,
            "status": str(response.status_code),
        }
        REQUEST_COUNT.labels(**labels).inc()
        REQUEST_LATENCY.labels(**labels).observe(elapsed)
        return response


app.add_middleware(MetricsMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_PUBLIC_ONBOARDING_PATH_LOG_PATTERN = re.compile(r"(/public/onboarding/sessions/)([^/]+)")
_PUBLIC_ONBOARDING_FINGERPRINT_HEADERS = ("x-device-fingerprint", "x-client-fingerprint")


def _filtered_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in {"host", "content-length", "transfer-encoding"}}


def _masked_identifier(value: str | None) -> str | None:
    if not value:
        return None
    return f"id_{hashlib.sha256(value.encode('utf-8')).hexdigest()[:10]}"


def _sanitize_log_path(path: str) -> str:
    return _PUBLIC_ONBOARDING_PATH_LOG_PATTERN.sub(
        lambda match: f"{match.group(1)}{_masked_identifier(match.group(2))}",
        path,
    )


def _require_auth(request: Request) -> str:
    """Ensure an Authorization header exists and normalize the bearer token."""
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing authorization token")
    return auth if auth.lower().startswith("bearer ") else f"Bearer {auth}"


async def _upstream_request(
    *,
    method: str,
    path: str,
    request: Request,
    params: Optional[Dict[str, Any]] = None,
    json_payload: Optional[dict] = None,
    require_auth: bool = True,
) -> httpx.Response:
    """Forward a validated request to the upstream API with consistent headers/timeouts."""
    headers = _filtered_headers(dict(request.headers))
    if require_auth:
        headers["authorization"] = _require_auth(request)
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    headers["x-request-id"] = request_id

    upstream_url = f"{UPSTREAM_BASE}{path}"
    client: httpx.AsyncClient = request.app.state.http_client
    try:
        resp = await client.request(
            method=method,
            url=upstream_url,
            params=params,
            headers=headers,
            json=json_payload,
        )
    except httpx.RequestError as exc:
        UPSTREAM_ERRORS.labels(method, path, "connection_error").inc()
        logger.error(
            json.dumps({
                "event": "bff_upstream_request_failed",
                "request_id": request_id,
                "method": method,
                "path": path,
                "upstream": upstream_url,
                "error": str(exc),
            })
        )
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Upstream request failed") from exc
    return resp


def _normalize_upstream_error_detail(detail: Any) -> Any:
    current = detail
    # Flatten repeated wrappers such as {"detail": {"detail": {...}}}
    while isinstance(current, dict) and "detail" in current and len(current) == 1:
        current = current.get("detail")
    return current


def _extract_error_type(detail: Any) -> str | None:
    if isinstance(detail, dict):
        value = detail.get("error_type")
        if isinstance(value, str) and value:
            return value
    return None


def _json_or_error(resp: httpx.Response) -> Any:
    if resp.status_code >= 400:
        try:
            detail = resp.json()
        except ValueError:
            detail = resp.text
        raise HTTPException(status_code=resp.status_code, detail=_normalize_upstream_error_detail(detail))
    try:
        return resp.json()
    except ValueError:
        raise HTTPException(status_code=502, detail="Upstream did not return JSON")


@app.api_route("/api/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], include_in_schema=False)
async def proxy(path: str, request: Request):
    """
    Thin proxy to the upstream API. For small teams, this gives a single edge
    endpoint (port 8080 by default) while reusing the existing backend.
    Auth is enforced by the tenant middleware at this layer.
    """
    url = f"{UPSTREAM_BASE}/api/v1/{path}"
    body = await request.body()
    headers = _filtered_headers(dict(request.headers))
    # Ensure the request ID follows the call into upstream services.
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    headers["x-request-id"] = request_id

    client: httpx.AsyncClient = request.app.state.http_client
    try:
        resp = await client.request(
            method=request.method,
            url=url,
            params=request.query_params,
            headers=headers,
            content=body if body else None,
        )
    except httpx.RequestError as exc:
        UPSTREAM_ERRORS.labels(request.method, f"/api/v1/{path}", "connection_error").inc()
        logger.error(
            json.dumps({
                "event": "bff_upstream_request_failed",
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "upstream": url,
                "error": str(exc),
            })
        )
        return JSONResponse(
            status_code=502,
            content={"detail": "Upstream request failed", "request_id": request_id},
        )

    proxy_headers = _filtered_headers(resp.headers)
    if resp.status_code >= 500:
        UPSTREAM_ERRORS.labels(request.method, f"/api/v1/{path}", f"status_{resp.status_code}").inc()

    return Response(content=resp.content, status_code=resp.status_code, headers=proxy_headers)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "bff", "upstream": UPSTREAM_BASE}


@app.get("/metrics")
async def metrics(request: Request):
    if METRICS_TOKEN:
        auth = request.headers.get("authorization", "")
        if not auth or auth != f"Bearer {METRICS_TOKEN}":
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ---------------------------------------------------------------------------
# Typed, UI-focused onboarding endpoints (validated before proxying upstream)
# ---------------------------------------------------------------------------


class PublicOnboardingSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PublicOnboardingSessionOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    session_id: str = Field(alias="sessionId")
    expires_at: datetime = Field(alias="expiresAt")
    next_step: str = Field(alias="nextStep")


class PublicOnboardingResumeCompanyDetailsOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    legal_name: str | None = Field(default=None, alias="legalName")
    industry_code: str | None = Field(default=None, alias="industryCode")
    geography: str | None = None


class PublicOnboardingResumeDraftSnapshotOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    cvr: str | None = None
    company_details: PublicOnboardingResumeCompanyDetailsOut | None = Field(default=None, alias="companyDetails")
    risk_appetite: str | None = Field(default=None, alias="riskAppetite")
    selected_asset_categories: list[str] | None = Field(default=None, alias="selectedAssetCategories")
    baseline_computed: bool | None = Field(default=None, alias="baselineComputed")


class PublicOnboardingResumeOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    session_id: str = Field(alias="sessionId")
    expires_at: datetime = Field(alias="expiresAt")
    current_step: str | None = Field(default=None, alias="currentStep")
    draft_snapshot: PublicOnboardingResumeDraftSnapshotOut | None = Field(default=None, alias="draftSnapshot")
    next_step: str = Field(alias="nextStep")


class CvrEnrichmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cvr: str = Field(..., min_length=1, max_length=64)

    @field_validator("cvr")
    @classmethod
    def _normalize_cvr(cls, value: str) -> str:
        normalized = re.sub(r"\D+", "", value or "")
        if len(normalized) != 8 or not normalized.isdigit():
            raise ValueError("cvr must be 8 digits")
        return normalized


class BusinessContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    primary_business_activity: PrimaryBusinessActivity | None = Field(default=None, alias="primaryBusinessActivity")
    critical_business_activity: CriticalBusinessActivity | None = Field(default=None, alias="criticalBusinessActivity")
    customer_visible_impact: list[CustomerVisibleImpact] | None = Field(default=None, alias="customerVisibleImpact")
    time_sensitivity: TimeSensitivity | None = Field(default=None, alias="timeSensitivity")
    hard_to_replace_quickly: list[HardToReplaceQuickly] | None = Field(default=None, alias="hardToReplaceQuickly")
    operational_reach: OperationalReach | None = Field(default=None, alias="operationalReach")


class CvrEnrichmentResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    cvr: str
    legal_name: str = Field(alias="legalName")
    trade_name: str | None = Field(default=None, alias="tradeName")
    address: str | None = None
    postal_code: str | None = Field(default=None, alias="postalCode")
    city: str | None = None
    country: str = "DK"
    industry_code: str | None = Field(default=None, alias="industryCode")
    industry: str | None = None
    # #227 — present on the API's model, absent here, therefore stripped by
    # `response_model` before reaching the client. Both feed the company profile
    # the onboarding UI shows back for confirmation.
    size_bracket: str | None = Field(default=None, alias="sizeBracket")
    geography: str | None = None


class CvrLookupDraftOrganisationResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    cvr: str
    legal_name: str = Field(alias="legalName")
    trade_name: str | None = Field(default=None, alias="tradeName")
    address: str | None = None
    postal_code: str | None = Field(default=None, alias="postalCode")
    city: str | None = None
    country: str | None = None
    industry_code: str | None = Field(default=None, alias="industryCode")
    industry: str | None = None
    size_bracket: str | None = Field(default=None, alias="sizeBracket")
    geography: str | None = None


class CvrLookupResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    session_id: str = Field(alias="sessionId")
    expires_at: datetime = Field(alias="expiresAt")
    next_step: str = Field(alias="nextStep")
    draft_organisation: CvrLookupDraftOrganisationResponse = Field(alias="draftOrganisation")
    assumption_preview: dict[str, Any] = Field(alias="assumptionPreview")


class OrgLookupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vat: str = Field(..., min_length=1, max_length=64)

    @field_validator("vat")
    @classmethod
    def _normalize_vat(cls, value: str) -> str:
        normalized = normalize_vat(value)
        if not normalized:
            raise ValueError("vat must be 8 digits")
        return normalized


class OrgLookupResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    vat: str
    name: str
    legal_form: str = Field(alias="legalForm")
    industry: str
    org_size_band: str = Field(alias="orgSizeBand")
    employee_count: int = Field(alias="employeeCount")
    site_count: int = Field(alias="siteCount")
    multi_site: bool = Field(alias="multiSite")
    lifecycle_stage: str = Field(alias="lifecycleStage")


class OrgConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vat: str = Field(..., min_length=1, max_length=64)
    session_id: str = Field(..., alias="sessionId", min_length=3, max_length=256)
    confirmed: bool

    @field_validator("vat")
    @classmethod
    def _normalize_vat(cls, value: str) -> str:
        normalized = normalize_vat(value)
        if not normalized:
            raise ValueError("vat must be 8 digits")
        return normalized

    @field_validator("session_id")
    @classmethod
    def _validate_session_id(cls, value: str) -> str:
        session_id = value.strip()
        if not re.fullmatch(r"^[A-Za-z0-9_-]{3,256}$", session_id):
            raise ValueError("sessionId is invalid")
        return session_id


class OrgConfirmResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    vat: str
    name: str
    industry_cluster: str = Field(alias="industryCluster")
    org_size_band: str = Field(alias="orgSizeBand")
    legal_form_band: str = Field(alias="legalFormBand")
    site_count: int = Field(alias="siteCount")
    multi_site: bool = Field(alias="multiSite")
    lifecycle_stage: str = Field(alias="lifecycleStage")
    confirmation_timestamp: datetime = Field(alias="confirmationTimestamp")
    session_id: str = Field(alias="sessionId")


class BaselineRiskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    force_recompute: bool = Field(default=False, alias="forceRecompute")


class BaselineRiskResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    session_id: str | None = Field(default=None, alias="sessionId")
    expires_at: datetime | None = Field(default=None, alias="expiresAt")
    baseline: Dict[str, Any] | None = None
    model_version: str = Field(alias="modelVersion")
    baseline_risk_landscape: Dict[str, Any] | None = Field(default=None, alias="baselineRiskLandscape")
    baseline_status: str | None = Field(default=None, alias="baselineStatus")
    baseline_computed_at: datetime | None = Field(default=None, alias="baselineComputedAt")
    # #227 — both are REQUIRED on the API's own model and were absent here, so
    # `response_model` stripped them before the client ever saw them. Dropping
    # `requiresHumanReview` is the worst of the two: it is the signal that a
    # person still has to decide, in a product whose first rule is that the system
    # never decides. A caller reading only the BFF's contract had no way to know
    # the flag existed.
    assumption_status: str = Field(alias="assumptionStatus")
    requires_human_review: bool = Field(alias="requiresHumanReview")


class FinalizePublicOnboardingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FinalizePublicOnboardingResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    session_id: str = Field(alias="sessionId")
    draft_status: str = Field(alias="draftStatus")
    redirect_url: str = Field(alias="redirectUrl")
    token_expires_at: datetime = Field(alias="tokenExpiresAt")


class PublicOnboardingDraftOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    session_id: str = Field(alias="sessionId")
    expires_at: datetime = Field(alias="expiresAt")
    current_step: str | None = Field(default=None, alias="currentStep")
    cvr: str | None = None
    legal_name: str | None = Field(default=None, alias="legalName")
    trade_name: str | None = Field(default=None, alias="tradeName")
    address: str | None = None
    postal_code: str | None = Field(default=None, alias="postalCode")
    city: str | None = None
    country: str | None = None
    industry_code: str | None = Field(default=None, alias="industryCode")
    size_bracket: str | None = Field(default=None, alias="sizeBracket")
    geography: str | None = None
    locations: int | None = None
    it_dependency: str | None = Field(default=None, alias="itDependency")
    risk_appetite: str | None = Field(default=None, alias="riskAppetite")
    selected_asset_categories: list[str] | None = Field(default=None, alias="selectedAssetCategories")
    regulatory_flags: list[str] | None = Field(default=None, alias="regulatoryFlags")
    baseline_status: str | None = Field(default=None, alias="baselineStatus")
    model_version: str | None = Field(default=None, alias="modelVersion")
    baseline_risk_landscape: Dict[str, Any] | None = Field(default=None, alias="baselineRiskLandscape")
    draft_organisation: Optional["PublicOnboardingDraftOrganisationOut"] = Field(
        default=None,
        alias="draftOrganisation",
    )


class PublicOnboardingDraftOrganisationOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    cvr: str | None = None
    legal_name: str | None = Field(default=None, alias="legalName")
    trade_name: str | None = Field(default=None, alias="tradeName")
    address: str | None = None
    postal_code: str | None = Field(default=None, alias="postalCode")
    city: str | None = None
    country: str | None = None
    industry_code: str | None = Field(default=None, alias="industryCode")
    size_bracket: str | None = Field(default=None, alias="sizeBracket")
    geography: str | None = None
    locations: int | None = None
    it_dependency: str | None = Field(default=None, alias="itDependency")
    risk_appetite: str | None = Field(default=None, alias="riskAppetite")
    selected_asset_categories: list[str] | None = Field(default=None, alias="selectedAssetCategories")
    regulatory_flags: list[str] | None = Field(default=None, alias="regulatoryFlags")
    baseline_status: str | None = Field(default=None, alias="baselineStatus")


PublicOnboardingDraftOut.model_rebuild()


class RedeemActivationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(..., min_length=12, max_length=512)


class RedeemActivationResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    outcome: str = Field(default="ACTIVATED")
    message: str | None = None
    organization_id: int | None = Field(default=None, alias="organizationId")
    organization_name: str | None = Field(default=None, alias="organizationName")
    organization_slug: str | None = Field(default=None, alias="organizationSlug")
    user_id: int | None = Field(default=None, alias="userId")
    user_email: str | None = Field(default=None, alias="userEmail")
    workspace_url: str | None = Field(default=None, alias="workspaceUrl")
    activated_at: datetime | None = Field(default=None, alias="activatedAt")
    model_version: str | None = Field(default=None, alias="modelVersion")


class SignupStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    activation_token: str = Field(alias="activationToken", min_length=12, max_length=512)
    email: str
    password: str = Field(min_length=8, max_length=256)


class SignupStartResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    challenge_id: str = Field(alias="challengeId")
    masked_destination: str = Field(alias="maskedDestination")
    expires_at: datetime = Field(alias="expiresAt")
    verification_method: str = Field(alias="verificationMethod")
    message: str


class SignupVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    activation_token: str = Field(alias="activationToken", min_length=12, max_length=512)
    challenge_id: str = Field(alias="challengeId", min_length=1, max_length=256)
    code: str = Field(min_length=4, max_length=12)


class SignupResendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    activation_token: str = Field(alias="activationToken", min_length=12, max_length=512)
    challenge_id: str = Field(alias="challengeId", min_length=1, max_length=256)


class SignupVerifyUser(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: int
    organization_id: int = Field(alias="organizationId")
    email: str
    email_verified: bool = Field(alias="emailVerified")
    status: str
    role: str
    permissions: list[str]


class SignupVerifyTenant(BaseModel):
    # The API emits this object in snake_case (sso_required, local_login_enabled).
    # Without populate_by_name the aliases are the *only* accepted names, so
    # serialising the upstream response raised ResponseValidationError and the
    # BFF returned 500 for a signup the API had already completed. Every sibling
    # here already carries this config; this model was the one that missed it.
    model_config = ConfigDict(populate_by_name=True)

    id: int
    name: str
    sso_required: bool = Field(alias="ssoRequired")
    local_login_enabled: bool = Field(alias="localLoginEnabled")


class SignupVerifyResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    access_token: str = Field(alias="accessToken")
    token_type: str = Field(alias="tokenType")
    user: SignupVerifyUser
    tenant: SignupVerifyTenant
    workspace_url: str = Field(alias="workspaceUrl")
    activated_at: datetime = Field(alias="activatedAt")
    model_version: str | None = Field(default=None, alias="modelVersion")


class WorkspaceBootstrapSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    organization_id: int = Field(alias="organizationId")
    organization_name: str = Field(alias="organizationName")
    organization_slug: str = Field(alias="organizationSlug")
    user_id: int = Field(alias="userId")
    user_email: str = Field(alias="userEmail")


class WorkspaceBaselineSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    model_version: str | None = Field(default=None, alias="modelVersion")
    generated_at: datetime | None = Field(default=None, alias="generatedAt")
    overall_risk_score: int | None = Field(default=None, alias="overallRiskScore")
    risk_level: str | None = Field(default=None, alias="riskLevel")
    focus_areas: list[str] = Field(default_factory=list, alias="focusAreas")
    hypotheses_count: int = Field(default=0, alias="hypothesesCount")


class WorkspaceNextStep(BaseModel):
    code: str
    title: str
    description: str


class WorkspaceBootstrapResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    workspace: WorkspaceBootstrapSummary
    baseline_summary: WorkspaceBaselineSummary | None = Field(default=None, alias="baselineSummary")
    next_steps: list[WorkspaceNextStep] = Field(default_factory=list, alias="nextSteps")
    auto_monitoring_enabled: bool = Field(alias="autoMonitoringEnabled")


_public_onboarding_counters: Dict[str, Dict[str, float]] = {}
PUBLIC_ONBOARDING_RESUME_RATE_LIMIT_PER_MINUTE = int(
    os.getenv("BFF_PUBLIC_ONBOARDING_RESUME_RATE_LIMIT_PER_MINUTE", "60")
)
PUBLIC_ONBOARDING_PATCH_RATE_LIMIT_PER_MINUTE = int(
    os.getenv("BFF_PUBLIC_ONBOARDING_PATCH_RATE_LIMIT_PER_MINUTE", "30")
)
PUBLIC_ONBOARDING_CVR_RATE_LIMIT_PER_MINUTE = int(
    os.getenv("BFF_PUBLIC_ONBOARDING_CVR_RATE_LIMIT_PER_MINUTE", "10")
)
PUBLIC_ONBOARDING_ORG_LOOKUP_RATE_LIMIT_PER_MINUTE = int(
    os.getenv("BFF_PUBLIC_ONBOARDING_ORG_LOOKUP_RATE_LIMIT_PER_MINUTE", "12")
)
PUBLIC_ONBOARDING_ORG_CONFIRM_RATE_LIMIT_PER_MINUTE = int(
    os.getenv("BFF_PUBLIC_ONBOARDING_ORG_CONFIRM_RATE_LIMIT_PER_MINUTE", "8")
)
PUBLIC_ONBOARDING_BASELINE_POST_RATE_LIMIT_PER_MINUTE = int(
    os.getenv("BFF_PUBLIC_ONBOARDING_BASELINE_POST_RATE_LIMIT_PER_MINUTE", "8")
)
PUBLIC_ONBOARDING_BASELINE_GET_RATE_LIMIT_PER_MINUTE = int(
    os.getenv("BFF_PUBLIC_ONBOARDING_BASELINE_GET_RATE_LIMIT_PER_MINUTE", "20")
)
PUBLIC_ONBOARDING_FINALIZE_RATE_LIMIT_PER_MINUTE = int(
    os.getenv("BFF_PUBLIC_ONBOARDING_FINALIZE_RATE_LIMIT_PER_MINUTE", "5")
)
APP_ACTIVATION_REDEEM_RATE_LIMIT_PER_MINUTE = int(
    os.getenv("BFF_APP_ACTIVATE_REDEEM_RATE_LIMIT_PER_MINUTE", "20")
)
PUBLIC_ONBOARDING_SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,256}$")


def _public_onboarding_rate_limit_or_429(
    request: Request,
    route_key: str,
    limit_per_minute: int,
    *,
    session_hint: str | None = None,
) -> JSONResponse | None:
    client_ip = request.client.host if request.client else "unknown"
    effective_session_hint = session_hint or request.headers.get("x-onboarding-session-id")
    session_hint_masked = _masked_identifier(effective_session_hint) or "-"
    device_fingerprint = None
    for header_name in _PUBLIC_ONBOARDING_FINGERPRINT_HEADERS:
        raw_value = request.headers.get(header_name)
        if raw_value:
            device_fingerprint = _masked_identifier(raw_value)
            break
    now = time.time()
    window = int(now // 60)
    key = f"{route_key}:{client_ip}:{device_fingerprint or '-'}:{session_hint_masked}:{window}"
    count = _public_onboarding_counters.get(key, {"count": 0, "ts": window})
    count["count"] += 1
    _public_onboarding_counters[key] = count

    stale_windows = [k for k in _public_onboarding_counters if k.endswith(f":{window-2}")]
    for k in stale_windows:
        _public_onboarding_counters.pop(k, None)

    if count["count"] > limit_per_minute:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"},
            headers={"Retry-After": "60"},
        )
    return None


def _validate_public_onboarding_session_id(session_id: str) -> None:
    if not PUBLIC_ONBOARDING_SESSION_ID_PATTERN.fullmatch(session_id):
        raise HTTPException(
            status_code=400,
            detail={
                "error_type": "invalid_session_id",
                "message": "Invalid sessionId",
            },
        )


_app_activation_counters: Dict[str, Dict[str, float]] = {}


def _app_activation_rate_limit_or_429(request: Request, route_key: str, limit_per_minute: int) -> JSONResponse | None:
    client_ip = request.client.host if request.client else "unknown"
    tenant_ctx = getattr(request.state, "tenant_context", None)
    user_hint = _masked_identifier(getattr(tenant_ctx, "email", None)) or "-"
    now = time.time()
    window = int(now // 60)
    key = f"{route_key}:{client_ip}:{user_hint}:{window}"
    count = _app_activation_counters.get(key, {"count": 0, "ts": window})
    count["count"] += 1
    _app_activation_counters[key] = count

    stale_windows = [k for k in _app_activation_counters if k.endswith(f":{window-2}")]
    for k in stale_windows:
        _app_activation_counters.pop(k, None)

    if count["count"] > limit_per_minute:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"},
            headers={"Retry-After": "60"},
        )
    return None


@app.post("/public/onboarding/sessions", status_code=201, response_model=PublicOnboardingSessionOut)
async def start_public_onboarding_session(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    try:
        payload = await request.json()
    except Exception as err:
        raise HTTPException(
            status_code=400,
            detail={
                "error_type": "invalid_schema",
                "message": "Invalid schema",
            },
        ) from err
    if not isinstance(payload, dict) or payload:
        raise HTTPException(
            status_code=400,
            detail={
                "error_type": "invalid_schema",
                "message": "Invalid schema",
            },
        )
    limited = _public_onboarding_rate_limit_or_429(request, "start", PUBLIC_ONBOARDING_RATE_LIMIT_PER_MINUTE)
    if limited is not None:
        return limited

    resp = await _upstream_request(
        method="POST",
        path="/public/onboarding/sessions",
        request=request,
        json_payload=payload,
        require_auth=False,
    )
    data = _json_or_error(resp)
    logger.info(
        json.dumps(
            {
                "event": "public_onboarding_session_created",
                "request_id": request.headers.get("x-request-id") or "missing",
                "client_ip": client_ip,
                "status": resp.status_code,
            }
        )
    )
    return data


@app.get("/public/onboarding/sessions/{session_id}", response_model=PublicOnboardingResumeOut)
async def get_public_onboarding_session(session_id: str, request: Request):
    _validate_public_onboarding_session_id(session_id)
    limited = _public_onboarding_rate_limit_or_429(request, f"resume:{session_id}", PUBLIC_ONBOARDING_RESUME_RATE_LIMIT_PER_MINUTE)
    if limited is not None:
        return limited
    resp = await _upstream_request(
        method="GET",
        path=f"/public/onboarding/sessions/{session_id}",
        request=request,
        require_auth=False,
    )
    data = _json_or_error(resp)
    logger.info(
        json.dumps(
            {
                "event": "public_onboarding_session_checked",
                "request_id": request.headers.get("x-request-id") or "missing",
                "client_ip": request.client.host if request.client else "unknown",
                "status": resp.status_code,
                "session_id_masked": _masked_identifier(session_id),
            }
        )
    )
    return data


@app.patch("/public/onboarding/sessions/{session_id}", response_model=PublicOnboardingDraftOut)
async def update_public_onboarding_session(session_id: str, payload: Dict[str, Any], request: Request):
    _validate_public_onboarding_session_id(session_id)
    limited = _public_onboarding_rate_limit_or_429(request, f"patch:{session_id}", PUBLIC_ONBOARDING_PATCH_RATE_LIMIT_PER_MINUTE)
    if limited is not None:
        return limited
    resp = await _upstream_request(
        method="PATCH",
        path=f"/public/onboarding/sessions/{session_id}",
        request=request,
        json_payload=payload,
        require_auth=False,
    )
    return _json_or_error(resp)


@app.post("/public/onboarding/sessions/{session_id}/cvr", response_model=CvrEnrichmentResponse)
async def enrich_public_cvr(session_id: str, payload: CvrEnrichmentRequest, request: Request):
    _validate_public_onboarding_session_id(session_id)
    limited = _public_onboarding_rate_limit_or_429(request, f"cvr:{session_id}", PUBLIC_ONBOARDING_CVR_RATE_LIMIT_PER_MINUTE)
    if limited is not None:
        return limited
    resp = await _upstream_request(
        method="POST",
        path=f"/public/onboarding/sessions/{session_id}/cvr",
        request=request,
        json_payload=payload.model_dump(),
        require_auth=False,
    )
    try:
        return _json_or_error(resp)
    except HTTPException as exc:
        detail = exc.detail
        logger.info(
            json.dumps(
                {
                    "event": "public_onboarding_cvr_failed",
                    "request_id": request.headers.get("x-request-id") or "missing",
                    "client_ip": request.client.host if request.client else "unknown",
                    "status": exc.status_code,
                    "error_type": _extract_error_type(detail),
                    "session_id_masked": _masked_identifier(session_id),
                }
            )
        )
        raise


@app.post("/public/onboarding/sessions/{session_id}/cvr/lookup", response_model=CvrLookupResponse)
async def enrich_public_cvr_lookup(session_id: str, payload: CvrEnrichmentRequest, request: Request):
    _validate_public_onboarding_session_id(session_id)
    limited = _public_onboarding_rate_limit_or_429(request, f"cvr_lookup:{session_id}", PUBLIC_ONBOARDING_CVR_RATE_LIMIT_PER_MINUTE)
    if limited is not None:
        return limited
    resp = await _upstream_request(
        method="POST",
        path=f"/public/onboarding/sessions/{session_id}/cvr/lookup",
        request=request,
        json_payload=payload.model_dump(),
        require_auth=False,
    )
    try:
        return _json_or_error(resp)
    except HTTPException as exc:
        detail = exc.detail
        logger.info(
            json.dumps(
                {
                    "event": "public_onboarding_cvr_lookup_failed",
                    "request_id": request.headers.get("x-request-id") or "missing",
                    "client_ip": request.client.host if request.client else "unknown",
                    "status": exc.status_code,
                    "error_type": _extract_error_type(detail),
                    "session_id_masked": _masked_identifier(session_id),
                }
            )
        )
        raise


@app.post("/public/onboarding/sessions/{session_id}/business-context", response_model=CvrLookupResponse)
async def refine_public_business_context(session_id: str, payload: BusinessContextRequest, request: Request):
    _validate_public_onboarding_session_id(session_id)
    limited = _public_onboarding_rate_limit_or_429(request, f"business_context:{session_id}", PUBLIC_ONBOARDING_PATCH_RATE_LIMIT_PER_MINUTE)
    if limited is not None:
        return limited
    response = await _upstream_request(
        method="POST",
        path=f"/public/onboarding/sessions/{session_id}/business-context",
        request=request,
        json_payload=payload.model_dump(by_alias=True, exclude_none=True),
        require_auth=False,
    )
    return _json_or_error(response)


@app.post("/public/onboarding/org-lookup", response_model=OrgLookupResponse)
async def lookup_public_org(payload: OrgLookupRequest, request: Request):
    limited = _public_onboarding_rate_limit_or_429(
        request,
        "org_lookup",
        PUBLIC_ONBOARDING_ORG_LOOKUP_RATE_LIMIT_PER_MINUTE,
    )
    if limited is not None:
        return limited
    resp = await _upstream_request(
        method="POST",
        path="/public/onboarding/org-lookup",
        request=request,
        json_payload=payload.model_dump(),
        require_auth=False,
    )
    return _json_or_error(resp)


@app.post("/public/onboarding/org-confirm", response_model=OrgConfirmResponse)
async def confirm_public_org(payload: OrgConfirmRequest, request: Request):
    limited = _public_onboarding_rate_limit_or_429(
        request,
        "org_confirm",
        PUBLIC_ONBOARDING_ORG_CONFIRM_RATE_LIMIT_PER_MINUTE,
        session_hint=payload.session_id,
    )
    if limited is not None:
        return limited
    resp = await _upstream_request(
        method="POST",
        path="/public/onboarding/org-confirm",
        request=request,
        json_payload=payload.model_dump(by_alias=True),
        require_auth=False,
    )
    return _json_or_error(resp)


@app.post(
    "/public/onboarding/sessions/{session_id}/baseline",
    response_model=BaselineRiskResponse,
    response_model_exclude_none=True,
)
async def generate_public_baseline(session_id: str, payload: BaselineRiskRequest, request: Request):
    _validate_public_onboarding_session_id(session_id)
    limited = _public_onboarding_rate_limit_or_429(
        request,
        f"baseline_post:{session_id}",
        PUBLIC_ONBOARDING_BASELINE_POST_RATE_LIMIT_PER_MINUTE,
    )
    if limited is not None:
        return limited
    resp = await _upstream_request(
        method="POST",
        path=f"/public/onboarding/sessions/{session_id}/baseline",
        request=request,
        json_payload=payload.model_dump(by_alias=True),
        require_auth=False,
    )
    return _json_or_error(resp)


@app.get(
    "/public/onboarding/sessions/{session_id}/baseline",
    response_model=BaselineRiskResponse,
    response_model_exclude_none=True,
)
async def get_public_baseline(session_id: str, request: Request):
    _validate_public_onboarding_session_id(session_id)
    limited = _public_onboarding_rate_limit_or_429(
        request,
        f"baseline_get:{session_id}",
        PUBLIC_ONBOARDING_BASELINE_GET_RATE_LIMIT_PER_MINUTE,
    )
    if limited is not None:
        return limited
    resp = await _upstream_request(
        method="GET",
        path=f"/public/onboarding/sessions/{session_id}/baseline",
        request=request,
        require_auth=False,
    )
    return _json_or_error(resp)


@app.post("/public/onboarding/sessions/{session_id}/finalize", response_model=FinalizePublicOnboardingResponse)
async def finalize_public_onboarding_session(
    session_id: str,
    payload: FinalizePublicOnboardingRequest,
    request: Request,
):
    _validate_public_onboarding_session_id(session_id)
    limited = _public_onboarding_rate_limit_or_429(
        request,
        f"finalize:{session_id}",
        PUBLIC_ONBOARDING_FINALIZE_RATE_LIMIT_PER_MINUTE,
    )
    if limited is not None:
        return limited
    resp = await _upstream_request(
        method="POST",
        path=f"/public/onboarding/sessions/{session_id}/finalize",
        request=request,
        json_payload=payload.model_dump(),
        require_auth=False,
    )
    return _json_or_error(resp)


@app.post(
    "/app/activate/redeem",
    response_model=RedeemActivationResponse,
    response_model_exclude_none=True,
)
async def redeem_activation(payload: RedeemActivationRequest, request: Request):
    limited = _app_activation_rate_limit_or_429(
        request,
        "app_activate_redeem",
        APP_ACTIVATION_REDEEM_RATE_LIMIT_PER_MINUTE,
    )
    if limited is not None:
        return limited
    resp = await _upstream_request(
        method="POST",
        path="/app/activate/redeem",
        request=request,
        json_payload=payload.model_dump(),
        require_auth=True,
    )
    return _json_or_error(resp)


@app.post("/app/auth/signup/start", response_model=SignupStartResponse)
async def app_signup_start(payload: SignupStartRequest, request: Request):
    resp = await _upstream_request(
        method="POST",
        path="/api/v1/auth/signup/start",
        request=request,
        json_payload=payload.model_dump(by_alias=False),
        require_auth=False,
    )
    return _json_or_error(resp)


@app.post("/app/auth/signup/verify", response_model=SignupVerifyResponse)
async def app_signup_verify(payload: SignupVerifyRequest, request: Request):
    resp = await _upstream_request(
        method="POST",
        path="/api/v1/auth/signup/verify",
        request=request,
        json_payload=payload.model_dump(by_alias=False),
        require_auth=False,
    )
    return _json_or_error(resp)


@app.post("/app/auth/signup/resend", response_model=SignupStartResponse)
async def app_signup_resend(payload: SignupResendRequest, request: Request):
    resp = await _upstream_request(
        method="POST",
        path="/api/v1/auth/signup/resend",
        request=request,
        json_payload=payload.model_dump(by_alias=False),
        require_auth=False,
    )
    return _json_or_error(resp)


@app.get("/app/workspace/bootstrap", response_model=WorkspaceBootstrapResponse)
async def get_workspace_bootstrap(request: Request):
    resp = await _upstream_request(
        method="GET",
        path="/app/workspace/bootstrap",
        request=request,
        require_auth=True,
    )
    return _json_or_error(resp)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("bff.app:app", host="0.0.0.0", port=8080, reload=True)
