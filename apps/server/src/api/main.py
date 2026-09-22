"""
FastAPI application for Risklence Tower.

Multi-tenant SaaS platform for cloud compliance and security monitoring.
"""

from contextlib import asynccontextmanager
from typing import Any, Dict

import sqlalchemy
from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api.middleware.global_rate_limit import GlobalRateLimitMiddleware
from src.api.middleware.pretenant_guard import PreTenantGuardMiddleware
from src.api.middleware.tenant_context import TenantContextMiddleware, require_authenticated
from src.api.routes.access_connector_lifecycle import (
    router as access_connector_lifecycle_router,
)
from src.api.routes.access_connectors import router as access_connectors_router
from src.api.routes.activation import router as activation_router
from src.api.routes.appetite import router as appetite_router
from src.api.routes.artefact_access_lifecycle import (
    router as artefact_access_lifecycle_router,
)
from src.api.routes.artefact_inventory import router as artefact_inventory_router
from src.api.routes.artefact_review import router as artefact_review_router
from src.api.routes.artefact_verification import router as artefact_verification_router
from src.api.routes.assets import router as assets_router
from src.api.routes.audit import router as audit_router
from src.api.routes.auth import app_auth_router
from src.api.routes.auth import router as auth_router
from src.api.routes.baseline_hypothesis import router as baseline_hypothesis_router
from src.api.routes.bundles import router as bundles_router
from src.api.routes.business_processes import router as business_processes_router
from src.api.routes.connector_access_test_agent import (
    router as connector_access_test_agent_router,
)
from src.api.routes.connector_access_tests import router as connector_access_tests_router
from src.api.routes.contextual_access_policies import router as contextual_access_router
from src.api.routes.discovery_command_agent import router as discovery_command_agent_router
from src.api.routes.discovery_execution_agent import router as discovery_execution_agent_router
from src.api.routes.discovery_run import router as discovery_run_router
from src.api.routes.evidence_scanner import router as evidence_scanner_router
from src.api.routes.evidence_source import router as evidence_source_router
from src.api.routes.graph import router as graph_router
from src.api.routes.leadership_authorization import router as leadership_authorization_router
from src.api.routes.learning import (
    internal_router as learning_internal_router,
)
from src.api.routes.learning import (
    router as learning_router,
)
from src.api.routes.onboarding_page_submission import router as onboarding_page_submission_router
from src.api.routes.org_access import router as org_access_router
from src.api.routes.org_template_config import router as org_template_config_router
from src.api.routes.organization_bia import router as organization_bia_router
from src.api.routes.organization_identity import router as organization_identity_router
from src.api.routes.organization_structure import router as organization_structure_router
from src.api.routes.permission_profiles import router as permission_profiles_router
from src.api.routes.process_activation import router as process_activation_router
from src.api.routes.process_dashboard import router as process_dashboard_router
from src.api.routes.process_ownership import router as process_ownership_router
from src.api.routes.process_scan_scopes import router as process_scan_scopes_router
from src.api.routes.process_template_variants import router as process_template_variants_router
from src.api.routes.process_workspace_readiness import router as process_workspace_readiness_router
from src.api.routes.processes import router as processes_router
from src.api.routes.public_onboarding import router as public_onboarding_router
from src.api.routes.public_onboarding_workspace import router as public_onboarding_workspace_router
from src.api.routes.recommendations import router as recommendations_router
from src.api.routes.recovery import router as recovery_router
from src.api.routes.recurrence_schedules import router as recurrence_schedules_router
from src.api.routes.resolutions import router as resolutions_router
from src.api.routes.risk_appetite_policies import router as risk_appetite_policies_router
from src.api.routes.risk_intel import router as risk_intel_router
from src.api.routes.risk_intelligence_ingestion import router as risk_intelligence_ingestion_router
from src.api.routes.scanner_agent import router as scanner_agent_router
from src.api.routes.scanner_management import router as scanner_management_router
from src.api.routes.scenarios import router as scenarios_router
from src.api.routes.service_appetite_reassessment_routes import (
    router as service_appetite_reassessment_router,
)
from src.api.routes.service_artefact_dependencies import (
    router as service_artefact_dependencies_router,
)
from src.api.routes.service_bia_exceptions import router as service_bia_exceptions_router
from src.api.routes.service_change_notices import router as service_change_notices_router
from src.api.routes.service_ownership import router as service_ownership_router
from src.api.routes.services import router as services_router
from src.api.routes.settings import router as settings_router
from src.api.routes.signals import router as signals_router
from src.api.routes.template_governance import (
    internal_router as template_governance_internal_router,
)
from src.api.routes.template_governance import (
    router as template_governance_router,
)
from src.api.routes.template_library import router as template_library_router
from src.api.routes.tenant_security import router as tenant_security_router
from src.api.routes.testing import router as testing_router
from src.api.routes.threats import router as threats_router
from src.api.routes.timing import router as timing_router
from src.api.routes.user_locale import router as user_locale_router
from src.api.routes.value_streams import public_router as value_streams_public_router
from src.api.routes.value_streams import router as value_streams_router
from src.api.routes.workspace import router as workspace_router
from src.asset_monitoring.engine import AssetMonitoringEngine
from src.core.config import Environment, settings
from src.core.database import get_postgres_engine, get_session_factory
from src.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    ResourceNotFoundError,
    ValidationError,
)
from src.core.logging_config import get_logger

logger = get_logger(__name__)
monitoring_engine: AssetMonitoringEngine | None = None

#: The only environments where fabricated evidence is acceptable. Named
#: positively rather than blocking "production": a new environment name added
#: later must default to *safe*, and a deny-list would silently permit it.
_SIMULATOR_PERMITTED_ENVIRONMENTS = frozenset({"development", "local", "test"})


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    # Startup
    logger.info(
        "risklence_tower_starting",
        environment=settings.environment,
        version="1.0.0",
    )

    # The monitoring *simulator* (BUG-DISC-18). Fabricates signals into the
    # evidence store, so it is gated twice: by configuration, and by environment
    # regardless of configuration. The second gate is the one that matters — the
    # first was already there and was still on in every deployment, because
    # nothing set the variable it reads.
    global monitoring_engine
    simulator_permitted = settings.environment.lower() in _SIMULATOR_PERMITTED_ENVIRONMENTS
    if settings.monitoring.enabled and not simulator_permitted:
        logger.warning(
            "monitoring_simulator_refused",
            environment=settings.environment,
            reason="The monitoring engine fabricates evidence signals and cannot run outside development.",
        )
    if settings.monitoring.enabled and simulator_permitted:
        try:
            monitoring_engine = AssetMonitoringEngine(
                get_session_factory,
                interval_seconds=settings.monitoring.poll_interval_seconds,
                seed=settings.monitoring.simulation_seed,
            )
            monitoring_engine.start()
            app.state.monitoring_engine = monitoring_engine
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.warning(
                "monitoring_engine_start_failed",
                error=str(exc),
            )
            monitoring_engine = None
    else:
        logger.info("monitoring_engine_disabled")

    # TODO: Initialize database connection pool
    # TODO: Initialize Redis connection
    # TODO: Verify cloud provider credentials

    yield

    # Shutdown
    logger.info("risklence_tower_shutting_down")
    if monitoring_engine:
        monitoring_engine.stop()
    # TODO: Close database connections
    # TODO: Close Redis connections


# Create FastAPI application
app = FastAPI(
    title="Risklence Tower API",
    description="Multi-tenant cloud compliance and security monitoring platform",
    version="1.0.0",
    docs_url="/api/docs" if settings.environment != Environment.PRODUCTION else None,
    redoc_url="/api/redoc" if settings.environment != Environment.PRODUCTION else None,
    openapi_url="/openapi.json" if settings.environment != Environment.PRODUCTION else None,
    dependencies=[Depends(require_authenticated)],
    lifespan=lifespan,
)

# Optional global rate limiting (opt-in via env)
if settings.rate_limit_enabled and settings.rate_limit_requests_per_minute > 0:
    app.add_middleware(
        GlobalRateLimitMiddleware,
        requests_per_minute=settings.rate_limit_requests_per_minute,
    )

# Tenant context middleware for multi-tenant isolation
# This extracts organization_id from JWT and ensures data isolation
app.add_middleware(TenantContextMiddleware)
app.add_middleware(PreTenantGuardMiddleware)

# CORS configuration for frontend (added after tenant middleware so it wraps errors/responses)
# In development allow explicit localhost origins (3000/3001) with credentials so both login ports work.
if settings.environment != Environment.PRODUCTION:
    dev_origins = {
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
    }
    # dev_origins is always non-empty, so configured_origins can never be
    # empty here — no wildcard fallback needed (A1 security remediation:
    # a Semgrep wildcard-cors finding flagged the dead `else ["*"]` branch
    # this used to have, combined with allow_credentials=True below; removed
    # rather than left as unreachable-but-fragile code a future refactor
    # could accidentally activate).
    configured_origins = set(settings.allowed_origins or [])
    configured_origins.update(dev_origins)
    cors_origins = sorted(configured_origins)
    logger.info(
        "cors_config",
        allow_origins=cors_origins,
        allow_credentials=True,
        environment=settings.environment,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        max_age=600,
    )
else:
    configured_origins = [
        origin
        for origin in (settings.allowed_origins or [])
        if origin
        and not origin.startswith("http://localhost")
        and not origin.startswith("http://127.0.0.1")
    ]
    cors_origins = sorted(set(configured_origins))
    allow_credentials = bool(cors_origins)
    if not cors_origins:
        logger.warning("cors_config_missing_origins_in_production", fallback="none", allow_credentials=False)
    logger.info(
        "cors_config",
        allow_origins=cors_origins,
        allow_credentials=allow_credentials,
        environment=settings.environment,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
        max_age=600,
    )


# Exception handlers
@app.exception_handler(AuthenticationError)
async def authentication_error_handler(request: Request, exc: AuthenticationError):
    """Handle authentication errors."""
    logger.warning(
        "authentication_error",
        path=request.url.path,
        error=str(exc),
    )
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": str(exc), "error_type": "authentication_error"},
    )


@app.exception_handler(AuthorizationError)
async def authorization_error_handler(request: Request, exc: AuthorizationError):
    """Handle authorization errors."""
    logger.warning(
        "authorization_error",
        path=request.url.path,
        error=str(exc),
    )
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": str(exc), "error_type": "authorization_error"},
    )


@app.exception_handler(ResourceNotFoundError)
async def not_found_error_handler(request: Request, exc: ResourceNotFoundError):
    """Handle resource not found errors."""
    logger.info(
        "resource_not_found",
        path=request.url.path,
        error=str(exc),
    )
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": str(exc), "error_type": "resource_not_found"},
    )


@app.exception_handler(ValidationError)
async def validation_error_handler(request: Request, exc: ValidationError):
    """Handle validation errors."""
    logger.info(
        "validation_error",
        path=request.url.path,
        error=str(exc),
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": str(exc), "error_type": "validation_error"},
    )


@app.exception_handler(ConfigurationError)
async def configuration_error_handler(request: Request, exc: ConfigurationError):
    """Handle configuration errors."""
    logger.error(
        "configuration_error",
        path=request.url.path,
        error=str(exc),
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Service configuration error", "error_type": "configuration_error"},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected errors."""
    logger.error(
        "unhandled_exception",
        path=request.url.path,
        error=str(exc),
        exc_info=True,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error", "error_type": "internal_error"},
    )


# ── Health checks ─────────────────────────────────────────────────────────────

@app.get("/healthz", tags=["Health"], include_in_schema=False)
@app.get("/health", tags=["Health"])
@app.get("/api/v1/health", tags=["Health"])
async def health_check() -> Dict[str, str]:
    """Liveness probe — confirms the process is running."""
    return {"status": "ok", "service": "risklence-tower", "version": "1.0.0"}


@app.get("/readyz", tags=["Health"])
async def readiness_check() -> Dict[str, Any]:
    """Readiness probe — checks DB and Redis are reachable before accepting traffic."""
    checks: Dict[str, str] = {}
    ready = True

    # Postgres
    try:
        engine = get_postgres_engine()
        with engine.connect() as conn:
            conn.execute(sqlalchemy.text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as exc:
        checks["postgres"] = f"error: {exc}"
        ready = False

    # Redis
    try:
        import redis as redis_lib
        r = redis_lib.from_url(settings.redis_url, socket_connect_timeout=2)
        r.ping()
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"error: {exc}"
        ready = False

    http_status = status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(
        status_code=http_status,
        content={"status": "ready" if ready else "not_ready", "checks": checks},
    )


@app.get("/", tags=["Root"])
async def root() -> Dict[str, str]:
    """Root endpoint."""
    return {
        "service": "Risklence Tower API",
        "version": "1.0.0",
        "docs": "/api/docs" if settings.environment != Environment.PRODUCTION else "disabled",
    }


# Mount API routers
# TODO: Add authentication routes
# app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])

# TODO: Add organization routes
# app.include_router(organizations_router, prefix="/api/v1/organizations", tags=["Organizations"])

# Auth routes
app.include_router(auth_router)
app.include_router(app_auth_router)
app.include_router(tenant_security_router)
app.include_router(activation_router)
app.include_router(workspace_router)
app.include_router(baseline_hypothesis_router)
app.include_router(risk_appetite_policies_router)
app.include_router(organization_bia_router)
app.include_router(leadership_authorization_router)
app.include_router(organization_identity_router)
app.include_router(organization_structure_router)
app.include_router(onboarding_page_submission_router)
app.include_router(evidence_source_router)
app.include_router(evidence_scanner_router)
app.include_router(discovery_run_router)
app.include_router(artefact_inventory_router)
app.include_router(contextual_access_router)
app.include_router(access_connectors_router)
app.include_router(access_connector_lifecycle_router)
app.include_router(connector_access_tests_router)
app.include_router(connector_access_test_agent_router)
app.include_router(artefact_access_lifecycle_router)
app.include_router(permission_profiles_router)
app.include_router(recurrence_schedules_router)
app.include_router(user_locale_router)
app.include_router(artefact_review_router)
app.include_router(service_artefact_dependencies_router)
app.include_router(artefact_verification_router)
app.include_router(audit_router)
app.include_router(discovery_command_agent_router)
app.include_router(discovery_execution_agent_router)
app.include_router(scanner_management_router)
app.include_router(scanner_agent_router)
app.include_router(org_access_router)
app.include_router(process_ownership_router)
app.include_router(process_scan_scopes_router)
app.include_router(service_ownership_router)
app.include_router(service_change_notices_router)
app.include_router(process_activation_router)
app.include_router(value_streams_router)
app.include_router(value_streams_public_router)
app.include_router(processes_router)
app.include_router(process_template_variants_router)
app.include_router(process_dashboard_router)
app.include_router(process_workspace_readiness_router)
app.include_router(graph_router)
app.include_router(template_library_router)
app.include_router(org_template_config_router)
app.include_router(template_governance_router)
app.include_router(template_governance_internal_router)
app.include_router(learning_router)
app.include_router(learning_internal_router)

# Onboarding routes
app.include_router(public_onboarding_router)
app.include_router(public_onboarding_workspace_router)
app.include_router(risk_intel_router)
app.include_router(risk_intelligence_ingestion_router)
app.include_router(timing_router)
# Asset monitoring/audit routes (both versioned and non-versioned paths)
app.include_router(assets_router, prefix="/api")
app.include_router(assets_router, prefix="/api/v1")

# Decision Layer routes
app.include_router(threats_router)
app.include_router(recommendations_router)
app.include_router(business_processes_router)
app.include_router(service_appetite_reassessment_router)
app.include_router(resolutions_router)
app.include_router(services_router)
app.include_router(service_bia_exceptions_router)
app.include_router(appetite_router)
app.include_router(recovery_router)
app.include_router(signals_router)
app.include_router(scenarios_router)
app.include_router(bundles_router)
app.include_router(testing_router)
app.include_router(settings_router)

# TODO: Add credentials routes
# app.include_router(credentials_router, prefix="/api/v1/credentials", tags=["Credentials"])

# TODO: Add compliance routes
# app.include_router(compliance_router, prefix="/api/v1/compliance", tags=["Compliance"])

# TODO: Add scanning routes
# app.include_router(scanning_router, prefix="/api/v1/scans", tags=["Scanning"])

# TODO: Add findings routes
# app.include_router(findings_router, prefix="/api/v1/findings", tags=["Findings"])

# TODO: Add remediation routes
# app.include_router(remediation_router, prefix="/api/v1/remediation", tags=["Remediation"])

# TODO: Add reporting routes
# app.include_router(reporting_router, prefix="/api/v1/reports", tags=["Reporting"])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.environment == Environment.DEVELOPMENT,
        log_level="info",
    )
