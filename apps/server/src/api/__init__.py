"""
FastAPI application for Risklence Tower multi-tenant SaaS.
"""

# Avoid importing FastAPI app (and heavy deps) when modules are imported for tests
try:  # pragma: no cover - defensive import guard for lightweight usage
    from src.api.main import app  # type: ignore
except Exception:
    app = None

__all__ = ["app"]
