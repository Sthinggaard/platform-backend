"""Decision Layer — Resilience Signals endpoint.

GET /api/v1/signals — derives drift signals from live threat data for the org.

Signals are derived from threats with status "detected" or "in-progress",
ordered by severity (critical first). Every endpoint is tenant-scoped via
TenantContext — organization_id is taken from the JWT and never from the caller.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.database import get_db
from src.core.logging_config import get_logger
from src.core.models import Threat

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/signals", tags=["Decision Layer"])

# Severity ordering for deterministic sort
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ─── SCHEMAS ──────────────────────────────────────────────────────────────────

class SignalResponse(BaseModel):
    id: str
    severity: str
    businessTitle: str
    businessContext: str
    financialExposure: Optional[str] = None
    affectedServices: list[str]
    trend: str


# ─── ROUTES ───────────────────────────────────────────────────────────────────

@router.get("", response_model=list[SignalResponse])
def list_signals(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[SignalResponse]:
    """Return resilience signals derived from active threats for the org."""
    threats = (
        db.query(Threat)
        .filter(
            Threat.organization_id == ctx.organization_id,
            Threat.status.in_(["detected", "in-progress"]),
        )
        .all()
    )

    # Sort by severity (critical first)
    threats.sort(key=lambda t: _SEVERITY_ORDER.get(t.severity, 99))

    signals: list[SignalResponse] = []
    for t in threats:
        exposure: Optional[str] = None
        if t.daily_cost and t.daily_cost > 0:
            hourly = t.daily_cost // 24
            exposure = f"€{hourly:,}/hr exposure"

        signals.append(
            SignalResponse(
                id=t.id,
                severity=t.severity,
                businessTitle=t.signal,
                businessContext=t.what_it_means,
                financialExposure=exposure,
                affectedServices=[],
                trend="worsening",
            )
        )

    logger.info(
        "signals_listed",
        org_id=ctx.organization_id,
        count=len(signals),
    )
    return signals
