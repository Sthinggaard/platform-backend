"""Decision Layer — Testing & Assurance endpoint.

GET /api/v1/tests — returns seed test data representing common resilience tests.

No DB table is required at this stage — data is hardcoded and representative of
the test types an executive dashboard would surface. Every endpoint is
tenant-scoped via TenantContext.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.logging_config import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/tests", tags=["Decision Layer"])


# ─── SCHEMAS ──────────────────────────────────────────────────────────────────

class TestItemResponse(BaseModel):
    id: str
    name: str
    result: str  # "pass" | "pass-findings" | "fail" | "scheduled" | "overdue"
    service: str
    owner: str
    lastRun: Optional[str] = None
    nextDue: Optional[str] = None
    target: Optional[str] = None
    actual: Optional[str] = None
    findings: list[str]


# ─── SEED DATA ────────────────────────────────────────────────────────────────

_SEED_TESTS: list[dict] = [
    {
        "id": "test-001",
        "name": "Disaster Recovery Test",
        "result": "pass-findings",
        "service": "Payment Processing",
        "owner": "Infrastructure Team",
        "lastRun": "2026-02-14",
        "nextDue": "2026-05-14",
        "target": "RTO < 4 hrs, RPO < 1 hr",
        "actual": "RTO 5 hrs 22 min, RPO 47 min",
        "findings": [
            "Recovery time exceeded 4-hour target by 82 minutes",
            "Manual intervention required for database failover — automation incomplete",
            "Two non-critical services did not auto-register after failover",
        ],
    },
    {
        "id": "test-002",
        "name": "Backup Restoration Test",
        "result": "pass",
        "service": "Customer Data Platform",
        "owner": "Data Engineering",
        "lastRun": "2026-03-01",
        "nextDue": "2026-06-01",
        "target": "Full restore < 2 hrs with zero data loss",
        "actual": "Restore completed in 1 hr 38 min, zero data loss confirmed",
        "findings": [],
    },
    {
        "id": "test-003",
        "name": "Payment Failover Test",
        "result": "fail",
        "service": "Checkout & Payments",
        "owner": "Payments Team",
        "lastRun": "2026-01-20",
        "nextDue": "2026-04-20",
        "target": "Seamless failover to backup provider within 60 seconds",
        "actual": "Failover triggered but backup provider returned 503 — no successful path",
        "findings": [
            "Backup payment provider credentials had expired",
            "No automated credential rotation in place",
            "Customers unable to complete checkout for 14 minutes during test window",
        ],
    },
    {
        "id": "test-004",
        "name": "Incident Response Drill",
        "result": "pass-findings",
        "service": "All Critical Services",
        "owner": "Security Operations",
        "lastRun": "2026-02-28",
        "nextDue": "2026-05-28",
        "target": "P1 escalation within 15 min, exec notification within 30 min",
        "actual": "Escalation at 12 min, exec notification at 41 min",
        "findings": [
            "Executive notification exceeded 30-minute target",
            "On-call rotation gap identified for weekend coverage",
        ],
    },
    {
        "id": "test-005",
        "name": "Business Continuity Plan Walkthrough",
        "result": "overdue",
        "service": "Business Operations",
        "owner": "COO Office",
        "lastRun": "2025-09-10",
        "nextDue": "2026-03-10",
        "target": "Annual full-team walkthrough with sign-off",
        "actual": None,
        "findings": [
            "BCP walkthrough is 14 days overdue",
            "Key personnel changes since last walkthrough not yet reflected in plan",
        ],
    },
    {
        "id": "test-006",
        "name": "Network Segmentation Audit",
        "result": "scheduled",
        "service": "Core Infrastructure",
        "owner": "Security Architecture",
        "lastRun": None,
        "nextDue": "2026-04-10",
        "target": "Zero lateral movement paths between production and development zones",
        "actual": None,
        "findings": [],
    },
]


# ─── ROUTES ───────────────────────────────────────────────────────────────────

@router.get("", response_model=list[TestItemResponse])
def list_tests(
    ctx: TenantContext = Depends(get_tenant_context),
) -> list[TestItemResponse]:
    """Return resilience test items for the authenticated organisation."""
    logger.info("tests_listed", org_id=ctx.organization_id, count=len(_SEED_TESTS))
    return [TestItemResponse(**item) for item in _SEED_TESTS]
