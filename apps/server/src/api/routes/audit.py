"""Epic A3 — audit, provenance and decision-traceability read surface.

Additive only: this router introduces genuinely new, general, cursor-paginated
read endpoints alongside DISC-41's own existing, narrower Discovery timeline
endpoint (``discovery_run.py``'s ``/evidence-sources/{source_id}/discovery-
runs/{run_id}/timeline``), which stays byte-for-byte unchanged. See
``docs/architecture/audit-provenance-and-traceability.md`` for the full
design and the explicit list of what this vertical slice does not cover.

Every route follows the same tenant-safety shape used across this codebase
(``discovery_run.py``'s ``_require_run``): resolve the underlying object
scoped to the caller's own organisation first, raising ``ResourceNotFoundError``
(never a distinguishable 403) if it does not exist or belongs to another
tenant — cross-tenant and nonexistent must look identical to the caller.
Read access itself is gated by ``is_active_org_member`` (any currently
active, non-expired org member), the same bar DISC-41 already uses for its
own diagnostics ("read-only, every active member, not just admins").

Deliberately mounted at ``/api/v1/audit-trail``, not ``/api/v1/audit`` —
``assets.py`` already owns ``/api/v1/audit/{overview,controls,export,
share-link,shared}`` for a completely different concept (compliance
control-coverage audit, not audit-event provenance). No literal route
collides, but sharing one prefix between two unrelated "audit" surfaces
would be confusing API design; a distinct prefix keeps them clearly separate.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.schemas.audit_timeline import AuditTimelinePage
from src.api.schemas.decision_trace import DecisionTraceListResponse, DecisionTraceResponse
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError
from src.core.model_defs.discovery_execution import DiscoveryExecutionPlan, EvidencePackage, ExecutionStage, ProviderExecution
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.value_streams import Threat
from src.core.models import User
from src.core.repository import TenantRepository
from src.core.services.audit_access import is_active_org_member
from src.core.services.audit_cursor import InvalidCursorError, decode_cursor
from src.core.services.audit_timeline_service import (
    DEFAULT_PAGE_SIZE as TIMELINE_DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE as TIMELINE_MAX_PAGE_SIZE,
    resolve_discovery_run_timeline_page,
    resolve_evidence_package_timeline_page,
    resolve_execution_plan_timeline_page,
    resolve_provider_execution_timeline_page,
)
from src.core.services.decision_trace_service import (
    DEFAULT_PAGE_SIZE as TRACE_DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE as TRACE_MAX_PAGE_SIZE,
    resolve_decision_trace,
    resolve_decision_trace_list_for_threat,
)

router = APIRouter(prefix="/api/v1/audit-trail", tags=["Audit Trail"])

_TIMELINE_ERROR = "Object not found for this organisation."
_TRACE_ERROR = "Decision record not found for this organisation."
_THREAT_ERROR = "Threat not found for this organisation."


def _require_read_access(db: Session, ctx: TenantContext) -> None:
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if not is_active_org_member(user):
        raise AuthorizationError("You do not have access to this organisation's audit history.")


def _decode_cursor_param(cursor: Optional[str]):
    if cursor is None:
        return None
    try:
        return decode_cursor(cursor)
    except InvalidCursorError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid pagination cursor.")


@router.get("/discovery-runs/{run_id}/timeline", response_model=AuditTimelinePage)
def get_discovery_run_audit_timeline(
    run_id: str,
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=TIMELINE_DEFAULT_PAGE_SIZE, ge=1, le=TIMELINE_MAX_PAGE_SIZE),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AuditTimelinePage:
    _require_read_access(db, ctx)
    run = TenantRepository(db, DiscoveryRun, ctx.organization_id).get_by_id(run_id)
    if run is None:
        raise ResourceNotFoundError(_TIMELINE_ERROR)
    decoded_cursor = _decode_cursor_param(cursor)
    return resolve_discovery_run_timeline_page(db, ctx.organization_id, run.id, cursor=decoded_cursor, limit=limit)


@router.get("/execution-plans/{plan_id}/timeline", response_model=AuditTimelinePage)
def get_execution_plan_audit_timeline(
    plan_id: str,
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=TIMELINE_DEFAULT_PAGE_SIZE, ge=1, le=TIMELINE_MAX_PAGE_SIZE),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AuditTimelinePage:
    _require_read_access(db, ctx)
    plan = TenantRepository(db, DiscoveryExecutionPlan, ctx.organization_id).get_by_id(plan_id)
    if plan is None:
        raise ResourceNotFoundError(_TIMELINE_ERROR)
    stage_ids = {
        stage.id for stage in db.query(ExecutionStage).filter(ExecutionStage.execution_plan_id == plan.id).all()
    }
    decoded_cursor = _decode_cursor_param(cursor)
    return resolve_execution_plan_timeline_page(
        db, ctx.organization_id, plan.id, stage_ids, cursor=decoded_cursor, limit=limit
    )


@router.get("/provider-executions/{provider_execution_id}/timeline", response_model=AuditTimelinePage)
def get_provider_execution_audit_timeline(
    provider_execution_id: str,
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=TIMELINE_DEFAULT_PAGE_SIZE, ge=1, le=TIMELINE_MAX_PAGE_SIZE),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AuditTimelinePage:
    _require_read_access(db, ctx)
    # ProviderExecution carries no organization_id of its own — tenant scope
    # is established through its owning plan, same join `_require_job_for_run`
    # already uses in discovery_run.py.
    job = (
        db.query(ProviderExecution)
        .join(ExecutionStage, ProviderExecution.execution_stage_id == ExecutionStage.id)
        .join(DiscoveryExecutionPlan, ExecutionStage.execution_plan_id == DiscoveryExecutionPlan.id)
        .filter(ProviderExecution.id == provider_execution_id, DiscoveryExecutionPlan.organization_id == ctx.organization_id)
        .first()
    )
    if job is None:
        raise ResourceNotFoundError(_TIMELINE_ERROR)
    decoded_cursor = _decode_cursor_param(cursor)
    return resolve_provider_execution_timeline_page(db, ctx.organization_id, job.id, cursor=decoded_cursor, limit=limit)


@router.get("/evidence-packages/{package_id}/timeline", response_model=AuditTimelinePage)
def get_evidence_package_audit_timeline(
    package_id: str,
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=TIMELINE_DEFAULT_PAGE_SIZE, ge=1, le=TIMELINE_MAX_PAGE_SIZE),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AuditTimelinePage:
    _require_read_access(db, ctx)
    package = TenantRepository(db, EvidencePackage, ctx.organization_id).get_by_id(package_id)
    if package is None:
        raise ResourceNotFoundError(_TIMELINE_ERROR)
    decoded_cursor = _decode_cursor_param(cursor)
    return resolve_evidence_package_timeline_page(
        db, ctx.organization_id, package.id, package.provider_execution_id, cursor=decoded_cursor, limit=limit
    )


@router.get("/decisions/{decision_record_id}/trace", response_model=DecisionTraceResponse)
def get_decision_trace(
    decision_record_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DecisionTraceResponse:
    _require_read_access(db, ctx)
    trace = resolve_decision_trace(db, ctx.organization_id, decision_record_id)
    if trace is None:
        raise ResourceNotFoundError(_TRACE_ERROR)
    return trace


@router.get("/threats/{threat_id}/decisions", response_model=DecisionTraceListResponse)
def get_decision_trace_list_for_threat(
    threat_id: str,
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=TRACE_DEFAULT_PAGE_SIZE, ge=1, le=TRACE_MAX_PAGE_SIZE),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DecisionTraceListResponse:
    _require_read_access(db, ctx)
    threat = TenantRepository(db, Threat, ctx.organization_id).get_by_id(threat_id)
    if threat is None:
        raise ResourceNotFoundError(_THREAT_ERROR)
    decoded_cursor = _decode_cursor_param(cursor)
    return resolve_decision_trace_list_for_threat(
        db, ctx.organization_id, threat.id, cursor=decoded_cursor, limit=limit
    )
