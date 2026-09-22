"""CA-10 (#50) — ProcessScanScope: an approved recurring assurance scope per
active Business Process (Programme Epic G7).

Authorization mirrors scanner_management.py's _require_process_link_access
exactly (org MANAGER_ROLES, or the process's own accepted owner) — a scan
scope is a governance object about what a ProcessScannerLink the same
authority already granted may do, not a heavier, organisation-wide decision
like risk appetite.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.schemas.process_scan_scope import (
    ApproveProcessScanScopeRequest,
    CreateProcessScanScopeRequest,
    MarkProcessScanScopeOutdatedRequest,
    ProcessScanScopeResponse,
    SubmitProcessScanScopeRequest,
)
from src.core.constants.evidence_source_enums import EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED
from src.core.constants.process_scan_scope_enums import (
    PROCESS_SCAN_SCOPE_AUDIT_APPROVED,
    PROCESS_SCAN_SCOPE_AUDIT_DRAFT_CREATED,
    PROCESS_SCAN_SCOPE_AUDIT_MARKED_OUTDATED,
    PROCESS_SCAN_SCOPE_AUDIT_REVOKED,
    PROCESS_SCAN_SCOPE_AUDIT_SUBMITTED,
    PROCESS_SCAN_SCOPE_ERROR_NOT_FOUND,
)
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.process_scan_scope import ProcessScanScope
from src.core.models import AuditEvent, User
from src.core.repository import TenantRepository
from src.core.roles import MANAGER_ROLES
from src.core.services.process_ownership_service import (
    ProcessOwnershipValidationError,
    require_accepted_process_owner,
)
from src.core.services.process_scan_scope_service import (
    ProcessScanScopeNotFoundError,
    ProcessScanScopeValidationError,
    approve_process_scan_scope,
    create_process_scan_scope_draft,
    mark_process_scan_scope_outdated,
    require_process_scan_scope,
    resolve_effective_process_scan_scope,
    revoke_process_scan_scope,
    submit_process_scan_scope,
)
from src.core.services.process_scanner_link_service import ProcessScannerLinkNotFoundError

router = APIRouter(prefix="/api/v1/processes", tags=["Process scan scopes"])


def _require_process_scan_scope_access(db: Session, ctx: TenantContext, *, business_process_id: str) -> None:
    """Same authority as scanner_management.py's _require_process_link_access:
    org MANAGER_ROLES, or the process's own accepted owner."""
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active:
        raise AuthorizationError(EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED)
    if user.role in MANAGER_ROLES:
        return
    try:
        require_accepted_process_owner(
            db, organization_id=ctx.organization_id, process_id=business_process_id, user_id=ctx.user_id
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED) from exc


def _write_audit(db: Session, *, ctx: TenantContext, event_type: str, metadata: dict) -> None:
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id, actor_user_id=ctx.user_id, event_type=event_type, metadata_json=metadata
        )
    )


def _scope_response(scope: ProcessScanScope) -> ProcessScanScopeResponse:
    return ProcessScanScopeResponse(
        id=scope.id,
        organization_id=scope.organization_id,
        business_process_id=scope.business_process_id,
        revision=scope.revision,
        status=scope.status,
        bundle_version_ids=scope.bundle_version_ids or [],
        artefacts=scope.artefacts or [],
        connectors=scope.connectors or [],
        checks=scope.checks or [],
        profile_versions=scope.profile_versions or {},
        rationale=scope.rationale or {},
        derived_at=scope.derived_at,
        submitted_by_user_id=scope.submitted_by_user_id,
        submitted_at=scope.submitted_at,
        approved_by_user_id=scope.approved_by_user_id,
        approved_at=scope.approved_at,
        decision_note=scope.decision_note,
        outdated_at=scope.outdated_at,
        outdated_reason=scope.outdated_reason,
        revoked_by_user_id=scope.revoked_by_user_id,
        revoked_at=scope.revoked_at,
        superseded_by_scope_id=scope.superseded_by_scope_id,
        created_at=scope.created_at,
        updated_at=scope.updated_at,
    )


def _require_scope(db: Session, *, ctx: TenantContext, process_id: str, scope_id: str) -> ProcessScanScope:
    try:
        scope = require_process_scan_scope(db, organization_id=ctx.organization_id, scope_id=scope_id)
    except ProcessScanScopeNotFoundError as exc:
        raise ResourceNotFoundError(str(exc)) from exc
    if scope.business_process_id != process_id:
        raise ResourceNotFoundError(PROCESS_SCAN_SCOPE_ERROR_NOT_FOUND)
    return scope


@router.post("/{process_id}/scan-scopes", response_model=ProcessScanScopeResponse)
def create_process_scan_scope_route(
    process_id: str,
    body: CreateProcessScanScopeRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessScanScopeResponse:
    _require_process_scan_scope_access(db, ctx, business_process_id=process_id)
    try:
        scope = create_process_scan_scope_draft(
            db,
            organization_id=ctx.organization_id,
            business_process_id=process_id,
            bundle_version_ids=body.bundle_version_ids,
            artefacts=body.artefacts,
            connectors=body.connectors,
            checks=body.checks,
            profile_versions=body.profile_versions,
            rationale=body.rationale,
        )
    except ProcessScannerLinkNotFoundError as exc:
        raise ResourceNotFoundError(str(exc)) from exc
    except ProcessScanScopeValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=PROCESS_SCAN_SCOPE_AUDIT_DRAFT_CREATED,
        metadata={"process_scan_scope_id": scope.id, "business_process_id": scope.business_process_id},
    )
    db.commit()
    db.refresh(scope)
    return _scope_response(scope)


@router.post("/{process_id}/scan-scopes/{scope_id}/submit", response_model=ProcessScanScopeResponse)
def submit_process_scan_scope_route(
    process_id: str,
    scope_id: str,
    body: SubmitProcessScanScopeRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessScanScopeResponse:
    _require_process_scan_scope_access(db, ctx, business_process_id=process_id)
    scope = _require_scope(db, ctx=ctx, process_id=process_id, scope_id=scope_id)
    try:
        scope = submit_process_scan_scope(
            db, scope, submitted_by_user_id=ctx.user_id, decision_note=body.decision_note
        )
    except ProcessScanScopeValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=PROCESS_SCAN_SCOPE_AUDIT_SUBMITTED,
        metadata={"process_scan_scope_id": scope.id, "business_process_id": scope.business_process_id},
    )
    db.commit()
    db.refresh(scope)
    return _scope_response(scope)


@router.post("/{process_id}/scan-scopes/{scope_id}/approve", response_model=ProcessScanScopeResponse)
def approve_process_scan_scope_route(
    process_id: str,
    scope_id: str,
    body: ApproveProcessScanScopeRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessScanScopeResponse:
    _require_process_scan_scope_access(db, ctx, business_process_id=process_id)
    scope = _require_scope(db, ctx=ctx, process_id=process_id, scope_id=scope_id)
    try:
        scope = approve_process_scan_scope(
            db, scope, approved_by_user_id=ctx.user_id, decision_note=body.decision_note
        )
    except ProcessScanScopeValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=PROCESS_SCAN_SCOPE_AUDIT_APPROVED,
        metadata={"process_scan_scope_id": scope.id, "business_process_id": scope.business_process_id},
    )
    db.commit()
    db.refresh(scope)
    return _scope_response(scope)


@router.post("/{process_id}/scan-scopes/{scope_id}/mark-outdated", response_model=ProcessScanScopeResponse)
def mark_process_scan_scope_outdated_route(
    process_id: str,
    scope_id: str,
    body: MarkProcessScanScopeOutdatedRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessScanScopeResponse:
    _require_process_scan_scope_access(db, ctx, business_process_id=process_id)
    scope = _require_scope(db, ctx=ctx, process_id=process_id, scope_id=scope_id)
    try:
        scope = mark_process_scan_scope_outdated(db, scope, reason=body.reason)
    except ProcessScanScopeValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=PROCESS_SCAN_SCOPE_AUDIT_MARKED_OUTDATED,
        metadata={"process_scan_scope_id": scope.id, "business_process_id": scope.business_process_id, "reason": body.reason},
    )
    db.commit()
    db.refresh(scope)
    return _scope_response(scope)


@router.post("/{process_id}/scan-scopes/{scope_id}/revoke", response_model=ProcessScanScopeResponse)
def revoke_process_scan_scope_route(
    process_id: str,
    scope_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessScanScopeResponse:
    _require_process_scan_scope_access(db, ctx, business_process_id=process_id)
    scope = _require_scope(db, ctx=ctx, process_id=process_id, scope_id=scope_id)
    try:
        scope = revoke_process_scan_scope(db, scope, revoked_by_user_id=ctx.user_id)
    except ProcessScanScopeValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=PROCESS_SCAN_SCOPE_AUDIT_REVOKED,
        metadata={"process_scan_scope_id": scope.id, "business_process_id": scope.business_process_id},
    )
    db.commit()
    db.refresh(scope)
    return _scope_response(scope)


@router.get("/{process_id}/scan-scopes/effective", response_model=ProcessScanScopeResponse)
def get_effective_process_scan_scope_route(
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessScanScopeResponse:
    _require_process_scan_scope_access(db, ctx, business_process_id=process_id)
    scope = resolve_effective_process_scan_scope(
        db, organization_id=ctx.organization_id, business_process_id=process_id
    )
    if scope is None:
        raise ResourceNotFoundError("No approved, currently-effective scan scope for this process.")
    return _scope_response(scope)
