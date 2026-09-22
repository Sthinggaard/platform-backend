"""Evidence Source routes — at least one functioning evidence source
(post-ORG-STRUCT stage).

Sits between Organisation Structure and Leadership Authorisation in the
onboarding readiness sequence. Mutations require the platform
``org_admin``/``admin`` role, following the same ``_require_org_admin``
pattern as ``organization_structure.py``/``leadership_authorization.py``.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, UploadFile
from pydantic import BaseModel

from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.evidence_source_enums import (
    EVIDENCE_SOURCE_AUDIT_ARCHIVED,
    EVIDENCE_SOURCE_AUDIT_COMPLETED,
    EVIDENCE_SOURCE_AUDIT_CREATED,
    EVIDENCE_SOURCE_AUDIT_DISABLED,
    EVIDENCE_SOURCE_AUDIT_EXCEPTION_APPROVED,
    EVIDENCE_SOURCE_AUDIT_EXCEPTION_RESOLVED,
    EVIDENCE_SOURCE_AUDIT_FRESHNESS_POLICY_SET,
    EVIDENCE_SOURCE_AUDIT_IMPORT_MAPPING_CONFIRMED,
    EVIDENCE_SOURCE_AUDIT_IMPORT_UPLOADED,
    EVIDENCE_SOURCE_AUDIT_MANUAL_ENTRY_ADDED,
    EVIDENCE_SOURCE_AUDIT_OWNER_ASSIGNED,
    EVIDENCE_SOURCE_AUDIT_SCOPE_CONFIRMED,
    EVIDENCE_SOURCE_AUDIT_SCOPE_SAVED,
    EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED,
    EVIDENCE_SOURCE_ERROR_BATCH_NOT_FOUND,
    EVIDENCE_SOURCE_ERROR_EXCEPTION_NOT_FOUND,
    EVIDENCE_SOURCE_ERROR_NOT_FOUND,
    EVIDENCE_SOURCE_ERROR_SCOPE_NOT_FOUND,
    EvidenceSourceExceptionReasonCode,
    EvidenceSourceScopeType,
    EvidenceSourceType,
)
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.common import utcnow
from src.core.model_defs.evidence_source import (
    EvidenceImportBatch,
    EvidenceManualEntry,
    EvidenceSource,
    EvidenceSourceException,
    EvidenceSourceScope,
)
from src.core.models import AuditEvent, User
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES
from src.core.services.evidence_source_readiness_service import (
    build_prepared_evidence_sources,
    evaluate_evidence_source_readiness,
    evaluate_source_health_signals,
)
from src.core.services.evidence_source_service import (
    EvidenceSourceValidationError,
    add_manual_evidence_entry,
    archive_source,
    assign_owner,
    confirm_import_mapping,
    confirm_scope,
    create_evidence_source,
    create_exception,
    disable_source,
    list_evidence_sources,
    list_exceptions,
    list_import_batches,
    list_manual_entries,
    resolve_exception,
    save_scope,
    upload_import_file,
)
from src.api.schemas.timestamps import UtcTimestamp

router = APIRouter(prefix="/api/v1/evidence-sources", tags=["Evidence sources"])


class EvidenceSourceRequest(BaseModel):
    name: str
    source_type: EvidenceSourceType
    owner_user_id: int | None = None


class EvidenceSourceResponse(BaseModel):
    id: str
    name: str
    type: str
    mode: str
    status: str
    owner_user_id: int | None
    first_evidence_received_at: UtcTimestamp | None
    last_successful_sync_at: UtcTimestamp | None
    last_attempted_sync_at: UtcTimestamp | None


class OwnerRequest(BaseModel):
    owner_user_id: int


class ScopeRequest(BaseModel):
    scope_type: EvidenceSourceScopeType
    organisation_unit_ids: list[str] = []
    legal_entity_ids: list[str] = []
    country_codes: list[str] = []


class ScopeResponse(BaseModel):
    id: str
    scope_type: str
    organisation_unit_ids: list[str]
    legal_entity_ids: list[str]
    country_codes: list[str]
    status: str


class ImportBatchResponse(BaseModel):
    id: str
    filename: str
    file_type: str
    status: str
    detected_columns: list[str]
    column_mapping: dict[str, str | None]
    preview_rows: list[dict]
    total_rows: int | None
    accepted_rows: int | None
    rejected_rows: int | None
    warning_rows: int | None


class ConfirmMappingRequest(BaseModel):
    column_mapping: dict[str, str | None]


class ManualEntryRequest(BaseModel):
    description: str


class ManualEntryResponse(BaseModel):
    id: str
    description: str
    entered_by_user_id: int | None
    entered_at: UtcTimestamp


class ExceptionRequest(BaseModel):
    reason_code: EvidenceSourceExceptionReasonCode
    description: str
    review_at: UtcTimestamp


class ExceptionResponse(BaseModel):
    id: str
    reason_code: str
    description: str
    review_at: UtcTimestamp
    status: str


class ReadinessResponse(BaseModel):
    ready: bool
    readiness: str
    # Whether the evidence-source *setup step* is done — weaker than `ready`,
    # which also requires evidence to have arrived (UX-ONB-01).
    setup_complete: bool = False
    functioning_source_ids: list[str]
    degraded_source_ids: list[str]
    blocked_source_ids: list[str]
    missing_reasons: list[str]


class PreparedSourceResponse(BaseModel):
    id: str
    name: str
    type: str
    mode: str
    status: str
    healthy: bool
    owner_user_id: int | None
    scope_id: str | None
    health_status: str
    first_evidence_received_at: UtcTimestamp | None
    last_successful_sync_at: UtcTimestamp | None


class PreparedActiveExceptionResponse(BaseModel):
    id: str
    evidence_source_id: str
    reason_code: str
    review_at: UtcTimestamp


class PreparedResponse(BaseModel):
    organization_id: int
    sources: list[PreparedSourceResponse]
    functioning_source_ids: list[str]
    degraded_source_ids: list[str]
    blocked_source_ids: list[str]
    active_exceptions: list[PreparedActiveExceptionResponse]
    readiness: str


class HealthSignalsResponse(BaseModel):
    connectivity_healthy: bool | None
    authorisation_healthy: bool | None
    permissions_sufficient: bool | None
    evidence_received: bool
    evidence_fresh: bool
    schema_compatible: bool
    last_checked_at: UtcTimestamp
    last_healthy_at: UtcTimestamp | None
    status: str
    reasons: list[str]


class FreshnessPolicyRequest(BaseModel):
    warning_after_hours: int | None = None
    stale_after_hours: int | None = None


PREVIEW_ROW_LIMIT = 20


def _require_org_admin(db: Session, ctx: TenantContext) -> None:
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or user.role not in ADMIN_ROLES:
        raise AuthorizationError(EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED)


def _write_audit(db: Session, *, ctx: TenantContext, event_type: str, metadata: dict) -> None:
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=event_type,
            metadata_json=metadata,
        )
    )


def _require_source(db: Session, *, ctx: TenantContext, source_id: str) -> EvidenceSource:
    source = TenantRepository(db, EvidenceSource, ctx.organization_id).get_by_id(source_id)
    if source is None:
        raise ResourceNotFoundError(EVIDENCE_SOURCE_ERROR_NOT_FOUND)
    return source


def _require_batch(db: Session, *, ctx: TenantContext, batch_id: str) -> EvidenceImportBatch:
    batch = TenantRepository(db, EvidenceImportBatch, ctx.organization_id).get_by_id(batch_id)
    if batch is None:
        raise ResourceNotFoundError(EVIDENCE_SOURCE_ERROR_BATCH_NOT_FOUND)
    return batch


def _require_exception(db: Session, *, ctx: TenantContext, exception_id: str) -> EvidenceSourceException:
    exception = TenantRepository(db, EvidenceSourceException, ctx.organization_id).get_by_id(exception_id)
    if exception is None:
        raise ResourceNotFoundError(EVIDENCE_SOURCE_ERROR_EXCEPTION_NOT_FOUND)
    return exception


def _source_response(source: EvidenceSource) -> EvidenceSourceResponse:
    return EvidenceSourceResponse(
        id=source.id,
        name=source.name,
        type=source.type,
        mode=source.mode,
        status=source.status,
        owner_user_id=source.owner_user_id,
        first_evidence_received_at=source.first_evidence_received_at,
        last_successful_sync_at=source.last_successful_sync_at,
        last_attempted_sync_at=source.last_attempted_sync_at,
    )


def _scope_response(scope: EvidenceSourceScope) -> ScopeResponse:
    return ScopeResponse(
        id=scope.id,
        scope_type=scope.scope_type,
        organisation_unit_ids=scope.organisation_unit_ids or [],
        legal_entity_ids=scope.legal_entity_ids or [],
        country_codes=scope.country_codes or [],
        status=scope.status,
    )


def _batch_response(batch: EvidenceImportBatch) -> ImportBatchResponse:
    return ImportBatchResponse(
        id=batch.id,
        filename=batch.filename,
        file_type=batch.file_type,
        status=batch.status,
        detected_columns=batch.detected_columns or [],
        column_mapping=batch.column_mapping or {},
        preview_rows=(batch.parsed_rows_json or [])[:PREVIEW_ROW_LIMIT],
        total_rows=batch.total_rows,
        accepted_rows=batch.accepted_rows,
        rejected_rows=batch.rejected_rows,
        warning_rows=batch.warning_rows,
    )


def _manual_entry_response(entry: EvidenceManualEntry) -> ManualEntryResponse:
    return ManualEntryResponse(
        id=entry.id,
        description=entry.description,
        entered_by_user_id=entry.entered_by_user_id,
        entered_at=entry.entered_at,
    )


def _exception_response(exception: EvidenceSourceException) -> ExceptionResponse:
    return ExceptionResponse(
        id=exception.id,
        reason_code=exception.reason_code,
        description=exception.description,
        review_at=exception.review_at,
        status=exception.status,
    )


@router.get("", response_model=list[EvidenceSourceResponse])
def list_sources_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[EvidenceSourceResponse]:
    sources = list_evidence_sources(db, ctx.organization_id)
    return [_source_response(s) for s in sources]


@router.post("", response_model=EvidenceSourceResponse)
def create_source_route(
    body: EvidenceSourceRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> EvidenceSourceResponse:
    _require_org_admin(db, ctx)
    try:
        source = create_evidence_source(
            db,
            organization_id=ctx.organization_id,
            name=body.name,
            source_type=body.source_type,
            owner_user_id=body.owner_user_id,
        )
    except EvidenceSourceValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=EVIDENCE_SOURCE_AUDIT_CREATED, metadata={"evidence_source_id": source.id})
    db.commit()
    db.refresh(source)
    return _source_response(source)


# Static-path routes below (readiness/prepared/complete) must be declared
# before "/{source_id}" — FastAPI matches path operations in registration
# order, and a single dynamic segment would otherwise swallow these first.


@router.get("/readiness", response_model=ReadinessResponse)
def get_readiness_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ReadinessResponse:
    result = evaluate_evidence_source_readiness(db, ctx.organization_id)
    return ReadinessResponse(
        ready=result.ready,
        readiness=result.readiness.value,
        setup_complete=result.setup_complete,
        functioning_source_ids=result.functioning_source_ids,
        degraded_source_ids=result.degraded_source_ids,
        blocked_source_ids=result.blocked_source_ids,
        missing_reasons=result.missing_reasons,
    )


@router.get("/prepared", response_model=PreparedResponse)
def get_prepared_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> PreparedResponse:
    prepared = build_prepared_evidence_sources(db, ctx.organization_id)
    return PreparedResponse(
        organization_id=prepared.organization_id,
        sources=[
            PreparedSourceResponse(
                id=s.id,
                name=s.name,
                type=s.type,
                mode=s.mode,
                status=s.status,
                healthy=s.healthy,
                owner_user_id=s.owner_user_id,
                scope_id=s.scope_id,
                health_status=s.health_status.value,
                first_evidence_received_at=s.first_evidence_received_at,
                last_successful_sync_at=s.last_successful_sync_at,
            )
            for s in prepared.sources
        ],
        functioning_source_ids=prepared.functioning_source_ids,
        degraded_source_ids=prepared.degraded_source_ids,
        blocked_source_ids=prepared.blocked_source_ids,
        active_exceptions=[
            PreparedActiveExceptionResponse(
                id=e.id, evidence_source_id=e.evidence_source_id, reason_code=e.reason_code, review_at=e.review_at
            )
            for e in prepared.active_exceptions
        ],
        readiness=prepared.readiness.value,
    )


@router.get("/{source_id}/health", response_model=HealthSignalsResponse)
def get_source_health_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> HealthSignalsResponse:
    source = _require_source(db, ctx=ctx, source_id=source_id)
    signals = evaluate_source_health_signals(db, source, now=utcnow().replace(tzinfo=None))
    return HealthSignalsResponse(
        connectivity_healthy=signals.connectivity_healthy,
        authorisation_healthy=signals.authorisation_healthy,
        permissions_sufficient=signals.permissions_sufficient,
        evidence_received=signals.evidence_received,
        evidence_fresh=signals.evidence_fresh,
        schema_compatible=signals.schema_compatible,
        last_checked_at=signals.last_checked_at,
        last_healthy_at=signals.last_healthy_at,
        status=signals.status.value,
        reasons=signals.reasons,
    )


@router.put("/{source_id}/freshness-policy", response_model=EvidenceSourceResponse)
def set_freshness_policy_route(
    source_id: str,
    body: FreshnessPolicyRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> EvidenceSourceResponse:
    _require_org_admin(db, ctx)
    source = _require_source(db, ctx=ctx, source_id=source_id)
    source.warning_after_hours = body.warning_after_hours
    source.stale_after_hours = body.stale_after_hours
    db.add(source)
    _write_audit(
        db,
        ctx=ctx,
        event_type=EVIDENCE_SOURCE_AUDIT_FRESHNESS_POLICY_SET,
        metadata={
            "evidence_source_id": source.id,
            "warning_after_hours": body.warning_after_hours,
            "stale_after_hours": body.stale_after_hours,
        },
    )
    db.commit()
    db.refresh(source)
    return _source_response(source)


@router.post("/complete", response_model=ReadinessResponse)
def complete_evidence_source_setup_route(
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ReadinessResponse:
    _require_org_admin(db, ctx)
    result = evaluate_evidence_source_readiness(db, ctx.organization_id)
    if not result.ready:
        raise ValidationError(
            "No evidence source is functioning yet: " + ", ".join(result.missing_reasons)
        )
    _write_audit(
        db, ctx=ctx, event_type=EVIDENCE_SOURCE_AUDIT_COMPLETED, metadata={"organization_id": ctx.organization_id}
    )
    db.commit()
    return ReadinessResponse(
        ready=result.ready,
        readiness=result.readiness.value,
        functioning_source_ids=result.functioning_source_ids,
        degraded_source_ids=result.degraded_source_ids,
        blocked_source_ids=result.blocked_source_ids,
        missing_reasons=[],
    )


@router.get("/{source_id}", response_model=EvidenceSourceResponse)
def get_source_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> EvidenceSourceResponse:
    source = _require_source(db, ctx=ctx, source_id=source_id)
    return _source_response(source)


@router.patch("/{source_id}/owner", response_model=EvidenceSourceResponse)
def assign_owner_route(
    source_id: str,
    body: OwnerRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> EvidenceSourceResponse:
    _require_org_admin(db, ctx)
    source = _require_source(db, ctx=ctx, source_id=source_id)
    try:
        assign_owner(db, source, owner_user_id=body.owner_user_id)
    except EvidenceSourceValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=EVIDENCE_SOURCE_AUDIT_OWNER_ASSIGNED,
        metadata={"evidence_source_id": source.id, "owner_user_id": body.owner_user_id},
    )
    db.commit()
    db.refresh(source)
    return _source_response(source)


@router.get("/{source_id}/scope", response_model=ScopeResponse)
def get_scope_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ScopeResponse:
    source = _require_source(db, ctx=ctx, source_id=source_id)
    scope = db.query(EvidenceSourceScope).filter(EvidenceSourceScope.evidence_source_id == source.id).first()
    if scope is None:
        raise ResourceNotFoundError(EVIDENCE_SOURCE_ERROR_SCOPE_NOT_FOUND)
    return _scope_response(scope)


@router.put("/{source_id}/scope", response_model=ScopeResponse)
def save_scope_route(
    source_id: str,
    body: ScopeRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ScopeResponse:
    _require_org_admin(db, ctx)
    source = _require_source(db, ctx=ctx, source_id=source_id)
    scope = save_scope(
        db,
        source,
        scope_type=body.scope_type,
        organisation_unit_ids=body.organisation_unit_ids,
        legal_entity_ids=body.legal_entity_ids,
        country_codes=body.country_codes,
    )
    _write_audit(db, ctx=ctx, event_type=EVIDENCE_SOURCE_AUDIT_SCOPE_SAVED, metadata={"evidence_source_id": source.id})
    db.commit()
    db.refresh(scope)
    return _scope_response(scope)


@router.post("/{source_id}/scope/confirm", response_model=ScopeResponse)
def confirm_scope_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ScopeResponse:
    _require_org_admin(db, ctx)
    source = _require_source(db, ctx=ctx, source_id=source_id)
    scope = db.query(EvidenceSourceScope).filter(EvidenceSourceScope.evidence_source_id == source.id).first()
    if scope is None:
        raise ValidationError("A scope must be saved before it can be confirmed.")
    confirm_scope(db, scope, confirmed_by_user_id=ctx.user_id)
    _write_audit(
        db, ctx=ctx, event_type=EVIDENCE_SOURCE_AUDIT_SCOPE_CONFIRMED, metadata={"evidence_source_id": source.id}
    )
    db.commit()
    db.refresh(scope)
    return _scope_response(scope)


@router.post("/{source_id}/imports", response_model=ImportBatchResponse)
async def upload_import_route(
    source_id: str,
    file: UploadFile,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ImportBatchResponse:
    _require_org_admin(db, ctx)
    source = _require_source(db, ctx=ctx, source_id=source_id)
    content_bytes = await file.read()
    try:
        batch = upload_import_file(
            db,
            source,
            filename=file.filename or "upload",
            content_bytes=content_bytes,
            uploaded_by_user_id=ctx.user_id,
        )
    except EvidenceSourceValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=EVIDENCE_SOURCE_AUDIT_IMPORT_UPLOADED,
        metadata={"evidence_source_id": source.id, "batch_id": batch.id, "filename": batch.filename},
    )
    db.commit()
    db.refresh(batch)
    return _batch_response(batch)


@router.post("/{source_id}/imports/{batch_id}/confirm", response_model=ImportBatchResponse)
def confirm_import_route(
    source_id: str,
    batch_id: str,
    body: ConfirmMappingRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ImportBatchResponse:
    _require_org_admin(db, ctx)
    _require_source(db, ctx=ctx, source_id=source_id)
    batch = _require_batch(db, ctx=ctx, batch_id=batch_id)
    try:
        confirm_import_mapping(
            db, batch, column_mapping=body.column_mapping, confirmed_by_user_id=ctx.user_id
        )
    except EvidenceSourceValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=EVIDENCE_SOURCE_AUDIT_IMPORT_MAPPING_CONFIRMED,
        metadata={"evidence_source_id": source_id, "batch_id": batch.id, "status": batch.status},
    )
    db.commit()
    db.refresh(batch)
    return _batch_response(batch)


@router.get("/{source_id}/imports", response_model=list[ImportBatchResponse])
def list_imports_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[ImportBatchResponse]:
    _require_source(db, ctx=ctx, source_id=source_id)
    batches = list_import_batches(db, source_id)
    return [_batch_response(b) for b in batches]


@router.get("/{source_id}/imports/{batch_id}", response_model=ImportBatchResponse)
def get_import_route(
    source_id: str,
    batch_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ImportBatchResponse:
    _require_source(db, ctx=ctx, source_id=source_id)
    batch = _require_batch(db, ctx=ctx, batch_id=batch_id)
    return _batch_response(batch)


@router.post("/{source_id}/manual-entries", response_model=ManualEntryResponse)
def create_manual_entry_route(
    source_id: str,
    body: ManualEntryRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ManualEntryResponse:
    _require_org_admin(db, ctx)
    source = _require_source(db, ctx=ctx, source_id=source_id)
    try:
        entry = add_manual_evidence_entry(
            db, source, description=body.description, entered_by_user_id=ctx.user_id
        )
    except EvidenceSourceValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=EVIDENCE_SOURCE_AUDIT_MANUAL_ENTRY_ADDED,
        metadata={"evidence_source_id": source.id, "entry_id": entry.id},
    )
    db.commit()
    db.refresh(entry)
    return _manual_entry_response(entry)


@router.get("/{source_id}/manual-entries", response_model=list[ManualEntryResponse])
def list_manual_entries_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[ManualEntryResponse]:
    _require_source(db, ctx=ctx, source_id=source_id)
    entries = list_manual_entries(db, source_id)
    return [_manual_entry_response(e) for e in entries]


@router.post("/{source_id}/exceptions", response_model=ExceptionResponse)
def create_exception_route(
    source_id: str,
    body: ExceptionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ExceptionResponse:
    _require_org_admin(db, ctx)
    source = _require_source(db, ctx=ctx, source_id=source_id)
    try:
        exception = create_exception(
            db,
            source,
            reason_code=body.reason_code,
            description=body.description,
            approved_by_user_id=ctx.user_id,
            review_at=body.review_at,
        )
    except EvidenceSourceValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=EVIDENCE_SOURCE_AUDIT_EXCEPTION_APPROVED,
        metadata={"evidence_source_id": source.id, "exception_id": exception.id, "reason_code": body.reason_code.value},
    )
    db.commit()
    db.refresh(exception)
    return _exception_response(exception)


@router.get("/{source_id}/exceptions", response_model=list[ExceptionResponse])
def list_exceptions_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[ExceptionResponse]:
    _require_source(db, ctx=ctx, source_id=source_id)
    exceptions = list_exceptions(db, source_id)
    return [_exception_response(e) for e in exceptions]


@router.post("/exceptions/{exception_id}/resolve", response_model=ExceptionResponse)
def resolve_exception_route(
    exception_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ExceptionResponse:
    _require_org_admin(db, ctx)
    exception = _require_exception(db, ctx=ctx, exception_id=exception_id)
    resolve_exception(db, exception)
    _write_audit(
        db,
        ctx=ctx,
        event_type=EVIDENCE_SOURCE_AUDIT_EXCEPTION_RESOLVED,
        metadata={"exception_id": exception.id},
    )
    db.commit()
    db.refresh(exception)
    return _exception_response(exception)


@router.post("/{source_id}/disable", response_model=EvidenceSourceResponse)
def disable_source_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> EvidenceSourceResponse:
    _require_org_admin(db, ctx)
    source = _require_source(db, ctx=ctx, source_id=source_id)
    disable_source(db, source)
    _write_audit(db, ctx=ctx, event_type=EVIDENCE_SOURCE_AUDIT_DISABLED, metadata={"evidence_source_id": source.id})
    db.commit()
    db.refresh(source)
    return _source_response(source)


@router.post("/{source_id}/archive", response_model=EvidenceSourceResponse)
def archive_source_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> EvidenceSourceResponse:
    _require_org_admin(db, ctx)
    source = _require_source(db, ctx=ctx, source_id=source_id)
    archive_source(db, source)
    _write_audit(db, ctx=ctx, event_type=EVIDENCE_SOURCE_AUDIT_ARCHIVED, metadata={"evidence_source_id": source.id})
    db.commit()
    db.refresh(source)
    return _source_response(source)
