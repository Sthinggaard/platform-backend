"""#463 — a Business Service's BIA in one Business Process: what it inherits, and its exceptions.

Søren, 2026-09-15 (option B): the owner sees the process's answers and records only where the service
genuinely differs, in that one process, with a structured reason. An exception belongs to the service
in that process, so recording or withdrawing one needs edit access to **that** process. Every change is
kept (an exception is withdrawn, never overwritten) and audited.

GET    /api/v1/services/{service_id}/processes/{process_id}/bia
PUT    /api/v1/services/{service_id}/processes/{process_id}/bia-exceptions/{field}
DELETE /api/v1/services/{service_id}/processes/{process_id}/bia-exceptions/{field}
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.schemas.timestamps import UtcTimestamp
from src.core.constants.bia_exception_reasons import (
    BIA_EXCEPTION_REASON_PROMPT,
    BIA_EXCEPTION_REASONS,
    BIA_EXCEPTION_REASONS_REQUIRING_NOTE,
)
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError
from src.core.models import BusinessService, ServiceBiaException, ValueStream
from src.core.services.bia_inheritance_service import (
    BIA_FIELD_KEYS,
    bia_is_complete,
    effective_service_bia,
    service_bia_provenance,
)
from src.core.services.effective_process_bia_service import (
    resolve_effective_process_bia_by_process,
)
from src.core.services.process_ownership_service import (
    ProcessOwnershipValidationError,
    require_process_editor,
)
from src.core.services.service_bia_exception_service import (
    BiaExceptionError,
    BiaExceptionNotFoundError,
    active_bia_exceptions,
    exceptions_for,
    record_bia_exception,
    withdraw_bia_exception,
)

router = APIRouter(prefix="/api/v1/services", tags=["Service BIA exceptions"])

_REASON_LABEL: dict[str, str] = dict(BIA_EXCEPTION_REASONS)


class BiaExceptionReasonOut(BaseModel):
    code: str
    label: str
    noteRequired: bool


class ServiceBiaExceptionOut(BaseModel):
    field: str
    value: str
    previousValue: str | None
    reasonCode: str | None
    reasonLabel: str | None
    reasonNote: str | None
    #: Carried over from before reasons were required: no reason and no actor, and it says so.
    recordedBeforeReasons: bool
    recordedByUserId: int | None
    #: #284 (TZ-6) — the column is naive, so the offset is attached on the way out.
    recordedAt: UtcTimestamp


class OtherProcessImpactOut(BaseModel):
    """#463 AC 10–11 — another Business Process that relies on this service, and what an outage costs
    the business there. Søren, 2026-09-15: stated in the BIA levels the platform holds now; in € once
    #479 adds a cost-per-hour question. The tenant composes the sentence."""

    processId: str
    processName: str
    impact1h: str | None
    impact4h: str | None
    impact24h: str | None
    mtd: str | None
    #: The service's answers in that process include exceptions of its own there.
    hasExceptions: bool


class ServiceProcessBiaResponse(BaseModel):
    serviceId: str
    processId: str
    #: The process's BIA in force: attested assessment, organisation baseline, or legacy projection.
    processAnswers: dict[str, Any] | None
    #: What applies to the service in this process: the process's answers with its exceptions over them.
    answers: dict[str, Any] | None
    #: Per question: `inherited`, `exception` or `recorded_before_reasons`.
    provenance: dict[str, str]
    complete: bool
    exceptions: list[ServiceBiaExceptionOut]
    reasonPrompt: str
    reasons: list[BiaExceptionReasonOut]
    #: The other processes this service is part of — ownership may sit outside this one.
    otherProcesses: list[OtherProcessImpactOut]


class RecordBiaExceptionRequest(BaseModel):
    value: str = Field(..., min_length=1, max_length=200)
    reasonCode: str = Field(..., min_length=1, max_length=40)
    reasonNote: str | None = Field(default=None, max_length=2000)


def _load(
    ctx: TenantContext, db: Session, service_id: str, process_id: str
) -> tuple[BusinessService, ValueStream]:
    service = (
        db.query(BusinessService)
        .filter(
            BusinessService.organization_id == ctx.organization_id,
            BusinessService.id == service_id,
        )
        .one_or_none()
    )
    if service is None:
        raise ResourceNotFoundError("Business Service not found in this organisation")
    process = (
        db.query(ValueStream)
        .filter(ValueStream.organization_id == ctx.organization_id, ValueStream.id == process_id)
        .one_or_none()
    )
    if process is None:
        raise ResourceNotFoundError("Business Process not found in this organisation")
    if process.id not in (service.value_stream_ids or []):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="This service is not part of that Business Process.",
        )
    return service, process


def _require_editor_of(ctx: TenantContext, db: Session, process: ValueStream) -> None:
    try:
        require_process_editor(
            db,
            organization_id=ctx.organization_id,
            process_id=process.id,
            actor_user_id=ctx.user_id,
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(
            "Business Process Owner or organisation administrator access is required."
        ) from exc


def _process_answers(ctx: TenantContext, db: Session, process: ValueStream) -> dict | None:
    return resolve_effective_process_bia_by_process(
        db, organization_id=ctx.organization_id, processes=[process]
    )[process.id].answers


def _bia_only(answers: dict | None) -> dict[str, Any] | None:
    if answers is None:
        return None
    return {field: answers[field] for field in sorted(BIA_FIELD_KEYS) if field in answers}


def _exception_out(exception: ServiceBiaException) -> ServiceBiaExceptionOut:
    return ServiceBiaExceptionOut(
        field=exception.field,
        value=exception.value,
        previousValue=exception.previous_value,
        reasonCode=exception.reason_code,
        reasonLabel=_REASON_LABEL.get(exception.reason_code) if exception.reason_code else None,
        reasonNote=exception.reason_note,
        recordedBeforeReasons=bool(exception.recorded_before_reasons),
        recordedByUserId=exception.recorded_by_user_id,
        recordedAt=exception.recorded_at,
    )


def _response(
    ctx: TenantContext, db: Session, service: BusinessService, process: ValueStream
) -> ServiceProcessBiaResponse:
    # This process and every other process the service is part of, resolved together: one BIA
    # resolution and one exceptions read for the whole response.
    other_ids = [pid for pid in (service.value_stream_ids or []) if pid != process.id]
    others_by_id = (
        {
            other.id: other
            for other in db.query(ValueStream)
            .filter(
                ValueStream.organization_id == ctx.organization_id, ValueStream.id.in_(other_ids)
            )
            .all()
        }
        if other_ids
        else {}
    )
    others = [others_by_id[pid] for pid in other_ids if pid in others_by_id]
    effective_by_process = resolve_effective_process_bia_by_process(
        db, organization_id=ctx.organization_id, processes=[process, *others]
    )
    all_exceptions = active_bia_exceptions(
        db,
        organization_id=ctx.organization_id,
        service_ids=[service.id],
        process_ids=[process.id, *(other.id for other in others)],
    )

    process_answers = effective_by_process[process.id].answers
    exceptions = exceptions_for(all_exceptions, service.id, process.id)
    answers = effective_service_bia(process_answers, exceptions)

    other_processes: list[OtherProcessImpactOut] = []
    for other in others:
        other_exceptions = exceptions_for(all_exceptions, service.id, other.id)
        in_force = (
            effective_service_bia(effective_by_process[other.id].answers, other_exceptions) or {}
        )
        other_processes.append(
            OtherProcessImpactOut(
                processId=other.id,
                processName=other.name,
                impact1h=in_force.get("impact1h"),
                impact4h=in_force.get("impact4h"),
                impact24h=in_force.get("impact24h"),
                mtd=in_force.get("mtd"),
                hasExceptions=bool(other_exceptions),
            )
        )

    return ServiceProcessBiaResponse(
        otherProcesses=other_processes,
        serviceId=service.id,
        processId=process.id,
        processAnswers=_bia_only(process_answers),
        answers=_bia_only(answers),
        provenance=service_bia_provenance(exceptions),
        complete=bia_is_complete(answers),
        exceptions=[_exception_out(exception) for exception in exceptions],
        reasonPrompt=BIA_EXCEPTION_REASON_PROMPT,
        reasons=[
            BiaExceptionReasonOut(
                code=code, label=label, noteRequired=code in BIA_EXCEPTION_REASONS_REQUIRING_NOTE
            )
            for code, label in BIA_EXCEPTION_REASONS
        ],
    )


@router.get("/{service_id}/processes/{process_id}/bia", response_model=ServiceProcessBiaResponse)
def get_service_process_bia(
    service_id: str,
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ServiceProcessBiaResponse:
    """What this service inherits from the process, and where it differs."""
    service, process = _load(ctx, db, service_id, process_id)
    return _response(ctx, db, service, process)


@router.put(
    "/{service_id}/processes/{process_id}/bia-exceptions/{field}",
    response_model=ServiceProcessBiaResponse,
)
def record_service_bia_exception(
    service_id: str,
    process_id: str,
    field: str,
    body: RecordBiaExceptionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ServiceProcessBiaResponse:
    """Record that the service answers one question differently in this process, and why."""
    service, process = _load(ctx, db, service_id, process_id)
    _require_editor_of(ctx, db, process)
    try:
        record_bia_exception(
            db,
            service=service,
            process_id=process.id,
            field=field,
            value=body.value,
            reason_code=body.reasonCode,
            reason_note=body.reasonNote,
            process_answers=_process_answers(ctx, db, process),
            actor_user_id=ctx.user_id,
        )
    except BiaExceptionError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    db.commit()
    return _response(ctx, db, service, process)


@router.delete(
    "/{service_id}/processes/{process_id}/bia-exceptions/{field}",
    response_model=ServiceProcessBiaResponse,
)
def withdraw_service_bia_exception(
    service_id: str,
    process_id: str,
    field: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ServiceProcessBiaResponse:
    """Withdraw the service's exception for one question; it inherits the process's answer again."""
    service, process = _load(ctx, db, service_id, process_id)
    _require_editor_of(ctx, db, process)
    try:
        withdraw_bia_exception(
            db,
            service=service,
            process_id=process.id,
            field=field,
            process_answers=_process_answers(ctx, db, process),
            actor_user_id=ctx.user_id,
        )
    except BiaExceptionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except BiaExceptionError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    db.commit()
    return _response(ctx, db, service, process)
