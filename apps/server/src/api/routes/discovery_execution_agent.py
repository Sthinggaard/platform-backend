"""Step 4.2 Part 2 — scanner-facing result reporting for a delegated
ProviderExecution job.

Kept separate from ``discovery_command_agent.py`` (Step 4.1's whole-run
command delivery/acknowledgement/status surface, whose own docstring
explicitly disclaimed accepting a technical payload) for the same SRP
reason that module was itself kept separate from ``scanner_agent.py``.
Authenticated by the exact same per-instance Bearer credential via the
shared ``require_scanner_instance``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from sqlalchemy.orm import Session

from src.api.routes.scanner_agent import require_scanner_instance
from src.core.constants.discovery_execution_enums import (
    EVIDENCE_PACKAGE_AUDIT_RECEIVED,
    PROVIDER_EXECUTION_AUDIT_COMPLETED,
    PROVIDER_EXECUTION_AUDIT_FAILED,
    ProviderExecutionStatus,
)
from src.core.database import get_db
from src.core.exceptions import ValidationError
from src.core.model_defs.discovery_run import ScannerCommand
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.services.discovery_command_service import DiscoveryCommandError
from src.core.services.discovery_execution_command_service import record_provider_execution_result

router = APIRouter(prefix="/api/v1/scanner-agent", tags=["Discovery execution agent"])


def _write_audit(db: Session, *, organization_id: int, event_type: str, metadata: dict) -> None:
    # Same system-actor convention as discovery_command_agent.py — this
    # module authenticates by per-instance Bearer credential, never a
    # browser session, so there is no human actor to attribute the event to.
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=None,
            event_type=event_type,
            metadata_json=metadata,
        )
    )


def _with_process_context(metadata: dict, command: ScannerCommand | None) -> dict:
    """CA-04.8 — camelCase, matching this file's own existing metadata
    keys. command is Optional purely defensively — record_provider_
    execution_result already raised above if it genuinely didn't exist,
    so this is never actually None in practice at either call site below."""
    return {
        **metadata,
        "businessProcessId": command.business_process_id if command is not None else None,
        "businessServiceId": command.business_service_id if command is not None else None,
        "slotInstanceId": None,
    }


class ProviderExecutionResultRequest(BaseModel):
    status: str
    evidence_format: str | None = None
    raw_evidence_payload: str | None = None
    schema_version: str = "v1"
    checkpoint: dict | None = None
    failure_code: str | None = None
    failure_message: str | None = None


class ProviderExecutionResultResponse(BaseModel):
    provider_execution_id: str
    status: str


@router.post("/commands/{command_id}/result", response_model=ProviderExecutionResultResponse)
def provider_execution_result_route(
    command_id: str, body: ProviderExecutionResultRequest, request: Request, db: Session = Depends(get_db)
) -> ProviderExecutionResultResponse:
    instance = require_scanner_instance(request, db)
    try:
        provider_execution = record_provider_execution_result(
            db,
            instance,
            command_id,
            status=body.status,
            evidence_format=body.evidence_format,
            raw_evidence_payload=body.raw_evidence_payload,
            schema_version=body.schema_version,
            checkpoint=body.checkpoint,
            failure_code=body.failure_code,
            failure_message=body.failure_message,
        )
    except DiscoveryCommandError as exc:
        db.commit()
        raise ValidationError(str(exc)) from exc

    # CA-04.8 — a cheap, single extra lookup by an id already in hand
    # (command_id, the route's own path param), purely so both audit
    # events below can carry this command's own business_process_id/
    # business_service_id (CA-04.7). Explicit organization_id filter
    # (not just id), matching this codebase's own tenant-isolation
    # structural check (scripts/check_tenant_isolation.py) even though
    # record_provider_execution_result above already enforced the real
    # instance-scoped guarantee.
    command = (
        db.query(ScannerCommand)
        .filter(ScannerCommand.id == command_id, ScannerCommand.organization_id == instance.organization_id)
        .first()
    )

    if body.raw_evidence_payload is not None:
        _write_audit(
            db,
            organization_id=instance.organization_id,
            event_type=EVIDENCE_PACKAGE_AUDIT_RECEIVED,
            metadata=_with_process_context(
                {"providerExecutionId": provider_execution.id, "commandId": command_id}, command
            ),
        )
    audit_event = (
        PROVIDER_EXECUTION_AUDIT_FAILED
        if body.status == ProviderExecutionStatus.FAILED.value
        else PROVIDER_EXECUTION_AUDIT_COMPLETED
    )
    _write_audit(
        db,
        organization_id=instance.organization_id,
        event_type=audit_event,
        metadata=_with_process_context(
            {"providerExecutionId": provider_execution.id, "status": provider_execution.status}, command
        ),
    )
    db.commit()
    db.refresh(provider_execution)
    return ProviderExecutionResultResponse(provider_execution_id=provider_execution.id, status=provider_execution.status)
