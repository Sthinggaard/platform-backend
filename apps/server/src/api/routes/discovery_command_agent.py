"""Step 4.1 — scanner-facing command delivery/acknowledgement/status routes.

Kept separate from ``scanner_agent.py`` (SRP — that module is Step 3.5's
setup/heartbeat surface; this one is Step 4.1's command lifecycle) but
authenticated by the exact same per-instance Bearer credential via the
shared ``require_scanner_instance``. Status/stage updates only — no
technical observation payload is accepted here (spec §21).
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from sqlalchemy.orm import Session

from src.api.routes.scanner_agent import require_scanner_instance
from src.core.constants.discovery_run_enums import (
    DISCOVERY_RUN_AUDIT_CANCELLED,
    DISCOVERY_RUN_AUDIT_COMMAND_ACKNOWLEDGED,
    DISCOVERY_RUN_AUDIT_COMMAND_REJECTED,
    DISCOVERY_RUN_AUDIT_COMPLETED,
    DISCOVERY_RUN_AUDIT_FAILED,
    DISCOVERY_RUN_AUDIT_STAGE_CHANGED,
    DiscoveryRunStatus,
)
from src.core.database import get_db
from src.core.exceptions import ValidationError
from src.core.model_defs.discovery_run import DiscoveryRun, ScannerCommand
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.model_defs.verification_run import VerificationRun
from src.core.model_defs.verification_inspection_command import VerificationInspectionCommand
from src.core.services.verification_inspection_queue_service import (
    InspectionCommandError,
    envelope_for,
    next_inspection_for_scanner,
    record_inspection_result,
    reject_inspection,
)
from src.core.services.discovery_run_service import DiscoveryRunValidationError
from src.core.services.provider_execution_lifecycle_service import (
    ProviderExecutionTransitionError,
)
from src.core.services.discovery_command_service import (
    DiscoveryCommandError,
    acknowledge_command,
    get_command_target_snapshot,
    get_next_command_for_scanner,
    record_status_update,
)
from src.api.schemas.timestamps import UtcTimestamp

router = APIRouter(prefix="/api/v1/scanner-agent", tags=["Discovery command agent"])

# Step 4.1D — this module authenticates by per-instance Bearer credential,
# never a browser TenantContext (see require_scanner_instance's own
# docstring), so audit events here are always system-actor
# (actor_user_id=None) — matching the established convention elsewhere in
# this codebase (auth.py's pre-session LOGIN_FAILED, activation.py's
# pre-session token-redeem events) rather than fabricating a human actor
# for a machine-initiated report. Reuses discovery_run_enums.py's own
# DISCOVERY_RUN_AUDIT_* constants — designed at Step 4.1 (DISC-01) for
# exactly these events, never actually written until now.
_TERMINAL_STATUS_AUDIT_EVENTS: dict[str, str] = {
    DiscoveryRunStatus.COMPLETED.value: DISCOVERY_RUN_AUDIT_COMPLETED,
    DiscoveryRunStatus.PARTIALLY_COMPLETED.value: DISCOVERY_RUN_AUDIT_COMPLETED,
    DiscoveryRunStatus.FAILED.value: DISCOVERY_RUN_AUDIT_FAILED,
    DiscoveryRunStatus.CANCELLED.value: DISCOVERY_RUN_AUDIT_CANCELLED,
}


def _write_audit(db: Session, *, organization_id: int, event_type: str, metadata: dict) -> None:
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=None,
            event_type=event_type,
            metadata_json=metadata,
        )
    )


def _with_process_context(metadata: dict, obj: ScannerCommand | DiscoveryRun) -> dict:
    """CA-04.8 — camelCase to match this file's own existing metadata keys
    (discoveryRunId, scannerInstanceId, ...). Works for either a
    ScannerCommand or a DiscoveryRun since both carry business_process_id/
    business_service_id (CA-04.7). slotInstanceId stays null until
    CA-09A's dependency-slot mapping genuinely exists and is approved."""
    return {
        **metadata,
        "businessProcessId": obj.business_process_id,
        "businessServiceId": obj.business_service_id,
        "slotInstanceId": None,
    }


class CommandEnvelopeResponse(BaseModel):
    command_id: str
    command_type: str
    organisation_id: int
    scanner_instance_id: str
    discovery_run_id: str
    # CA-04.1 — part of the signable payload (discovery_command_service.
    # _signable_payload) and always None for a whole-run Step 4.1 command;
    # included so the Collector can reconstruct that exact payload for
    # real client-side verification rather than guessing this field.
    provider_execution_id: str | None
    # CA-04.2 — the registered check this command represents (nmap today);
    # None for a whole-run Step 4.1 command, which spans whatever the
    # run's profile capabilities allow rather than one single check.
    check_key: str | None
    # CA-04.7 — which Business Process/Service (if any) this command was
    # created for, snapshotted from the run at command-creation time; both
    # None for an org-wide, not-process-scoped run.
    business_process_id: str | None
    business_service_id: str | None
    issued_at: UtcTimestamp
    not_before: UtcTimestamp | None
    expires_at: UtcTimestamp
    profile: dict
    # CA-04.2 — re-validated against live approval state at delivery time,
    # not the run's frozen target_snapshot directly: a target excluded
    # since run creation never appears here even though it is still
    # present in that snapshot.
    targets: list[dict]
    execution_policy: dict
    signature_version: str
    signature: str


class InspectionEnvelopeResponse(BaseModel):
    """CA-08.2 — a signed instruction to read one thing on one host.

    Every field is one the Collector needs to verify the signature or run the
    command. There is deliberately **no** field for a credential, a username or
    a key: CA-07.2's rule is that the platform *cannot* receive secret material,
    and an envelope with somewhere to put it is an invitation to start.
    """

    command_id: str
    signature_version: str
    signature: str
    scanner_instance_id: str
    run_id: str
    organization_id: int
    asset_id: int
    connector_id: str
    capability: str
    argv: list[str]
    # UtcTimestamp, not str: #281's rule is that every timestamp leaves the API
    # with an explicit offset, and here it is load-bearing rather than cosmetic
    # — the Collector verifies a signature computed over these exact strings.
    issued_at: UtcTimestamp
    expires_at: UtcTimestamp


class NextCommandResponse(BaseModel):
    has_command: bool
    command: CommandEnvelopeResponse | None = None
    # CA-08.2 — the same poll, a second kind of work. A Collector asks one
    # endpoint what to do next; which table the answer came from is ours to
    # know. Optional and defaulted so an older agent, which reads only
    # ``command``, is unaffected by its presence.
    inspection: InspectionEnvelopeResponse | None = None


class AcknowledgeCommandRequest(BaseModel):
    accepted: bool
    rejection_code: str | None = None
    rejection_message: str | None = None
    scanner_runtime_version: str | None = None


class AcknowledgeCommandResponse(BaseModel):
    command_id: str
    discovery_run_id: str
    status: str
    accepted: bool


class StatusUpdateRequest(BaseModel):
    status: str | None = None
    stage: str | None = None


class CancellationAcknowledgementRequest(BaseModel):
    status: str


class DiscoveryRunAgentResponse(BaseModel):
    discovery_run_id: str
    status: str
    current_stage: str


def _envelope_response(db: Session, command: ScannerCommand, run: DiscoveryRun) -> CommandEnvelopeResponse:
    return CommandEnvelopeResponse(
        command_id=command.id,
        command_type=command.command_type,
        organisation_id=command.organization_id,
        scanner_instance_id=command.scanner_instance_id,
        discovery_run_id=command.discovery_run_id,
        provider_execution_id=command.provider_execution_id,
        check_key=command.check_key,
        business_process_id=command.business_process_id,
        business_service_id=command.business_service_id,
        issued_at=command.issued_at,
        not_before=command.not_before,
        expires_at=command.expires_at,
        profile=run.profile_snapshot,
        targets=get_command_target_snapshot(db, command, run),
        execution_policy=command.execution_policy,
        signature_version=command.signature_version,
        signature=command.signature,
    )


@router.get("/commands/next", response_model=NextCommandResponse)
def next_command_route(request: Request, db: Session = Depends(get_db)) -> NextCommandResponse:
    instance = require_scanner_instance(request, db)
    try:
        command = get_next_command_for_scanner(db, instance)
    except (DiscoveryCommandError, DiscoveryRunValidationError) as exc:
        # The poll loop is a Collector's only way to receive work. A 500 here
        # does not fail one request — it stops that Collector permanently,
        # because it cannot get past whatever produced the error (BUG-DISC-04).
        # Anything the platform cannot make sense of is reported as a refusal
        # the agent can log and retry past, never an unhandled server error.
        db.commit()
        raise ValidationError(str(exc)) from exc
    if command is None:
        # Nothing to discover. Deep verification queues its work elsewhere
        # (verification_inspection_commands) because an inspection has no
        # discovery run to hang off — but it is the same poll, so a Collector
        # never learns there are two tables.
        inspection = _next_inspection_envelope(db, instance)
        db.commit()
        if inspection is None:
            return NextCommandResponse(has_command=False)
        return NextCommandResponse(has_command=True, inspection=inspection)
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == command.discovery_run_id).first()
    db.commit()
    db.refresh(command)
    return NextCommandResponse(has_command=True, command=_envelope_response(db, command, run))


def _next_inspection_envelope(db: Session, instance) -> InspectionEnvelopeResponse | None:
    """Discovery first, then inspections.

    Ordered rather than interleaved: a discovery run is the thing a person is
    usually waiting on, and an inspection is short. Starving discovery behind a
    queue of inspections would make the visible thing feel broken.
    """
    inspection_command = next_inspection_for_scanner(db, scanner_instance_id=instance.id)
    if inspection_command is None:
        return None
    run = (
        db.query(VerificationRun)
        .filter(
            VerificationRun.id == inspection_command.verification_run_id,
            # Scoped to the organisation as well as the id. The id came from a
            # row already scoped to this Collector, so this is defence in depth
            # — but the tenant-isolation check is right that a query without it
            # is a query that can be made to cross a tenant later.
            VerificationRun.organization_id == inspection_command.organization_id,
        )
        .first()
    )
    if run is None:
        return None
    return InspectionEnvelopeResponse(**envelope_for(inspection_command, run=run))


class ReportInspectionRequest(BaseModel):
    """What the Collector observed, and nothing it concluded.

    Søren, 2026-08-24: the Collector collects, the engine reads. There is no
    ``outcome`` field here on purpose — the platform decides what an exit status
    means (``verification_outcome_service``), and accepting a Collector's own
    verdict would put that decision back on the far side of the wire.

    ``stdout`` arrives (CA-08.4) because it is what an inspection is *for* — but
    it is never stored. It is read for what it establishes about the artefact
    and dropped; there is still no column for it. And it is only accepted at all
    from capabilities that cannot return a credential, which is enforced in
    ``verification_identity_recording_service``, not here.
    """

    exit_code: int | None = None
    stderr: str = ""
    stdout: str = ""
    # #296 — that a credential was present in what was read, never what it was.
    # The Collector redacted the value before this request was made; these carry
    # only a service, a setting name and which rule matched.
    credential_findings: list[dict] = []
    timed_out: bool = False
    #: Set when the Collector would not run it at all — a bad signature, a
    #: wrong instance, an expired command. Distinct from a command that ran and
    #: failed: only one of those is a fact about the customer's estate.
    rejection_reason: str | None = None


class ReportInspectionResponse(BaseModel):
    status: str
    outcome: str | None = None
    # CA-08.4 — what the run established, echoed back so the Collector's own
    # log says something a person can read. "succeeded" answers *did it run*;
    # this answers *did it learn anything*, which is the question the epic is
    # actually about.
    identity_name: str | None = None
    identity_basis: str | None = None


@router.post("/inspections/{command_id}/report", response_model=ReportInspectionResponse)
def report_inspection_route(
    command_id: str,
    body: ReportInspectionRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> ReportInspectionResponse:
    instance = require_scanner_instance(request, db)
    command = (
        db.query(VerificationInspectionCommand)
        .filter(
            VerificationInspectionCommand.id == command_id,
            # Scoped to the Collector that was given it, not merely to the id.
            # An id is guessable; being the instance it was issued to is not.
            VerificationInspectionCommand.scanner_instance_id == instance.id,
            VerificationInspectionCommand.organization_id == instance.organization_id,
        )
        .first()
    )
    if command is None:
        raise ValidationError("No such inspection for this Collector")

    try:
        if body.rejection_reason is not None:
            reject_inspection(db, command=command, reason=body.rejection_reason)
        else:
            record_inspection_result(
                db,
                command=command,
                exit_code=body.exit_code,
                stderr=body.stderr,
                stdout=body.stdout,
                credential_findings=body.credential_findings,
                timed_out=body.timed_out,
            )
    except InspectionCommandError as exc:
        # Same reasoning as the poll route: a Collector that cannot get past an
        # error stops permanently. A refusal it can log and move on from.
        db.commit()
        raise ValidationError(str(exc)) from exc

    db.commit()
    db.refresh(command)
    return ReportInspectionResponse(
        status=command.status,
        outcome=command.outcome,
        identity_name=command.identity_name,
        identity_basis=command.identity_basis,
    )


@router.post("/commands/{command_id}/acknowledge", response_model=AcknowledgeCommandResponse)
def acknowledge_command_route(
    command_id: str, body: AcknowledgeCommandRequest, request: Request, db: Session = Depends(get_db)
) -> AcknowledgeCommandResponse:
    instance = require_scanner_instance(request, db)
    try:
        command = acknowledge_command(
            db,
            instance,
            command_id,
            accepted=body.accepted,
            rejection_code=body.rejection_code,
            rejection_message=body.rejection_message,
            scanner_runtime_version=body.scanner_runtime_version,
        )
    except (
        DiscoveryCommandError,
        DiscoveryRunValidationError,
        # 🐞 ProviderExecutionTransitionError was not caught, so acknowledging a
        # job that had already moved on — reclaimed after a lease expiry, then
        # retried — raised out of an agent-facing route and returned 500. The
        # Collector logged "could not be completed, will retry next cycle" and
        # re-sent the same acknowledgement forever.
        #
        # Acknowledging work somebody else has already taken is not a server
        # fault; it is a race the protocol allows, and the honest answer is a
        # refusal the Collector can log and move past. Same reasoning the poll
        # route records: a 500 does not fail one request, it stops that
        # Collector.
        ProviderExecutionTransitionError,
    ) as exc:
        # Even a rejected acknowledgement (e.g. an expired command) may have
        # made a real state change (command/run flipped to EXPIRED) that
        # must survive the error response, not be silently rolled back.
        db.commit()
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        organization_id=instance.organization_id,
        event_type=DISCOVERY_RUN_AUDIT_COMMAND_ACKNOWLEDGED if body.accepted else DISCOVERY_RUN_AUDIT_COMMAND_REJECTED,
        metadata=_with_process_context(
            {
                "commandId": command.id,
                "discoveryRunId": command.discovery_run_id,
                "scannerInstanceId": instance.id,
                "rejectionCode": body.rejection_code,
            },
            command,
        ),
    )
    db.commit()
    db.refresh(command)
    return AcknowledgeCommandResponse(
        command_id=command.id, discovery_run_id=command.discovery_run_id, status=command.status, accepted=bool(command.accepted)
    )


@router.post("/discovery-runs/{run_id}/status", response_model=DiscoveryRunAgentResponse)
def discovery_run_status_route(
    run_id: str, body: StatusUpdateRequest, request: Request, db: Session = Depends(get_db)
) -> DiscoveryRunAgentResponse:
    instance = require_scanner_instance(request, db)
    try:
        run = record_status_update(db, instance, run_id, status=body.status, stage=body.stage)
    except (DiscoveryCommandError, DiscoveryRunValidationError) as exc:
        # A stage update can succeed before a subsequent status transition
        # fails — commit whatever real change happened rather than losing it.
        db.commit()
        raise ValidationError(str(exc)) from exc
    if body.stage is not None:
        _write_audit(
            db,
            organization_id=instance.organization_id,
            event_type=DISCOVERY_RUN_AUDIT_STAGE_CHANGED,
            metadata=_with_process_context({"discoveryRunId": run.id, "stage": body.stage}, run),
        )
    terminal_event = _TERMINAL_STATUS_AUDIT_EVENTS.get(body.status or "")
    if terminal_event is not None:
        _write_audit(
            db,
            organization_id=instance.organization_id,
            event_type=terminal_event,
            metadata=_with_process_context({"discoveryRunId": run.id, "status": body.status}, run),
        )
    db.commit()
    db.refresh(run)
    return DiscoveryRunAgentResponse(discovery_run_id=run.id, status=run.status, current_stage=run.current_stage)


@router.post("/discovery-runs/{run_id}/cancellation-acknowledgement", response_model=DiscoveryRunAgentResponse)
def discovery_run_cancellation_ack_route(
    run_id: str, body: CancellationAcknowledgementRequest, request: Request, db: Session = Depends(get_db)
) -> DiscoveryRunAgentResponse:
    instance = require_scanner_instance(request, db)
    try:
        run = record_status_update(db, instance, run_id, status=body.status, stage=None)
    except (DiscoveryCommandError, DiscoveryRunValidationError) as exc:
        db.commit()
        raise ValidationError(str(exc)) from exc
    terminal_event = _TERMINAL_STATUS_AUDIT_EVENTS.get(body.status)
    if terminal_event is not None:
        _write_audit(
            db,
            organization_id=instance.organization_id,
            event_type=terminal_event,
            metadata=_with_process_context({"discoveryRunId": run.id, "status": body.status}, run),
        )
    db.commit()
    db.refresh(run)
    return DiscoveryRunAgentResponse(discovery_run_id=run.id, status=run.status, current_stage=run.current_stage)
