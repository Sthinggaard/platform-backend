"""Step 4.2 Part 2 — per-job (ProviderExecution) command lifecycle for
DELEGATED providers (Nmap/Subfinder/Nuclei — anything that must run on the
customer's own scanner agent, never directly from Risklence's backend).

Sibling to ``discovery_command_service.py`` (Step 4.1's whole-run command
lifecycle), never replacing it: ``create_command_for_run`` still creates
the original run-scoped command for callers that still use it; this module
creates one *additional* command scoped to a single ``ProviderExecution``
job, linked via ``ScannerCommand.provider_execution_id``. A run's
``DiscoveryExecutionPlan`` can spawn many delegated jobs (one Nmap job per
stage, potentially several stages), so a run may now have more than one
*concurrent* command — a deliberate extension of Step 4.1's original "one
active command per run" assumption, safe because nothing in that model
enforces single-command-per-run at the schema level (only an index, no
unique constraint on discovery_run_id alone).

Imports ``discovery_command_service.sign_command`` for reuse (same HMAC
idiom, one signing implementation). ``discovery_command_service`` does the
reverse import (of ``handle_provider_execution_acknowledgement``) lazily,
inside its own ``acknowledge_command`` function, purely to avoid a circular
top-level import between these two sibling modules — both are fully loaded
by the time that call actually happens.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.core.constants.discovery_execution_enums import (
    DISCOVERY_EXECUTION_ERROR_EVIDENCE_STORAGE_FAILED,
    DISCOVERY_EXECUTION_ERROR_PROVIDER_EXECUTION_NOT_FOUND,
    EVIDENCE_PACKAGE_AUDIT_STORAGE_FAILED,
    PROVIDER_EXECUTION_AUDIT_COMPLETED,
    PROVIDER_EXECUTION_AUDIT_LEASED,
    PROVIDER_EXECUTION_AUDIT_STARTED,
    PROVIDER_EXECUTION_STATUSES_AN_ACK_CANNOT_ADVANCE,
    WORKER_LEASE_DEFAULT_SECONDS,
    EvidenceNormalizationStatus,
    EvidencePackageProcessingStatus,
    ProviderExecutionStatus,
)
from src.core.constants.discovery_run_enums import (
    DISCOVERY_COMMAND_EXPIRY_SECONDS,
    DISCOVERY_COMMAND_SIGNATURE_VERSION,
    CheckKey,
    CommandRejectionCode,
    ScannerCommandStatus,
)
from src.core.constants.lifecycle_enums import LifecycleFamily, LifecycleTransitionSource
from src.core.model_defs.discovery_execution import EvidencePackage, ProviderExecution, WorkerLease
from src.core.model_defs.discovery_run import DiscoveryRun, ScannerCommand
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.services.discovery_command_service import (
    DiscoveryCommandError,
    command_type_for_run,
    sign_command,
    utcnow,
)
from src.core.services.discovery_execution_retry_service import handle_job_failure, release_lease
from src.core.services.discovery_execution_scheduler_service import advance_stage_completion
from src.core.services.evidence_storage_backend import (
    EvidenceStorageError,
    get_evidence_storage_backend,
)
from src.core.services.lifecycle_audit_service import (
    LifecycleAuditDetails,
    with_lifecycle_audit_metadata,
)
from src.core.services.provider_execution_lifecycle_service import transition_provider_execution


def _write_audit(db: Session, *, organization_id: int, event_type: str, metadata: dict) -> None:
    # This module is called from both the browser-facing dispatch path and
    # the scanner's own Bearer-authenticated report-back — neither has a
    # human actor in the loop at this layer (the route above, if any, is
    # where a real ctx.user_id would attribute a browser-triggered event).
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=None,
            event_type=event_type,
            metadata_json=metadata,
        )
    )


def _with_process_context(metadata: dict, obj: ScannerCommand | DiscoveryRun) -> dict:
    """CA-04.8 — camelCase, matching this file's own existing metadata
    keys (providerExecutionId, workerId, ...). Works for either a
    ScannerCommand or a DiscoveryRun since both carry business_process_id/
    business_service_id (CA-04.7)."""
    return {
        **metadata,
        "businessProcessId": obj.business_process_id,
        "businessServiceId": obj.business_service_id,
        "slotInstanceId": None,
    }


def create_command_for_provider_execution(
    db: Session, run: DiscoveryRun, provider_execution: ProviderExecution
) -> ScannerCommand:
    """Creates one signed, short-lived command for a single delegated job.
    Does not transition the DiscoveryRun itself — the run already reached
    RUNNING when its DiscoveryExecutionPlan started (DISC-24); only the
    ProviderExecution/WorkerLease change here.

    CA-04.2 — provider_execution.provider_id can only ever be a registered
    provider id in practice (discovery_execution_plan_service only ever
    sets it from get_registered_providers()), so this check is defense in
    depth against a bypass of that path, not a scenario the normal flow can
    reach — the same "wire an already-safe invariant into a real
    enforcement point" pattern CA-04.1 used for verify_command_signature."""
    if provider_execution.provider_id not in {key.value for key in CheckKey}:
        raise DiscoveryCommandError(
            f"'{provider_execution.provider_id}' is not a registered check key.",
            code=CommandRejectionCode.CHECK_KEY_UNKNOWN.value,
        )

    now = utcnow()
    command = ScannerCommand(
        organization_id=run.organization_id,
        scanner_instance_id=run.scanner_instance_id,
        discovery_run_id=run.id,
        business_process_id=run.business_process_id,
        business_service_id=run.business_service_id,
        provider_execution_id=provider_execution.id,
        check_key=provider_execution.provider_id,
        command_type=command_type_for_run(run),
        status=ScannerCommandStatus.PENDING.value,
        issued_at=now,
        expires_at=now + timedelta(seconds=DISCOVERY_COMMAND_EXPIRY_SECONDS),
        execution_policy={
            "maximumDurationSeconds": DISCOVERY_COMMAND_EXPIRY_SECONDS,
            "stopAtWindowEnd": True,
            "allowPartialUpload": True,
        },
        signature_version=DISCOVERY_COMMAND_SIGNATURE_VERSION,
        signature="",
    )
    db.add(command)
    db.flush()  # populate command.id before signing, same reason as create_command_for_run
    command.signature = sign_command(db, command)
    db.add(command)

    previous_state = provider_execution.status
    transition_provider_execution(provider_execution, ProviderExecutionStatus.LEASED.value)
    db.add(provider_execution)

    lease = WorkerLease(
        provider_execution_id=provider_execution.id,
        worker_id=f"scanner:{run.scanner_instance_id}",
        lease_expires_at=now + timedelta(seconds=WORKER_LEASE_DEFAULT_SECONDS),
    )
    db.add(lease)
    _write_audit(
        db,
        organization_id=run.organization_id,
        event_type=PROVIDER_EXECUTION_AUDIT_LEASED,
        metadata=with_lifecycle_audit_metadata(
            _with_process_context({"providerExecutionId": provider_execution.id, "workerId": lease.worker_id}, run),
            LifecycleAuditDetails(
                object_type="provider_execution",
                object_id=provider_execution.id,
                family=LifecycleFamily.EXECUTION,
                source=LifecycleTransitionSource.SYSTEM_EXECUTED,
                previous_state=previous_state,
                current_state=provider_execution.status,
            ),
        ),
    )
    return command


def handle_provider_execution_acknowledgement(
    db: Session,
    command: ScannerCommand,
    *,
    accepted: bool,
    rejection_code: str | None,
) -> None:
    """Called from discovery_command_service.acknowledge_command once it
    has already set command.status/accepted/acknowledged_at — this only
    updates the ProviderExecution/WorkerLease side, never the whole
    DiscoveryRun (unlike the Step 4.1 whole-run path)."""
    provider_execution = db.get(ProviderExecution, command.provider_execution_id)
    if provider_execution is None:
        return  # command row is inconsistent; nothing to update, not this function's job to fail loudly here
    if provider_execution.status in PROVIDER_EXECUTION_STATUSES_AN_ACK_CANNOT_ADVANCE:
        # DISC-31: already resolved — most commonly a plan/stage-level
        # cancellation that landed while this ack was in flight. A late
        # acknowledgement must never overwrite an already-recorded real
        # outcome (e.g. flip a CANCELLED job back to RUNNING/FAILED).
        #
        # The set also covers RETRY_SCHEDULED, which is *superseded* rather than
        # terminal. Reading only the terminal set let such an ack fall through
        # to a transition that is not legal from there, and the raise became a
        # 422 the Collector could never get past — observed live on run
        # 6fcadc3c. Absorbing it is right for the same reason as the terminal
        # case: the job has moved on, and the agent is reporting old news.
        return
    if accepted:
        previous_state = provider_execution.status
        transition_provider_execution(provider_execution, ProviderExecutionStatus.RUNNING.value)
        if provider_execution.started_at is None:
            provider_execution.started_at = utcnow()
        _write_audit(
            db,
            organization_id=command.organization_id,
            event_type=PROVIDER_EXECUTION_AUDIT_STARTED,
            metadata=with_lifecycle_audit_metadata(
                _with_process_context({"providerExecutionId": provider_execution.id}, command),
                LifecycleAuditDetails(
                    object_type="provider_execution",
                    object_id=provider_execution.id,
                    family=LifecycleFamily.EXECUTION,
                    source=LifecycleTransitionSource.EXTERNAL_PROVIDER_REPORTED,
                    previous_state=previous_state,
                    current_state=provider_execution.status,
                ),
            ),
        )
    else:
        handle_job_failure(
            db,
            provider_execution,
            failure_code=rejection_code or "command_rejected",
            failure_message=None,
        )
        advance_stage_completion(db, provider_execution.execution_stage_id)
        return
    db.add(provider_execution)


def record_provider_execution_result(
    db: Session,
    instance: ScannerInstance,
    command_id: str,
    *,
    status: str,
    evidence_format: str | None,
    raw_evidence_payload: str | None,
    schema_version: str,
    checkpoint: dict | None,
    failure_code: str | None,
    failure_message: str | None,
) -> ProviderExecution:
    """The scanner's report-back for a delegated job — the one place a
    real evidence payload enters the system (spec's EvidencePackage
    contract). Simplification, disclosed not hidden: the payload travels
    as a JSON string field on this request rather than a separate
    multipart/streaming upload — reasonable for the Nmap-XML/text-sized
    payloads this pass targets; large-binary evidence and a presigned-URL
    upload path are a real follow-up, not fabricated here."""
    command = (
        db.query(ScannerCommand)
        .filter(ScannerCommand.id == command_id, ScannerCommand.scanner_instance_id == instance.id)
        .first()
    )
    if command is None or command.provider_execution_id is None:
        raise DiscoveryCommandError(
            DISCOVERY_EXECUTION_ERROR_PROVIDER_EXECUTION_NOT_FOUND, code="scanner_instance_mismatch"
        )
    provider_execution = db.get(ProviderExecution, command.provider_execution_id)
    if provider_execution is None:
        raise DiscoveryCommandError(
            DISCOVERY_EXECUTION_ERROR_PROVIDER_EXECUTION_NOT_FOUND, code="scanner_instance_mismatch"
        )
    if provider_execution.status in PROVIDER_EXECUTION_STATUSES_AN_ACK_CANNOT_ADVANCE:
        # DISC-31: already resolved (most commonly cancelled while this
        # report was in flight, since there is no live push channel to
        # stop a scanner mid-job) — a late report must never overwrite an
        # already-recorded real outcome. Not an error: the scanner did
        # nothing wrong, it just lost a race with a cancellation.
        #
        # RETRY_SCHEDULED belongs here for the same reason it belongs on the
        # acknowledgement guard above: the retry engine has already spawned the
        # sibling that will do this work, `_current_jobs_for_stage` excludes the
        # superseded row from the rollup, and recording an outcome on it would
        # be writing a result nothing reads onto a row nobody is waiting for.
        return provider_execution

    provider_execution.checkpoint = checkpoint
    if status == ProviderExecutionStatus.FAILED.value:
        handle_job_failure(
            db,
            provider_execution,
            failure_code=failure_code or "provider_reported_failure",
            failure_message=failure_message,
        )
        advance_stage_completion(db, provider_execution.execution_stage_id)
        return provider_execution

    if raw_evidence_payload is not None and evidence_format is not None:
        backend = get_evidence_storage_backend()
        try:
            stored = backend.store(
                organization_id=command.organization_id,
                payload=raw_evidence_payload.encode("utf-8"),
                evidence_format=evidence_format,
            )
        except EvidenceStorageError as exc:
            _write_audit(
                db,
                organization_id=command.organization_id,
                event_type=EVIDENCE_PACKAGE_AUDIT_STORAGE_FAILED,
                metadata=_with_process_context({"providerExecutionId": provider_execution.id, "error": str(exc)}, command),
            )
            handle_job_failure(
                db,
                provider_execution,
                failure_code="evidence_storage_failed",
                failure_message=DISCOVERY_EXECUTION_ERROR_EVIDENCE_STORAGE_FAILED,
            )
            advance_stage_completion(db, provider_execution.execution_stage_id)
            raise DiscoveryCommandError(str(exc), code="evidence_storage_failed") from exc

        package = EvidencePackage(
            discovery_run_id=command.discovery_run_id,
            execution_plan_id=_execution_plan_id_for_stage(
                db, provider_execution.execution_stage_id
            ),
            execution_stage_id=provider_execution.execution_stage_id,
            provider_execution_id=provider_execution.id,
            organization_id=command.organization_id,
            provider_id=provider_execution.provider_id,
            provider_version=provider_execution.provider_version,
            collector_version=None,
            captured_at=utcnow(),
            schema_version=schema_version,
            raw_evidence_reference=stored.reference,
            evidence_format=evidence_format,
            integrity_hash=stored.integrity_hash,
            execution_metadata={"reportedByScannerInstanceId": instance.id},
            provenance_metadata={
                "providerId": provider_execution.provider_id,
                "providerVersion": provider_execution.provider_version,
                "workerId": f"scanner:{instance.id}",
                "capturedAt": utcnow().isoformat(),
                "organizationId": command.organization_id,
                "executionStageId": provider_execution.execution_stage_id,
                "providerExecutionId": provider_execution.id,
                "discoveryRunId": command.discovery_run_id,
                # CA-04.7 — carried from the command's own snapshotted
                # context (not re-joined live) so this evidence package
                # stays fully self-describing/auditable even independently
                # of the discovery_runs row, without making the artefact
                # itself process-exclusive (CA-06's reconciliation job is
                # untouched and still reads raw_evidence_reference the
                # same way regardless of these two keys).
                "businessProcessId": command.business_process_id,
                "businessServiceId": command.business_service_id,
                # CA-04.8 — stays null until CA-09A's dependency-slot
                # mapping genuinely exists and is approved; never inferred.
                "slotInstanceId": None,
            },
            processing_status=EvidencePackageProcessingStatus.STORED.value,
            normalization_status=EvidenceNormalizationStatus.PENDING.value,
        )
        db.add(package)
        try:
            db.flush()
        except IntegrityError:
            # DISC-34: a genuine concurrent duplicate result-report race —
            # two requests for the same attempt both passed the
            # terminal-status check above before either committed, and the
            # other one won. uq_evidence_package_provider_execution is what
            # actually catches this (a plain status check alone cannot,
            # since both requests observed the same not-yet-terminal state
            # before either flushed). Discard this request's now-redundant
            # attempt and return the real, already-committed outcome
            # instead of raising — the scanner did nothing wrong, it just
            # lost the race.
            db.rollback()
            return db.get(ProviderExecution, provider_execution.id)

    if status == ProviderExecutionStatus.PARTIALLY_COMPLETED.value:
        # CA-09V — why it was partial, kept rather than dropped. A partial
        # result already carried a reason on the wire and nothing wrote it
        # down, so a truncated scan looked, in the database, exactly like a
        # complete one with a different status word. These two columns are the
        # existing home for "what went wrong with this attempt"; a partial is a
        # job that fell short, and giving it a second pair of columns would be
        # a second place to look. No retry is scheduled: a re-run under the
        # same budget truncates identically, so this is a fact for a person,
        # not a job for the scheduler.
        provider_execution.failure_code = failure_code
        provider_execution.failure_message = failure_message

    previous_state = provider_execution.status
    transition_provider_execution(provider_execution, status)
    provider_execution.completed_at = utcnow()
    _write_audit(
        db,
        organization_id=command.organization_id,
        event_type=PROVIDER_EXECUTION_AUDIT_COMPLETED,
        metadata=with_lifecycle_audit_metadata(
            _with_process_context({"providerExecutionId": provider_execution.id}, command),
            LifecycleAuditDetails(
                object_type="provider_execution",
                object_id=provider_execution.id,
                family=LifecycleFamily.EXECUTION,
                source=LifecycleTransitionSource.EXTERNAL_PROVIDER_REPORTED,
                previous_state=previous_state,
                current_state=provider_execution.status,
            ),
        ),
    )
    db.add(provider_execution)
    release_lease(db, provider_execution.id)
    advance_stage_completion(db, provider_execution.execution_stage_id)
    return provider_execution


def _execution_plan_id_for_stage(db: Session, execution_stage_id: str) -> str:
    from src.core.model_defs.discovery_execution import ExecutionStage

    stage = db.get(ExecutionStage, execution_stage_id)
    if stage is None:
        raise DiscoveryCommandError(
            "Execution stage not found for this job.", code="scanner_instance_mismatch"
        )
    return stage.execution_plan_id
