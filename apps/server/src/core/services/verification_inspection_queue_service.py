"""CA-08.2 (#290) — queueing a signed inspection, and reading what came back.

Separate from ``verification_inspection_service`` on purpose. That module answers
*may this run, and what exactly would it run?* — the boundary question, called
once per inspection. This one is delivery: hand it to a Collector, take the
report, write down what happened. Two responsibilities, two files, and the
boundary logic stays the thing that never has to change when transport does.

**Queueing goes through ``authorise_inspection``**, never around it. That is the
only place that asks ``assert_capability_permitted``, and an inspection reaching
the queue without passing it would be an approved-looking command nobody
authorised. It is checked at queue time rather than delivery time because the
answer must be the one that was true when a person's approval was current.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from src.core.constants.verification_inspection_enums import (
    INSPECTION_COMMAND_TERMINAL,
    InspectionOutcome,
    VERIFICATION_INSPECTION_AUDIT_REPORTED,
    InspectionCommandStatus,
)
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.verification_inspection_command import VerificationInspectionCommand
from src.core.model_defs.verification_run import VerificationRun
from src.core.services.audit_service import append_audit_event
from src.core.services.verification_inspection_service import (
    AuthorisedInspection,
    authorise_inspection,
    inspection_envelope,
)
from src.core.services.credential_exposure_service import record_credential_exposure
from src.core.services.verification_identity_recording_service import (
    record_identity_from_inspection,
)
from src.core.services.verification_outcome_service import classify_inspection_outcome


def _as_utc(value: datetime) -> datetime:
    """Give a naive UTC column back the offset it was signed with."""
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


class InspectionCommandError(ValueError):
    """The queue was asked for something it cannot do."""


def queue_inspection(
    db: Session,
    *,
    run: VerificationRun,
    connector: AccessConnector,
    capability: str,
    platform: str | None,
    parameters: dict[str, str] | None = None,
    config_target: str | None = None,
) -> VerificationInspectionCommand:
    """Authorise, sign, and put one inspection where a Collector will find it."""
    authorised: AuthorisedInspection = authorise_inspection(
        db,
        run=run,
        connector=connector,
        capability=capability,
        platform=platform,
        parameters=parameters,
        config_target=config_target,
    )

    command = VerificationInspectionCommand(
        organization_id=run.organization_id,
        verification_run_id=run.id,
        asset_id=run.asset_id,
        connector_id=connector.id,
        scanner_instance_id=connector.scanner_instance_id,
        capability=authorised.capability,
        platform=authorised.platform,
        argv=list(authorised.argv),
        permission_profile_id=authorised.permission_profile_id,
        signature=authorised.signature,
        signature_version=authorised.signature_version,
        issued_at=authorised.issued_at.replace(tzinfo=None),
        expires_at=authorised.expires_at.replace(tzinfo=None),
        status=InspectionCommandStatus.PENDING.value,
    )
    db.add(command)
    db.flush()
    return command


def next_inspection_for_scanner(
    db: Session, *, scanner_instance_id: str
) -> VerificationInspectionCommand | None:
    """The oldest inspection this Collector has not been given yet.

    Expired work is retired here rather than handed over. A Collector that
    received an already-expired command would verify it, refuse it, and report a
    rejection — correct, but three round trips to learn what the platform
    already knew.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    pending = (
        db.query(VerificationInspectionCommand)
        .filter(
            VerificationInspectionCommand.scanner_instance_id == scanner_instance_id,
            VerificationInspectionCommand.status == InspectionCommandStatus.PENDING.value,
        )
        .order_by(VerificationInspectionCommand.issued_at)
        .all()
    )

    for command in pending:
        if command.expires_at <= now:
            command.status = InspectionCommandStatus.EXPIRED.value
            db.add(command)
            continue
        command.status = InspectionCommandStatus.DELIVERED.value
        command.delivered_at = now
        db.add(command)
        return command
    return None


def envelope_for(
    command: VerificationInspectionCommand, *, run: VerificationRun
) -> dict:
    """The wire shape, rebuilt from the stored row rather than re-signed.

    The signature travels as it was issued. Recomputing it here would sign
    whatever the row says now, which would make a tampered row verify perfectly.

    🐞 **UTC is re-attached, and it is not cosmetic.** These columns are
    ``timestamp without time zone``, so they read back **naive** — and the
    signature was computed over an *aware* ``isoformat()`` ending ``+00:00``.
    Rebuilding the envelope from the naive value produced a different string
    from the one that was signed, so every inspection delivered from this queue
    would have failed verification on the Collector. Caught by #281's
    timestamp-boundary test, which exists for exactly this class of defect.
    """
    authorised = AuthorisedInspection(
        run_id=command.verification_run_id,
        organization_id=command.organization_id,
        asset_id=run.asset_id,
        connector_id=command.connector_id,
        capability=command.capability,
        platform=command.platform,
        argv=tuple(command.argv),
        issued_at=_as_utc(command.issued_at),
        expires_at=_as_utc(command.expires_at),
        signature=command.signature,
        signature_version=command.signature_version,
        permission_profile_id=command.permission_profile_id,
    )
    envelope = inspection_envelope(
        authorised, scanner_instance_id=command.scanner_instance_id
    )
    envelope["command_id"] = command.id
    return envelope


def record_inspection_result(
    db: Session,
    *,
    command: VerificationInspectionCommand,
    exit_code: int | None,
    stderr: str,
    stdout: str = "",
    credential_findings: list[dict] | None = None,
    timed_out: bool = False,
) -> VerificationInspectionCommand:
    """Take the Collector's facts and let the engine read them.

    This is the join Søren's ruling created: the Collector reports ``exit_code``
    and ``stderr`` and nothing else, and the conclusion is reached **here**, on
    the platform, by ``classify_inspection_outcome``.
    """
    if command.status in INSPECTION_COMMAND_TERMINAL:
        raise InspectionCommandError(
            "This inspection has already been reported; a second report would overwrite "
            "what the first one said happened."
        )

    command.exit_code = exit_code
    # Bounded rather than stored whole. stderr is diagnostic, and an unbounded
    # column filled from a customer host is somewhere a very large or very
    # sensitive string can quietly land.
    command.stderr = (stderr or "")[:4000]
    command.outcome = classify_inspection_outcome(
        exit_code=exit_code, stderr=stderr, timed_out=timed_out
    )
    command.status = InspectionCommandStatus.COMPLETED.value
    command.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.add(command)

    # CA-08.4 — the point of the run. Only on success, and only for capabilities
    # whose output cannot hold a credential (#296 owns the rest). The output
    # itself is never stored on this row; what survives is the name it yielded
    # and the evidence line that supports it.
    if command.outcome == InspectionOutcome.SUCCEEDED.value:
        record_identity_from_inspection(db, command=command, stdout=stdout)

        # #296 — a credential sitting in the open is a weakness in the customer's
        # environment, not merely something we had to redact. The value never
        # reached here; the Collector stripped it where it was read.
        if credential_findings:
            record_credential_exposure(
                db,
                organization_id=command.organization_id,
                asset_id=command.asset_id,
                findings=credential_findings,
            )

    append_audit_event(
        db,
        command.organization_id,
        VERIFICATION_INSPECTION_AUDIT_REPORTED,
        metadata={
            "command_id": command.id,
            "run_id": command.verification_run_id,
            "capability": command.capability,
            "outcome": command.outcome,
            "exit_code": exit_code,
        },
    )
    return command


def withdraw_outstanding_inspections(db: Session, *, run: VerificationRun) -> int:
    """Take back work nobody wants any more, and say how much there was.

    CA-08.5 (#293). A cancelled run must not leave commands sitting in the queue
    for a Collector to collect afterwards — it would run them, report them, and
    the platform would record evidence gathered for a run somebody stopped.

    Only what has not been reported. A command already ``COMPLETED`` describes
    something that genuinely happened on a host, and rewriting that to hide it
    would be falsifying the record rather than cancelling work.
    """
    outstanding = (
        db.query(VerificationInspectionCommand)
        .filter(
            VerificationInspectionCommand.verification_run_id == run.id,
            VerificationInspectionCommand.status.in_(
                (
                    InspectionCommandStatus.PENDING.value,
                    InspectionCommandStatus.DELIVERED.value,
                )
            ),
        )
        .all()
    )

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for command in outstanding:
        command.status = InspectionCommandStatus.EXPIRED.value
        command.completed_at = now
        db.add(command)

    return len(outstanding)


def reject_inspection(
    db: Session, *, command: VerificationInspectionCommand, reason: str
) -> VerificationInspectionCommand:
    """The Collector would not run it — a bad signature, a wrong instance.

    Kept as a distinct status rather than folded into a failed outcome: "the
    Collector refused this instruction" and "the host refused this command" are
    different facts, and only one of them is about the customer's estate.
    """
    command.status = InspectionCommandStatus.REJECTED.value
    command.stderr = (reason or "")[:4000]
    command.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.add(command)
    return command
