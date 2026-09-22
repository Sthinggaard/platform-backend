"""CA-08.5 (#293) — a run whose Collector has stopped is not left running for ever.

The failure this exists for: a Collector dies mid-verification. It sends no
result and no failure, because it is not there to send anything. The run stays
``RUNNING``, the artefact stays ``RUNNING``, and the surface shows an
examination in progress that will never end. Nobody is told, because nothing
happened — and "nothing happened" is exactly what a stalled run looks like from
the platform's side.

**Derived, not swept.** ``resolve_scanner_liveness`` already answers *"is this
Collector actually alive?"* by reading its last heartbeat at the moment somebody
asks, and BUG-DISC-05 records why: a status raised by a heartbeat and lowered by
nothing shows "Connected" with a green tick while a run waits for ever. This
reuses that answer instead of adding a background job to notice the same thing
later. There is no window in which the platform believes something the data does
not support.

**No second scheduler, queue or retry policy** — the contract's rule, and the
reason this module holds one read-time question and no loop of its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from src.core.constants.evidence_scanner_enums import ScannerInstanceStatus
from src.core.constants.verification_run_enums import (
    VERIFICATION_RUN_COLLECTOR_LOST,
    VerificationRunStatus,
)
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.model_defs.verification_inspection_command import VerificationInspectionCommand
from src.core.model_defs.verification_run import VerificationRun
from src.core.services.evidence_scanner_service import resolve_scanner_liveness


@dataclass(frozen=True)
class RunLiveness:
    """Whether a run is still being worked on, and what to say if it is not."""

    stalled: bool
    #: Business language, ready to show. ``None`` when the run is healthy.
    explanation: str | None


def assess_run_liveness(
    db: Session, *, run: VerificationRun, now: datetime | None = None
) -> RunLiveness:
    """Is anything still working on this run?

    A run is stalled when its Collector is no longer effectively online. That is
    the whole test, and it is deliberately not "has it taken too long": a slow
    scan and a dead Collector look identical on a clock, and guessing between
    them from elapsed time is how a healthy long-running job gets killed. The
    Collector's own silence is the honest signal.
    """
    if run.status != VerificationRunStatus.RUNNING.value:
        return RunLiveness(stalled=False, explanation=None)

    instance = _instance_for(db, run)
    if instance is None:
        # No Collector on record at all. Nothing is going to finish this.
        return RunLiveness(stalled=True, explanation=VERIFICATION_RUN_COLLECTOR_LOST)

    liveness = resolve_scanner_liveness(instance, now=now or datetime.now(timezone.utc))
    if liveness == ScannerInstanceStatus.ONLINE.value:
        return RunLiveness(stalled=False, explanation=None)

    return RunLiveness(stalled=True, explanation=VERIFICATION_RUN_COLLECTOR_LOST)


def _instance_for(db: Session, run: VerificationRun) -> ScannerInstance | None:
    """The Collector doing this run's work, reached through its own commands.

    A ``VerificationRun`` does not name a Collector — an inspection does, via the
    connector it was issued against. Read from the run's own queued work rather
    than stored a second time on the run, so the two can never disagree about
    which machine is responsible.
    """
    command = (
        db.query(VerificationInspectionCommand)
        .filter(
            VerificationInspectionCommand.verification_run_id == run.id,
            VerificationInspectionCommand.organization_id == run.organization_id,
        )
        .order_by(VerificationInspectionCommand.issued_at.desc())
        .first()
    )
    if command is None:
        # Nothing was ever queued, so no Collector was ever asked. The run is
        # not stalled by a dead machine; it simply has no work.
        return None

    connector = (
        db.query(AccessConnector)
        .filter(
            AccessConnector.id == command.connector_id,
            AccessConnector.organization_id == run.organization_id,
        )
        .first()
    )
    if connector is None:
        return None

    return (
        db.query(ScannerInstance)
        .filter(
            ScannerInstance.id == connector.scanner_instance_id,
            ScannerInstance.organization_id == run.organization_id,
        )
        .first()
    )
