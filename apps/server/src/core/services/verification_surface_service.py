"""CA-08.6 (#294) — what was verified, when, under whose approval, and what it found.

The first part of this epic a person ever sees. Everything before it refuses
things; this is the only piece that answers a question somebody actually asked.

**Three states, and keeping them apart is the whole job.**

- *Never verified* — nobody has asked, and the artefact is whatever discovery
  called it.
- *Verified, and it established something* — the artefact has a name that came
  from inside it, under a named approval.
- *Verified, and it established nothing* — somebody approved a deeper look, it
  ran, and the host still would not say what it is.

The third is the one a surface usually gets wrong, by rendering it the same as
the first. They are opposite facts: one is an argument for granting access, the
other is the record that access was granted and exhausted. CA-08.6's criterion
says so explicitly, and ``never_verified`` versus ``VERIFIED_NOTHING_IDENTIFYING``
is how it is carried.

**Redaction runs over everything leaving here**, through CA-07.6's ``redact`` —
the one choke point, not a second implementation. It matters most on this
surface because verification output is the richest material the platform holds,
and because ``stderr`` arrives verbatim from a customer's host: nothing about
its shape stops a credential appearing in it.

This module shapes data and renders nothing. The component that displays it
holds no logic of its own (Søren's standing rule), so every string it needs is
composed here.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from src.core.constants.artefact_identity_evidence_enums import (
    IDENTITY_UNDETERMINED_EXPLANATION,
)
from src.core.constants.secret_redaction import redact
from src.core.model_defs.common import to_utc_iso
from src.core.constants.verification_inspection_enums import InspectionOutcome
from src.core.constants.verification_run_enums import VerificationRunStatus
from src.core.model_defs.verification_inspection_command import VerificationInspectionCommand
from src.core.model_defs.verification_run import VerificationRun
from src.core.services.verification_run_liveness_service import assess_run_liveness
from src.core.models import User

#: What each outcome means to somebody who does not run infrastructure. The
#: platform's language rule: never "exit 255", always what it means for them.
OUTCOME_EXPLANATION: dict[str, str] = {
    InspectionOutcome.SUCCEEDED.value: "Read successfully.",
    InspectionOutcome.AUTHENTICATION_FAILED.value: (
        "The credential was refused. This artefact cannot be examined until access is restored."
    ),
    InspectionOutcome.HOST_UNREACHABLE.value: (
        "Nothing answered at this address, so there was nothing to examine."
    ),
    InspectionOutcome.PERMISSION_DENIED_ON_HOST.value: (
        "Access was accepted, but the account is not allowed to read this."
    ),
    InspectionOutcome.COMMAND_NOT_AVAILABLE.value: (
        "This artefact does not provide what was asked for."
    ),
    InspectionOutcome.COMMAND_FAILED.value: (
        "The read was attempted and did not complete."
    ),
    InspectionOutcome.TIMED_OUT.value: "The artefact did not answer in time.",
}

#: How a name was established, for a reader. The basis vocabulary is technical
#: because it has to be rankable; what a person sees never has to be. Held here
#: rather than in the component, which holds no logic of its own.
BASIS_EXPLANATION: dict[str, str] = {
    "container_image": "read from the container image it was built from",
    "listening_process": "read from the program answering on its open port",
    "os_release": "read from the operating system it reports",
    "http_title": "taken from the web page it serves",
    "tls_certificate": "taken from the certificate it presents",
    "service_product": "inferred from how it answered a network probe",
    "hardware_vendor": "inferred from the manufacturer of the hardware",
}


#: What a capability reads, in business language. The vocabulary is technical by
#: necessity; what a person is shown never has to be.
CAPABILITY_DESCRIPTION: dict[str, str] = {
    "read_os_version": "What operating system this runs",
    "read_installed_packages": "What software is installed",
    "read_running_processes": "What is running",
    "read_listening_socket_owner": "What is answering on its open ports",
    "read_service_config": "How its services are configured",
    "list_containers": "What containers it runs",
    "inspect_container": "What one container is built from",
    "read_image_metadata": "What an image contains",
    "read_api_inventory": "What its API exposes",
}


@dataclass(frozen=True)
class InspectionView:
    """One read, as a person reads it."""

    capability: str
    what_was_read: str
    outcome: str | None
    what_it_means: str
    established: str | None
    #: The line of output the name came from. Redacted like everything else.
    evidence: str | None
    completed_at: datetime | None


@dataclass(frozen=True)
class VerificationRunView:
    run_id: str
    began_at: datetime
    finished_at: datetime | None
    status: str
    #: Who allowed it. The question an auditor asks first, which is why #289
    #: snapshots it onto the run rather than resolving it later.
    approved_by: str | None
    approval_source: str
    #: CA-08.5 (#293) — why it did not finish, in words. None for a run that
    #: completed. A failure must be as visible as a success, which means it
    #: needs somewhere to be said, not just a status nobody renders.
    outcome_explanation: str | None
    #: True when the Collector doing this run has stopped reporting. Derived at
    #: read time from its heartbeat, never swept — so the surface cannot show a
    #: run "in progress" that nothing is working on.
    stalled: bool
    inspections: list[InspectionView]


@dataclass(frozen=True)
class ArtefactVerificationView:
    asset_id: int
    #: False when nobody has ever asked. Distinct from a run that found nothing.
    ever_verified: bool
    identity_name: str | None
    identity_basis: str | None
    #: How that name was established, in words. None when there is no name.
    identity_explanation: str | None
    #: One sentence a person can act on, covering all three states.
    summary: str
    runs: list[VerificationRunView]


def build_artefact_verification_view(
    db: Session, *, organization_id: int, asset_id: int
) -> ArtefactVerificationView:
    """Everything known about this artefact's verification, ready to render."""
    runs = (
        db.query(VerificationRun)
        .filter(
            VerificationRun.organization_id == organization_id,
            VerificationRun.asset_id == asset_id,
        )
        .order_by(VerificationRun.began_at.desc())
        .all()
    )

    commands = (
        db.query(VerificationInspectionCommand)
        .filter(
            VerificationInspectionCommand.organization_id == organization_id,
            VerificationInspectionCommand.asset_id == asset_id,
        )
        .order_by(VerificationInspectionCommand.issued_at.desc())
        .all()
    )

    by_run: dict[str, list[VerificationInspectionCommand]] = {}
    for command in commands:
        by_run.setdefault(command.verification_run_id, []).append(command)

    identity_name, identity_basis = _best_identity(commands)

    run_views = [
        VerificationRunView(
            run_id=run.id,
            began_at=run.began_at,
            finished_at=run.finished_at,
            status=run.status,
            approved_by=_approver_name(db, organization_id, run.approved_by_user_id),
            approval_source=run.approval_source,
            outcome_explanation=_run_explanation(db, run),
            stalled=assess_run_liveness(db, run=run).stalled,
            inspections=[_inspection_view(c) for c in by_run.get(run.id, [])],
        )
        for run in runs
    ]

    return ArtefactVerificationView(
        asset_id=asset_id,
        ever_verified=bool(runs),
        identity_name=identity_name,
        identity_basis=identity_basis,
        identity_explanation=(
            BASIS_EXPLANATION.get(identity_basis) if identity_basis else None
        ),
        summary=_summary(runs, commands, identity_name),
        runs=run_views,
    )


def _run_explanation(db: Session, run: VerificationRun) -> str | None:
    """What to tell a reader about a run that did not simply succeed.

    A run has three ways of not finishing well and they are not the same thing:
    somebody stopped it, it broke, or the Collector doing it went away and it is
    still nominally running. Rendering all three as "failed" would hide the only
    one that is nobody's fault and the only one that is still recoverable.
    """
    if run.status == VerificationRunStatus.RUNNING.value:
        return assess_run_liveness(db, run=run).explanation
    if run.status in (
        VerificationRunStatus.FAILED.value,
        VerificationRunStatus.CANCELLED.value,
    ):
        return run.failure_reason
    return None


def _inspection_view(command: VerificationInspectionCommand) -> InspectionView:
    return InspectionView(
        capability=command.capability,
        what_was_read=CAPABILITY_DESCRIPTION.get(command.capability, command.capability),
        outcome=command.outcome,
        what_it_means=OUTCOME_EXPLANATION.get(
            command.outcome or "", "This read has not come back yet."
        ),
        established=command.identity_name,
        evidence=command.identity_evidence,
        completed_at=command.completed_at,
    )


def _best_identity(
    commands: list[VerificationInspectionCommand],
) -> tuple[str | None, str | None]:
    """The name the strongest verification produced, newest first among equals."""
    from src.core.constants.artefact_identity_evidence_enums import (
        IDENTITY_BASIS_PRECEDENCE,
    )

    order = [basis.value for basis in IDENTITY_BASIS_PRECEDENCE]
    named = [c for c in commands if c.identity_name and c.identity_basis in order]
    if not named:
        return None, None
    best = min(named, key=lambda c: order.index(c.identity_basis))
    return best.identity_name, best.identity_basis


def _summary(
    runs: list[VerificationRun],
    commands: list[VerificationInspectionCommand],
    identity_name: str | None,
) -> str:
    """The three states, in one sentence each.

    Written out rather than assembled from fragments: this is the line a person
    reads first, and a sentence stitched from clauses is how a surface ends up
    saying "verified 0 times".
    """
    if not runs:
        return (
            "This has never been examined from the inside. What it is called comes from "
            "what could be seen over the network."
        )
    if identity_name:
        return f"Examined with approval, and identified as {identity_name}."
    if any(c.outcome == InspectionOutcome.AUTHENTICATION_FAILED.value for c in commands):
        return (
            "Examination was approved, but the credential was refused, so nothing could "
            "be established."
        )
    return IDENTITY_UNDETERMINED_EXPLANATION["verified_nothing_identifying"]


def _approver_name(db: Session, organization_id: int, user_id: int | None) -> str | None:
    if user_id is None:
        # A standing approval carried it and named nobody — #289 records that
        # deliberately, and saying "unknown" here would misreport a policy
        # decision as a missing one.
        return None
    user = (
        db.query(User)
        .filter(User.id == user_id, User.organization_id == organization_id)
        .first()
    )
    return getattr(user, "email", None) if user else None


def view_as_dict(view: ArtefactVerificationView) -> dict:
    """The view as a plain dict, redacted, with every timestamp unambiguous.

    Two boundary rules applied in one place, both for the same reason: a field
    added to any of these dataclasses later is covered without anybody
    remembering to cover it.

    - **Redaction**, through CA-07.6's ``redact``.
    - **#281's timestamp rule.** This route returns a plain dict rather than a
      response model, so ``UtcTimestamp`` never sees these values and the
      timestamp-boundary test cannot scan them. Left alone they serialise naive
      — ``2026-08-24T16:37:27`` — and a browser outside UTC renders a 16:37
      event at its own local hour. The rule is the same whether or not a test
      can reach the field.
    """
    return redact(_isoformat_datetimes(asdict(view)))


def _isoformat_datetimes(value):
    """Every ``datetime``, as a UTC instant that says so."""
    if isinstance(value, dict):
        return {key: _isoformat_datetimes(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_isoformat_datetimes(item) for item in value]
    if isinstance(value, datetime):
        return to_utc_iso(value)
    return value
