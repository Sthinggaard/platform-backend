"""CA-08.1 (#289) — a verification run begins, and only where a person said so.

**This module starts nothing.** It records that a run began and that it ended.
Whatever does the verifying calls in; nothing here reaches out. That is the same
shape CA-07.5 gave the lifecycle, and it is why ``ARTEFACT_ACCESS_TRANSITIONS``
has no edge into ``RUNNING`` except through ``mark_running``.

The rule the epic exists to protect: **``VERIFICATION_READY`` is not
permission.** It means a human may now be asked. Beginning a run from it is
refused, and the test that proves it is the most important test in this epic.

The caller owns the transaction (commit).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.artefact_access_lifecycle_enums import ArtefactAccessState
from src.core.constants.verification_run_enums import (
    VERIFICATION_RUN_AUDIT_CANCELLED,
    VERIFICATION_RUN_CANCELLED_BY_PERSON,
    VERIFICATION_RUN_AUDIT_BEGAN,
    VERIFICATION_RUN_AUDIT_COMPLETED,
    VERIFICATION_RUN_AUDIT_FAILED,
    VERIFICATION_RUN_ERROR_ALREADY_FINISHED,
    VERIFICATION_RUN_ERROR_ALREADY_RUNNING,
    VERIFICATION_RUN_ERROR_NOT_APPROVED,
    VERIFICATION_RUN_ERROR_NO_PROFILE,
    VERIFICATION_RUN_TERMINAL,
    VerificationApprovalSource,
    VerificationRunStatus,
)
from src.core.model_defs.artefact_access_lifecycle import ArtefactAccessLifecycle
from src.core.model_defs.common import utcnow
from src.core.model_defs.verification_run import VerificationRun
from src.core.services.artefact_access_lifecycle_service import (
    mark_complete,
    mark_run_ended_without_completing,
    mark_running,
)
from src.core.services.audit_service import append_audit_event
from src.core.services.verification_inspection_queue_service import (
    withdraw_outstanding_inspections,
)


class VerificationRunError(ValueError):
    """A run that cannot begin, or cannot end the way it was asked to."""


def _open_run(db: Session, *, organization_id: int, asset_id: int) -> VerificationRun | None:
    return (
        db.query(VerificationRun)
        .filter(
            VerificationRun.organization_id == organization_id,
            VerificationRun.asset_id == asset_id,
            VerificationRun.status == VerificationRunStatus.RUNNING.value,
        )
        .first()
    )


def begin_verification_run(
    db: Session,
    *,
    organization_id: int,
    lifecycle: ArtefactAccessLifecycle,
    permission_profile_id: str,
    began_by_user_id: int | None = None,
) -> VerificationRun:
    """Record that verification began on an artefact a person approved.

    Refuses anything not already ``APPROVED``. The lifecycle enforces that too,
    in ``mark_running`` — deliberately twice, because this is the boundary the
    contract is built around and one of the two checks will outlive the other.
    """
    if lifecycle.organization_id != organization_id:
        raise VerificationRunError(VERIFICATION_RUN_ERROR_NOT_APPROVED)
    # Asked before the state check on purpose. A run already under way has moved
    # the lifecycle to RUNNING, so the state check would fire first and tell the
    # caller nobody had approved this — when somebody had, and the real answer is
    # that it is already happening. A true message is worth an extra query.
    if _open_run(db, organization_id=organization_id, asset_id=lifecycle.asset_id):
        raise VerificationRunError(VERIFICATION_RUN_ERROR_ALREADY_RUNNING)
    if lifecycle.state != ArtefactAccessState.APPROVED.value:
        raise VerificationRunError(VERIFICATION_RUN_ERROR_NOT_APPROVED)
    if not permission_profile_id:
        # #291 enforces what a run may reach; this refuses a run that has no
        # answer to that question at all.
        raise VerificationRunError(VERIFICATION_RUN_ERROR_NO_PROFILE)

    run = VerificationRun(
        organization_id=organization_id,
        asset_id=lifecycle.asset_id,
        lifecycle_id=lifecycle.id,
        # Snapshotted: the policy behind a standing approval can be superseded,
        # and this run's authority must not change when it is.
        approval_source=lifecycle.verification_approved_source
        or VerificationApprovalSource.PER_ARTEFACT.value,
        approved_by_user_id=lifecycle.verification_approved_by_user_id,
        approved_at=lifecycle.verification_approved_at,
        permission_profile_id=permission_profile_id,
        status=VerificationRunStatus.RUNNING.value,
        began_by_user_id=began_by_user_id,
    )
    db.add(run)
    db.flush()

    # The lifecycle moves because the run reported it, never the other way round.
    mark_running(db, lifecycle, actor_user_id=began_by_user_id)

    append_audit_event(
        db,
        organization_id,
        VERIFICATION_RUN_AUDIT_BEGAN,
        actor_user_id=began_by_user_id,
        metadata={
            "runId": run.id,
            "assetId": lifecycle.asset_id,
            "approvalSource": run.approval_source,
            "permissionProfileId": permission_profile_id,
        },
    )
    return run


def complete_verification_run(
    db: Session,
    run: VerificationRun,
    *,
    lifecycle: ArtefactAccessLifecycle,
    actor_user_id: int | None = None,
) -> VerificationRun:
    """The run finished, and the artefact's access journey is complete."""
    _require_open(run)
    run.status = VerificationRunStatus.COMPLETED.value
    run.finished_at = utcnow()
    db.add(run)

    mark_complete(db, lifecycle, actor_user_id=actor_user_id)

    append_audit_event(
        db,
        run.organization_id,
        VERIFICATION_RUN_AUDIT_COMPLETED,
        actor_user_id=actor_user_id,
        metadata={"runId": run.id, "assetId": run.asset_id},
    )
    return run


def fail_verification_run(
    db: Session,
    run: VerificationRun,
    *,
    reason: str,
    lifecycle: ArtefactAccessLifecycle | None = None,
    actor_user_id: int | None = None,
) -> VerificationRun:
    """It ran and did not finish, the record says why, and nothing is stranded.

    #289 left the lifecycle in ``RUNNING`` on purpose: moving it to ``COMPLETE``
    would make a failure indistinguishable from a success to every downstream
    reader. That was right, and it left the artefact with no way out — the state
    had exactly one exit and it was the wrong one.

    CA-08.5 (#293) closes it. The artefact goes back to ``APPROVED``: the run
    broke, the approval did not, and a person can start it again. ``COMPLETE``
    is still never reached by a failure, which is the part that mattered.

    ``lifecycle`` is optional only so existing callers that have not been
    updated keep working; every caller that has one should pass it, or the
    artefact stays exactly as stranded as before.
    """
    _require_open(run)
    run.status = VerificationRunStatus.FAILED.value
    run.finished_at = utcnow()
    run.failure_reason = reason
    db.add(run)

    if lifecycle is not None:
        mark_run_ended_without_completing(db, lifecycle, actor_user_id=actor_user_id)

    append_audit_event(
        db,
        run.organization_id,
        VERIFICATION_RUN_AUDIT_FAILED,
        actor_user_id=actor_user_id,
        metadata={"runId": run.id, "assetId": run.asset_id, "reason": reason},
    )
    return run


def cancel_verification_run(
    db: Session,
    run: VerificationRun,
    *,
    lifecycle: ArtefactAccessLifecycle | None = None,
    reason: str = VERIFICATION_RUN_CANCELLED_BY_PERSON,
    actor_user_id: int | None = None,
) -> VerificationRun:
    """Somebody stopped it.

    Its own status and its own audit event, not a flavour of failure: *"we
    stopped it"* and *"it broke"* are different facts about the organisation,
    and only one of them is a defect worth anybody's attention. #289 recorded
    that distinction in the status vocabulary; this is what finally sets it.

    Outstanding inspections are withdrawn so a Collector that polls after this
    is not handed work for a run nobody wants any more. **No second scheduler,
    queue or retry policy is introduced** — this cancels rows in the queue CA-08
    already has, exactly as the contract requires.
    """
    _require_open(run)
    withdrawn = withdraw_outstanding_inspections(db, run=run)

    run.status = VerificationRunStatus.CANCELLED.value
    run.finished_at = utcnow()
    run.failure_reason = reason
    db.add(run)

    if lifecycle is not None:
        mark_run_ended_without_completing(db, lifecycle, actor_user_id=actor_user_id)

    append_audit_event(
        db,
        run.organization_id,
        VERIFICATION_RUN_AUDIT_CANCELLED,
        actor_user_id=actor_user_id,
        metadata={
            "runId": run.id,
            "assetId": run.asset_id,
            "reason": reason,
            # Recorded because it is the consequence: work that was queued for a
            # Collector will now never be handed to it.
            "withdrawnInspections": withdrawn,
        },
    )
    return run


def _require_open(run: VerificationRun) -> None:
    if run.status in VERIFICATION_RUN_TERMINAL:
        raise VerificationRunError(VERIFICATION_RUN_ERROR_ALREADY_FINISHED)


def list_runs_for_asset(
    db: Session, *, organization_id: int, asset_id: int, limit: int = 50
) -> list[VerificationRun]:
    """An artefact's verification history, newest first.

    Paged from the start rather than capped, because #276 spent a story learning
    what a silently truncated ledger costs.
    """
    return (
        db.query(VerificationRun)
        .filter(
            VerificationRun.organization_id == organization_id,
            VerificationRun.asset_id == asset_id,
        )
        .order_by(VerificationRun.began_at.desc())
        .limit(limit)
        .all()
    )
