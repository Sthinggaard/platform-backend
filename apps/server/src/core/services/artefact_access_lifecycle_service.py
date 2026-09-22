"""CA-07.5 — moving an artefact through the seven access states, and stopping there.

**This module starts nothing.** It is the whole point of the story, so it is worth
being blunt about what that means in code: there is no import of any scheduler,
dispatcher, execution planner or recurrence primitive anywhere below, and there
is no call that creates work. ``mark_verification_ready`` writes a timestamp and
an audit event. That is all it does, and
``test_artefact_access_lifecycle.py::test_reaching_verification_ready_schedules_nothing``
fails if any scheduling table gains a single row.

The reason the rule needs a module to defend it is that readiness is *exactly*
the moment when starting the work would feel helpful. Everything is configured,
the connection is proven, the permissions are adequate — and the product's own
rule is that the system never decides. So readiness is where it stops and asks.

**Each transition demands its evidence.** Reaching ``CONFIGURED`` requires a
usable Connector with an approved profile; reaching ``TESTED`` requires a
connection test that actually succeeded, referenced by id. A state that could be
claimed rather than earned would turn the sequence into a set of labels somebody
typed.

The caller owns the transaction (commit).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.artefact_access_lifecycle_enums import (
    ACCESS_LIFECYCLE_AUDIT_REQUESTED,
    ACCESS_LIFECYCLE_AUDIT_TRANSITIONED,
    ACCESS_LIFECYCLE_AUDIT_VERIFICATION_APPROVED,
    ACCESS_LIFECYCLE_ERROR_ALREADY_STARTED,
    ACCESS_LIFECYCLE_ERROR_CHOICE_DOES_NOT_REQUEST_ACCESS,
    ACCESS_LIFECYCLE_ERROR_CONNECTOR_NOT_USABLE,
    ACCESS_LIFECYCLE_ERROR_CONNECTOR_REQUIRED,
    ACCESS_LIFECYCLE_ERROR_DEVIATION_REASON_REQUIRED,
    ACCESS_LIFECYCLE_ERROR_ILLEGAL_TRANSITION,
    ACCESS_LIFECYCLE_ERROR_NO_APPROVED_PROFILE,
    ACCESS_LIFECYCLE_ERROR_NO_STANDING_APPROVAL,
    ACCESS_LIFECYCLE_ERROR_NO_SUCCESSFUL_TEST,
    ACCESS_LIFECYCLE_ERROR_NOT_APPROVED,
    ARTEFACT_ACCESS_TRANSITIONS,
    ArtefactAccessState,
    VerificationApprovalSource,
)
from src.core.constants.connector_access_test_enums import ConnectorAccessTestStatus
from src.core.constants.contextual_access_enums import (
    AccessOperatingMode,
    ArtefactAccessChoice,
    ContextualAccessDecision,
)
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.artefact_access_lifecycle import ArtefactAccessLifecycle
from src.core.model_defs.common import utcnow
from src.core.model_defs.connector_access_test import ConnectorAccessTest
from src.core.services.audit_service import append_audit_event
from src.core.services.contextual_access_policy_service import (
    deviates_from_standing_default,
    get_active_policy,
)
from src.core.services.permission_profile_service import get_active_profile

#: The two choices that ask for deeper access. The other three — network-only,
#: exclude, review-later — are recorded decisions that end there, and starting a
#: lifecycle for one would say access was sought when the answer was that it was
#: not.
ACCESS_SEEKING_CHOICES = (
    ArtefactAccessChoice.CONNECT_HOST.value,
    ArtefactAccessChoice.GRANT_ACCESS.value,
)


class ArtefactAccessLifecycleError(ValueError):
    """Raised when an access transition is invalid or unauthorised."""


def get_lifecycle(
    db: Session, *, organization_id: int, asset_id: int
) -> ArtefactAccessLifecycle | None:
    return (
        db.query(ArtefactAccessLifecycle)
        .filter(
            ArtefactAccessLifecycle.organization_id == organization_id,
            ArtefactAccessLifecycle.asset_id == asset_id,
        )
        .one_or_none()
    )


def request_access(
    db: Session,
    *,
    organization_id: int,
    asset_id: int,
    choice: str,
    requested_by_user_id: int | None = None,
    deviation_reason: str | None = None,
) -> ArtefactAccessLifecycle:
    """Record that a person asked for deeper access to this artefact.

    A recorded decision, not a scan. The five choices stay available everywhere —
    this only starts a journey for the two that ask for access, and refuses the
    other three by name rather than silently doing nothing.

    A choice that departs from the organisation's standing default owes a reason,
    which is the platform's existing idiom (recommended route versus any other),
    not a new rule invented here.
    """
    if choice not in ACCESS_SEEKING_CHOICES:
        raise ArtefactAccessLifecycleError(
            ACCESS_LIFECYCLE_ERROR_CHOICE_DOES_NOT_REQUEST_ACCESS.format(choice=choice)
        )
    if get_lifecycle(db, organization_id=organization_id, asset_id=asset_id) is not None:
        raise ArtefactAccessLifecycleError(ACCESS_LIFECYCLE_ERROR_ALREADY_STARTED)

    reason = (deviation_reason or "").strip() or None
    if deviates_from_standing_default(db, organization_id, choice) and reason is None:
        raise ArtefactAccessLifecycleError(ACCESS_LIFECYCLE_ERROR_DEVIATION_REASON_REQUIRED)

    lifecycle = ArtefactAccessLifecycle(
        organization_id=organization_id,
        asset_id=asset_id,
        state=ArtefactAccessState.ACCESS_REQUESTED.value,
        requested_choice=choice,
        deviation_reason=reason,
        requested_by_user_id=requested_by_user_id,
    )
    db.add(lifecycle)
    db.flush()
    append_audit_event(
        db,
        organization_id,
        ACCESS_LIFECYCLE_AUDIT_REQUESTED,
        actor_user_id=requested_by_user_id,
        metadata=_metadata(lifecycle),
    )
    return lifecycle


def mark_configured(
    db: Session,
    lifecycle: ArtefactAccessLifecycle,
    connector: AccessConnector,
    *,
    actor_user_id: int | None = None,
) -> ArtefactAccessLifecycle:
    """Name the Connector that reaches this artefact, and prove it may be used.

    Both checks are here rather than trusted from the caller: a withdrawn
    Connector cannot be the route to anything, and one whose profile was never
    approved has no decided answer to "what may it do?" — configuring access
    through either would record a route that does not exist.
    """
    if connector is None:
        raise ArtefactAccessLifecycleError(ACCESS_LIFECYCLE_ERROR_CONNECTOR_REQUIRED)
    if connector.permission_subject_inactive_reason is not None:
        raise ArtefactAccessLifecycleError(
            ACCESS_LIFECYCLE_ERROR_CONNECTOR_NOT_USABLE.format(status=connector.status)
        )
    if (
        get_active_profile(
            db,
            organization_id=connector.organization_id,
            subject_id=connector.permission_subject_id,
        )
        is None
    ):
        raise ArtefactAccessLifecycleError(ACCESS_LIFECYCLE_ERROR_NO_APPROVED_PROFILE)

    _require_transition(lifecycle, ArtefactAccessState.CONFIGURED.value)
    lifecycle.connector_id = connector.id
    lifecycle.configured_at = utcnow()
    return _transition(db, lifecycle, ArtefactAccessState.CONFIGURED.value, actor_user_id)


def mark_tested(
    db: Session,
    lifecycle: ArtefactAccessLifecycle,
    test: ConnectorAccessTest,
    *,
    actor_user_id: int | None = None,
) -> ArtefactAccessLifecycle:
    """Point at the test that succeeded, so "tested" names evidence.

    A state that could be claimed without a passing test would be a label
    somebody typed, and the whole sequence would stop meaning anything.
    """
    if (
        test is None
        or test.status != ConnectorAccessTestStatus.SUCCEEDED.value
        or test.connector_id != lifecycle.connector_id
    ):
        raise ArtefactAccessLifecycleError(ACCESS_LIFECYCLE_ERROR_NO_SUCCESSFUL_TEST)

    _require_transition(lifecycle, ArtefactAccessState.TESTED.value)
    lifecycle.access_test_id = test.id
    lifecycle.tested_at = utcnow()
    return _transition(db, lifecycle, ArtefactAccessState.TESTED.value, actor_user_id)


def mark_verification_ready(
    db: Session, lifecycle: ArtefactAccessLifecycle, *, actor_user_id: int | None = None
) -> ArtefactAccessLifecycle:
    """Everything access can establish is established. **This starts nothing.**

    The contract's headline rule, at the exact line where it would be easiest to
    break: readiness is the moment when beginning the work would feel like a
    favour. Entering this state writes a timestamp and an audit event. It creates
    no run, no plan, no stage, no schedule and no occurrence — asserted by a test
    that counts rows in every scheduling table this platform has.

    What it means is narrower than it sounds: *a human may now be asked.*
    """
    _require_transition(lifecycle, ArtefactAccessState.VERIFICATION_READY.value)
    lifecycle.verification_ready_at = utcnow()
    return _transition(
        db, lifecycle, ArtefactAccessState.VERIFICATION_READY.value, actor_user_id
    )


def approve_verification(
    db: Session,
    lifecycle: ArtefactAccessLifecycle,
    *,
    approved_by_user_id: int,
) -> ArtefactAccessLifecycle:
    """A person says yes to verifying this artefact. Its own act, its own event.

    Separate from ``mark_verification_ready`` because the contract makes it
    separate, and separate from every other transition because *"a human
    authorised verification"* is the single most important thing this epic
    records — it must not be findable only by reading a generic transition
    event's payload.

    Authority is checked by the caller (the named leadership sponsor); what is
    checked here is that there was something to approve.
    """
    _require_transition(lifecycle, ArtefactAccessState.APPROVED.value)
    now = utcnow()
    lifecycle.verification_approved_at = now
    lifecycle.verification_approved_by_user_id = approved_by_user_id
    lifecycle.verification_approved_source = VerificationApprovalSource.PER_ARTEFACT.value
    lifecycle.state = ArtefactAccessState.APPROVED.value
    db.add(lifecycle)
    append_audit_event(
        db,
        lifecycle.organization_id,
        ACCESS_LIFECYCLE_AUDIT_VERIFICATION_APPROVED,
        actor_user_id=approved_by_user_id,
        metadata=_metadata(lifecycle),
    )
    return lifecycle


def inherit_standing_approval(
    db: Session, lifecycle: ArtefactAccessLifecycle
) -> ArtefactAccessLifecycle:
    """Approve verification from the organisation's standing Mode A decision.

    Søren's ruling, 2026-08-18: a standing approval satisfies the contract's
    *"verification is separately human-approved"* — under Mode A a human approves
    the cadence once, with a mandatory review date, and each run inherits it.

    So this is not a bypass, and it is written so it cannot become one. It
    resolves the *live* policy record — ``get_active_policy`` already returns
    ``None`` for a lapsed ``effective_to`` — refuses when none exists, refuses
    when the approved mode is not Mode A, and stores the policy's id, so "who
    approved this run?" resolves to a record a person signed rather than to the
    word "standing".
    """
    _require_transition(lifecycle, ArtefactAccessState.APPROVED.value)
    policy = get_active_policy(
        db,
        lifecycle.organization_id,
        ContextualAccessDecision.ACCESS_OPERATING_MODE.value,
    )
    if policy is None or policy.choice != AccessOperatingMode.SCHEDULED_AUTONOMOUS.value:
        raise ArtefactAccessLifecycleError(ACCESS_LIFECYCLE_ERROR_NO_STANDING_APPROVAL)

    lifecycle.verification_approved_at = utcnow()
    lifecycle.verification_approved_source = (
        VerificationApprovalSource.STANDING_OPERATING_MODE.value
    )
    lifecycle.verification_approval_policy_id = policy.id
    lifecycle.state = ArtefactAccessState.APPROVED.value
    db.add(lifecycle)
    append_audit_event(
        db,
        lifecycle.organization_id,
        ACCESS_LIFECYCLE_AUDIT_VERIFICATION_APPROVED,
        actor_user_id=None,
        metadata=_metadata(lifecycle),
    )
    return lifecycle


def mark_running(
    db: Session, lifecycle: ArtefactAccessLifecycle, *, actor_user_id: int | None = None
) -> ArtefactAccessLifecycle:
    """CA-08 reports that verification began. This module never causes that.

    The guard is the contract's rule read backwards: there is no edge into
    ``RUNNING`` except from ``APPROVED``, so a run against an artefact nobody
    approved cannot be recorded, let alone started.
    """
    if lifecycle.state != ArtefactAccessState.APPROVED.value:
        raise ArtefactAccessLifecycleError(ACCESS_LIFECYCLE_ERROR_NOT_APPROVED)
    lifecycle.running_at = utcnow()
    return _transition(db, lifecycle, ArtefactAccessState.RUNNING.value, actor_user_id)


def mark_complete(
    db: Session, lifecycle: ArtefactAccessLifecycle, *, actor_user_id: int | None = None
) -> ArtefactAccessLifecycle:
    _require_transition(lifecycle, ArtefactAccessState.COMPLETE.value)
    lifecycle.completed_at = utcnow()
    return _transition(db, lifecycle, ArtefactAccessState.COMPLETE.value, actor_user_id)


def mark_run_ended_without_completing(
    db: Session,
    lifecycle: ArtefactAccessLifecycle,
    *,
    actor_user_id: int | None = None,
) -> ArtefactAccessLifecycle:
    """CA-08.5 (#293) — a run stopped, and the artefact is not left mid-journey.

    #289 left the lifecycle in ``RUNNING`` on failure on purpose, because moving
    it to ``COMPLETE`` would make a failure indistinguishable from a success to
    every downstream reader. That was right, and it left the artefact stranded:
    ``RUNNING`` had exactly one way out, and it was the wrong one.

    The way out is back to ``APPROVED``. The approval stands — a run that broke
    is not somebody changing their mind — so the artefact returns to the state
    it was in before it started, ready to be run again by whoever is watching.

    ``running_at`` is cleared. Left set it would say a run is under way when
    none is, and *"how long has this been running?"* is a question the surface
    asks.
    """
    if lifecycle.state != ArtefactAccessState.RUNNING.value:
        raise ArtefactAccessLifecycleError(ACCESS_LIFECYCLE_ERROR_ILLEGAL_TRANSITION)
    lifecycle.running_at = None
    return _transition(db, lifecycle, ArtefactAccessState.APPROVED.value, actor_user_id)


def _require_transition(lifecycle: ArtefactAccessLifecycle, target: str) -> None:
    """One place that decides whether a move is legal, reading one map.

    Every state check goes through here, so the sequence cannot be widened by
    adding a branch somewhere — only by editing ``ARTEFACT_ACCESS_TRANSITIONS``,
    where the absence of a shortcut into ``RUNNING`` is visible at a glance.
    """
    allowed = ARTEFACT_ACCESS_TRANSITIONS.get(lifecycle.state, ())
    if target not in allowed:
        raise ArtefactAccessLifecycleError(
            ACCESS_LIFECYCLE_ERROR_ILLEGAL_TRANSITION.format(
                current=lifecycle.state, target=target
            )
        )


def _transition(
    db: Session, lifecycle: ArtefactAccessLifecycle, target: str, actor_user_id: int | None
) -> ArtefactAccessLifecycle:
    previous = lifecycle.state
    lifecycle.state = target
    db.add(lifecycle)
    append_audit_event(
        db,
        lifecycle.organization_id,
        ACCESS_LIFECYCLE_AUDIT_TRANSITIONED,
        actor_user_id=actor_user_id,
        metadata={**_metadata(lifecycle), "from_state": previous},
    )
    return lifecycle


def _metadata(lifecycle: ArtefactAccessLifecycle) -> dict:
    return {
        "lifecycle_id": lifecycle.id,
        "asset_id": lifecycle.asset_id,
        "state": lifecycle.state,
        "requested_choice": lifecycle.requested_choice,
        "connector_id": lifecycle.connector_id,
        "access_test_id": lifecycle.access_test_id,
        "verification_approved_source": lifecycle.verification_approved_source,
        "verification_approval_policy_id": lifecycle.verification_approval_policy_id,
    }
