"""CA-08.1 (#289) — the vocabulary of a verification that actually happened.

CA-07 built the lifecycle up to ``APPROVED`` and stopped there on purpose:
*"a human may now be asked"* is not *"something is running"*. ``mark_running``
and ``mark_complete`` have existed since then with **no caller**, waiting for
this epic to be the thing that calls them.

What was missing is the record itself. The lifecycle says an artefact reached
``RUNNING``; it cannot say what was verified, under whose approval, bounded by
which permission profile, or what came of it. A state is not an account of what
was done, and CA-08's contract is about evidence.
"""

from enum import StrEnum


class VerificationRunStatus(StrEnum):
    """Where a run is, from the only place it may start.

    There is no ``PENDING``. A run exists because it began; something merely
    intended is an approval, and the lifecycle already records those.
    """

    RUNNING = "running"
    COMPLETED = "completed"
    #: It ran and did not finish. Distinct from CANCELLED, which is somebody's
    #: decision — "it broke" and "we stopped it" are different facts about the
    #: organisation and must not look alike in a ledger.
    FAILED = "failed"
    CANCELLED = "cancelled"


#: A run in one of these is finished with; nothing revisits it.
VERIFICATION_RUN_TERMINAL = (
    VerificationRunStatus.COMPLETED.value,
    VerificationRunStatus.FAILED.value,
    VerificationRunStatus.CANCELLED.value,
)


class VerificationApprovalSource(StrEnum):
    """Which human decision this run is acting on.

    Recorded on the run rather than looked up later, because the approval it ran
    under is the question an auditor asks first and the policy behind it may be
    superseded by then. Mirrors the lifecycle's own
    ``verification_approved_source`` so the two cannot disagree.
    """

    #: Somebody approved this artefact.
    PER_ARTEFACT = "per_artefact"
    #: The organisation's standing Mode A decision, which Søren ruled satisfies
    #: the contract's "separately human-approved" (2026-08-18).
    STANDING = "standing"


# --- Audit events ---------------------------------------------------------

VERIFICATION_RUN_AUDIT_BEGAN = "verification_run_began"
VERIFICATION_RUN_AUDIT_COMPLETED = "verification_run_completed"
VERIFICATION_RUN_AUDIT_FAILED = "verification_run_failed"
#: CA-08.5 (#293) — somebody stopped it. Its own event because "we stopped it"
#: and "it broke" are different facts about the organisation, and only one of
#: them is a defect worth anybody's attention.
VERIFICATION_RUN_AUDIT_CANCELLED = "verification_run_cancelled"


# --- Errors ---------------------------------------------------------------

#: The epic's central rule, and the one this message exists to make legible.
#: What a reader is told when a run stopped because its Collector did. Business
#: language, per the platform's own rule: never "heartbeat timeout".
VERIFICATION_RUN_COLLECTOR_LOST = (
    "The Collector stopped reporting while this was running, so the examination could not "
    "finish. It will need to be started again once the Collector is back."
)

#: What a reader is told when a person stopped it.
VERIFICATION_RUN_CANCELLED_BY_PERSON = "Stopped before it finished."

VERIFICATION_RUN_ERROR_NOT_APPROVED = (
    "Verification cannot begin until a person has approved it for this artefact. "
    "Being ready for that question is not an answer to it"
)
VERIFICATION_RUN_ERROR_ALREADY_RUNNING = (
    "This artefact is already being verified"
)
VERIFICATION_RUN_ERROR_ALREADY_FINISHED = (
    "That verification run has already finished, and a finished run is not reopened"
)
VERIFICATION_RUN_ERROR_NO_PROFILE = (
    "Verification needs an approved permission profile, so that what it may reach "
    "is decided before it reaches anything"
)
