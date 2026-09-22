"""CA-07.5 — the seven access states, and the boundary the whole epic rests on.

The contract names them: *"Support ACCESS_REQUESTED, CONFIGURED, TESTED,
VERIFICATION_READY, APPROVED, RUNNING and COMPLETE."* And it names the rule they
exist to make visible: **"Access does not start verification. Verification is
separately human-approved."**

That rule is why ``VERIFICATION_READY`` and ``APPROVED`` are two states rather
than one. A single "ready" state would make being ready and being allowed the
same fact, and the moment they are the same fact, arriving at readiness is
arriving at permission. Here, ``VERIFICATION_READY`` means only *a human may now
be asked*. Nothing is scheduled, queued or dispatched on entry — asserted by a
test that fails if any scheduling table gains a row.

**This lifecycle is a second, independent state on an artefact.** CA-06 already
gives an artefact an *identity* lifecycle (in the inventory / not yet reviewed /
outside the approved boundary). An artefact can be confirmed with no access, or
unconfirmed with access already approved. Overloading one field would make two
questions look like one answer, so this is its own record with its own vocabulary
— and CA-07.6's surface must show both at once.

It is also independent of the Connector's own withdrawal state (CA-07.4). A
Connector is paused, revoked or disconnected; an artefact's access is requested,
tested, approved, running. The two answer different questions about different
things, and a revoked Connector does not rewrite the history of an access journey
that already completed.
"""

from enum import StrEnum


class ArtefactAccessState(StrEnum):
    """The seven states, in the order the contract lists them."""

    # A person chose "connect host" or "grant access" for this artefact. A
    # recorded decision, not a scan — CA-07.1 produces it.
    ACCESS_REQUESTED = "access_requested"
    # A Connector exists for it (CA-07.2) with an approved permission profile
    # (CA-07.3). The route to the artefact is described; nothing has been tried.
    CONFIGURED = "configured"
    # A connection test succeeded (CA-07.4): reachable, and the approved
    # permissions were adequate. Still nothing has been read about the estate.
    TESTED = "tested"
    # Everything access can establish is established. **A human may now be
    # asked.** This state starts nothing, and the test that proves it is the
    # single most important test in this epic.
    VERIFICATION_READY = "verification_ready"
    # A human said yes — either per artefact, or through the organisation's
    # standing Mode A approval, which Søren ruled satisfies the contract's
    # "separately human-approved" (2026-08-18).
    APPROVED = "approved"
    # CA-08 is executing. Entered by the verification run reporting that it
    # began, never by this module deciding to begin one.
    RUNNING = "running"
    COMPLETE = "complete"


#: The only legal moves. A dict rather than a chain of ``if`` statements, per
#: the repo's mapping rule — and readable as a whole, which is what makes it
#: possible to see that there is no edge from anywhere into ``RUNNING`` except
#: through ``APPROVED``. That single absence is the contract's rule expressed as
#: data: nothing can start without a human having said yes first.
ARTEFACT_ACCESS_TRANSITIONS: dict[str, tuple[str, ...]] = {
    ArtefactAccessState.ACCESS_REQUESTED.value: (ArtefactAccessState.CONFIGURED.value,),
    ArtefactAccessState.CONFIGURED.value: (ArtefactAccessState.TESTED.value,),
    ArtefactAccessState.TESTED.value: (ArtefactAccessState.VERIFICATION_READY.value,),
    ArtefactAccessState.VERIFICATION_READY.value: (ArtefactAccessState.APPROVED.value,),
    ArtefactAccessState.APPROVED.value: (ArtefactAccessState.RUNNING.value,),
    # CA-08.5 (#293) — ``APPROVED`` is the way *out* of a run that did not
    # finish, and adding it is what stops a failed verification stranding an
    # artefact in ``RUNNING`` for ever. #289 left that deliberately open.
    #
    # Back to APPROVED rather than VERIFICATION_READY: the person approved
    # verification of this artefact and a failure does not withdraw that. Asking
    # them again would treat a broken run as a change of mind.
    #
    # The contract's rule survives intact — the only edge *into* ``RUNNING`` is
    # still from ``APPROVED``, so nothing can start without a human having said
    # yes, and a re-run happens under the approval already given.
    ArtefactAccessState.RUNNING.value: (
        ArtefactAccessState.COMPLETE.value,
        ArtefactAccessState.APPROVED.value,
    ),
    ArtefactAccessState.COMPLETE.value: (),
}


#: CA-07.6 (#240) — the states where the journey is waiting on a person rather
#: than on the platform. Defined here, beside the states themselves, so the
#: inventory surface cannot answer "does this need me?" differently from the
#: lifecycle that owns the question.
#:
#: ``VERIFICATION_READY`` is the one that matters: it means *a human may now be
#: asked*, and if the surface did not mark it, the state would sit there
#: indefinitely looking like progress. ``ACCESS_REQUESTED`` and ``CONFIGURED``
#: are included because each advances only when a person does something — sets a
#: Connector up, runs a test.
#:
#: ``TESTED`` is **not** included: the move to ``VERIFICATION_READY`` is the
#: platform's own evaluation of what it has, not a decision anybody makes.
#: ``APPROVED``, ``RUNNING`` and ``COMPLETE`` are past the last human gate.
ACCESS_STATES_AWAITING_A_PERSON: frozenset[str] = frozenset(
    {
        ArtefactAccessState.ACCESS_REQUESTED.value,
        ArtefactAccessState.CONFIGURED.value,
        ArtefactAccessState.VERIFICATION_READY.value,
    }
)


class VerificationApprovalSource(StrEnum):
    """Where the human "yes" came from, recorded because the two differ.

    Søren's ruling (2026-08-18) is that a **standing** approval satisfies the
    contract's *"verification is separately human-approved"*: under Mode A a human
    approves the cadence once, with a mandatory review date, and each run inherits
    that approval. Both are genuine human approvals — but an auditor asking *"who
    approved this run?"* deserves to know whether somebody looked at this artefact
    or at a policy months earlier, so the answer is stored rather than flattened.
    """

    #: A person approved this artefact's verification, now.
    PER_ARTEFACT = "per_artefact"
    #: Inherited from the organisation's approved Mode A operating decision.
    STANDING_OPERATING_MODE = "standing_operating_mode"


# --- Audit events ---------------------------------------------------------

ACCESS_LIFECYCLE_AUDIT_REQUESTED = "artefact_access_requested"
ACCESS_LIFECYCLE_AUDIT_TRANSITIONED = "artefact_access_transitioned"
# Its own event. "A human authorised verification" is the single most important
# thing this epic records, and it must never be findable only by reading a
# generic transition event's payload.
ACCESS_LIFECYCLE_AUDIT_VERIFICATION_APPROVED = "artefact_access_verification_approved"


# --- Errors ---------------------------------------------------------------

ACCESS_LIFECYCLE_ERROR_ADMIN_REQUIRED = (
    "Organisation administrator access is required to manage deeper access to an artefact"
)
ACCESS_LIFECYCLE_ERROR_NOT_FOUND = "No access lifecycle exists for this artefact"
ACCESS_LIFECYCLE_ERROR_ARTEFACT_NOT_FOUND = "Artefact not found"
ACCESS_LIFECYCLE_ERROR_ALREADY_STARTED = (
    "Deeper access to this artefact has already been requested"
)
ACCESS_LIFECYCLE_ERROR_ILLEGAL_TRANSITION = (
    "Access cannot move from {current} to {target}. The states run in order, so that nothing "
    "reaches verification without having been configured, tested and approved first"
)
ACCESS_LIFECYCLE_ERROR_CHOICE_DOES_NOT_REQUEST_ACCESS = (
    "'{choice}' does not ask for deeper access, so there is no access to configure. Only "
    "connecting a host or granting access starts this"
)
ACCESS_LIFECYCLE_ERROR_DEVIATION_REASON_REQUIRED = (
    "This artefact departs from your organisation's standing answer, so it needs a recorded "
    "reason. Agreeing with the default costs nothing to say"
)
ACCESS_LIFECYCLE_ERROR_CONNECTOR_REQUIRED = (
    "Configuring access means naming the Connector that reaches this artefact"
)
ACCESS_LIFECYCLE_ERROR_CONNECTOR_NOT_USABLE = (
    "That Connector is {status} and may not be used, so access to this artefact cannot be "
    "configured through it"
)
ACCESS_LIFECYCLE_ERROR_NO_APPROVED_PROFILE = (
    "That Connector has no approved permission profile, so what it may do has not been decided yet"
)
ACCESS_LIFECYCLE_ERROR_NO_SUCCESSFUL_TEST = (
    "Access has not been proven to work. Run a connection test that succeeds before saying it "
    "was tested"
)
# The one that matters most. Reaching readiness is not permission, and the error
# says so in the words a person would use.
ACCESS_LIFECYCLE_ERROR_NOT_APPROVED = (
    "Verification has not been approved for this artefact. Being ready for verification is not "
    "the same as being allowed to verify — a person still has to say yes"
)
ACCESS_LIFECYCLE_ERROR_NO_STANDING_APPROVAL = (
    "Your organisation has no approved scheduled-access decision, so there is no standing "
    "approval for a run to inherit. Approve this artefact's verification instead"
)
ACCESS_LIFECYCLE_ERROR_APPROVER_REQUIRED = (
    "Only the organisation's named leadership sponsor may approve verification"
)
