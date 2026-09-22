"""CA-07.0 — the vocabulary of the organisation's own contextual-access decisions.

Two governed decisions share one lifecycle here because they are the same kind
of decision: an organisation-scoped standing choice about its own risk, made by
a named human, versioned and superseded rather than edited.

1. ``ACCESS_OPERATING_MODE`` — does deeper access run unattended on a cadence
   (Mode A) or only when a person triggers it (Mode B)? The two modes demand
   different credential models, which is why this gates CA-07.2 rather than
   being an assumption inside it.
2. ``DEEPER_ACCESS_DEFAULT`` — which of the five per-artefact access choices is
   the organisation's standing default answer.

**The second one is a default, not a gate.** ``CLAUDE.md:217`` — *"Decision
options always available (user is never locked out)"*. There is deliberately no
"permitted choices" or "allowed set" concept anywhere in this module: a policy
that withdrew an option would lock the user out, and would be exactly how a
blanket answer turns a real gap into an invisible one. The default supplies the
answer so the common case costs zero clicks; deviating for one artefact costs a
recorded reason, which is precisely how the intervention flow already treats the
recommended route versus any other.
"""

from enum import StrEnum


class ContextualAccessDecision(StrEnum):
    """Which organisational decision a policy record carries."""

    ACCESS_OPERATING_MODE = "access_operating_mode"
    DEEPER_ACCESS_DEFAULT = "deeper_access_default"


class AccessOperatingMode(StrEnum):
    """How deeper access runs, once an organisation has decided.

    Both are supported and both hold value. Choosing one does not remove the
    other — an organisation may run Mode B in production while preparing a
    Mode A decision for review.
    """

    # Mode A — a cadence triggers it; nobody is present at run time, so a
    # usable credential must be resident on the Collector and the approval
    # must be standing.
    SCHEDULED_AUTONOMOUS = "scheduled_autonomous"
    # Mode B — a person triggers it against a Business Process, so the
    # credential can be supplied per run and nothing durable is stored.
    PROCESS_TRIGGERED = "process_triggered"


class ArtefactAccessChoice(StrEnum):
    """The five per-artefact access choices named by the CA-07 checklist.

    Defined here rather than in CA-07.1 because the standing default (decision
    2 above) has to name one of them, and the same vocabulary must not be
    declared twice. CA-07.1 builds the per-artefact surface that offers all
    five; this module only records which one is the standing default.
    """

    CONNECT_HOST = "connect_host"
    GRANT_ACCESS = "grant_access"
    NETWORK_ONLY = "network_only"
    EXCLUDE = "exclude"
    REVIEW_LATER = "review_later"


class ContextualAccessPolicyStatus(StrEnum):
    """Same lifecycle as RiskAppetitePolicy and LeadershipAuthorization."""

    DRAFT = "draft"
    LEADERSHIP_REVIEW = "leadership_review"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


# The choice each decision accepts. Kept as one mapping so a new choice cannot
# be added to an enum and silently accepted by the wrong decision.
CONTEXTUAL_ACCESS_DECISION_CHOICES: dict[str, tuple[str, ...]] = {
    ContextualAccessDecision.ACCESS_OPERATING_MODE.value: tuple(m.value for m in AccessOperatingMode),
    ContextualAccessDecision.DEEPER_ACCESS_DEFAULT.value: tuple(c.value for c in ArtefactAccessChoice),
}


# --- Consequences, in business language -----------------------------------
#
# The acceptance criterion is that the consequence is stated *before* approval.
# These are the canonical statements; the approved record snapshots the text it
# actually showed, so the audit trail answers "what were they told?" rather than
# "what does today's copy say?".

CONSEQUENCE_SCHEDULED_AUTONOMOUS = (
    "Deeper access will run on a schedule with nobody watching. A credential that can reach "
    "your systems lives on the Collector until this decision is withdrawn or lapses."
)
CONSEQUENCE_PROCESS_TRIGGERED = (
    "Nothing runs unless a person starts it against a Business Process. No credential is kept "
    "after the run, so nothing can be used without someone present."
)

CONTEXTUAL_ACCESS_CONSEQUENCES: dict[str, str] = {
    AccessOperatingMode.SCHEDULED_AUTONOMOUS.value: CONSEQUENCE_SCHEDULED_AUTONOMOUS,
    AccessOperatingMode.PROCESS_TRIGGERED.value: CONSEQUENCE_PROCESS_TRIGGERED,
    ArtefactAccessChoice.CONNECT_HOST.value: (
        "Unless someone decides otherwise for a specific item, we will ask to connect to the host "
        "so we can answer what the network alone cannot."
    ),
    ArtefactAccessChoice.GRANT_ACCESS.value: (
        "Unless someone decides otherwise for a specific item, deeper access is granted by default."
    ),
    ArtefactAccessChoice.NETWORK_ONLY.value: (
        "Unless someone decides otherwise for a specific item, we stay on the network. Anything "
        "that cannot be determined from network evidence stays unknown — and we will still say so."
    ),
    ArtefactAccessChoice.EXCLUDE.value: (
        "Unless someone decides otherwise for a specific item, it is left out of scope entirely."
    ),
    ArtefactAccessChoice.REVIEW_LATER.value: (
        "Unless someone decides otherwise for a specific item, the decision is deferred and the "
        "item stays on someone's list."
    ),
}


# --- Audit events ---------------------------------------------------------

CONTEXTUAL_ACCESS_AUDIT_DRAFT_CREATED = "contextual_access_policy_draft_created"
CONTEXTUAL_ACCESS_AUDIT_SUBMITTED = "contextual_access_policy_submitted_for_review"
CONTEXTUAL_ACCESS_AUDIT_APPROVED = "contextual_access_policy_approved"
CONTEXTUAL_ACCESS_AUDIT_REJECTED = "contextual_access_policy_rejected"


# --- Errors ---------------------------------------------------------------

CONTEXTUAL_ACCESS_ERROR_ADMIN_REQUIRED = (
    "Organisation administrator access is required to prepare a contextual access decision"
)
CONTEXTUAL_ACCESS_ERROR_LEADERSHIP_SPONSOR_REQUIRED = (
    "Only the organisation's named leadership sponsor may approve or reject a contextual access decision"
)
CONTEXTUAL_ACCESS_ERROR_NOT_FOUND = "Contextual access decision not found"
CONTEXTUAL_ACCESS_ERROR_REVIEW_DATE_REQUIRED = (
    "Scheduled autonomous access requires a review date — standing permission that never expires "
    "is a default, not a decision"
)
CONTEXTUAL_ACCESS_ERROR_CONSEQUENCE_NOT_ACKNOWLEDGED = (
    "The consequence of this decision must be shown and acknowledged before it can be approved"
)
# CA-07.0 records the decision; #242 builds the schedule that makes Mode A run.
# Approving a mode the platform cannot honour would tell an organisation its
# systems are scanned every 30 days while nothing ever runs — the exact failure
# #242 names. Lifted when the recurrence primitive lands.
CONTEXTUAL_ACCESS_ERROR_RECURRENCE_UNAVAILABLE = (
    "Scheduled autonomous access cannot be approved yet: this platform has no recurrence schedule, "
    "so an approved cadence would never actually run. Process-triggered access is available now."
)
