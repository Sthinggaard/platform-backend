"""CA-07.0 — the lifecycle of the organisation's contextual-access decisions.

Mirrors ``risk_appetite_resolution_service`` and
``leadership_authorization_service``: draft -> leadership_review -> active ->
superseded/withdrawn, prepared by an administrator, approved by the named
leadership sponsor. Append-only — approving a new version supersedes the
previous active one rather than mutating it, so the decision's history stays
answerable.

Two rules in here are the story's whole point and are worth naming:

- ``resolve_*`` returns ``None`` when no decision has been approved. There is no
  fallback and no implied default anywhere in this module. An operating mode
  that was never chosen must read as *not chosen*, never as an inferred one.
- ``deviates_from_standing_default`` is the only place that decides whether a
  per-artefact access choice needs structured reasoning. The standing default
  supplies the answer; it never removes a choice.

The caller owns the transaction (commit), matching the services this follows.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from src.core.constants.contextual_access_enums import (
    CONTEXTUAL_ACCESS_CONSEQUENCES,
    CONTEXTUAL_ACCESS_DECISION_CHOICES,
    CONTEXTUAL_ACCESS_ERROR_CONSEQUENCE_NOT_ACKNOWLEDGED,
    CONTEXTUAL_ACCESS_ERROR_RECURRENCE_UNAVAILABLE,
    CONTEXTUAL_ACCESS_ERROR_REVIEW_DATE_REQUIRED,
    AccessOperatingMode,
    ArtefactAccessChoice,
    ContextualAccessDecision,
    ContextualAccessPolicyStatus,
)
from src.core.model_defs.common import naive_utc, utcnow
from src.core.model_defs.contextual_access_policy import ContextualAccessPolicy


class ContextualAccessPolicyValidationError(ValueError):
    """Raised when a contextual-access decision transition is invalid."""


def recurrence_primitive_available() -> bool:
    """Whether this platform can actually run an approved cadence.

    Returned ``False`` until #242 landed: there was no cron, interval or
    ``next_run_at`` anywhere in the codebase, so an approved Mode A would have
    been an intention that never ran. ``RecurrenceSchedule`` now exists, is
    swept on a cadence, and lapses when its authorising approval does — so a
    Mode A approval can be honoured, and this says so.

    Kept as a predicate rather than deleted: it is the one place the question
    "can we actually do what we are about to approve?" is asked, and a future
    capability that Mode A depends on belongs here rather than as a second
    check somewhere else.
    """
    return True


def _validate_choice(decision: str, choice: str) -> None:
    permitted = CONTEXTUAL_ACCESS_DECISION_CHOICES.get(decision)
    if permitted is None:
        raise ContextualAccessPolicyValidationError(
            f"Unknown contextual access decision '{decision}'."
        )
    if choice not in permitted:
        raise ContextualAccessPolicyValidationError(
            f"'{choice}' is not a valid answer for the '{decision}' decision."
        )


def consequence_for(choice: str) -> str:
    """The canonical business-language consequence of a choice.

    Read at draft time and snapshotted onto the record, so the approved decision
    keeps the words the approver actually saw.
    """
    statement = CONTEXTUAL_ACCESS_CONSEQUENCES.get(choice)
    if statement is None:
        raise ContextualAccessPolicyValidationError(
            f"No consequence is defined for '{choice}'. A choice whose consequence cannot be "
            "stated cannot be offered for approval."
        )
    return statement


def get_active_policy(
    db: Session, organization_id: int, decision: str
) -> ContextualAccessPolicy | None:
    """The organisation's current active record for one decision, if any.

    Deliberately returns ``None`` rather than a default: a decision that was
    never made must never look like one that was.
    """
    now = utcnow()
    policy = (
        db.query(ContextualAccessPolicy)
        .filter(
            ContextualAccessPolicy.organization_id == organization_id,
            ContextualAccessPolicy.decision == decision,
            ContextualAccessPolicy.status == ContextualAccessPolicyStatus.ACTIVE.value,
        )
        .order_by(ContextualAccessPolicy.version.desc())
        .first()
    )
    if policy is None:
        return None
    # An approval that has lapsed is not an active decision, whatever the row says.
    if policy.effective_to is not None and naive_utc(policy.effective_to) <= naive_utc(now):
        return None
    return policy


def resolve_operating_mode(db: Session, organization_id: int) -> str | None:
    """The organisation's approved operating mode, or ``None`` if never decided."""
    policy = get_active_policy(
        db, organization_id, ContextualAccessDecision.ACCESS_OPERATING_MODE.value
    )
    return policy.choice if policy else None


def resolve_deeper_access_default(db: Session, organization_id: int) -> str | None:
    """The organisation's standing default answer, or ``None`` if never decided.

    ``None`` means every artefact is an explicit per-artefact decision. That is
    more clicks, not fewer options — the five choices are always available
    either way.
    """
    policy = get_active_policy(
        db, organization_id, ContextualAccessDecision.DEEPER_ACCESS_DEFAULT.value
    )
    return policy.choice if policy else None


def deviates_from_default(standing_default: str | None, choice: str) -> bool:
    """Whether a per-artefact choice owes a recorded reason.

    The one definition of that rule. Pure, so a surface that has already
    resolved the standing default can classify all five choices without five
    more queries — and cannot express the rule slightly differently while doing
    so.

    This never answers "is this choice allowed" — every choice is allowed. It
    answers "does this one owe an explanation". With no standing default there
    is nothing to deviate from, and every artefact decision is deliberate on its
    own terms.
    """
    if standing_default is None:
        return False
    return choice != standing_default


def deviates_from_standing_default(db: Session, organization_id: int, choice: str) -> bool:
    """``deviates_from_default`` against the organisation's own standing default.

    The platform's existing decision idiom, applied unchanged: taking the
    recommended route is a single confirm; taking any other shows the
    consequence and requires a recorded reason. Here the standing default *is*
    the recommended route.
    """
    _validate_choice(ContextualAccessDecision.DEEPER_ACCESS_DEFAULT.value, choice)
    return deviates_from_default(resolve_deeper_access_default(db, organization_id), choice)


def create_policy_draft(
    db: Session,
    *,
    organization_id: int,
    decision: str,
    choice: str,
    prepared_by: str,
    review_at: datetime | None = None,
    effective_to: datetime | None = None,
    note: str | None = None,
) -> ContextualAccessPolicy:
    """Prepare a versioned decision for human approval, without activating it.

    Both modes can be in flight at once: an organisation running Mode B may
    prepare a Mode A draft for review, and preparing it changes nothing until
    someone approves it.
    """
    _validate_choice(decision, choice)

    if choice == AccessOperatingMode.SCHEDULED_AUTONOMOUS.value:
        # Standing permission that never expires is a default, not a decision —
        # the same rule appetite exceptions are already held to.
        if review_at is None:
            raise ContextualAccessPolicyValidationError(
                CONTEXTUAL_ACCESS_ERROR_REVIEW_DATE_REQUIRED
            )
    if review_at is not None and naive_utc(review_at) <= naive_utc(utcnow()):
        raise ContextualAccessPolicyValidationError("A review date must be in the future.")
    if effective_to is not None and naive_utc(effective_to) <= naive_utc(utcnow()):
        raise ContextualAccessPolicyValidationError("An expiry date must be in the future.")

    latest = (
        db.query(ContextualAccessPolicy)
        .filter(
            ContextualAccessPolicy.organization_id == organization_id,
            ContextualAccessPolicy.decision == decision,
        )
        .order_by(ContextualAccessPolicy.version.desc())
        .first()
    )
    policy = ContextualAccessPolicy(
        organization_id=organization_id,
        decision=decision,
        choice=choice,
        status=ContextualAccessPolicyStatus.DRAFT.value,
        version=(latest.version + 1) if latest else 1,
        consequence_statement=consequence_for(choice),
        prepared_by=prepared_by,
        review_at=naive_utc(review_at) if review_at else None,
        effective_to=naive_utc(effective_to) if effective_to else None,
        note=note,
    )
    db.add(policy)
    db.flush()
    return policy


def submit_policy_draft(
    db: Session, policy: ContextualAccessPolicy, *, submitted_by: str
) -> ContextualAccessPolicy:
    """Send a prepared decision to the named leadership sponsor for approval."""
    if policy.status != ContextualAccessPolicyStatus.DRAFT.value:
        raise ContextualAccessPolicyValidationError(
            "Only a contextual access draft can be submitted."
        )
    policy.status = ContextualAccessPolicyStatus.LEADERSHIP_REVIEW.value
    policy.submitted_by = submitted_by
    policy.submitted_at = utcnow()
    db.add(policy)
    return policy


def approve_policy_draft(
    db: Session,
    policy: ContextualAccessPolicy,
    *,
    approved_by: str,
    consequence_acknowledged: bool,
    approval_reference: str | None = None,
    effective_from: datetime | None = None,
) -> ContextualAccessPolicy:
    """Activate a decision the leadership sponsor has approved, superseding the previous one."""
    if policy.status != ContextualAccessPolicyStatus.LEADERSHIP_REVIEW.value:
        raise ContextualAccessPolicyValidationError(
            "Only a contextual access decision awaiting leadership review can be approved."
        )
    if not consequence_acknowledged:
        raise ContextualAccessPolicyValidationError(
            CONTEXTUAL_ACCESS_ERROR_CONSEQUENCE_NOT_ACKNOWLEDGED
        )
    if (
        policy.choice == AccessOperatingMode.SCHEDULED_AUTONOMOUS.value
        and not recurrence_primitive_available()
    ):
        raise ContextualAccessPolicyValidationError(
            CONTEXTUAL_ACCESS_ERROR_RECURRENCE_UNAVAILABLE
        )

    predecessor = (
        db.query(ContextualAccessPolicy)
        .filter(
            ContextualAccessPolicy.organization_id == policy.organization_id,
            ContextualAccessPolicy.decision == policy.decision,
            ContextualAccessPolicy.status == ContextualAccessPolicyStatus.ACTIVE.value,
        )
        .order_by(ContextualAccessPolicy.version.desc())
        .first()
    )
    policy.status = ContextualAccessPolicyStatus.ACTIVE.value
    policy.approved_by = approved_by
    policy.approved_at = utcnow()
    policy.approval_reference = approval_reference
    policy.consequence_acknowledged = True
    policy.effective_from = naive_utc(effective_from or utcnow())
    if predecessor is not None:
        predecessor.status = ContextualAccessPolicyStatus.SUPERSEDED.value
        predecessor.superseded_by_id = policy.id
        db.add(predecessor)
    db.add(policy)
    return policy


def reject_policy_draft(
    db: Session,
    policy: ContextualAccessPolicy,
    *,
    rejected_by: str,
    rejection_reason: str,
) -> ContextualAccessPolicy:
    """Withdraw a submitted decision while keeping its history."""
    if policy.status != ContextualAccessPolicyStatus.LEADERSHIP_REVIEW.value:
        raise ContextualAccessPolicyValidationError(
            "Only a contextual access decision awaiting leadership review can be rejected."
        )
    if not rejection_reason.strip():
        raise ContextualAccessPolicyValidationError("A rejection reason is required.")
    policy.status = ContextualAccessPolicyStatus.WITHDRAWN.value
    policy.rejected_by = rejected_by
    policy.rejected_at = utcnow()
    policy.rejection_reason = rejection_reason.strip()
    db.add(policy)
    return policy


def available_artefact_access_choices() -> tuple[str, ...]:
    """Every per-artefact access choice, always.

    A function rather than a passthrough constant so there is one obvious place
    to look for a filter — and to find that there isn't one. The standing
    default never narrows this list; see ``deviates_from_standing_default``.
    """
    return tuple(choice.value for choice in ArtefactAccessChoice)
