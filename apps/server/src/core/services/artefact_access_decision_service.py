"""CA-07.1 (#235) — the five choices, recorded as decisions, starting nothing.

The story: *a technical owner is shown what the platform does and does not know
about an artefact, and what deeper access would add, so that granting access is a
decision rather than a prompt they click past.*

Three rules from the checklist are enforced here rather than left to callers,
because each is a way the record could quietly become dishonest:

1. **All five choices are recordable.** ``network_only`` and ``review_later`` are
   answers, not the absence of one, and until now nothing could store them.
   ``exclude`` is recorded too — and *only* recorded; see below.
2. **A choice is measured against the standing default at the moment it is made**,
   and a deviation owes a reason. The comparison is snapshotted onto the row,
   because the policy is versioned and the answer to "was this a deviation?" must
   not change when the policy is later superseded.
3. **Choosing starts nothing.** The two access-seeking choices begin CA-07.5's
   lifecycle, which is a record of intent, not a scan. Nothing here schedules,
   queues or dispatches anything, and a test asserts it.

**Why ``exclude`` is recorded but not enacted.** The checklist says exclusion must
route through CA-06.5's boundary path *rather than a second mechanism*. The
temptation is to stamp ``lifecycle_state = WITHDRAWN`` from this call — and that
would **be** the second mechanism. CA-06.5 withdraws an artefact because an
*approved boundary* excludes it, and that boundary needs the Technical Setup
Owner or manager tier to approve it (CA-05.B). One person clicking "exclude" on
one row is not that approval, and honouring it directly would let a per-artefact
click bypass the governance the boundary exists to carry. So the decision is
recorded with attribution, and enacting it stays where it already lives.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.artefact_identity_evidence_enums import (
    IDENTITY_UNDETERMINED_EXPLANATION,
    ArtefactIdentityUndetermined,
)
from src.core.constants.contextual_access_enums import ArtefactAccessChoice
from src.core.model_defs.artefact_access_decision import ArtefactAccessDecision
from src.core.model_defs.assets_runtime import Asset
from src.core.services.artefact_access_lifecycle_service import (
    ACCESS_SEEKING_CHOICES,
    request_access,
)
from src.core.services.audit_service import append_audit_event
from src.core.services.contextual_access_policy_service import (
    deviates_from_standing_default,
    resolve_deeper_access_default,
)

#: One audit event per answer, whatever the answer was. A trail that only records
#: the choices which sought access would show a reviewer a history of requests
#: and none of the refusals, which is a different story from the one that happened.
ACCESS_DECISION_AUDIT_RECORDED = "artefact_access_decision_recorded"

ACCESS_DECISION_ERROR_UNKNOWN_CHOICE = (
    "'{choice}' is not one of the five access choices"
)
ACCESS_DECISION_ERROR_DEVIATION_REASON_REQUIRED = (
    "This artefact departs from your organisation's standing answer, so it needs a recorded "
    "reason before it can be saved"
)
ACCESS_DECISION_ERROR_ARTEFACT_NOT_FOUND = "Artefact not found"

#: What each choice would *answer*, never what it would run. The checklist's second
#: criterion in one place, so the surface composes from a single source and cannot
#: describe the same choice two ways on two screens.
ACCESS_CHOICE_ANSWERS: dict[str, str] = {
    ArtefactAccessChoice.CONNECT_HOST.value: (
        "Would tell you what this is, what it runs, and what it depends on — read from the "
        "host itself rather than guessed from the outside."
    ),
    ArtefactAccessChoice.GRANT_ACCESS.value: (
        "Would tell you what this service holds and who can reach it, using an account you "
        "authorise for the purpose."
    ),
    ArtefactAccessChoice.NETWORK_ONLY.value: (
        "Keeps to what can be seen from the network. You will know it exists and what it "
        "answers on, and not what it is or what it holds."
    ),
    ArtefactAccessChoice.EXCLUDE.value: (
        "Takes this out of scope. Nothing further is asked about it, and nothing will depend "
        "on it in your resilience picture."
    ),
    ArtefactAccessChoice.REVIEW_LATER.value: (
        "Leaves the question open and keeps it on the list. Nothing is assumed about it in "
        "the meantime."
    ),
}


class ArtefactAccessDecisionError(ValueError):
    """A decision was refused. Distinct from ValueError so a route can map it to
    a 4xx without swallowing a genuine programming error."""


@dataclass(frozen=True)
class ArtefactAccessQuestion:
    """What a person is being asked about one artefact, and on what evidence.

    The whole story in one shape: what we know, what we do not, what each choice
    would answer, and what the organisation has already decided by default.
    """

    asset_id: int
    display_name: str
    #: Null when the artefact has a determined name — there is no gap to state.
    identity_undetermined_reason: str | None
    #: The gap in the reader's words, or null when there is none.
    unknown_statement: str | None
    #: True only for ``PROBED_NOTHING_IDENTIFYING``: we looked and could not tell.
    #: The other two reasons are not arguments for credentials, and saying so is
    #: the difference between asking for access and asking for it *honestly*.
    deeper_access_would_help: bool
    #: All five, always. The standing default never narrows this.
    choices: tuple[str, ...]
    #: What each would answer, keyed by choice.
    choice_answers: dict[str, str]
    #: The organisation's standing answer, or null if none is approved.
    standing_default: str | None
    #: The decision currently standing on this artefact, if one has been taken.
    current_choice: str | None


def describe_access_question(
    db: Session, *, organization_id: int, asset: Asset
) -> ArtefactAccessQuestion:
    """What to put in front of a person for this artefact.

    Composed rather than stored: the identity gap comes from the evidence on the
    artefact, the default from the organisation's approved policy, and the
    standing decision from this table. None of the three is a copy of another.
    """
    reason = _identity_undetermined_reason(asset)
    latest = get_current_decision(db, organization_id=organization_id, asset_id=asset.id)

    return ArtefactAccessQuestion(
        asset_id=asset.id,
        display_name=asset.display_name,
        identity_undetermined_reason=reason,
        # Stated regardless of what the standing policy answers — the amendment's
        # third criterion, and the reason a default cannot hide a real gap.
        unknown_statement=IDENTITY_UNDETERMINED_EXPLANATION.get(reason) if reason else None,
        deeper_access_would_help=(
            reason == ArtefactIdentityUndetermined.PROBED_NOTHING_IDENTIFYING.value
        ),
        choices=tuple(choice.value for choice in ArtefactAccessChoice),
        choice_answers=dict(ACCESS_CHOICE_ANSWERS),
        standing_default=resolve_deeper_access_default(db, organization_id),
        current_choice=latest.choice if latest else None,
    )


def record_decision(
    db: Session,
    *,
    organization_id: int,
    asset: Asset,
    choice: str,
    decided_by_user_id: int | None = None,
    deviation_reason: str | None = None,
) -> ArtefactAccessDecision:
    """Record one answer, and start a lifecycle only if the answer asks for access."""
    if choice not in {member.value for member in ArtefactAccessChoice}:
        raise ArtefactAccessDecisionError(
            ACCESS_DECISION_ERROR_UNKNOWN_CHOICE.format(choice=choice)
        )

    standing_default = resolve_deeper_access_default(db, organization_id)
    reason = (deviation_reason or "").strip() or None
    if deviates_from_standing_default(db, organization_id, choice) and reason is None:
        raise ArtefactAccessDecisionError(ACCESS_DECISION_ERROR_DEVIATION_REASON_REQUIRED)

    decision = ArtefactAccessDecision(
        organization_id=organization_id,
        asset_id=asset.id,
        choice=choice,
        standing_default=standing_default,
        deviation_reason=reason,
        identity_undetermined_reason=_identity_undetermined_reason(asset),
        decided_by_user_id=decided_by_user_id,
    )
    db.add(decision)
    db.flush()

    append_audit_event(
        db,
        organization_id,
        ACCESS_DECISION_AUDIT_RECORDED,
        actor_user_id=decided_by_user_id,
        metadata={
            "assetId": asset.id,
            "displayName": asset.display_name,
            "choice": choice,
            "standingDefault": standing_default,
            "deviated": standing_default is not None and choice != standing_default,
            "identityUndeterminedReason": decision.identity_undetermined_reason,
        },
    )

    if choice in ACCESS_SEEKING_CHOICES:
        # The same call the lifecycle already exposes, rather than a second way
        # in. It re-checks the deviation rule, which is duplication that costs
        # nothing and means the lifecycle stays correct if it is ever called
        # directly.
        request_access(
            db,
            organization_id=organization_id,
            asset_id=asset.id,
            choice=choice,
            requested_by_user_id=decided_by_user_id,
            deviation_reason=reason,
        )

    return decision


def get_current_decision(
    db: Session, *, organization_id: int, asset_id: int
) -> ArtefactAccessDecision | None:
    """The answer standing on this artefact — the most recent one taken."""
    return (
        db.query(ArtefactAccessDecision)
        .filter(
            ArtefactAccessDecision.organization_id == organization_id,
            ArtefactAccessDecision.asset_id == asset_id,
        )
        .order_by(ArtefactAccessDecision.decided_at.desc(), ArtefactAccessDecision.id.desc())
        .first()
    )


def list_decisions(
    db: Session, *, organization_id: int, asset_id: int
) -> tuple[ArtefactAccessDecision, ...]:
    """Every answer ever given about this artefact, newest first.

    A history rather than a current value, because "we said network-only in
    August and changed our minds in October" is the fact an auditor is looking
    for, and a single mutable column cannot hold it.
    """
    rows = (
        db.query(ArtefactAccessDecision)
        .filter(
            ArtefactAccessDecision.organization_id == organization_id,
            ArtefactAccessDecision.asset_id == asset_id,
        )
        .order_by(ArtefactAccessDecision.decided_at.desc(), ArtefactAccessDecision.id.desc())
        .all()
    )
    return tuple(rows)


def _identity_undetermined_reason(asset: Asset) -> str | None:
    """Read from what slice 1 already recorded, never recomputed here.

    ``Asset.intent["identity"]`` is written by normalisation at the moment the
    evidence was seen. Recomputing at read time would answer from today's model
    about yesterday's scan.
    """
    intent = asset.intent if isinstance(asset.intent, dict) else {}
    identity = intent.get("identity")
    if not isinstance(identity, dict):
        return None
    reason = identity.get("undeterminedReason")
    return reason if isinstance(reason, str) and reason else None
