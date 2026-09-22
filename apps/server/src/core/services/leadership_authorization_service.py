"""Leadership authorisation of the onboarding programme (onboarding governance, phase 1).

Mirrors the organisation appetite lifecycle in
``risk_appetite_resolution_service`` — draft -> leadership_review -> active
-> superseded/withdrawn, administrator prepares, Approver/Escalation Contact
approves on the governing body's behalf. This module owns that lifecycle for
Leadership Authorization plus the gate it feeds: no Process Owner may be
invited until an active authorisation exists for the organisation.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.leadership_authorization_enums import (
    LeadershipApprovingBody,
    LeadershipAuthorizationStatus,
)
from src.core.constants.process_ownership_enums import ProcessOwnershipStatus
from src.core.model_defs.common import utcnow
from src.core.model_defs.leadership_authorization import LeadershipAuthorization
from src.core.model_defs.process_ownership import ProcessOwnerAcceptance
from src.core.model_defs.tenant_identity import User


class LeadershipAuthorizationValidationError(ValueError):
    """Raised when a leadership authorisation lifecycle transition is invalid."""


def get_active_leadership_authorization(
    db: Session, organization_id: int
) -> LeadershipAuthorization | None:
    """Return the current active authorisation for the org, if any."""
    return (
        db.query(LeadershipAuthorization)
        .filter(
            LeadershipAuthorization.organization_id == organization_id,
            LeadershipAuthorization.status == LeadershipAuthorizationStatus.ACTIVE.value,
        )
        .order_by(LeadershipAuthorization.version.desc())
        .first()
    )


def create_leadership_authorization_draft(
    db: Session,
    *,
    organization_id: int,
    sponsor_user_id: int,
    approving_body: LeadershipApprovingBody,
    authorized_scope: str,
    prepared_by: str,
    note: str | None = None,
) -> LeadershipAuthorization:
    """Create a versioned leadership-authorisation proposal without activating it.

    The named sponsor must be an active user of this organisation — they are
    the only one who may later approve or reject this record.
    """
    if not authorized_scope.strip():
        raise LeadershipAuthorizationValidationError("An authorised scope is required.")
    sponsor = (
        db.query(User)
        .filter(User.id == sponsor_user_id, User.organization_id == organization_id)
        .first()
    )
    if sponsor is None or not sponsor.is_active:
        raise LeadershipAuthorizationValidationError(
            "The sponsor must be an active user of this organisation."
        )

    latest: LeadershipAuthorization | None = (
        db.query(LeadershipAuthorization)
        .filter(LeadershipAuthorization.organization_id == organization_id)
        .order_by(LeadershipAuthorization.version.desc())
        .first()
    )
    authorization = LeadershipAuthorization(
        organization_id=organization_id,
        status=LeadershipAuthorizationStatus.DRAFT.value,
        sponsor_user_id=sponsor_user_id,
        approving_body=approving_body.value,
        authorized_scope=authorized_scope.strip(),
        prepared_by=prepared_by,
        note=note,
        version=(latest.version + 1) if latest else 1,
    )
    db.add(authorization)
    db.flush()
    return authorization


def self_authorize_leadership(
    db: Session,
    *,
    organization_id: int,
    acting_user_id: int,
    sponsor_user_id: int,
    approving_body: LeadershipApprovingBody,
    authorized_scope: str,
    note: str | None = None,
) -> LeadershipAuthorization:
    """Authorise the onboarding programme in one step, during onboarding itself.

    Only for the case the draft/review split exists to protect against most
    of the time: here, requiring the named sponsor to separately log in and
    click approve before the programme can proceed would stall onboarding
    itself. The person running onboarding (an org admin) names the real
    accountable leader — often themselves, sometimes not, e.g. an IT admin
    onboarding on behalf of the actual CEO — and that becomes active
    immediately. The sponsor is still always a real user account (never
    free text), and who actually performed this action (``acting_user_id``)
    versus who is named accountable (``sponsor_user_id``) are recorded
    distinctly so the audit trail never blurs the two. Recorded as its own
    audit event so this is never confused with a delegated approval either.
    """
    if not authorized_scope.strip():
        raise LeadershipAuthorizationValidationError("An authorised scope is required.")
    sponsor = (
        db.query(User)
        .filter(User.id == sponsor_user_id, User.organization_id == organization_id)
        .first()
    )
    if sponsor is None or not sponsor.is_active:
        raise LeadershipAuthorizationValidationError(
            "The sponsor must be an active user of this organisation."
        )

    latest: LeadershipAuthorization | None = (
        db.query(LeadershipAuthorization)
        .filter(LeadershipAuthorization.organization_id == organization_id)
        .order_by(LeadershipAuthorization.version.desc())
        .first()
    )
    predecessor = get_active_leadership_authorization(db, organization_id)
    now = utcnow()
    actor_id_str = str(acting_user_id)
    authorization = LeadershipAuthorization(
        organization_id=organization_id,
        status=LeadershipAuthorizationStatus.ACTIVE.value,
        sponsor_user_id=sponsor_user_id,
        approving_body=approving_body.value,
        authorized_scope=authorized_scope.strip(),
        prepared_by=actor_id_str,
        submitted_by=actor_id_str,
        submitted_at=now,
        approved_by=actor_id_str,
        approved_at=now,
        effective_from=now,
        note=note,
        version=(latest.version + 1) if latest else 1,
    )
    if predecessor is not None:
        predecessor.status = LeadershipAuthorizationStatus.SUPERSEDED.value
        db.add(predecessor)
    db.add(authorization)
    db.flush()
    if predecessor is not None:
        predecessor.superseded_by_id = authorization.id
        db.add(predecessor)
    return authorization


def submit_leadership_authorization_draft(
    db: Session,
    authorization: LeadershipAuthorization,
    *,
    submitted_by: str,
) -> LeadershipAuthorization:
    """Submit a prepared authorisation version for leadership review."""
    if authorization.status != LeadershipAuthorizationStatus.DRAFT.value:
        raise LeadershipAuthorizationValidationError(
            "Only a leadership authorisation draft can be submitted."
        )
    authorization.status = LeadershipAuthorizationStatus.LEADERSHIP_REVIEW.value
    authorization.submitted_by = submitted_by
    authorization.submitted_at = utcnow()
    db.add(authorization)
    return authorization


def approve_leadership_authorization_draft(
    db: Session,
    authorization: LeadershipAuthorization,
    *,
    approved_by: str,
    approval_reference: str | None,
) -> LeadershipAuthorization:
    """Activate a leadership-approved authorisation version, superseding the last active one."""
    if authorization.status != LeadershipAuthorizationStatus.LEADERSHIP_REVIEW.value:
        raise LeadershipAuthorizationValidationError(
            "Only a leadership authorisation awaiting review can be approved."
        )

    predecessor = get_active_leadership_authorization(db, authorization.organization_id)
    authorization.status = LeadershipAuthorizationStatus.ACTIVE.value
    authorization.approved_by = approved_by
    authorization.approved_at = utcnow()
    authorization.approval_reference = approval_reference
    authorization.effective_from = utcnow()
    if predecessor is not None and predecessor.id != authorization.id:
        predecessor.status = LeadershipAuthorizationStatus.SUPERSEDED.value
        predecessor.superseded_by_id = authorization.id
        db.add(predecessor)
    db.add(authorization)
    return authorization


def reject_leadership_authorization_draft(
    db: Session,
    authorization: LeadershipAuthorization,
    *,
    rejected_by: str,
    rejection_reason: str,
) -> LeadershipAuthorization:
    """Withdraw a reviewed proposal while retaining its audit history."""
    if authorization.status != LeadershipAuthorizationStatus.LEADERSHIP_REVIEW.value:
        raise LeadershipAuthorizationValidationError(
            "Only a leadership authorisation awaiting review can be rejected."
        )
    if not rejection_reason.strip():
        raise LeadershipAuthorizationValidationError("A leadership rejection reason is required.")
    authorization.status = LeadershipAuthorizationStatus.WITHDRAWN.value
    authorization.rejected_by = rejected_by
    authorization.rejected_at = utcnow()
    authorization.rejection_reason = rejection_reason.strip()
    db.add(authorization)
    return authorization


def backfill_leadership_authorization_for_legacy_org(
    db: Session, organization_id: int
) -> LeadershipAuthorization | None:
    """Synthesise a baseline authorisation for an org whose owners predate this gate.

    No-op when the org already has an active authorisation, or has no
    accepted Process Owner yet — a genuinely new org must go through the real
    draft/submit/approve flow rather than being backfilled. Always flagged
    ``backfilled=True`` so it is never mistaken for a real leadership decision.
    Deliberately leaves ``sponsor_user_id`` unset — a legacy baseline must
    never invent a sponsor who was never actually named; the UI shows
    "Not recorded" rather than attributing this to whoever happened to
    trigger the backfill.
    """
    if get_active_leadership_authorization(db, organization_id) is not None:
        return None
    has_existing_ownership = (
        db.query(ProcessOwnerAcceptance)
        .filter(
            ProcessOwnerAcceptance.organization_id == organization_id,
            ProcessOwnerAcceptance.status == ProcessOwnershipStatus.ACCEPTED.value,
        )
        .first()
    )
    if has_existing_ownership is None:
        return None

    authorization = LeadershipAuthorization(
        organization_id=organization_id,
        status=LeadershipAuthorizationStatus.ACTIVE.value,
        sponsor_user_id=None,
        approving_body=LeadershipApprovingBody.SENIOR_MANAGEMENT.value,
        authorized_scope=(
            "Backfilled: this organisation already had accepted Process Owners "
            "before leadership authorisation of the onboarding programme was required."
        ),
        approved_at=utcnow(),
        effective_from=utcnow(),
        backfilled=True,
    )
    db.add(authorization)
    db.flush()
    return authorization
