"""Risk appetite resolution at the process decision boundary (dashboard slice 2).

Single source of truth for the canonical precedence chain

    approved temporary decision exception (within its effective window)
    → active Business Process override
    → active Organisation Policy

and for writing policies (append-only supersede, never mutate history).

Rules (risklence-domain-decision-model):
- Missing appetite resolves to *nothing* — callers render ``not_proven`` /
  ``blocked``. It is never inferred from an asset tier or a service record.
- A service-level config can inform context but cannot substitute for the
  process decision boundary; this module never reads service configs.
- An expired exception is ignored for resolution, but reported so the
  dashboard can surface the lapsed review (verified-outcomes slice reopens it).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from src.core.model_defs.common import utcnow
from src.core.model_defs.risk_appetite_policy import (
    APPETITE_ERROR_ORGANISATION_DRAFT_REQUIRED,
    APPETITE_POLICY_ACTIVE,
    APPETITE_POLICY_DRAFT,
    APPETITE_POLICY_LEADERSHIP_REVIEW,
    APPETITE_POLICY_SUPERSEDED,
    APPETITE_POLICY_WITHDRAWN,
    APPETITE_SCOPE_BUSINESS_PROCESS,
    APPETITE_SCOPE_DECISION_EXCEPTION,
    APPETITE_SCOPE_ORGANISATION,
    APPETITE_SCOPES,
    RiskAppetitePolicy,
)


@dataclass(frozen=True)
class ResolvedProcessAppetite:
    """The effective appetite for one Business Process, with provenance."""

    answers: dict
    source_scope: str  # organisation | business_process | decision_exception
    policy_id: str
    version: int
    approved_by: str
    effective_from: datetime
    # Present only for temporary decision exceptions.
    effective_to: datetime | None
    review_at: datetime | None
    decision_reference: str | None
    # An approved exception whose window has lapsed without renewal — the
    # dashboard must surface this; it does not resolve appetite.
    expired_exception_reference: str | None = None


class AppetitePolicyValidationError(ValueError):
    """Raised when a policy write violates the scope contract."""


def _naive_utc(value: datetime) -> datetime:
    """Postgres DateTime columns are naive UTC; normalise before comparing."""
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _is_within_window(policy: RiskAppetitePolicy, at: datetime) -> bool:
    if policy.effective_from and _naive_utc(policy.effective_from) > at:
        return False
    if policy.effective_to and _naive_utc(policy.effective_to) <= at:
        return False
    return True


def _validate_future_review_at(review_at: datetime) -> None:
    if _naive_utc(review_at) <= _naive_utc(utcnow()):
        raise AppetitePolicyValidationError("An appetite review date must be in the future.")


def _to_resolved(policy: RiskAppetitePolicy, expired_reference: str | None) -> ResolvedProcessAppetite:
    return ResolvedProcessAppetite(
        answers=dict(policy.answers or {}),
        source_scope=policy.scope,
        policy_id=policy.id,
        version=policy.version,
        approved_by=policy.approved_by,
        effective_from=policy.effective_from,
        effective_to=policy.effective_to,
        review_at=policy.review_at,
        decision_reference=policy.decision_reference,
        expired_exception_reference=expired_reference,
    )


def list_active_process_appetite_reviews(
    db: Session, *, organization_id: int
) -> list[RiskAppetitePolicy]:
    """Every active Process Risk Appetite with a review date, org-wide.

    Feeds the Governance Control Centre's "decision reviews" health metric
    and the "review overdue" exception type — the only review-cadence data
    that genuinely exists today (see peer/appetite recommendation modules'
    docstrings for the broader governance contract).
    """
    return (
        db.query(RiskAppetitePolicy)
        .filter(
            RiskAppetitePolicy.organization_id == organization_id,
            RiskAppetitePolicy.scope == APPETITE_SCOPE_BUSINESS_PROCESS,
            RiskAppetitePolicy.status == APPETITE_POLICY_ACTIVE,
            RiskAppetitePolicy.review_at.isnot(None),
        )
        .all()
    )


def resolve_appetite_for_processes(
    db: Session,
    *,
    organization_id: int,
    process_ids: list[str],
    at: datetime | None = None,
) -> dict[str, ResolvedProcessAppetite]:
    """Resolve the effective appetite for each process; absent keys are unresolved."""
    now = _naive_utc(at or utcnow())
    policies: list[RiskAppetitePolicy] = (
        db.query(RiskAppetitePolicy)
        .filter(
            RiskAppetitePolicy.organization_id == organization_id,
            RiskAppetitePolicy.status == APPETITE_POLICY_ACTIVE,
        )
        .all()
    )

    org_policy = next(
        (p for p in policies if p.scope == APPETITE_SCOPE_ORGANISATION and _is_within_window(p, now)),
        None,
    )
    overrides_by_process = {
        p.process_id: p
        for p in policies
        if p.scope == APPETITE_SCOPE_BUSINESS_PROCESS and p.process_id and _is_within_window(p, now)
    }
    exceptions_by_process: dict[str, RiskAppetitePolicy] = {}
    expired_exception_refs: dict[str, str] = {}
    for p in policies:
        if p.scope != APPETITE_SCOPE_DECISION_EXCEPTION or not p.process_id:
            continue
        if _is_within_window(p, now):
            exceptions_by_process[p.process_id] = p
        elif p.effective_to and _naive_utc(p.effective_to) <= now:
            expired_exception_refs[p.process_id] = p.decision_reference or p.id

    resolved: dict[str, ResolvedProcessAppetite] = {}
    for process_id in process_ids:
        expired_ref = expired_exception_refs.get(process_id)
        policy = exceptions_by_process.get(process_id) or overrides_by_process.get(process_id) or org_policy
        if policy is not None:
            resolved[process_id] = _to_resolved(policy, expired_ref)
    return resolved


def resolve_process_appetite(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
    at: datetime | None = None,
) -> ResolvedProcessAppetite | None:
    return resolve_appetite_for_processes(
        db, organization_id=organization_id, process_ids=[process_id], at=at
    ).get(process_id)


def resolve_organisation_appetite(
    db: Session,
    *,
    organization_id: int,
    at: datetime | None = None,
) -> ResolvedProcessAppetite | None:
    """Return the current leadership-approved organisation appetite, if effective."""
    now = _naive_utc(at or utcnow())
    policy = (
        db.query(RiskAppetitePolicy)
        .filter(
            RiskAppetitePolicy.organization_id == organization_id,
            RiskAppetitePolicy.scope == APPETITE_SCOPE_ORGANISATION,
            RiskAppetitePolicy.status == APPETITE_POLICY_ACTIVE,
        )
        .order_by(RiskAppetitePolicy.version.desc())
        .first()
    )
    return _to_resolved(policy, None) if policy is not None and _is_within_window(policy, now) else None


def set_appetite_policy(
    db: Session,
    *,
    organization_id: int,
    scope: str,
    answers: dict,
    approved_by: str,
    process_id: str | None = None,
    decision_reference: str | None = None,
    note: str | None = None,
    effective_to: datetime | None = None,
    review_at: datetime | None = None,
) -> RiskAppetitePolicy:
    """Write a policy at one scope, superseding the previous active row.

    Append-only: history stays queryable; nothing is mutated or deleted.
    The caller owns the transaction (commit).
    """
    if scope not in APPETITE_SCOPES:
        raise AppetitePolicyValidationError(f"Unknown appetite scope '{scope}'.")
    if scope == APPETITE_SCOPE_ORGANISATION and process_id is not None:
        raise AppetitePolicyValidationError("An organisation policy is not process-specific.")
    if scope == APPETITE_SCOPE_ORGANISATION:
        raise AppetitePolicyValidationError(APPETITE_ERROR_ORGANISATION_DRAFT_REQUIRED)
    if scope in (APPETITE_SCOPE_BUSINESS_PROCESS, APPETITE_SCOPE_DECISION_EXCEPTION) and not process_id:
        raise AppetitePolicyValidationError(f"A {scope} policy requires a process.")
    if scope == APPETITE_SCOPE_DECISION_EXCEPTION:
        # Temporary by definition — an exception without an expiry and a
        # review date would be a silent permanent override.
        if effective_to is None or review_at is None:
            raise AppetitePolicyValidationError(
                "A decision exception requires an expiry (effective_to) and a review date."
            )
    if not answers:
        raise AppetitePolicyValidationError("Appetite answers are required.")
    if review_at is not None:
        _validate_future_review_at(review_at)

    predecessor: RiskAppetitePolicy | None = (
        db.query(RiskAppetitePolicy)
        .filter(
            RiskAppetitePolicy.organization_id == organization_id,
            RiskAppetitePolicy.scope == scope,
            RiskAppetitePolicy.process_id == process_id,
            RiskAppetitePolicy.status == APPETITE_POLICY_ACTIVE,
        )
        .order_by(RiskAppetitePolicy.version.desc())
        .first()
    )

    policy = RiskAppetitePolicy(
        organization_id=organization_id,
        scope=scope,
        process_id=process_id,
        decision_reference=decision_reference,
        answers=dict(answers),
        approved_by=approved_by,
        note=note,
        effective_to=_naive_utc(effective_to) if effective_to else None,
        review_at=_naive_utc(review_at) if review_at else None,
        version=(predecessor.version + 1) if predecessor else 1,
    )
    db.add(policy)
    db.flush()

    if predecessor is not None:
        predecessor.status = APPETITE_POLICY_SUPERSEDED
        predecessor.superseded_by_id = policy.id
        db.add(predecessor)

    return policy


def _validate_draft_scope(scope: str, process_id: str | None) -> None:
    if scope not in (APPETITE_SCOPE_ORGANISATION, APPETITE_SCOPE_BUSINESS_PROCESS):
        raise AppetitePolicyValidationError(f"Unsupported appetite governance scope '{scope}'.")
    if scope == APPETITE_SCOPE_ORGANISATION and process_id is not None:
        raise AppetitePolicyValidationError("An organisation appetite is not process-specific.")
    if scope == APPETITE_SCOPE_BUSINESS_PROCESS and not process_id:
        raise AppetitePolicyValidationError("A Business Process appetite draft requires a process.")


def create_appetite_draft(
    db: Session,
    *,
    organization_id: int,
    scope: str,
    process_id: str | None = None,
    answers: dict,
    prepared_by: str,
    review_at: datetime,
    note: str | None = None,
) -> RiskAppetitePolicy:
    """Create a versioned appetite proposal (organisation or Business Process) without activating it."""
    _validate_draft_scope(scope, process_id)
    if not answers:
        raise AppetitePolicyValidationError("Appetite answers are required.")
    _validate_future_review_at(review_at)

    latest_policy: RiskAppetitePolicy | None = (
        db.query(RiskAppetitePolicy)
        .filter(
            RiskAppetitePolicy.organization_id == organization_id,
            RiskAppetitePolicy.scope == scope,
            RiskAppetitePolicy.process_id == process_id,
        )
        .order_by(RiskAppetitePolicy.version.desc())
        .first()
    )
    policy = RiskAppetitePolicy(
        organization_id=organization_id,
        scope=scope,
        process_id=process_id,
        answers=dict(answers),
        status=APPETITE_POLICY_DRAFT,
        prepared_by=prepared_by,
        review_at=_naive_utc(review_at),
        note=note,
        version=(latest_policy.version + 1) if latest_policy else 1,
    )
    db.add(policy)
    db.flush()
    return policy


def submit_appetite_draft(
    db: Session,
    policy: RiskAppetitePolicy,
    *,
    submitted_by: str,
) -> RiskAppetitePolicy:
    """Submit a prepared appetite version for human approval."""
    if policy.status != APPETITE_POLICY_DRAFT:
        raise AppetitePolicyValidationError("Only an appetite draft can be submitted.")
    policy.status = APPETITE_POLICY_LEADERSHIP_REVIEW
    policy.submitted_by = submitted_by
    policy.submitted_at = utcnow()
    db.add(policy)
    return policy


def approve_appetite_draft(
    db: Session,
    policy: RiskAppetitePolicy,
    *,
    approved_by: str,
    approval_reference: str | None,
    effective_from: datetime | None = None,
) -> RiskAppetitePolicy:
    """Activate a leadership-approved appetite version, superseding the previous active one at its scope."""
    if policy.status != APPETITE_POLICY_LEADERSHIP_REVIEW:
        raise AppetitePolicyValidationError("Only an appetite awaiting leadership review can be approved.")

    predecessor: RiskAppetitePolicy | None = (
        db.query(RiskAppetitePolicy)
        .filter(
            RiskAppetitePolicy.organization_id == policy.organization_id,
            RiskAppetitePolicy.scope == policy.scope,
            RiskAppetitePolicy.process_id == policy.process_id,
            RiskAppetitePolicy.status == APPETITE_POLICY_ACTIVE,
        )
        .order_by(RiskAppetitePolicy.version.desc())
        .first()
    )
    policy.status = APPETITE_POLICY_ACTIVE
    policy.approved_by = approved_by
    policy.approved_at = utcnow()
    policy.approval_reference = approval_reference
    policy.effective_from = _naive_utc(effective_from or utcnow())
    if predecessor is not None:
        predecessor.status = APPETITE_POLICY_SUPERSEDED
        predecessor.superseded_by_id = policy.id
        db.add(predecessor)
    db.add(policy)
    return policy


def reject_appetite_draft(
    db: Session,
    policy: RiskAppetitePolicy,
    *,
    rejected_by: str,
    rejection_reason: str,
) -> RiskAppetitePolicy:
    """Withdraw a leadership-reviewed proposal while retaining its audit history."""
    if policy.status != APPETITE_POLICY_LEADERSHIP_REVIEW:
        raise AppetitePolicyValidationError("Only an appetite awaiting leadership review can be rejected.")
    if not rejection_reason.strip():
        raise AppetitePolicyValidationError("A leadership rejection reason is required.")
    policy.status = APPETITE_POLICY_WITHDRAWN
    policy.rejected_by = rejected_by
    policy.rejected_at = utcnow()
    policy.rejection_reason = rejection_reason.strip()
    db.add(policy)
    return policy
