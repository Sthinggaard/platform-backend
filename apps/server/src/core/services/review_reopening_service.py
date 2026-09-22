"""Review reopening (dashboard slice 4).

Finds time-bound decisions whose review date has lapsed without verified
evidence, and reopens the affected Business Process: a fresh Risk Evaluation
is created (the old one stays as history), an auditable Scenario Snapshot
records the consequence of the exposure continuing, and a notification signal
is emitted for the review owner. The original human decision is preserved
untouched — reopening never remediates anything by itself.

Two lapse sources exist today:
- a DecisionRecord whose ``review_date`` has passed while its threat still
  lacks a successful verification;
- a temporary appetite exception whose effective window has ended.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from src.core.constants.decision_runtime import VERIFICATION_STATUS_SUCCESSFUL
from src.core.constants.value_stream_events import ValueStreamEvent
from src.core.model_defs.common import utcnow
from src.core.model_defs.review_reopening import (
    REOPENING_SOURCE_APPETITE_EXCEPTION,
    REOPENING_SOURCE_DECISION_REVIEW,
    ReviewReopening,
)
from src.core.model_defs.risk_appetite_policy import (
    APPETITE_POLICY_ACTIVE,
    APPETITE_SCOPE_DECISION_EXCEPTION,
    RiskAppetitePolicy,
)
from src.core.services.process_dashboard_projection_service import (
    mapped_asset_names,
    normalize_asset_id,
    normalize_asset_name,
)
from src.core.services.risk_evaluation_service import run_risk_evaluation_pass


@dataclass(frozen=True)
class OverdueReview:
    source: str  # decision_review | appetite_exception
    process_id: str
    decision_reference: str
    review_due_at: str
    review_owner: str | None
    description: str


def _parse_review_date(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value.strip()[: len(fmt) + 6], fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def find_overdue_reviews(db: Session, *, organization_id: int, at: datetime | None = None) -> list[OverdueReview]:
    """Lapsed reviews that have not already been reopened."""
    from src.core.models import (  # local import to avoid module cycles
        Asset,
        BusinessService,
        DecisionRecord,
        Threat,
        VerificationRecord,
    )

    now = (at or utcnow()).replace(tzinfo=None)

    already_reopened = {
        (row.process_id, row.source, row.decision_reference, row.review_due_at)
        for row in db.query(ReviewReopening).filter(ReviewReopening.organization_id == organization_id).all()
    }

    overdue: list[OverdueReview] = []

    # ── Decision reviews ──────────────────────────────────────────────────────
    decisions = (
        db.query(DecisionRecord)
        .filter(
            DecisionRecord.organization_id == organization_id,
            DecisionRecord.review_date.isnot(None),
        )
        .all()
    )
    verified_threat_ids = {
        v.threat_id
        for v in db.query(VerificationRecord)
        .filter(VerificationRecord.organization_id == organization_id)
        .all()
        if v.threat_id and v.verification_status == VERIFICATION_STATUS_SUCCESSFUL
    }
    lapsed_decisions = [
        d
        for d in decisions
        if (due := _parse_review_date(d.review_date)) is not None
        and due <= now
        and d.threat_id
        and d.threat_id not in verified_threat_ids
    ]

    if lapsed_decisions:
        threats_by_id = {
            t.id: t
            for t in db.query(Threat).filter(Threat.organization_id == organization_id).all()
        }
        assets = db.query(Asset).filter(Asset.organization_id == organization_id).all()
        services = (
            db.query(BusinessService)
            .filter(BusinessService.organization_id == organization_id)
            .all()
        )
        asset_name_by_id = {
            normalize_asset_id(a.id): normalize_asset_name(a.display_name) for a in assets
        }
        # process -> set of mapped asset names
        process_asset_names: dict[str, set[str]] = {}
        for service in services:
            if getattr(service, "archived_at", None) is not None:
                continue
            names = mapped_asset_names([service], asset_name_by_id)
            for process_id in service.value_stream_ids or []:
                process_asset_names.setdefault(process_id, set()).update(names)

        for decision in lapsed_decisions:
            threat = threats_by_id.get(decision.threat_id)
            if threat is None:
                continue
            threat_asset = normalize_asset_name(threat.asset)
            for process_id, names in process_asset_names.items():
                if threat_asset not in names:
                    continue
                if (process_id, REOPENING_SOURCE_DECISION_REVIEW, decision.id, decision.review_date) in already_reopened:
                    continue
                overdue.append(
                    OverdueReview(
                        source=REOPENING_SOURCE_DECISION_REVIEW,
                        process_id=process_id,
                        decision_reference=decision.id,
                        review_due_at=decision.review_date,
                        review_owner=decision.decided_by,
                        description=(
                            f"The '{decision.selected_action}' decision on '{threat.asset}' passed its "
                            f"review date ({decision.review_date}) without verified evidence."
                        ),
                    )
                )

    # ── Appetite exceptions ───────────────────────────────────────────────────
    exceptions = (
        db.query(RiskAppetitePolicy)
        .filter(
            RiskAppetitePolicy.organization_id == organization_id,
            RiskAppetitePolicy.scope == APPETITE_SCOPE_DECISION_EXCEPTION,
            RiskAppetitePolicy.status == APPETITE_POLICY_ACTIVE,
        )
        .all()
    )
    for policy in exceptions:
        if not policy.effective_to or not policy.process_id:
            continue
        effective_to = policy.effective_to.replace(tzinfo=None)
        if effective_to > now:
            continue
        reference = policy.decision_reference or policy.id
        due = effective_to.isoformat()
        if (policy.process_id, REOPENING_SOURCE_APPETITE_EXCEPTION, reference, due) in already_reopened:
            continue
        overdue.append(
            OverdueReview(
                source=REOPENING_SOURCE_APPETITE_EXCEPTION,
                process_id=policy.process_id,
                decision_reference=reference,
                review_due_at=due,
                review_owner=policy.approved_by,
                description=(
                    f"The temporary appetite exception '{reference}' expired on {due} "
                    "without renewal or verified evidence."
                ),
            )
        )

    return overdue


def find_outstanding_reviews(
    db: Session, *, organization_id: int, at: datetime | None = None
) -> list[OverdueReview]:
    """Everything a human still owes a decision on: fresh lapses plus
    reopened reviews whose underlying exposure remains unverified.

    A reopening is *open* until verified evidence or a superseding decision
    arrives — until then the dashboard must keep showing the decision need.
    """
    from src.core.models import DecisionRecord, VerificationRecord

    outstanding = find_overdue_reviews(db, organization_id=organization_id, at=at)

    now = (at or utcnow()).replace(tzinfo=None)
    verified_threat_ids = {
        v.threat_id
        for v in db.query(VerificationRecord)
        .filter(VerificationRecord.organization_id == organization_id)
        .all()
        if v.threat_id and v.verification_status == VERIFICATION_STATUS_SUCCESSFUL
    }
    decisions_by_id = {
        d.id: d
        for d in db.query(DecisionRecord)
        .filter(DecisionRecord.organization_id == organization_id)
        .all()
    }

    for row in (
        db.query(ReviewReopening)
        .filter(ReviewReopening.organization_id == organization_id)
        .all()
    ):
        if row.source == REOPENING_SOURCE_DECISION_REVIEW:
            decision = decisions_by_id.get(row.decision_reference)
            threat_id = decision.threat_id if decision else None
            if threat_id and threat_id in verified_threat_ids:
                continue  # evidence arrived — resolved
            renewed = decision is not None and any(
                d.threat_id == threat_id
                and d.id != decision.id
                and (due := _parse_review_date(d.review_date)) is not None
                and due > now
                for d in decisions_by_id.values()
            )
            if renewed:
                continue  # a newer decision with a future review date supersedes it
        outstanding.append(
            OverdueReview(
                source=row.source,
                process_id=row.process_id,
                decision_reference=row.decision_reference,
                review_due_at=row.review_due_at,
                review_owner=row.review_owner,
                description=(
                    f"Reopened: the review due {row.review_due_at} is still awaiting a renewed "
                    "decision or verified evidence."
                ),
            )
        )

    return outstanding


@dataclass(frozen=True)
class ReopeningPassResult:
    reopened: list[str]  # decision references reopened this pass


def run_review_reopening_pass(db: Session, *, organization_id: int, at: datetime | None = None) -> ReopeningPassResult:
    """Reopen every lapsed review: fresh evaluation, scenario snapshot, signal.

    Idempotent (unique constraint per lapsed reference). The caller owns the
    commit. Nothing here remediates anything — it creates records and notifies.
    """
    from src.core.models import ValueStreamSignal  # local import to avoid cycles

    overdue = find_overdue_reviews(db, organization_id=organization_id, at=at)
    if not overdue:
        return ReopeningPassResult(reopened=[])

    overdue_by_process: dict[str, list[OverdueReview]] = {}
    for item in overdue:
        overdue_by_process.setdefault(item.process_id, []).append(item)

    # Reopen = re-evaluate the affected processes with the lapse in evidence.
    pass_result = run_risk_evaluation_pass(
        db,
        organization_id=organization_id,
        process_ids=list(overdue_by_process.keys()),
        overdue_reviews_by_process={
            process_id: [item.__dict__ for item in items]
            for process_id, items in overdue_by_process.items()
        },
    )

    reopened: list[str] = []
    for item in overdue:
        evaluation = pass_result.evaluations_by_process_id.get(item.process_id)
        forecast_estimate = None
        if evaluation is not None and evaluation.forecast_id:
            forecast_estimate = "see_forecast"  # linked through the evaluation
        scenario_snapshot = {
            "kind": "exposure_continues_unresolved",
            "statement": item.description,
            "consequence": {
                "risk_status": evaluation.status if evaluation else "not_proven",
                "preparedness": evaluation.preparedness if evaluation else "cannot_prove",
                "forecast": forecast_estimate,
            },
            "lapsed": {
                "source": item.source,
                "decision_reference": item.decision_reference,
                "review_due_at": item.review_due_at,
                "review_owner": item.review_owner,
            },
            "generated_at": utcnow().isoformat(),
        }
        db.add(
            ReviewReopening(
                organization_id=organization_id,
                process_id=item.process_id,
                source=item.source,
                decision_reference=item.decision_reference,
                review_due_at=item.review_due_at,
                review_owner=item.review_owner,
                evaluation_id=evaluation.id if evaluation else None,
                scenario_snapshot=scenario_snapshot,
            )
        )
        # Notification: the review owner is the accountable person we know today;
        # mandate-holder routing arrives with the org-access slice.
        db.add(
            ValueStreamSignal(
                organization_id=organization_id,
                user_id=None,
                event=ValueStreamEvent.REVIEW_REOPENED,
                stream_id=item.process_id,
                library_item_id=None,
                stream_key=None,
                name=None,
                priority=None,
                source="review_reopening",
                payload={
                    "process_id": item.process_id,
                    "decision_reference": item.decision_reference,
                    "review_due_at": item.review_due_at,
                    "notify": item.review_owner,
                    "evaluation_id": evaluation.id if evaluation else None,
                },
            )
        )
        reopened.append(item.decision_reference)

    return ReopeningPassResult(reopened=reopened)
