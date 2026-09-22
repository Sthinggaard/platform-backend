"""Verification runner for scanner-backed resolution outcomes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from src.core.constants.decision_runtime import (
    RESOLUTION_TYPE_ACCEPTED_RISK,
    RESOLUTION_TYPE_FOLLOWED_RECOMMENDATION,
    RESOLUTION_TYPE_SOLVED_DIFFERENTLY,
    VERIFICATION_STATUS_ALTERNATIVE,
    VERIFICATION_STATUS_INSUFFICIENT,
    VERIFICATION_STATUS_NOT_VERIFIED,
    VERIFICATION_STATUS_PENDING,
    VERIFICATION_STATUS_SUCCESSFUL,
)
from src.core.models import (
    Asset,
    AssetEvidenceSignal,
    AssetStatus,
    AssetStatusHistory,
    Recommendation,
    ResolutionRecord,
    VerificationRecord,
)

LOW_CONFIDENCE_THRESHOLD = 55
PARTIAL_RISK_DROP_THRESHOLD = 5.0
STRONG_RISK_DROP_THRESHOLD = 15.0
DEFAULT_PENDING_NOTE = "Awaiting post-resolution scanner observation."
ACCEPTED_RISK_NOTE = "Verification skipped because the recorded resolution accepted the risk."
MISSING_ASSET_NOTE = "No scanner-backed asset context is linked to this recommendation."
NO_IMPROVEMENT_NOTE = "Post-resolution scanner observations did not show a meaningful improvement."
SUCCESS_NOTE = "Scanner observations show the issue improved in line with the recorded recommendation path."
ALTERNATIVE_NOTE = "Scanner observations show improvement through an alternative resolution path."
INSUFFICIENT_NOTE = "Scanner observations changed, but the issue does not appear fully resolved yet."
LOW_CONFIDENCE_NOTE = "Scanner observations improved, but confidence remains too low to mark the resolution as successful."


@dataclass(frozen=True)
class ObservationSnapshot:
    status: str | None
    risk_score: float | None
    findings_count: int | None
    observed_at: datetime | None


@dataclass(frozen=True)
class VerificationOutcome:
    status: str
    confidence: int
    notes: str
    observed_changes: list[dict[str, str | None]]
    compared_observed_at: datetime | None


def get_latest_verification_for_resolution(
    resolution_id: str,
    org_id: int,
    db: Session,
) -> VerificationRecord | None:
    return (
        db.query(VerificationRecord)
        .filter(
            VerificationRecord.resolution_record_id == resolution_id,
            VerificationRecord.organization_id == org_id,
        )
        .order_by(VerificationRecord.created_at.desc())
        .first()
    )


def verify_resolution_status(
    db: Session,
    resolution: ResolutionRecord,
    *,
    org_id: int,
) -> VerificationRecord | None:
    recommendation = _get_recommendation_for_resolution(db, resolution, org_id)
    latest_verification = get_latest_verification_for_resolution(resolution.id, org_id, db)

    if resolution.resolution_type == RESOLUTION_TYPE_ACCEPTED_RISK:
        outcome = VerificationOutcome(
            status=VERIFICATION_STATUS_NOT_VERIFIED,
            confidence=0,
            notes=ACCEPTED_RISK_NOTE,
            observed_changes=[],
            compared_observed_at=None,
        )
        return _store_verification_outcome(
            db,
            resolution=resolution,
            recommendation=recommendation,
            outcome=outcome,
            latest_verification=latest_verification,
        )

    asset = _resolve_asset(recommendation, org_id, db)
    if asset is None:
        outcome = VerificationOutcome(
            status=VERIFICATION_STATUS_NOT_VERIFIED,
            confidence=0,
            notes=MISSING_ASSET_NOTE,
            observed_changes=[],
            compared_observed_at=None,
        )
        return _store_verification_outcome(
            db,
            resolution=resolution,
            recommendation=recommendation,
            outcome=outcome,
            latest_verification=latest_verification,
        )

    post_signals = _get_post_resolution_signals(db, asset.id, resolution.created_at)
    if not post_signals:
        return latest_verification

    latest_signal_at = post_signals[0].observed_at
    if (
        latest_verification is not None
        and latest_verification.compared_observed_at is not None
        and latest_verification.compared_observed_at >= latest_signal_at
    ):
        return latest_verification

    baseline = _get_baseline_snapshot(db, asset.id, resolution.created_at)
    post_snapshot = _get_post_resolution_snapshot(db, asset.id, resolution.created_at)
    if post_snapshot is None:
        return latest_verification

    outcome = _build_verification_outcome(
        resolution=resolution,
        recommendation=recommendation,
        baseline=baseline,
        post_snapshot=post_snapshot,
        post_signals=post_signals,
    )
    return _store_verification_outcome(
        db,
        resolution=resolution,
        recommendation=recommendation,
        outcome=outcome,
        latest_verification=latest_verification,
    )


def run_verification_for_asset(
    db: Session,
    *,
    organization_id: int,
    asset_id: int,
) -> list[VerificationRecord]:
    records: list[VerificationRecord] = []
    for resolution in _list_latest_resolutions_for_org(db, organization_id):
        recommendation = _get_recommendation_for_resolution(db, resolution, organization_id)
        asset = _resolve_asset(recommendation, organization_id, db)
        if asset is None or asset.id != asset_id:
            continue
        record = verify_resolution_status(db, resolution, org_id=organization_id)
        if record is not None:
            records.append(record)
    return records


def build_pending_verification_payload(
    resolution_id: str,
    *,
    notes: str = DEFAULT_PENDING_NOTE,
) -> dict[str, object]:
    return {
        "resolutionId": resolution_id,
        "verificationStatus": VERIFICATION_STATUS_PENDING,
        "verificationTimestamp": None,
        "observedChanges": [],
        "confidence": 0,
        "notes": notes,
    }


def serialize_verification_record(record: VerificationRecord) -> dict[str, object]:
    return {
        "resolutionId": record.resolution_record_id,
        "verificationStatus": record.verification_status,
        # #281/#284 — the model attaches the offset; a bare isoformat here
        # would hand the reader a naive instant again.
        "verificationTimestamp": record.created_at,
        "observedChanges": record.observed_changes or [],
        "confidence": record.confidence_score,
        "notes": record.notes,
    }


def _build_verification_outcome(
    *,
    resolution: ResolutionRecord,
    recommendation: Recommendation,
    baseline: ObservationSnapshot | None,
    post_snapshot: ObservationSnapshot,
    post_signals: list[AssetEvidenceSignal],
) -> VerificationOutcome:
    observed_changes = _summarize_observed_changes(baseline, post_snapshot)
    scanner_confidence = _average_signal_confidence(post_signals)
    strong_improvement, partial_improvement = _classify_improvement(
        baseline=baseline,
        post_snapshot=post_snapshot,
    )

    if strong_improvement:
        if scanner_confidence < LOW_CONFIDENCE_THRESHOLD:
            return VerificationOutcome(
                status=VERIFICATION_STATUS_INSUFFICIENT,
                confidence=scanner_confidence,
                notes=LOW_CONFIDENCE_NOTE,
                observed_changes=observed_changes,
                compared_observed_at=post_snapshot.observed_at,
            )
        if resolution.resolution_type == RESOLUTION_TYPE_SOLVED_DIFFERENTLY:
            return VerificationOutcome(
                status=VERIFICATION_STATUS_ALTERNATIVE,
                confidence=scanner_confidence,
                notes=ALTERNATIVE_NOTE,
                observed_changes=observed_changes,
                compared_observed_at=post_snapshot.observed_at,
            )
        if resolution.resolution_type == RESOLUTION_TYPE_FOLLOWED_RECOMMENDATION:
            return VerificationOutcome(
                status=VERIFICATION_STATUS_SUCCESSFUL,
                confidence=scanner_confidence,
                notes=SUCCESS_NOTE,
                observed_changes=observed_changes,
                compared_observed_at=post_snapshot.observed_at,
            )
        return VerificationOutcome(
            status=VERIFICATION_STATUS_INSUFFICIENT,
            confidence=scanner_confidence,
            notes=INSUFFICIENT_NOTE,
            observed_changes=observed_changes,
            compared_observed_at=post_snapshot.observed_at,
        )

    if partial_improvement:
        return VerificationOutcome(
            status=VERIFICATION_STATUS_INSUFFICIENT,
            confidence=scanner_confidence,
            notes=INSUFFICIENT_NOTE,
            observed_changes=observed_changes,
            compared_observed_at=post_snapshot.observed_at,
        )

    return VerificationOutcome(
        status=VERIFICATION_STATUS_NOT_VERIFIED,
        confidence=scanner_confidence,
        notes=(
            NO_IMPROVEMENT_NOTE
            if recommendation.linked_context_type == "asset"
            else MISSING_ASSET_NOTE
        ),
        observed_changes=observed_changes,
        compared_observed_at=post_snapshot.observed_at,
    )


def _classify_improvement(
    *,
    baseline: ObservationSnapshot | None,
    post_snapshot: ObservationSnapshot,
) -> tuple[bool, bool]:
    if baseline is None:
        status_improved = _status_rank(post_snapshot.status) <= _status_rank(AssetStatus.OPERATIONALLY_COMPLIANT.value)
        findings_cleared = (post_snapshot.findings_count or 0) == 0
        return status_improved and findings_cleared, status_improved or findings_cleared

    baseline_findings = baseline.findings_count or 0
    post_findings = post_snapshot.findings_count or 0
    findings_drop = post_findings < baseline_findings
    findings_cleared = baseline_findings > 0 and post_findings == 0

    baseline_risk = baseline.risk_score or 0.0
    post_risk = post_snapshot.risk_score or 0.0
    risk_drop = baseline_risk - post_risk

    status_improved = _status_rank(post_snapshot.status) < _status_rank(baseline.status)
    strong_improvement = (
        findings_cleared
        or (risk_drop >= STRONG_RISK_DROP_THRESHOLD and status_improved)
        or (
            baseline.status == AssetStatus.AT_RISK.value
            and post_snapshot.status == AssetStatus.OPERATIONALLY_COMPLIANT.value
        )
    )
    partial_improvement = (
        strong_improvement
        or findings_drop
        or risk_drop >= PARTIAL_RISK_DROP_THRESHOLD
        or status_improved
    )
    return strong_improvement, partial_improvement


def _summarize_observed_changes(
    baseline: ObservationSnapshot | None,
    post_snapshot: ObservationSnapshot,
) -> list[dict[str, str | None]]:
    changes: list[dict[str, str | None]] = []
    if baseline is None:
        if post_snapshot.status is not None:
            changes.append(
                {
                    "type": "status_observed",
                    "description": f"Scanner observed asset status {post_snapshot.status}.",
                    "before": None,
                    "after": post_snapshot.status,
                }
            )
        if post_snapshot.findings_count is not None:
            changes.append(
                {
                    "type": "findings_observed",
                    "description": f"Scanner reported {post_snapshot.findings_count} open findings.",
                    "before": None,
                    "after": str(post_snapshot.findings_count),
                }
            )
        return changes

    if baseline.status != post_snapshot.status:
        changes.append(
            {
                "type": "asset_status",
                "description": "Asset status changed after the recorded resolution.",
                "before": baseline.status,
                "after": post_snapshot.status,
            }
        )

    if baseline.findings_count != post_snapshot.findings_count:
        changes.append(
            {
                "type": "findings_count",
                "description": "Open findings count changed after the recorded resolution.",
                "before": None if baseline.findings_count is None else str(baseline.findings_count),
                "after": None if post_snapshot.findings_count is None else str(post_snapshot.findings_count),
            }
        )

    baseline_risk = baseline.risk_score or 0.0
    post_risk = post_snapshot.risk_score or 0.0
    if abs(baseline_risk - post_risk) >= 0.1:
        changes.append(
            {
                "type": "risk_score",
                "description": "Risk score changed after the recorded resolution.",
                "before": f"{baseline_risk:.1f}",
                "after": f"{post_risk:.1f}",
            }
        )

    return changes


def _average_signal_confidence(post_signals: list[AssetEvidenceSignal]) -> int:
    if not post_signals:
        return 0
    confidences = [signal.confidence if signal.confidence is not None else 0.5 for signal in post_signals]
    return max(0, min(100, round((sum(confidences) / len(confidences)) * 100)))


def _get_recommendation_for_resolution(
    db: Session,
    resolution: ResolutionRecord,
    org_id: int,
) -> Recommendation:
    recommendation = (
        db.query(Recommendation)
        .filter(
            Recommendation.id == resolution.recommendation_id,
            Recommendation.organization_id == org_id,
        )
        .first()
    )
    assert recommendation is not None
    return recommendation


def _resolve_asset(
    recommendation: Recommendation,
    org_id: int,
    db: Session,
) -> Asset | None:
    if recommendation.linked_context_type != "asset":
        return None

    context_id = (recommendation.linked_context_id or "").strip()
    if context_id.isdigit():
        asset = (
            db.query(Asset)
            .filter(
                Asset.id == int(context_id),
                Asset.organization_id == org_id,
            )
            .first()
        )
        if asset is not None:
            return asset

    candidate_labels = [recommendation.linked_context_label, recommendation.linked_context_id]
    for candidate in candidate_labels:
        if not candidate:
            continue
        asset = (
            db.query(Asset)
            .filter(
                Asset.organization_id == org_id,
                func.lower(Asset.display_name) == candidate.strip().lower(),
            )
            .first()
        )
        if asset is not None:
            return asset
    return None


def _get_post_resolution_signals(
    db: Session,
    asset_id: int,
    resolution_time: datetime,
) -> list[AssetEvidenceSignal]:
    return (
        db.query(AssetEvidenceSignal)
        .filter(
            AssetEvidenceSignal.asset_id == asset_id,
            AssetEvidenceSignal.observed_at > resolution_time,
        )
        .order_by(AssetEvidenceSignal.observed_at.desc())
        .limit(3)
        .all()
    )


def _get_baseline_snapshot(
    db: Session,
    asset_id: int,
    resolution_time: datetime,
) -> ObservationSnapshot | None:
    row = (
        db.query(AssetStatusHistory)
        .filter(
            AssetStatusHistory.asset_id == asset_id,
            AssetStatusHistory.observed_at <= resolution_time,
        )
        .order_by(AssetStatusHistory.observed_at.desc())
        .first()
    )
    return _snapshot_from_history(row)


def _get_post_resolution_snapshot(
    db: Session,
    asset_id: int,
    resolution_time: datetime,
) -> ObservationSnapshot | None:
    row = (
        db.query(AssetStatusHistory)
        .filter(
            AssetStatusHistory.asset_id == asset_id,
            AssetStatusHistory.observed_at > resolution_time,
        )
        .order_by(AssetStatusHistory.observed_at.desc())
        .first()
    )
    return _snapshot_from_history(row)


def _snapshot_from_history(row: AssetStatusHistory | None) -> ObservationSnapshot | None:
    if row is None:
        return None
    status = row.status.value if hasattr(row.status, "value") else row.status
    return ObservationSnapshot(
        status=status,
        risk_score=row.risk_score,
        findings_count=row.findings_count,
        observed_at=row.observed_at,
    )


def _list_latest_resolutions_for_org(
    db: Session,
    org_id: int,
) -> list[ResolutionRecord]:
    rows = (
        db.query(ResolutionRecord)
        .filter(ResolutionRecord.organization_id == org_id)
        .order_by(ResolutionRecord.created_at.desc())
        .all()
    )
    latest_by_recommendation: dict[str, ResolutionRecord] = {}
    for row in rows:
        latest_by_recommendation.setdefault(row.recommendation_id, row)
    return list(latest_by_recommendation.values())


def _status_rank(status: str | None) -> int:
    order = {
        AssetStatus.OPERATIONALLY_COMPLIANT.value: 0,
        AssetStatus.PARTIALLY_OBSERVED.value: 1,
        AssetStatus.AT_RISK.value: 2,
        AssetStatus.NOT_CONNECTED.value: 3,
    }
    return order.get(status or "", 99)


def _store_verification_outcome(
    db: Session,
    *,
    resolution: ResolutionRecord,
    recommendation: Recommendation,
    outcome: VerificationOutcome,
    latest_verification: VerificationRecord | None,
) -> VerificationRecord:
    if latest_verification is not None:
        same_status = latest_verification.verification_status == outcome.status
        same_notes = (latest_verification.notes or "") == outcome.notes
        same_changes = (latest_verification.observed_changes or []) == outcome.observed_changes
        latest_observed_at = latest_verification.compared_observed_at
        if same_status and same_notes and same_changes and latest_observed_at == outcome.compared_observed_at:
            return latest_verification

    record = VerificationRecord(
        organization_id=resolution.organization_id,
        resolution_record_id=resolution.id,
        recommendation_id=resolution.recommendation_id,
        threat_id=resolution.threat_id,
        verification_status=outcome.status,
        confidence_score=outcome.confidence,
        observed_changes=outcome.observed_changes,
        notes=outcome.notes,
        linked_context_type=recommendation.linked_context_type,
        linked_context_id=recommendation.linked_context_id,
        compared_observed_at=outcome.compared_observed_at,
    )
    db.add(record)
    db.flush()
    return record
