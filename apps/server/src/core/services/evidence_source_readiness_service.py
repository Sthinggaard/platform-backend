"""Evidence Source — readiness evaluation + prepared read model.

Read-side companion to ``evidence_source_service`` (SRP, mirrors
``organization_structure_readiness_service``). Readiness is always derived
from underlying records, never a status a caller can set directly.

A source only counts as *functioning* once it has an owner, a confirmed
scope, and at least one ``EvidenceReceipt`` — and, for a manual source, an
active, not-yet-due-for-review ``EvidenceSourceException`` (spec §2/§19: a
manually entered asset should not satisfy this gate on its own).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.orm import Session

from src.core.constants.evidence_source_enums import (
    DEFAULT_FRESHNESS_STALE_AFTER_HOURS,
    DEFAULT_FRESHNESS_WARNING_AFTER_HOURS,
    EvidenceImportStatus,
    EvidenceReceiptStatus,
    EvidenceSourceExceptionStatus,
    EvidenceSourceHealthStatus,
    EvidenceSourceReadiness,
    EvidenceSourceScopeStatus,
    EvidenceSourceStatus,
    EvidenceSourceType,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.model_defs.evidence_source import (
    EvidenceImportBatch,
    EvidenceReceipt,
    EvidenceSource,
    EvidenceSourceException,
    EvidenceSourceScope,
)


def _latest_batch(db: Session, evidence_source_id: str) -> EvidenceImportBatch | None:
    return (
        db.query(EvidenceImportBatch)
        .filter(EvidenceImportBatch.evidence_source_id == evidence_source_id)
        .order_by(EvidenceImportBatch.uploaded_at.desc())
        .first()
    )


def _latest_receipt(db: Session, evidence_source_id: str) -> EvidenceReceipt | None:
    return (
        db.query(EvidenceReceipt)
        .filter(EvidenceReceipt.evidence_source_id == evidence_source_id)
        .order_by(EvidenceReceipt.received_at.desc())
        .first()
    )


def _has_receipt(db: Session, evidence_source_id: str) -> bool:
    return (
        db.query(EvidenceReceipt).filter(EvidenceReceipt.evidence_source_id == evidence_source_id).first()
        is not None
    )


def _has_active_exception(db: Session, evidence_source_id: str, *, now: datetime) -> bool:
    return (
        db.query(EvidenceSourceException)
        .filter(
            EvidenceSourceException.evidence_source_id == evidence_source_id,
            EvidenceSourceException.status == EvidenceSourceExceptionStatus.ACTIVE.value,
            EvidenceSourceException.review_at > now,
        )
        .first()
        is not None
    )


@dataclass(frozen=True)
class EvidenceSourceHealthResult:
    functioning: bool
    healthy: bool
    # Set up and capable of delivering, whether or not it has delivered yet.
    # Distinct from `functioning` on purpose (UX-ONB-01): "the source is
    # connected" is a setup milestone, "the source is delivering" is
    # operational health, and collapsing them sent a user who had installed and
    # activated a Collector back to "let's connect a source of evidence"
    # every time they refreshed — because evidence had not arrived yet.
    configured: bool = False


def _evaluate_source_health(db: Session, source: EvidenceSource, *, now: datetime) -> EvidenceSourceHealthResult:
    if source.owner_user_id is None:
        return EvidenceSourceHealthResult(functioning=False, healthy=False)

    if source.type == EvidenceSourceType.SCANNER.value:
        # A scanner source satisfies none of the checks below, and not because
        # it is unhealthy — they describe a different kind of source (BUG-DISC-13):
        #
        #   * Scope: scanner setup confirms its scope on the ScannerInstance
        #     (`scope_confirmed_at`, via POST .../scanner/scope/confirm), not as
        #     an EvidenceSourceScope row — that record models import scoping and
        #     nothing in the scanner flow ever writes one. Gating a Collector on
        #     it made a confirmed scanner permanently look unconfirmed.
        #   * Evidence: it produces EvidencePackages, never an
        #     EvidenceImportBatch, so the batch check below could never pass.
        instance = (
            db.query(ScannerInstance).filter(ScannerInstance.evidence_source_id == source.id).first()
        )
        if instance is None or instance.scope_confirmed_at is None:
            return EvidenceSourceHealthResult(functioning=False, healthy=False)
        # Installed, activated and scoped — the setup step is genuinely done at
        # this point, even though no evidence has arrived yet.
        receipt = _latest_receipt(db, source.id)
        if receipt is None:
            return EvidenceSourceHealthResult(functioning=False, healthy=False, configured=True)
        return EvidenceSourceHealthResult(
            functioning=True,
            healthy=receipt.status == EvidenceReceiptStatus.PROCESSED.value,
            configured=True,
        )

    scope = db.query(EvidenceSourceScope).filter(EvidenceSourceScope.evidence_source_id == source.id).first()
    if scope is None or scope.status != EvidenceSourceScopeStatus.CONFIRMED.value:
        return EvidenceSourceHealthResult(functioning=False, healthy=False)
    # For an import or manual source, a confirmed scope *is* the setup step.
    if not _has_receipt(db, source.id):
        return EvidenceSourceHealthResult(functioning=False, healthy=False, configured=True)

    if source.type == EvidenceSourceType.MANUAL.value:
        if not _has_active_exception(db, source.id, now=now):
            return EvidenceSourceHealthResult(functioning=False, healthy=False, configured=True)
        # Manual evidence is always the weaker, exception-gated path —
        # functioning, but never "healthy" in the sense a clean import is.
        return EvidenceSourceHealthResult(functioning=True, healthy=False, configured=True)

    batch = _latest_batch(db, source.id)
    if batch is None or batch.status not in (
        EvidenceImportStatus.COMPLETED.value,
        EvidenceImportStatus.COMPLETED_WITH_WARNINGS.value,
    ):
        return EvidenceSourceHealthResult(functioning=False, healthy=False, configured=True)
    return EvidenceSourceHealthResult(
        functioning=True,
        healthy=batch.status == EvidenceImportStatus.COMPLETED.value,
        configured=True,
    )


def _resolve_freshness_hours(source: EvidenceSource) -> tuple[int | None, int | None]:
    warning = source.warning_after_hours
    stale = source.stale_after_hours
    if warning is None:
        warning = DEFAULT_FRESHNESS_WARNING_AFTER_HOURS.get(source.type)
    if stale is None:
        stale = DEFAULT_FRESHNESS_STALE_AFTER_HOURS.get(source.type)
    return warning, stale


@dataclass(frozen=True)
class EvidenceSourceHealthSignals:
    """Explainable per-source health (spec §12) — always derived, never
    stored. ``connectivity_healthy``/``authorisation_healthy``/
    ``permissions_sufficient`` are ``None`` (not applicable, never a
    fabricated True) for v1's source types, none of which hold a live
    connection to check."""

    connectivity_healthy: bool | None
    authorisation_healthy: bool | None
    permissions_sufficient: bool | None
    evidence_received: bool
    evidence_fresh: bool
    schema_compatible: bool
    last_checked_at: datetime
    last_healthy_at: datetime | None
    status: EvidenceSourceHealthStatus
    reasons: list[str]


def evaluate_source_health_signals(
    db: Session, source: EvidenceSource, *, now: datetime
) -> EvidenceSourceHealthSignals:
    if source.status in (EvidenceSourceStatus.DISABLED.value, EvidenceSourceStatus.ARCHIVED.value):
        return EvidenceSourceHealthSignals(
            connectivity_healthy=None,
            authorisation_healthy=None,
            permissions_sufficient=None,
            evidence_received=source.first_evidence_received_at is not None,
            evidence_fresh=False,
            schema_compatible=True,
            last_checked_at=now,
            last_healthy_at=source.last_successful_sync_at,
            status=EvidenceSourceHealthStatus.DISABLED,
            reasons=[f"This source is {source.status}."],
        )

    base = _evaluate_source_health(db, source, now=now)
    reasons: list[str] = []

    if source.owner_user_id is None:
        reasons.append("No responsible owner has been assigned.")
    scope = db.query(EvidenceSourceScope).filter(EvidenceSourceScope.evidence_source_id == source.id).first()
    if scope is None or scope.status != EvidenceSourceScopeStatus.CONFIRMED.value:
        reasons.append("The source scope has not been confirmed.")

    evidence_received = _has_receipt(db, source.id)
    if not evidence_received:
        reasons.append("No evidence has been received from this source yet.")
    elif source.type == EvidenceSourceType.MANUAL.value and not _has_active_exception(db, source.id, now=now):
        reasons.append(
            "A manual source requires an approved, review-dated exception to count as functioning."
        )

    schema_compatible = True
    if source.type != EvidenceSourceType.MANUAL.value:
        batch = _latest_batch(db, source.id)
        if batch is not None and batch.status == EvidenceImportStatus.FAILED.value:
            schema_compatible = False
            reasons.append("The most recent import failed — no rows passed validation.")
        elif batch is not None and batch.status == EvidenceImportStatus.COMPLETED_WITH_WARNINGS.value:
            reasons.append("The most recent import completed with warnings.")

    warning_hours, stale_hours = _resolve_freshness_hours(source)
    evidence_fresh = True
    reference_time = source.last_successful_sync_at or source.first_evidence_received_at
    if evidence_received and reference_time is not None and stale_hours is not None:
        age_hours = (now - reference_time).total_seconds() / 3600
        age_days = int(age_hours // 24)
        if age_hours > stale_hours:
            evidence_fresh = False
            reasons.append(
                f"Last successful sync was {age_days} days ago, exceeding the "
                f"{stale_hours // 24}-day freshness policy."
            )
        elif warning_hours is not None and age_hours > warning_hours:
            reasons.append(
                f"Last successful sync was {age_days} days ago — approaching the freshness policy limit."
            )

    if base.functioning and base.healthy and schema_compatible and evidence_fresh:
        status = EvidenceSourceHealthStatus.HEALTHY
    elif base.functioning or evidence_received:
        status = EvidenceSourceHealthStatus.DEGRADED
    else:
        status = EvidenceSourceHealthStatus.PENDING

    return EvidenceSourceHealthSignals(
        connectivity_healthy=None,
        authorisation_healthy=None,
        permissions_sufficient=None,
        evidence_received=evidence_received,
        evidence_fresh=evidence_fresh,
        schema_compatible=schema_compatible,
        last_checked_at=now,
        last_healthy_at=source.last_successful_sync_at,
        status=status,
        reasons=reasons,
    )


@dataclass(frozen=True)
class EvidenceSourceReadinessResult:
    ready: bool
    readiness: EvidenceSourceReadiness
    functioning_source_ids: list[str] = field(default_factory=list)
    healthy_source_ids: list[str] = field(default_factory=list)
    degraded_source_ids: list[str] = field(default_factory=list)
    blocked_source_ids: list[str] = field(default_factory=list)
    configured_source_ids: list[str] = field(default_factory=list)
    missing_reasons: list[str] = field(default_factory=list)

    @property
    def setup_complete(self) -> bool:
        """Whether the *evidence-source setup step* is done — at least one
        source is connected and capable of delivering. Deliberately weaker than
        ``ready``, which additionally requires evidence to have arrived
        (UX-ONB-01: a connected, activated Collector satisfies the step; whether
        it has scanned yet is the next step's business, not this one's)."""
        return bool(self.configured_source_ids)


def evaluate_evidence_source_readiness(db: Session, organization_id: int) -> EvidenceSourceReadinessResult:
    sources = (
        db.query(EvidenceSource)
        .filter(EvidenceSource.organization_id == organization_id)
        .filter(EvidenceSource.status != "archived")
        .all()
    )
    # DB DateTime columns are naive; utcnow() is timezone-aware — normalise
    # before comparing, matching the convention already established in
    # risk_appetite_resolution_service.py / review_reopening_service.py.
    now = utcnow().replace(tzinfo=None)

    functioning_ids: list[str] = []
    healthy_ids: list[str] = []
    degraded_ids: list[str] = []
    blocked_ids: list[str] = []
    configured_ids: list[str] = []

    for source in sources:
        health = _evaluate_source_health(db, source, now=now)
        if health.configured:
            configured_ids.append(source.id)
        if health.functioning:
            functioning_ids.append(source.id)
            (healthy_ids if health.healthy else degraded_ids).append(source.id)
        else:
            blocked_ids.append(source.id)

    reasons: list[str] = []
    if not sources:
        reasons.append("no_evidence_source_created")
    elif not functioning_ids:
        reasons.append("no_functioning_evidence_source")

    ready = bool(functioning_ids)
    if not sources:
        readiness = EvidenceSourceReadiness.MISSING
    elif not ready:
        readiness = EvidenceSourceReadiness.IN_PROGRESS
    elif healthy_ids:
        readiness = EvidenceSourceReadiness.READY
    else:
        readiness = EvidenceSourceReadiness.DEGRADED

    return EvidenceSourceReadinessResult(
        ready=ready,
        readiness=readiness,
        functioning_source_ids=functioning_ids,
        healthy_source_ids=healthy_ids,
        degraded_source_ids=degraded_ids,
        blocked_source_ids=blocked_ids,
        configured_source_ids=configured_ids,
        missing_reasons=reasons,
    )


@dataclass(frozen=True)
class PreparedEvidenceSourceSummary:
    id: str
    name: str
    type: str
    mode: str
    status: str
    healthy: bool
    owner_user_id: int | None
    scope_id: str | None
    health_status: EvidenceSourceHealthStatus
    first_evidence_received_at: datetime | None
    last_successful_sync_at: datetime | None


@dataclass(frozen=True)
class PreparedActiveException:
    id: str
    evidence_source_id: str
    reason_code: str
    review_at: datetime


@dataclass(frozen=True)
class PreparedEvidenceSources:
    """Business-readable summary consumed by Step 4 (first import/discovery
    → shared artefact inventory) — deliberately does not include asset
    uniqueness, criticality, or ownership conclusions (spec §26/§27)."""

    organization_id: int
    sources: list[PreparedEvidenceSourceSummary]
    functioning_source_ids: list[str]
    degraded_source_ids: list[str]
    blocked_source_ids: list[str]
    active_exceptions: list[PreparedActiveException]
    readiness: EvidenceSourceReadiness


def build_prepared_evidence_sources(db: Session, organization_id: int) -> PreparedEvidenceSources:
    sources = (
        db.query(EvidenceSource)
        .filter(EvidenceSource.organization_id == organization_id)
        .filter(EvidenceSource.status != "archived")
        .all()
    )
    readiness_result = evaluate_evidence_source_readiness(db, organization_id)
    now = utcnow().replace(tzinfo=None)

    summaries = [
        PreparedEvidenceSourceSummary(
            id=s.id,
            name=s.name,
            type=s.type,
            mode=s.mode,
            status=s.status,
            healthy=s.id in readiness_result.healthy_source_ids,
            owner_user_id=s.owner_user_id,
            scope_id=(
                db.query(EvidenceSourceScope.id)
                .filter(EvidenceSourceScope.evidence_source_id == s.id)
                .scalar()
            ),
            health_status=evaluate_source_health_signals(db, s, now=now).status,
            first_evidence_received_at=s.first_evidence_received_at,
            last_successful_sync_at=s.last_successful_sync_at,
        )
        for s in sources
    ]

    active_exceptions = [
        PreparedActiveException(
            id=e.id, evidence_source_id=e.evidence_source_id, reason_code=e.reason_code, review_at=e.review_at
        )
        for e in db.query(EvidenceSourceException)
        .filter(
            EvidenceSourceException.organization_id == organization_id,
            EvidenceSourceException.status == EvidenceSourceExceptionStatus.ACTIVE.value,
            EvidenceSourceException.review_at > now,
        )
        .all()
    ]

    return PreparedEvidenceSources(
        organization_id=organization_id,
        sources=summaries,
        functioning_source_ids=readiness_result.functioning_source_ids,
        degraded_source_ids=readiness_result.degraded_source_ids,
        blocked_source_ids=readiness_result.blocked_source_ids,
        active_exceptions=active_exceptions,
        readiness=readiness_result.readiness,
    )
