"""How long an evidence signal is kept, and why (BUG-DISC-18).

``asset_evidence_signals`` had no retention policy and no cap: it grew for as
long as the platform ran. On Søren's own database it reached **14.5 million rows
and 3.6 GB behind 84 assets**, which is what made normalisation unable to finish
at all (BUG-DISC-12 fixed the query; this addresses the volume).

**The distinction that governs everything here is evidence vs telemetry.**

An *evidence-bearing* signal is the reason an artefact exists or a decision was
taken. Someone confirmed an artefact because a scan observed `http` on it; an
auditor asking "why is this in your inventory, and on what basis?" is entitled
to that answer. Deleting it destroys the justification for a record the
organisation is still relying on, so it is kept, and it is never pruned while it
is the *only* remaining evidence for a live artefact — pruning by age alone
would leave artefacts asserting things nothing on record supports.

An *operational* signal is a heartbeat. It says a thing was reachable and how it
was performing at one instant. It is useful in aggregate and briefly, and it is
not the basis of any decision. Keeping seven months of it is not diligence, it
is cost — and under GDPR's storage-limitation principle, keeping personal-
adjacent operational data indefinitely because nobody chose a horizon is not a
defensible position either.

Retention is therefore per-kind, not global. Horizons are configurable, because
a customer's own regulator may require longer, and defaults are deliberately
conservative in the direction that preserves evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.core.constants.artefact_identity_enums import AssetEvidenceSignalKind
from src.core.model_defs.assets_runtime import AssetEvidenceSignal
from src.core.model_defs.common import utcnow

#: Signals that justify an artefact or a decision. These answer "why is this on
#: record?", so they outlive the operational noise around them.
EVIDENCE_BEARING_KINDS: frozenset[str] = frozenset(
    {
        AssetEvidenceSignalKind.RISK_INTELLIGENCE_INGESTION.value,
        AssetEvidenceSignalKind.COLLECTOR_HOST_OBSERVATION.value,
        # Written by the manual connector path in assets_service — proof a
        # customer's own credentials verified against a provider.
        "HANDSHAKE",
    }
)

#: Written only by ``AssetMonitoringEngine``, which is a **simulator**: the
#: payloads are randomly generated latency, throughput and event counts. They
#: were never evidence of anything, and at ~25,000 rows/hour they accounted for
#: 99.9% of the table. The engine is now off by default and refuses to run
#: outside development, but the kinds stay named here so existing rows can be
#: identified and removed, and so nothing ever mistakes them for evidence again.
SIMULATED_KINDS: frozenset[str] = frozenset({"health", "network_scan", "identity_event"})

#: Days after which a signal of each kind may be removed. Anything not named
#: here is treated as evidence-bearing — the safe default, since an unrecognised
#: kind is more likely to be new evidence than new noise, and wrongly keeping
#: data is recoverable while wrongly deleting it is not.
DEFAULT_RETENTION_DAYS: dict[str, int] = {
    **{kind: 730 for kind in EVIDENCE_BEARING_KINDS},  # two years
    **{kind: 30 for kind in SIMULATED_KINDS},
}

#: Deleted in chunks so a prune can never hold a long transaction or a large
#: lock on a table the discovery pipeline is writing to.
PRUNE_BATCH_SIZE = 5_000


@dataclass(frozen=True)
class SignalVolume:
    """What is actually in the store, by kind. The observability half of the
    contract: growth has to be visible before it is an incident, and "someone
    ran a count once" is not visibility."""

    kind: str
    rows: int
    oldest: datetime | None
    newest: datetime | None


@dataclass(frozen=True)
class PruneOutcome:
    deleted_by_kind: dict[str, int]
    protected_as_last_evidence: int

    @property
    def total_deleted(self) -> int:
        return sum(self.deleted_by_kind.values())


def retention_days_for(kind: str, overrides: dict[str, int] | None = None) -> int:
    """Unrecognised kinds fall back to the evidence horizon deliberately — see
    ``DEFAULT_RETENTION_DAYS``."""
    policy = {**DEFAULT_RETENTION_DAYS, **(overrides or {})}
    return policy.get(kind, max(DEFAULT_RETENTION_DAYS[k] for k in EVIDENCE_BEARING_KINDS))


def summarise_signal_volume(db: Session) -> list[SignalVolume]:
    """Row counts and age spans per kind, newest-heaviest first."""
    rows = db.execute(
        select(
            AssetEvidenceSignal.kind,
            func.count(AssetEvidenceSignal.id),
            func.min(AssetEvidenceSignal.observed_at),
            func.max(AssetEvidenceSignal.observed_at),
        ).group_by(AssetEvidenceSignal.kind)
    ).all()
    return sorted(
        (SignalVolume(kind=kind, rows=count, oldest=oldest, newest=newest) for kind, count, oldest, newest in rows),
        key=lambda volume: volume.rows,
        reverse=True,
    )


def _last_evidence_signal_ids(db: Session) -> set[int]:
    """The newest evidence-bearing signal for each asset.

    Never pruned, whatever its age. An artefact that outlives its own
    justification is worse than a slightly larger table: the row would keep
    asserting something with nothing on record behind it, and an auditor asking
    "on what basis?" would get silence.
    """
    newest = (
        select(
            AssetEvidenceSignal.asset_id.label("asset_id"),
            func.max(AssetEvidenceSignal.id).label("signal_id"),
        )
        .where(AssetEvidenceSignal.kind.in_(EVIDENCE_BEARING_KINDS))
        .group_by(AssetEvidenceSignal.asset_id)
        .subquery()
    )
    return {row.signal_id for row in db.execute(select(newest.c.signal_id)).all()}


def prune_expired_signals(
    db: Session,
    *,
    now: datetime | None = None,
    overrides: dict[str, int] | None = None,
    batch_size: int = PRUNE_BATCH_SIZE,
) -> PruneOutcome:
    """Remove signals past their kind's horizon, keeping every artefact's own
    last piece of evidence.

    Organisation-wide on purpose: retention is a property of the store, not of
    one tenant's view of it, and a per-tenant prune would leave the table's
    growth unbounded in exactly the multi-tenant case that matters.
    """
    now = now or utcnow()
    protected = _last_evidence_signal_ids(db)
    deleted_by_kind: dict[str, int] = {}

    kinds = [row[0] for row in db.execute(select(AssetEvidenceSignal.kind).distinct()).all()]
    for kind in kinds:
        cutoff = now - timedelta(days=retention_days_for(kind, overrides))
        deleted = 0
        while True:
            # Protected ids are excluded in SQL, not filtered out afterwards:
            # applying the LIMIT first and then dropping protected rows in
            # Python would return an empty batch as soon as one full page
            # happened to be protected, and stop the prune with unprotected
            # rows still behind it. The list is bounded by asset count, which is
            # orders of magnitude smaller than the signal count it filters.
            conditions = [
                AssetEvidenceSignal.kind == kind,
                AssetEvidenceSignal.observed_at < cutoff,
            ]
            if protected:
                conditions.append(AssetEvidenceSignal.id.notin_(protected))
            ids = [
                row[0]
                for row in db.execute(
                    select(AssetEvidenceSignal.id).where(*conditions).limit(batch_size)
                ).all()
            ]
            if not ids:
                break
            db.query(AssetEvidenceSignal).filter(AssetEvidenceSignal.id.in_(ids)).delete(
                synchronize_session=False
            )
            db.commit()
            deleted += len(ids)
        if deleted:
            deleted_by_kind[kind] = deleted

    return PruneOutcome(deleted_by_kind=deleted_by_kind, protected_as_last_evidence=len(protected))
