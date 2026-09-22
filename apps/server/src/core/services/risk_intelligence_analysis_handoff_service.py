"""The sweep that turns a normalised batch into threats a person can decide on.

Mirrors ``discovery_normalization_handoff_service``: a periodic sweep that owns
the selection rule and the per-batch failure isolation, with a deliberately thin
Celery wrapper around it, so both stay testable without a running worker.

**Why this exists.** ``analyze_normalized_ingestion_batch`` was reachable only
from ``POST /risk-intelligence/batches/{id}/analyze``. Normalisation had a sweep
and a beat entry; analysis had neither, so a Collector's evidence became an
``AssetFinding`` on its own and then stopped. Read from the running platform on
2026-09-07: 61 batches in ``NEEDS_REVIEW``, 20 in ``NORMALIZED``, and **zero**
in ``ANALYZED`` — every finding any scan had ever produced sat one step short of
the ``Threat`` that carries it onto a process map, an intervention feed and a
decision. The Collector could run perfectly and still deliver nothing.

**This does not remove a human decision.** The batch lifecycle is
``RECEIVED → NEEDS_REVIEW → ANALYZED → REVIEWED``, and the human decision is the
*last* transition: ``REVIEWED`` is written by
``risk_intelligence_ingestion_service`` only when a person records a
``DecisionRecord`` against a recommendation. Analysis creates the ``Threat``
(status ``detected``) and the recommendation that person then decides on — it is
the surface the decision is made on, not the decision. Leaving it unrun never
protected the decision point; it made the decision point unreachable.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.logging_config import get_logger
from src.core.model_defs.risk_intelligence_ingestion import (
    RiskIngestionBatch,
    RiskIngestionBatchStatus,
)
from src.core.services.risk_intelligence_analysis_service import (
    analyze_normalized_ingestion_batch,
)

logger = get_logger(__name__)

#: The one status that means "normalisation produced findings, nothing has
#: analysed them yet".
#:
#: ⚠️ ``NORMALIZED`` is deliberately **not** here, and the names invite exactly
#: the opposite mistake. ``normalize_ingestion_batch`` has two terminal states:
#: ``_empty_normalization_result`` writes ``NORMALIZED`` for a batch that
#: observed *nothing*, while the path that actually creates signals and findings
#: writes ``NEEDS_REVIEW``. Sweeping ``NORMALIZED`` would re-analyse empty
#: batches forever and never touch a single real finding.
_ANALYSABLE_BATCH_STATUSES = (RiskIngestionBatchStatus.NEEDS_REVIEW,)


def process_pending_analysis_batches(db: Session) -> list[RiskIngestionBatch]:
    """Analyse every batch whose findings have not been turned into threats.

    Each batch is analysed independently: ``analyze_normalized_ingestion_batch``
    commits its own work, so one batch failing leaves every batch before it
    committed and must not abort the sweep. The session is rolled back after a
    failure — without it the next batch inherits a poisoned transaction and the
    whole sweep fails on one bad row.

    A failed batch keeps its ``NEEDS_REVIEW`` status and is retried on the next
    sweep. That is the deliberate choice for a transient fault (a lock, a
    restart), and it is the wrong shape for a permanently unanalysable batch,
    which will log on every sweep instead of being quarantined. There is no
    ``ANALYSIS_FAILED`` status to move it to, and inventing one to silence a
    repeating log would hide the only signal there is while Observability
    (#220) is deferred. Loud and repeating beats silent and dropped.
    """
    batches = (
        db.query(RiskIngestionBatch)
        .filter(RiskIngestionBatch.status.in_(_ANALYSABLE_BATCH_STATUSES))
        .order_by(RiskIngestionBatch.received_at)
        .all()
    )

    analysed: list[RiskIngestionBatch] = []
    for batch in batches:
        try:
            analyze_normalized_ingestion_batch(
                db,
                organization_id=batch.organization_id,
                actor_user_id=None,
                batch_id=batch.id,
            )
        except Exception as exc:  # noqa: BLE001 — one batch must never stop the sweep
            db.rollback()
            logger.warning(
                "risk_intelligence_batch_analysis_failed",
                organization_id=batch.organization_id,
                ingestion_batch_id=batch.id,
                error=str(exc),
            )
            continue
        analysed.append(batch)

    return analysed


__all__ = ["process_pending_analysis_batches"]
