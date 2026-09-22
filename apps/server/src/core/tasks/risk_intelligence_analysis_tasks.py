"""Celery task wrapper for the risk-intelligence analysis sweep.

Deliberately thin, matching ``discovery_normalization_tasks.py``'s own
convention — all real logic lives in
``risk_intelligence_analysis_handoff_service.py``, independently testable
without a running Celery worker.
"""

from __future__ import annotations

from src.core.celery_app import celery_app
from src.core.database import get_db_context
from src.core.logging_config import get_logger
from src.core.services.risk_intelligence_analysis_handoff_service import (
    process_pending_analysis_batches,
)

logger = get_logger(__name__)


@celery_app.task(name="src.core.tasks.risk_intelligence_analysis_tasks.analyze_pending_ingestion_batches")
def analyze_pending_ingestion_batches() -> int:
    with get_db_context() as db:
        analysed = process_pending_analysis_batches(db)
        # `analyze_normalized_ingestion_batch` commits each batch itself, so
        # this commit only settles a session left open by an empty sweep.
        db.commit()
        if analysed:
            logger.info("risk_intelligence_batches_analyzed", count=len(analysed))
        return len(analysed)
