"""Step 4.2 Part 2 — DISC-32: Celery task wrapper for the normalization
handoff sweep. Deliberately thin, matching discovery_execution_tasks.py's
own convention — all real logic lives in
discovery_normalization_handoff_service.py, independently testable
without a running Celery worker.
"""

from __future__ import annotations

from src.core.celery_app import celery_app
from src.core.database import get_db_context
from src.core.logging_config import get_logger
from src.core.services.discovery_normalization_handoff_service import process_pending_evidence_packages

logger = get_logger(__name__)


@celery_app.task(name="src.core.tasks.discovery_normalization_tasks.process_pending_discovery_evidence")
def process_pending_discovery_evidence() -> int:
    with get_db_context() as db:
        processed = process_pending_evidence_packages(db)
        db.commit()
        if processed:
            logger.info("discovery_evidence_packages_normalized", count=len(processed))
        return len(processed)
