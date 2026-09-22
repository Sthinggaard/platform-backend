"""Step 4.2 Part 2 — DISC-22 / DISC-27/28: Celery task wrappers.

Deliberately thin — all real logic lives in
discovery_execution_scheduler_service.py and
discovery_execution_retry_service.py, both independently testable without a
running Celery worker. This file only owns opening a session
(get_db_context, the documented non-FastAPI-context helper), committing,
and logging.

Lease-expiry reconciliation and due-retry spawning run before the dispatch
sweep, in the same tick and the same transaction — a stage a stale lease
just unblocked, or a job a retry just spawned, should be eligible for
dispatch on this same pass rather than waiting a full extra tick.
"""

from __future__ import annotations

from src.core.celery_app import celery_app
from src.core.database import get_db_context
from src.core.logging_config import get_logger
from src.core.services.discovery_execution_retry_service import process_due_retries, reconcile_expired_leases
from src.core.services.discovery_execution_scheduler_service import dispatch_ready_jobs

logger = get_logger(__name__)


@celery_app.task(name="src.core.tasks.discovery_execution_tasks.dispatch_ready_discovery_jobs")
def dispatch_ready_discovery_jobs() -> int:
    with get_db_context() as db:
        reconciled = reconcile_expired_leases(db)
        if reconciled:
            logger.info("discovery_execution_leases_reconciled", count=len(reconciled))

        retried = process_due_retries(db)
        if retried:
            logger.info("discovery_execution_retries_spawned", count=len(retried))

        dispatched = dispatch_ready_jobs(db)
        db.commit()
        if dispatched:
            logger.info("discovery_execution_jobs_dispatched", count=len(dispatched))
        return len(dispatched)
