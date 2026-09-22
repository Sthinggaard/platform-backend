"""Periodic enforcement of the signal retention policy (BUG-DISC-18).

A thin wrapper around ``signal_retention_service``, matching the pattern the
other task modules use: the schedule lives here, the reasoning and the rules
live in the service where they can be tested without a broker.

Runs hourly rather than on the fast dispatch loop. Retention is a horizon
measured in days — nothing is gained by checking every fifteen seconds, and a
prune competing with discovery writes for locks would be actively worse.
"""

from __future__ import annotations

from src.core.celery_app import celery_app
from src.core.database import get_db_context
from src.core.logging_config import get_logger
from src.core.services.signal_retention_service import (
    prune_expired_signals,
    summarise_signal_volume,
)

logger = get_logger(__name__)


@celery_app.task(name="src.core.tasks.signal_retention_tasks.enforce_signal_retention")
def enforce_signal_retention() -> dict:
    """Prune expired signals, then report what remains.

    The volume report is emitted every run, not only when something was
    deleted: "growth is observable" means someone can see the trend before it
    becomes an incident, and a log line that only appears once there is a
    problem is not observability.
    """
    with get_db_context() as db:
        outcome = prune_expired_signals(db)
        volumes = summarise_signal_volume(db)

    logger.info(
        "signal_retention_enforced",
        deleted_total=outcome.total_deleted,
        deleted_by_kind=outcome.deleted_by_kind,
        protected_as_last_evidence=outcome.protected_as_last_evidence,
        remaining_by_kind={volume.kind: volume.rows for volume in volumes},
        remaining_total=sum(volume.rows for volume in volumes),
    )
    return {
        "deleted": outcome.total_deleted,
        "remaining": sum(volume.rows for volume in volumes),
    }
