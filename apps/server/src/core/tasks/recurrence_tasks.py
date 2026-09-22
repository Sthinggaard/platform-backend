"""#242 — the sweep that notices due schedules.

Deliberately thin, matching ``discovery_execution_tasks``: all real logic lives
in ``recurrence_occurrence_service``, independently testable without a running
Celery worker. This file owns opening a session, committing, and logging.

The distinction #242 turns on: **this beat entry is not the recurrence.** Beat
is how a due schedule gets noticed; the schedule itself is a row the
organisation can see, pause and cancel, owned by whoever approved it. The
criterion rules out a recurrence that exists *only* as a beat entry, not the use
of beat to drive one.
"""

from __future__ import annotations

from src.core.celery_app import celery_app
from src.core.database import get_db_context
from src.core.logging_config import get_logger
from src.core.services.recurrence_occurrence_service import materialize_due_occurrences

logger = get_logger(__name__)


@celery_app.task(name="src.core.tasks.recurrence_tasks.materialize_due_recurrence_occurrences")
def materialize_due_recurrence_occurrences() -> int:
    with get_db_context() as db:
        occurrences = materialize_due_occurrences(db)
        db.commit()
        if occurrences:
            logger.info("recurrence_occurrences_materialized", count=len(occurrences))
        return len(occurrences)
