"""Step 4.2 Part 2 — DISC-22: the Celery application.

Activates the already-declared-but-unused celery/redis/kombu dependencies
(see TASKS.md DISC-17's Open Decision 1, confirmed with Søren 2026-07-21)
against the Redis instance already deployed in both docker-compose files —
this is the first thing in this repo to actually use Celery, not a new
external dependency.

Kept deliberately minimal: one app instance, one queue, one periodic beat
schedule. Task bodies live in src/core/tasks/ (thin wrappers around real,
independently-testable service functions in discovery_execution_scheduler_service.py)
— business logic never lives inside a @task-decorated function itself.
"""

from __future__ import annotations

from celery import Celery

from src.core.config import settings

celery_app = Celery(
    "risklence",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "src.core.tasks.discovery_execution_tasks",
        "src.core.tasks.discovery_normalization_tasks",
        "src.core.tasks.risk_intelligence_analysis_tasks",
        "src.core.tasks.signal_retention_tasks",
        "src.core.tasks.recurrence_tasks",
    ],
)

celery_app.conf.update(
    task_default_queue="discovery_execution",
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

# Runs every 15 seconds — frequent enough that a READY stage's jobs start
# promptly, cheap enough that an empty sweep (the common case between real
# discovery runs) costs one no-op query round-trip.
celery_app.conf.beat_schedule = {
    "dispatch-ready-discovery-execution-jobs": {
        "task": "src.core.tasks.discovery_execution_tasks.dispatch_ready_discovery_jobs",
        "schedule": 15.0,
    },
    # DISC-32: normalization is not on the same tight loop as dispatch —
    # a package doesn't need to become an Asset/signal within seconds the
    # way a stalled job needs reclaiming does, so this runs less often.
    "process-pending-discovery-evidence": {
        "task": "src.core.tasks.discovery_normalization_tasks.process_pending_discovery_evidence",
        "schedule": 60.0,
    },
    # The step after normalisation, and it had no sweep at all: analysis was
    # reachable only from POST /batches/{id}/analyze, so a Collector's findings
    # became AssetFindings automatically and then stopped — 0 batches had ever
    # reached ANALYZED. A finding is not a threat anybody can act on until this
    # runs, so it is not optional plumbing.
    #
    # Slower than normalisation on purpose: this one builds threats and
    # recommendations for a whole organisation, so it is the more expensive
    # sweep, and a finding arriving 90 seconds later changes nothing for a
    # person reading a dashboard.
    "analyze-pending-ingestion-batches": {
        "task": "src.core.tasks.risk_intelligence_analysis_tasks.analyze_pending_ingestion_batches",
        "schedule": 90.0,
    },
    # BUG-DISC-18: hourly, not on the fast loop. Retention horizons are measured
    # in days, so nothing is gained by checking more often, and a prune
    # competing with discovery writes for locks would be actively worse.
    "enforce-signal-retention": {
        "task": "src.core.tasks.signal_retention_tasks.enforce_signal_retention",
        "schedule": 3600.0,
    },
    # #242: every 5 minutes. Cadences are measured in days, so this could run
    # far less often — but a schedule's whole value is that its next occurrence
    # is visible and punctual, and five minutes keeps the worst-case lateness
    # small enough that nobody has to reason about it. An empty sweep is one
    # indexed no-op query.
    #
    # Note this entry is the *mechanism*, not the recurrence. The schedule is a
    # RecurrenceSchedule row an organisation can see and pause; entries here are
    # platform sweeps, identical for every tenant, which is exactly what #242
    # ruled out as a way to express an approved cadence.
    "materialize-due-recurrence-occurrences": {
        "task": "src.core.tasks.recurrence_tasks.materialize_due_recurrence_occurrences",
        "schedule": 300.0,
    },
}
