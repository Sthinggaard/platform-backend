"""Keeping a lease alive while the Collector holding it is still working.

Søren, 2026-08-25, watching a real scan of a /24 retry forever: nmap attempt 1
expired, attempt 2 expired, attempt 3 started, and the run never finished.

**The gap.** ``WORKER_LEASE_DEFAULT_SECONDS`` is a flat five minutes, and its
comment explains why: *"a dead worker's job must become reclaimable soon, not
after a long silent gap"*. That reasoning is right. What it cannot do is tell a
**dead** worker from a **slow** one — and a standard-discovery sweep of a /24
with service fingerprinting takes far longer than five minutes on any real
network. So a healthy Collector, mid-scan, had its job reclaimed underneath it,
retried, and reclaimed again.

**The fix keeps the intent exactly.** A lease is renewed only while the
Collector holding it is heartbeating. Heartbeats stop — the machine died, the
container was killed, the network went — and the lease expires on the original
schedule and the job is reclaimed, which is the behaviour that was wanted. A
Collector that is alive and working keeps its lease, which is the behaviour that
was missing.

``WorkerLease.heartbeat_at`` has existed since the model was written and was
never set by anything — the same shape as Gap A in
``discovery_execution_retry_service``, where ``lease_expires_at`` was recorded
and never read. It is written here, so "when did we last hear from the holder of
this lease?" becomes answerable rather than inferred.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from src.core.constants.discovery_execution_enums import (
    WORKER_LEASE_DEFAULT_SECONDS,
    ProviderExecutionStatus,
)
from src.core.model_defs.discovery_execution import (
    DiscoveryExecutionPlan,
    ExecutionStage,
    ProviderExecution,
    WorkerLease,
)
from src.core.model_defs.discovery_run import DiscoveryRun

#: Only work that is genuinely in flight. A lease on anything else is not being
#: worked on, and extending it would hold a slot nobody is using.
_IN_FLIGHT = (
    ProviderExecutionStatus.LEASED.value,
    ProviderExecutionStatus.RUNNING.value,
)


def renew_leases_for_scanner(db: Session, *, scanner_instance_id: str) -> int:
    """Extend every in-flight lease held on this Collector's behalf.

    Returns how many were renewed, so a caller can say so rather than guess.

    Scoped by the run's ``scanner_instance_id`` — the only link between a lease
    and the machine actually doing the work. A Collector can therefore only ever
    renew leases for its own jobs, which matters because this is reached from an
    agent-authenticated route.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    leases = (
        db.query(WorkerLease)
        .join(ProviderExecution, ProviderExecution.id == WorkerLease.provider_execution_id)
        .join(ExecutionStage, ExecutionStage.id == ProviderExecution.execution_stage_id)
        .join(
            DiscoveryExecutionPlan,
            DiscoveryExecutionPlan.id == ExecutionStage.execution_plan_id,
        )
        .join(DiscoveryRun, DiscoveryRun.id == DiscoveryExecutionPlan.discovery_run_id)
        .filter(
            WorkerLease.released_at.is_(None),
            DiscoveryRun.scanner_instance_id == scanner_instance_id,
            ProviderExecution.status.in_(_IN_FLIGHT),
        )
        .all()
    )

    for lease in leases:
        lease.heartbeat_at = now
        lease.lease_expires_at = now + timedelta(seconds=WORKER_LEASE_DEFAULT_SECONDS)
        db.add(lease)

    return len(leases)
