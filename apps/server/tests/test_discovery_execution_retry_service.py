"""Step 4.2 Part 2 — DISC-27/28: lease-expiry reconciliation + retry engine.

handle_job_failure (the classification), reconcile_expired_leases (Gap A —
a dead/offline scanner's stale lease must unblock its job, not stall the
stage/plan forever), and process_due_retries (Gap B — a retryable failure
actually gets a new sibling attempt once its backoff elapses, rather than
RETRYABLE_PROVIDER_FAILURE_CODES/NON_RETRYABLE_PROVIDER_FAILURE_CODES being
defined but never consulted)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.discovery_execution_enums import ExecutionPlanStatus, ExecutionStageStatus, ProviderExecutionStatus
from src.core.constants.discovery_run_enums import DiscoveryRunStatus, DiscoveryStage
from src.core.constants.evidence_scanner_enums import ScannerInstallationMethod, ScannerProfile
from src.core.constants.evidence_source_enums import EvidenceSourceType
from src.core.database import Base
from src.core.model_defs.discovery_execution import (
    DiscoveryExecutionPlan,
    EvidencePackage,
    ExecutionStage,
    ExecutionStageDependency,
    ProviderExecution,
    WorkerLease,
)
from src.core.model_defs.discovery_run import DiscoveryRun, ScannerCommand
from src.core.model_defs.discovery_scope_proposal import DiscoveryScopeProposal
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.model_defs.evidence_scanner import ScannerDomainTarget, ScannerInstance, ScannerNetworkTarget
from src.core.model_defs.evidence_scanner import CollectorReadinessReport
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.models import Organization, User
from src.core.services.discovery_command_service import utcnow
from src.core.services.discovery_execution_plan_service import generate_execution_plan
from src.core.services.discovery_execution_retry_service import (
    ProviderExecutionRetryError,
    handle_job_failure,
    process_due_retries,
    reconcile_expired_leases,
    retry_provider_execution,
)
from src.core.services.discovery_execution_scheduler_service import advance_stage_completion, dispatch_ready_jobs
from src.core.services.discovery_run_service import approve_discovery_run, create_discovery_run
from src.core.services.evidence_scanner_service import (
    add_domain_target,
    approve_domain_target,
    install_scanner,
    record_heartbeat,
    record_tool_validation,
    select_scan_profile,
)
from src.core.services.evidence_source_service import create_evidence_source
from discovery_boundary_fixture import approve_test_boundary


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            User.__table__,
            EvidenceSource.__table__,
            ScannerInstance.__table__,
            CollectorReadinessReport.__table__,
            ScannerDomainTarget.__table__,
            ScannerNetworkTarget.__table__,
            DiscoveryRun.__table__,
            DiscoveryScopeProposal.__table__,
            # #248 — the proposal points at a PermissionProfile now, and a
            # profile hangs off a PermissionSubject. Both must exist or every
            # test touching a proposal dies on a missing table.
            PermissionSubject.__table__,
            PermissionProfile.__table__,
            ScannerCommand.__table__,
            DiscoveryExecutionPlan.__table__,
            ExecutionStage.__table__,
            ExecutionStageDependency.__table__,
            ProviderExecution.__table__,
            WorkerLease.__table__,
            EvidencePackage.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org", country="DK", technical_setup_owner_user_id=1),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _plan_for_profile(db: Session, *, profile: str) -> DiscoveryExecutionPlan:
    source = create_evidence_source(db, organization_id=1, name="Scanner", source_type=EvidenceSourceType.SCANNER)
    db.commit()
    result = install_scanner(db, source, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    instance = result.instance
    record_heartbeat(db, instance)
    select_scan_profile(db, instance, profile=profile)
    record_tool_validation(
        db,
        instance,
        tool_status={"nmap": "available", "subfinder": "available", "nuclei": "available", "nuclei_templates": "available"},
    )
    db.commit()
    target = add_domain_target(db, source, domain="example.com")
    approve_domain_target(db, target, approved_by_user_id=1)
    db.commit()

    approve_test_boundary(db, organization_id=1, evidence_source_id=source.id)
    organization = db.query(Organization).filter(Organization.id == 1).first()
    run = create_discovery_run(db, organization=organization, instance=instance, requested_by_user_id=1)
    if run.status == DiscoveryRunStatus.AWAITING_APPROVAL.value:
        approve_discovery_run(db, run, approved_by_user_id=1)
    db.commit()
    db.refresh(run)

    plan = generate_execution_plan(db, run)
    db.commit()
    db.refresh(plan)
    return plan


def _stage(db: Session, plan: DiscoveryExecutionPlan, stage_key: str) -> ExecutionStage:
    return (
        db.query(ExecutionStage)
        .filter(ExecutionStage.execution_plan_id == plan.id, ExecutionStage.stage_key == stage_key)
        .first()
    )


def _jobs(db: Session, stage: ExecutionStage) -> list[ProviderExecution]:
    return db.query(ProviderExecution).filter(ProviderExecution.execution_stage_id == stage.id).all()


def _resolve_all_jobs(db: Session, stage: ExecutionStage, status: str) -> None:
    """CA-04.3 — EXTERNAL_DISCOVERY now has two real jobs (nmap,
    subfinder); a stage-level assertion needs every one of them terminal,
    not just _jobs(db, stage)[0]."""
    for job in _jobs(db, stage):
        job.status = status
        db.add(job)


def test_retryable_failure_schedules_retry_with_backoff(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    job = _jobs(db, external)[0]
    assert job.attempt_number == 1

    handle_job_failure(db, job, failure_code="provider_timeout", failure_message="timed out")
    db.commit()
    db.refresh(job)

    assert job.status == ProviderExecutionStatus.RETRY_SCHEDULED.value
    assert job.failure_code == "provider_timeout"
    assert job.next_retry_at is not None
    assert job.next_retry_at > utcnow()


def test_non_retryable_failure_terminal_fails_and_cascades(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    internal = _stage(db, plan, DiscoveryStage.INTERNAL_DISCOVERY.value)
    fingerprinting = _stage(db, plan, DiscoveryStage.SERVICE_FINGERPRINTING.value)

    for stage in (external, internal):
        # CA-04.3 — external has two jobs (nmap, subfinder); all of them
        # must fail non-retryably for the stage to fail outright.
        for job in _jobs(db, stage):
            handle_job_failure(db, job, failure_code="credentials_invalid", failure_message="bad creds")
        db.commit()
        advance_stage_completion(db, stage.id)
        db.commit()

    db.refresh(external)
    db.refresh(fingerprinting)
    assert external.status == ExecutionStageStatus.FAILED.value
    # Non-retryable failure never gets a next_retry_at.
    assert all(job.next_retry_at is None for job in _jobs(db, external))
    # Failure Isolation still holds: both prerequisites permanently failed
    # but the dependent still unblocks.
    assert fingerprinting.status == ExecutionStageStatus.READY.value


def test_retryable_failure_terminal_fails_once_max_attempts_exhausted(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    job = _jobs(db, external)[0]
    job.attempt_number = 3  # nmap's own declared maxAttempts (see nmap_provider.capabilities())
    db.add(job)
    db.commit()

    handle_job_failure(db, job, failure_code="provider_timeout", failure_message="timed out again")
    db.commit()
    db.refresh(job)

    assert job.status == ProviderExecutionStatus.FAILED.value
    assert job.next_retry_at is None


def test_reconcile_expired_leases_unblocks_a_stuck_job(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    dispatch_ready_jobs(db)
    db.commit()

    job = _jobs(db, external)[0]
    assert job.status == ProviderExecutionStatus.LEASED.value
    lease = db.query(WorkerLease).filter(WorkerLease.provider_execution_id == job.id).first()
    assert lease is not None and lease.released_at is None

    lease.lease_expires_at = utcnow() - timedelta(minutes=1)
    db.add(lease)
    db.commit()

    reconciled = reconcile_expired_leases(db)
    db.commit()

    assert len(reconciled) == 1
    db.refresh(job)
    db.refresh(lease)
    assert lease.released_at is not None
    # worker_lease_expired is retryable and this is attempt 1 — scheduled,
    # not terminally failed.
    assert job.status == ProviderExecutionStatus.RETRY_SCHEDULED.value
    assert job.failure_code == "worker_lease_expired"
    assert job.next_retry_at is not None


def test_reconcile_expired_leases_skips_already_resolved_job(db: Session):
    """A lease whose job already reached a terminal status through some
    other path (e.g. the scanner reported a result right as its lease was
    about to expire) must not be double-processed."""
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    dispatch_ready_jobs(db)
    db.commit()

    job = _jobs(db, external)[0]
    lease = db.query(WorkerLease).filter(WorkerLease.provider_execution_id == job.id).first()
    lease.lease_expires_at = utcnow() - timedelta(minutes=1)
    db.add(lease)
    job.status = ProviderExecutionStatus.COMPLETED.value
    job.completed_at = utcnow()
    db.add(job)
    db.commit()

    reconciled = reconcile_expired_leases(db)
    db.commit()

    assert reconciled == []
    db.refresh(job)
    assert job.status == ProviderExecutionStatus.COMPLETED.value  # untouched


def test_process_due_retries_spawns_exactly_one_child_per_original(db: Session):
    """A due retry must be consumed when it spawns.

    Before this was fixed the original kept its due next_retry_at, so every
    scheduler tick (15s) selected it again and spawned another sibling.
    Observed locally: one original produced 374 children and a single run
    accumulated roughly 10,000 provider executions.
    """
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    original, _other = _jobs(db, external)

    handle_job_failure(db, original, failure_code="provider_timeout", failure_message="timed out")
    db.commit()
    original.next_retry_at = utcnow() - timedelta(seconds=1)
    db.add(original)
    db.commit()

    first = process_due_retries(db)
    db.commit()
    second = process_due_retries(db)
    db.commit()
    third = process_due_retries(db)
    db.commit()

    assert len(first) == 1
    assert second == []
    assert third == []

    children = (
        db.query(ProviderExecution)
        .filter(ProviderExecution.retry_of_provider_execution_id == original.id)
        .all()
    )
    assert len(children) == 1


def test_process_due_retries_spawns_sibling_job_and_stage_completes_after(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    internal = _stage(db, plan, DiscoveryStage.INTERNAL_DISCOVERY.value)
    # CA-04.3 — external has two jobs (nmap, subfinder); this test only
    # exercises retrying one of them (the other completes normally below).
    original, other_external_job = _jobs(db, external)

    handle_job_failure(db, original, failure_code="provider_timeout", failure_message="timed out")
    db.commit()
    advance_stage_completion(db, external.id)
    db.commit()
    db.refresh(external)
    # Still open — a retry is scheduled, not yet a terminal stage outcome.
    assert external.status == ExecutionStageStatus.READY.value

    # Not due yet.
    assert process_due_retries(db) == []

    original.next_retry_at = utcnow() - timedelta(seconds=1)
    db.add(original)
    db.commit()

    spawned = process_due_retries(db)
    db.commit()

    assert len(spawned) == 1
    retry_job = spawned[0]
    assert retry_job.retry_of_provider_execution_id == original.id
    assert retry_job.attempt_number == original.attempt_number + 1
    assert retry_job.status == ProviderExecutionStatus.PENDING.value
    assert retry_job.execution_stage_id == external.id

    db.refresh(original)
    assert original.status == ProviderExecutionStatus.RETRY_SCHEDULED.value  # never mutated

    # The superseded original must not keep the stage open forever now that
    # its replacement exists — completing the retry job (and internal's own
    # job) should resolve the stage/plan normally.
    retry_job.status = ProviderExecutionStatus.COMPLETED.value
    db.add(retry_job)
    other_external_job.status = ProviderExecutionStatus.COMPLETED.value
    db.add(other_external_job)
    internal_job = _jobs(db, internal)[0]
    internal_job.status = ProviderExecutionStatus.COMPLETED.value
    db.add(internal_job)
    db.commit()

    advance_stage_completion(db, external.id)
    advance_stage_completion(db, internal.id)
    db.commit()

    db.refresh(external)
    db.refresh(internal)
    assert external.status == ExecutionStageStatus.COMPLETED.value
    assert internal.status == ExecutionStageStatus.COMPLETED.value


# --- DISC-40: customer-triggered stage/job-level retry ----------------------


def test_customer_retry_reopens_a_terminally_failed_stage_while_plan_still_executing(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    # CA-04.3 — external has two jobs (nmap, subfinder); both must exhaust
    # their attempts and fail for the stage itself to fail outright.
    jobs = _jobs(db, external)
    for job in jobs:
        job.attempt_number = 3  # exhausts each provider's own declared maxAttempts
        db.add(job)
    db.commit()
    for job in jobs:
        handle_job_failure(db, job, failure_code="provider_timeout", failure_message="timed out")
    db.commit()
    advance_stage_completion(db, external.id)
    db.commit()
    db.refresh(external)
    job = jobs[0]
    db.refresh(job)
    assert job.status == ProviderExecutionStatus.FAILED.value
    assert external.status == ExecutionStageStatus.FAILED.value
    db.refresh(plan)
    assert plan.status == ExecutionPlanStatus.EXECUTING.value  # internal stage still open

    retry_job = retry_provider_execution(db, job)
    db.commit()

    assert retry_job.retry_of_provider_execution_id == job.id
    assert retry_job.attempt_number == job.attempt_number + 1
    assert retry_job.status == ProviderExecutionStatus.PENDING.value
    db.refresh(external)
    assert external.status == ExecutionStageStatus.READY.value  # reopened for dispatch
    db.refresh(job)
    assert job.status == ProviderExecutionStatus.FAILED.value  # original never mutated


def test_customer_retry_rejects_a_non_retryable_failure_code(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    job = _jobs(db, external)[0]
    handle_job_failure(db, job, failure_code="credentials_invalid", failure_message="bad creds")
    db.commit()
    db.refresh(job)
    assert job.status == ProviderExecutionStatus.FAILED.value

    with pytest.raises(ProviderExecutionRetryError) as excinfo:
        retry_provider_execution(db, job)
    assert excinfo.value.reason_code == "not_retryable"


def test_customer_retry_rejects_a_job_that_is_not_failed_yet(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    job = _jobs(db, external)[0]  # still PENDING/LEASED, never failed

    with pytest.raises(ProviderExecutionRetryError) as excinfo:
        retry_provider_execution(db, job)
    assert excinfo.value.reason_code == "not_failed"


def test_customer_retry_rejects_once_the_whole_plan_has_gone_terminal(db: Session):
    """The architectural boundary this ticket must respect: once every
    required stage is terminal, _advance_plan_completion's own guard
    never re-evaluates that plan again, so a job-level retry can no
    longer meaningfully resurrect it — the whole-run /retry route (a
    fresh plan) is the only correct path from here."""
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    internal = _stage(db, plan, DiscoveryStage.INTERNAL_DISCOVERY.value)
    fingerprinting = _stage(db, plan, DiscoveryStage.SERVICE_FINGERPRINTING.value)

    for stage in (external, internal):
        # CA-04.3 — external has two jobs (nmap, subfinder); all of them
        # must exhaust and fail for the stage itself to fail outright.
        jobs = _jobs(db, stage)
        for job in jobs:
            job.attempt_number = 3
            db.add(job)
        db.commit()
        for job in jobs:
            handle_job_failure(db, job, failure_code="provider_timeout", failure_message="timed out")
        db.commit()
        advance_stage_completion(db, stage.id)
        db.commit()

    # Failure Isolation promoted fingerprinting to READY once both its
    # dependencies went terminal — it still needs its own job resolved
    # before every stage in the plan is terminal.
    db.refresh(fingerprinting)
    fingerprinting_job = _jobs(db, fingerprinting)[0]
    fingerprinting_job.attempt_number = 3
    db.add(fingerprinting_job)
    db.commit()
    handle_job_failure(db, fingerprinting_job, failure_code="provider_timeout", failure_message="timed out")
    db.commit()
    advance_stage_completion(db, fingerprinting.id)
    db.commit()

    db.refresh(plan)
    assert plan.status == ExecutionPlanStatus.FAILED.value

    failed_job = _jobs(db, external)[0]
    assert failed_job.status == ProviderExecutionStatus.FAILED.value

    with pytest.raises(ProviderExecutionRetryError) as excinfo:
        retry_provider_execution(db, failed_job)
    assert excinfo.value.reason_code == "plan_already_terminal"


# --- Cancellation must actually stop work (Søren's stress test) ----------------------------


def test_a_cancelled_run_does_not_have_its_work_respawned_by_the_retry_tick(db: Session):
    """The reason a cancellation never completed. cancel_execution_plan cancels
    the jobs that exist *now*; process_due_retries then selected RETRY_SCHEDULED
    rows organisation-wide, with no reference to their run, and spawned fresh
    PENDING siblings on the very next tick. The run could never leave
    CANCELLATION_REQUESTED. Observed live: 8 jobs still RETRY_SCHEDULED while
    the run was cancelling."""
    from src.core.constants.discovery_run_enums import DiscoveryRunStatus
    from src.core.services.discovery_execution_retry_service import process_due_retries

    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    job, _other = _jobs(db, external)
    handle_job_failure(db, job, failure_code="provider_timeout", failure_message="timed out")
    db.commit()
    job.next_retry_at = utcnow() - timedelta(seconds=1)
    db.add(job)
    db.commit()

    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == plan.discovery_run_id).one()
    run.status = DiscoveryRunStatus.CANCELLATION_REQUESTED.value
    db.commit()

    spawned = process_due_retries(db)
    db.commit()

    assert spawned == []
    db.refresh(job)
    # The schedule is consumed, so the tick cannot keep reconsidering it.
    assert job.next_retry_at is None


def test_a_live_run_still_gets_its_retry(db: Session):
    """The guard must not break the thing retries exist for."""
    from src.core.services.discovery_execution_retry_service import process_due_retries

    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    job, _other = _jobs(db, external)
    handle_job_failure(db, job, failure_code="provider_timeout", failure_message="timed out")
    db.commit()
    job.next_retry_at = utcnow() - timedelta(seconds=1)
    db.add(job)
    db.commit()

    spawned = process_due_retries(db)

    assert len(spawned) == 1
    assert spawned[0].retry_of_provider_execution_id == job.id


# --- A live Collector must not have its job reclaimed underneath it ---------


def _lease_for(db: Session, job: ProviderExecution, *, expires_in_seconds: int) -> WorkerLease:
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    lease = WorkerLease(
        provider_execution_id=job.id,
        worker_id="worker-1",
        leased_at=now,
        lease_expires_at=now + timedelta(seconds=expires_in_seconds),
    )
    db.add(lease)
    db.commit()
    return lease


def test_a_heartbeating_collector_keeps_the_lease_on_work_it_is_running(db: Session):
    """Søren watched a /24 scan retry forever.

    WORKER_LEASE_DEFAULT_SECONDS is five minutes, and a standard-discovery sweep
    of a /24 with service fingerprinting takes far longer. The lease expired
    while the Collector was still scanning, the job was reclaimed, retried, and
    reclaimed again — attempts 1 and 2 both `worker_lease_expired`.

    The five-minute default is right for what it was for: telling that a worker
    died. What it could not do is tell a dead worker from a slow one.
    """
    from src.core.services.worker_lease_renewal_service import renew_leases_for_scanner

    plan = _plan_for_profile(db, profile=ScannerProfile.STANDARD_DISCOVERY.value)
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == plan.discovery_run_id).one()
    stage = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    job = _jobs(db, stage)[0]
    job.status = ProviderExecutionStatus.RUNNING.value
    db.commit()

    lease = _lease_for(db, job, expires_in_seconds=10)
    before = lease.lease_expires_at

    renewed = renew_leases_for_scanner(db, scanner_instance_id=run.scanner_instance_id)
    db.commit()
    db.refresh(lease)

    assert renewed == 1
    assert lease.lease_expires_at > before
    # `heartbeat_at` has existed since the model was written and nothing set it,
    # so "when did we last hear from this lease's holder?" was unanswerable.
    assert lease.heartbeat_at is not None


def test_a_silent_collector_still_loses_its_lease(db: Session):
    """The behaviour the five-minute default exists to produce, kept intact.

    Renewal happens on a heartbeat and nowhere else. A Collector that has died —
    machine gone, container killed, network cut — sends none, so its lease
    expires on the original schedule and the job becomes reclaimable. That is
    the whole point of leasing, and it must survive this change.
    """
    from src.core.services.worker_lease_renewal_service import renew_leases_for_scanner

    plan = _plan_for_profile(db, profile=ScannerProfile.STANDARD_DISCOVERY.value)
    stage = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    job = _jobs(db, stage)[0]
    job.status = ProviderExecutionStatus.RUNNING.value
    db.commit()
    lease = _lease_for(db, job, expires_in_seconds=-30)
    before = lease.lease_expires_at

    # A *different* Collector heartbeating renews nothing here.
    renewed = renew_leases_for_scanner(db, scanner_instance_id="some-other-instance")
    db.commit()
    db.refresh(lease)

    assert renewed == 0
    assert lease.lease_expires_at == before


def test_a_lease_on_work_that_is_not_running_is_not_extended(db: Session):
    """Extending it would hold a slot nobody is using."""
    from src.core.services.worker_lease_renewal_service import renew_leases_for_scanner

    plan = _plan_for_profile(db, profile=ScannerProfile.STANDARD_DISCOVERY.value)
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == plan.discovery_run_id).one()
    stage = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    job = _jobs(db, stage)[0]
    job.status = ProviderExecutionStatus.COMPLETED.value
    db.commit()
    _lease_for(db, job, expires_in_seconds=10)

    assert renew_leases_for_scanner(db, scanner_instance_id=run.scanner_instance_id) == 0
