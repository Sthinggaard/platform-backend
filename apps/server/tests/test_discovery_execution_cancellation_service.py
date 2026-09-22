"""Step 4.2 Part 2 — DISC-31: plan/stage/job-level cancellation.

cancel_execution_plan (propagating a run-level cancellation into an
in-flight DiscoveryExecutionPlan — the disclosed follow-up from DISC-24)
and the late-report guards in discovery_execution_command_service.py that
keep a scanner's stale report from overwriting an already-cancelled job."""

from __future__ import annotations

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
from src.core.services.discovery_execution_cancellation_service import cancel_execution_plan
from src.core.services.discovery_execution_command_service import (
    handle_provider_execution_acknowledgement,
    record_provider_execution_result,
)
from src.core.services.discovery_execution_plan_service import generate_execution_plan
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


def test_cancel_execution_plan_cancels_pending_stages_and_jobs(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == plan.discovery_run_id).first()

    cancelled_plan = cancel_execution_plan(db, run)
    db.commit()

    assert cancelled_plan.id == plan.id
    assert cancelled_plan.status == ExecutionPlanStatus.CANCELLED.value
    assert cancelled_plan.completed_at is not None

    stages = db.query(ExecutionStage).filter(ExecutionStage.execution_plan_id == plan.id).all()
    assert stages and all(s.status == ExecutionStageStatus.CANCELLED.value for s in stages)
    for stage in stages:
        assert all(job.status == ProviderExecutionStatus.CANCELLED.value for job in _jobs(db, stage))


def test_cancel_execution_plan_preserves_already_terminal_stages_and_releases_active_leases(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == plan.discovery_run_id).first()
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    internal = _stage(db, plan, DiscoveryStage.INTERNAL_DISCOVERY.value)

    # external already genuinely completed before the cancellation request.
    # CA-04.3 — it has two jobs (nmap, subfinder); both must complete for
    # the stage itself to reach a real terminal COMPLETED status.
    external_jobs = _jobs(db, external)
    for job in external_jobs:
        job.status = ProviderExecutionStatus.COMPLETED.value
        db.add(job)
    db.commit()
    advance_stage_completion(db, external.id)
    db.commit()
    external_job = external_jobs[0]

    # internal is in-flight (dispatched, leased) when cancellation lands.
    dispatch_ready_jobs(db)
    db.commit()
    internal_job = _jobs(db, internal)[0]
    assert internal_job.status == ProviderExecutionStatus.LEASED.value
    lease = db.query(WorkerLease).filter(WorkerLease.provider_execution_id == internal_job.id).first()
    assert lease is not None and lease.released_at is None

    cancel_execution_plan(db, run)
    db.commit()

    db.refresh(external)
    db.refresh(external_job)
    db.refresh(internal)
    db.refresh(internal_job)
    db.refresh(lease)

    # external's real outcome (COMPLETED) is untouched by the cancellation.
    assert external.status == ExecutionStageStatus.COMPLETED.value
    assert external_job.status == ProviderExecutionStatus.COMPLETED.value
    # internal's in-flight job is cancelled and its lease released.
    assert internal.status == ExecutionStageStatus.CANCELLED.value
    assert internal_job.status == ProviderExecutionStatus.CANCELLED.value
    assert lease.released_at is not None


def test_cancel_execution_plan_is_a_noop_without_a_plan_or_once_already_terminal(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Scanner", source_type=EvidenceSourceType.SCANNER)
    db.commit()
    result = install_scanner(db, source, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    record_heartbeat(db, result.instance)
    select_scan_profile(db, result.instance, profile=ScannerProfile.SAFE_DISCOVERY.value)
    db.commit()
    organization = db.query(Organization).filter(Organization.id == 1).first()
    run_without_plan = create_discovery_run(db, organization=organization, instance=result.instance, requested_by_user_id=1)
    db.commit()
    assert cancel_execution_plan(db, run_without_plan) is None  # no target approved yet, so no plan was ever generated

    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    run2 = db.query(DiscoveryRun).filter(DiscoveryRun.id == plan.discovery_run_id).first()
    cancel_execution_plan(db, run2)
    db.commit()
    db.refresh(plan)
    assert plan.status == ExecutionPlanStatus.CANCELLED.value

    # A second call once already terminal must not raise or re-stamp completed_at.
    first_completed_at = plan.completed_at
    again = cancel_execution_plan(db, run2)
    db.commit()
    db.refresh(plan)
    assert again.id == plan.id
    assert plan.completed_at == first_completed_at


def test_late_acknowledgement_after_cancellation_is_a_noop(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == plan.discovery_run_id).first()
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)

    dispatch_ready_jobs(db)
    db.commit()
    job = _jobs(db, external)[0]
    command = db.query(ScannerCommand).filter(ScannerCommand.provider_execution_id == job.id).first()

    cancel_execution_plan(db, run)
    db.commit()
    db.refresh(job)
    assert job.status == ProviderExecutionStatus.CANCELLED.value

    # The scanner's acknowledgement arrives after the cancellation already landed.
    handle_provider_execution_acknowledgement(db, command, accepted=True, rejection_code=None)
    db.commit()
    db.refresh(job)
    assert job.status == ProviderExecutionStatus.CANCELLED.value  # untouched, not flipped back to RUNNING


def test_late_result_report_after_cancellation_is_a_noop(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == plan.discovery_run_id).first()
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)

    dispatch_ready_jobs(db)
    db.commit()
    job = _jobs(db, external)[0]
    command = db.query(ScannerCommand).filter(ScannerCommand.provider_execution_id == job.id).first()
    instance = db.query(ScannerInstance).filter(ScannerInstance.id == run.scanner_instance_id).first()

    cancel_execution_plan(db, run)
    db.commit()
    db.refresh(job)
    assert job.status == ProviderExecutionStatus.CANCELLED.value

    result = record_provider_execution_result(
        db,
        instance,
        command.id,
        status=ProviderExecutionStatus.COMPLETED.value,
        evidence_format=None,
        raw_evidence_payload=None,
        schema_version="1.0",
        checkpoint=None,
        failure_code=None,
        failure_message=None,
    )
    db.commit()
    db.refresh(job)
    assert result.status == ProviderExecutionStatus.CANCELLED.value  # untouched, not flipped to COMPLETED
    assert job.status == ProviderExecutionStatus.CANCELLED.value
    assert db.query(EvidencePackage).filter(EvidencePackage.provider_execution_id == job.id).first() is None


# --- A superseded retry is old news, not an error (2026-08-25) ----------------


def test_an_acknowledgement_for_a_retry_scheduled_job_is_absorbed(db: Session):
    """Observed live on run 6fcadc3c: a Collector acknowledged a command whose
    execution had since been retry-scheduled, the transition to RUNNING was
    refused, and the 422 put the agent into a permanent loop — "could not be
    completed, will retry next cycle", every cycle, for ever.

    RETRY_SCHEDULED is not terminal, so the DISC-31 guard did not cover it. It
    is *superseded*: the retry engine spawns the next attempt as a new sibling
    row and never mutates this one, so an ack for it is late news about a job
    somebody else has already moved on from."""
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)

    dispatch_ready_jobs(db)
    db.commit()
    job = _jobs(db, external)[0]
    command = db.query(ScannerCommand).filter(ScannerCommand.provider_execution_id == job.id).first()

    job.status = ProviderExecutionStatus.RETRY_SCHEDULED.value
    db.add(job)
    db.commit()

    # Must not raise. The raise is what became the 422 the Collector could
    # never get past.
    handle_provider_execution_acknowledgement(db, command, accepted=True, rejection_code=None)
    db.commit()
    db.refresh(job)

    assert job.status == ProviderExecutionStatus.RETRY_SCHEDULED.value


def test_a_result_report_for_a_retry_scheduled_job_is_absorbed(db: Session):
    """The same guard on the reporting half. Recording an outcome on a
    superseded row would write a result nothing reads onto a row nobody is
    waiting for — `_current_jobs_for_stage` excludes it from the rollup."""
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == plan.discovery_run_id).first()
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)

    dispatch_ready_jobs(db)
    db.commit()
    job = _jobs(db, external)[0]
    command = db.query(ScannerCommand).filter(ScannerCommand.provider_execution_id == job.id).first()
    instance = db.query(ScannerInstance).filter(ScannerInstance.id == run.scanner_instance_id).first()

    job.status = ProviderExecutionStatus.RETRY_SCHEDULED.value
    db.add(job)
    db.commit()

    result = record_provider_execution_result(
        db,
        instance,
        command.id,
        status=ProviderExecutionStatus.COMPLETED.value,
        evidence_format=None,
        raw_evidence_payload=None,
        schema_version="1.0",
        checkpoint=None,
        failure_code=None,
        failure_message=None,
    )
    db.commit()
    db.refresh(job)

    assert result.status == ProviderExecutionStatus.RETRY_SCHEDULED.value
    assert job.status == ProviderExecutionStatus.RETRY_SCHEDULED.value
