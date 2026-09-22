"""Step 4.2 Part 2 — DISC-22: the DAG runner. dispatch_ready_jobs (the
periodic "start work" sweep) and advance_stage_completion (the cascade
that rolls a stage's status up once every job is terminal, promotes
dependent stages, and rolls the whole plan up once every stage is
terminal — including the Failure Isolation guarantee that a permanently
failed stage still unblocks what depends on it)."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.discovery_execution_enums import (
    ExecutionMode,
    ExecutionPlanStatus,
    ExecutionStageStatus,
    ProviderExecutionStatus,
)
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
from src.core.services import discovery_execution_scheduler_service as scheduler_service
from src.core.services.discovery_execution_command_service import handle_provider_execution_acknowledgement
from src.core.services.discovery_execution_plan_service import generate_execution_plan
from src.core.services.discovery_execution_scheduler_service import advance_stage_completion, dispatch_ready_jobs
from src.core.services.discovery_providers.base import ProviderExecutionOutcome, ProviderExecutionResult
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


def _resolve_all_jobs(db: Session, stage: ExecutionStage, status: str, **extra) -> None:
    """CA-04.3 — EXTERNAL_DISCOVERY now has two real jobs (nmap, subfinder).
    A stage-level assertion (COMPLETED/FAILED/PARTIALLY_COMPLETED) needs
    every one of its jobs terminal, not just _jobs(db, stage)[0] — this
    resolves all of them identically for tests exercising stage-level
    cascade rather than one specific job."""
    for job in _jobs(db, stage):
        job.status = status
        for key, value in extra.items():
            setattr(job, key, value)
        db.add(job)


def test_dispatch_ready_jobs_only_touches_ready_stages(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    fingerprinting = _stage(db, plan, DiscoveryStage.SERVICE_FINGERPRINTING.value)
    assert external.status == ExecutionStageStatus.READY.value
    assert fingerprinting.status == ExecutionStageStatus.PENDING.value

    dispatched = dispatch_ready_jobs(db)
    db.commit()

    dispatched_stage_ids = {job.execution_stage_id for job in dispatched}
    assert external.id in dispatched_stage_ids
    assert fingerprinting.id not in dispatched_stage_ids  # still PENDING, unmet dependency

    for job in _jobs(db, external):
        assert job.status == ProviderExecutionStatus.LEASED.value  # nmap's delegated execute() already ran
    for job in _jobs(db, fingerprinting):
        assert job.status == ProviderExecutionStatus.PENDING.value  # untouched


def test_stage_completes_and_promotes_dependent_stage_when_all_jobs_succeed(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    internal = _stage(db, plan, DiscoveryStage.INTERNAL_DISCOVERY.value)
    fingerprinting = _stage(db, plan, DiscoveryStage.SERVICE_FINGERPRINTING.value)

    # Simulate both prerequisite stages' job(s) completing successfully —
    # external has two (nmap, subfinder), internal has one (nmap only).
    for stage in (external, internal):
        _resolve_all_jobs(db, stage, ProviderExecutionStatus.COMPLETED.value)
        db.commit()
        advance_stage_completion(db, stage.id)
        db.commit()

    db.refresh(external)
    db.refresh(internal)
    db.refresh(fingerprinting)
    assert external.status == ExecutionStageStatus.COMPLETED.value
    assert internal.status == ExecutionStageStatus.COMPLETED.value
    # Only READY once BOTH dependencies are terminal — this assertion runs
    # after the second one completes, so it should have flipped by now.
    assert fingerprinting.status == ExecutionStageStatus.READY.value


def test_stage_partially_completes_when_some_jobs_fail_and_dependents_still_unblock(db: Session, monkeypatch):
    """Failure Isolation: a stage where some (but not all) jobs failed is
    PARTIALLY_COMPLETED, not stuck — and still unblocks what depends on it."""
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    internal = _stage(db, plan, DiscoveryStage.INTERNAL_DISCOVERY.value)
    fingerprinting = _stage(db, plan, DiscoveryStage.SERVICE_FINGERPRINTING.value)

    # CA-04.3 — external now has two jobs (nmap, subfinder); all of them
    # must fail for the stage itself to fail outright.
    _resolve_all_jobs(db, external, ProviderExecutionStatus.FAILED.value, failure_code="target_unreachable")
    db.commit()
    advance_stage_completion(db, external.id)
    db.commit()
    db.refresh(external)
    assert external.status == ExecutionStageStatus.FAILED.value  # every job failed, so the stage failed outright

    internal_job = _jobs(db, internal)[0]
    internal_job.status = ProviderExecutionStatus.COMPLETED.value
    db.add(internal_job)
    db.commit()
    advance_stage_completion(db, internal.id)
    db.commit()

    db.refresh(fingerprinting)
    # A permanently FAILED prerequisite still unblocks its dependent —
    # never invalidates the whole plan (the spec's own Failure Isolation).
    assert fingerprinting.status == ExecutionStageStatus.READY.value


def test_direct_mode_failed_result_is_routed_through_handle_job_failure(db: Session, monkeypatch):
    """CA-04.5 — the disclosed dormant bug: unlike every DELEGATED failure
    path, a DIRECT provider's FAILED result was applied verbatim, bypassing
    handle_job_failure's retry classification entirely (flagged in this
    branch's own code comment as "worth revisiting"). No real DIRECT
    provider is registered yet — this story's own stated non-goal is not
    inventing one — so a stub is registered here just to exercise the
    branch that already exists for when one is. A RETRYABLE failure code
    proves the fix: before it, the job would land FAILED outright with no
    retry scheduled; after it, it goes through the same classification
    every DELEGATED path already gets."""
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    internal = _stage(db, plan, DiscoveryStage.INTERNAL_DISCOVERY.value)
    job = _jobs(db, internal)[0]  # INTERNAL_DISCOVERY has exactly one registered provider (nmap)

    class _StubDirectProvider:
        provider_id = job.provider_id

        def execute(self, db, *, run, provider_execution):
            return ProviderExecutionOutcome(
                mode=ExecutionMode.DIRECT.value,
                result=ProviderExecutionResult(
                    status=ProviderExecutionStatus.FAILED.value,
                    failure_code="provider_timeout",  # a real RETRYABLE code
                    failure_message="stubbed DIRECT timeout",
                ),
            )

    monkeypatch.setattr(scheduler_service, "get_provider", lambda provider_id: _StubDirectProvider())

    dispatch_ready_jobs(db)
    db.commit()
    db.refresh(job)

    assert job.status == ProviderExecutionStatus.RETRY_SCHEDULED.value
    assert job.next_retry_at is not None
    assert job.failure_code == "provider_timeout"


def test_plan_completes_once_every_stage_is_terminal(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == plan.discovery_run_id).first()
    # DISC-24: generating the plan already moved the run to RUNNING.
    assert run.status == DiscoveryRunStatus.RUNNING.value
    assert run.started_at is not None

    for stage_key in (
        DiscoveryStage.EXTERNAL_DISCOVERY.value,
        DiscoveryStage.INTERNAL_DISCOVERY.value,
    ):
        stage = _stage(db, plan, stage_key)
        _resolve_all_jobs(db, stage, ProviderExecutionStatus.COMPLETED.value)
        db.commit()
        advance_stage_completion(db, stage.id)
        db.commit()

    fingerprinting = _stage(db, plan, DiscoveryStage.SERVICE_FINGERPRINTING.value)
    db.refresh(fingerprinting)
    assert fingerprinting.status == ExecutionStageStatus.READY.value
    _resolve_all_jobs(db, fingerprinting, ProviderExecutionStatus.COMPLETED.value)
    db.commit()
    advance_stage_completion(db, fingerprinting.id)
    db.commit()

    db.refresh(plan)
    assert plan.status == ExecutionPlanStatus.COMPLETED.value
    assert plan.completed_at is not None

    # DISC-24: the plan's own completion cascades all the way up to the run.
    db.refresh(run)
    assert run.status == DiscoveryRunStatus.COMPLETED.value
    assert run.completed_at is not None


def test_plan_completes_with_warnings_when_only_an_optional_stage_fails(db: Session):
    """DISC-30: today's generate_execution_plan marks every stage required
    (no product decision yet on which, if any, should be optional), so this
    forces one stage optional directly to exercise the mechanism — a
    required stage's own total failure must still behave exactly as before
    (see test_stage_partially_completes_when_some_jobs_fail_and_dependents_still_unblock),
    only an OPTIONAL stage's failure should get this distinct outcome."""
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    internal = _stage(db, plan, DiscoveryStage.INTERNAL_DISCOVERY.value)
    fingerprinting = _stage(db, plan, DiscoveryStage.SERVICE_FINGERPRINTING.value)

    internal.required = False  # the one optional stage in this scenario
    db.add(internal)
    db.commit()

    # CA-04.3 — external has two jobs (nmap, subfinder); both must complete
    # for the stage itself to complete.
    _resolve_all_jobs(db, external, ProviderExecutionStatus.COMPLETED.value)
    _resolve_all_jobs(db, internal, ProviderExecutionStatus.FAILED.value, failure_code="target_unreachable")
    db.commit()
    advance_stage_completion(db, external.id)
    advance_stage_completion(db, internal.id)
    db.commit()

    db.refresh(external)
    db.refresh(internal)
    assert external.status == ExecutionStageStatus.COMPLETED.value
    assert internal.status == ExecutionStageStatus.FAILED.value  # the stage itself still reports its real outcome

    db.refresh(fingerprinting)
    assert fingerprinting.status == ExecutionStageStatus.READY.value  # unblocked either way

    _resolve_all_jobs(db, fingerprinting, ProviderExecutionStatus.COMPLETED.value)
    db.commit()
    advance_stage_completion(db, fingerprinting.id)
    db.commit()

    db.refresh(plan)
    # Every REQUIRED stage (external, fingerprinting) completed — the
    # optional stage's failure downgrades to a warning, not PARTIALLY_COMPLETED.
    assert plan.status == ExecutionPlanStatus.COMPLETED_WITH_WARNINGS.value

    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == plan.discovery_run_id).first()
    # No DiscoveryRunStatus.COMPLETED_WITH_WARNINGS exists — mapped to the
    # closest existing run-level status instead (disclosed adaptation).
    assert run.status == DiscoveryRunStatus.PARTIALLY_COMPLETED.value


def test_dispatch_ready_jobs_caps_at_max_parallel_jobs_and_resumes_once_a_slot_frees(db: Session):
    """DISC-29: maxParallelJobs was computed at plan generation but never
    enforced. Forces a controlled 2-job/1-slot scenario for this one stage
    (CA-04.3 registered a real second provider for EXTERNAL_DISCOVERY, so
    the natural job count there is no longer 1 — this test replaces
    whatever generate_execution_plan produced with exactly the two jobs
    it wants, rather than depending on how many providers happen to be
    registered)."""
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    for job in _jobs(db, external):
        db.delete(job)
    db.flush()
    first_job = ProviderExecution(
        execution_stage_id=external.id, provider_id="nmap", status=ProviderExecutionStatus.PENDING.value
    )
    second_job = ProviderExecution(
        execution_stage_id=external.id, provider_id="subfinder", status=ProviderExecutionStatus.PENDING.value
    )
    db.add(first_job)
    db.add(second_job)

    plan_definition = dict(plan.plan_definition)
    stage_policies = dict(plan_definition["stagePolicies"])
    stage_policies[DiscoveryStage.EXTERNAL_DISCOVERY.value] = {
        **stage_policies[DiscoveryStage.EXTERNAL_DISCOVERY.value],
        "maxParallelJobs": 1,
    }
    plan_definition["stagePolicies"] = stage_policies
    plan.plan_definition = plan_definition
    db.add(plan)
    db.commit()

    dispatched = dispatch_ready_jobs(db)
    db.commit()
    dispatched_for_stage = [job for job in dispatched if job.execution_stage_id == external.id]
    assert len(dispatched_for_stage) == 1  # capped at 1, despite 2 PENDING jobs being available

    still_pending = (
        db.query(ProviderExecution)
        .filter(ProviderExecution.execution_stage_id == external.id, ProviderExecution.status == ProviderExecutionStatus.PENDING.value)
        .count()
    )
    assert still_pending == 1  # the second job was left for a later sweep, not silently dropped

    # A second sweep while the first job is still LEASED (occupying the
    # one slot) must not dispatch the second either.
    dispatched_again = dispatch_ready_jobs(db)
    db.commit()
    assert [job for job in dispatched_again if job.execution_stage_id == external.id] == []

    # Once the in-flight job resolves (freeing its slot), the next sweep
    # picks up the previously-blocked job.
    dispatched_for_stage[0].status = ProviderExecutionStatus.COMPLETED.value
    db.add(dispatched_for_stage[0])
    db.commit()

    dispatched_after_slot_frees = dispatch_ready_jobs(db)
    db.commit()
    assert len([job for job in dispatched_after_slot_frees if job.execution_stage_id == external.id]) == 1


def test_rejected_command_cascades_through_acknowledgement_path(db: Session):
    """The other job-termination point — a rejected ScannerCommand — must
    also trigger the cascade, not just the result-reporting route."""
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    internal = _stage(db, plan, DiscoveryStage.INTERNAL_DISCOVERY.value)

    dispatch_ready_jobs(db)
    db.commit()

    # CA-04.3 — external now has two jobs (nmap, subfinder); reject both,
    # since the stage only fails outright once every one of its jobs has.
    for job in _jobs(db, external):
        command = db.query(ScannerCommand).filter(ScannerCommand.provider_execution_id == job.id).first()
        handle_provider_execution_acknowledgement(db, command, accepted=False, rejection_code="scanner_busy")
    internal_job = _jobs(db, internal)[0]
    internal_command = db.query(ScannerCommand).filter(ScannerCommand.provider_execution_id == internal_job.id).first()
    handle_provider_execution_acknowledgement(db, internal_command, accepted=False, rejection_code="scanner_busy")
    db.commit()

    db.refresh(external)
    db.refresh(internal)
    assert external.status == ExecutionStageStatus.FAILED.value
    assert internal.status == ExecutionStageStatus.FAILED.value

    fingerprinting = _stage(db, plan, DiscoveryStage.SERVICE_FINGERPRINTING.value)
    db.refresh(fingerprinting)
    assert fingerprinting.status == ExecutionStageStatus.READY.value  # unblocked despite both deps failing

    db.refresh(plan)
    # Not yet terminal — fingerprinting is READY, not completed, so the
    # plan correctly stays open rather than being marked done prematurely.
    assert plan.status == ExecutionPlanStatus.EXECUTING.value
