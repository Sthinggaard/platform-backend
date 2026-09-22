"""Step 4.2 Part 2 — DISC-35: audit-event coverage completion.

Every EXECUTION_PLAN_AUDIT_*/EXECUTION_STAGE_AUDIT_*/PROVIDER_EXECUTION_AUDIT_*
constant defined since DISC-18 is now actually written somewhere — this
file exercises the real code paths that write each newly-wired one and
confirms the AuditEvent row lands with the right organization_id and
metadata, rather than just trusting the code compiles."""

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

from src.core.constants.discovery_execution_enums import (
    EVIDENCE_PACKAGE_AUDIT_STORAGE_FAILED,
    EXECUTION_PLAN_AUDIT_COMPLETED,
    EXECUTION_PLAN_AUDIT_COMPLETED_WITH_WARNINGS,
    EXECUTION_PLAN_AUDIT_FAILED,
    EXECUTION_STAGE_AUDIT_CANCELLED,
    EXECUTION_STAGE_AUDIT_COMPLETED,
    EXECUTION_STAGE_AUDIT_FAILED,
    EXECUTION_STAGE_AUDIT_STARTED,
    PROVIDER_EXECUTION_AUDIT_CANCELLED,
    PROVIDER_EXECUTION_AUDIT_LEASE_RECLAIMED,
    PROVIDER_EXECUTION_AUDIT_LEASED,
    PROVIDER_EXECUTION_AUDIT_RETRY_QUEUED,
    PROVIDER_EXECUTION_AUDIT_STARTED,
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
from src.core.model_defs.evidence_scanner import (
    CollectorReadinessReport,
    ScannerDomainTarget,
    ScannerInstance,
    ScannerNetworkTarget,
)
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.model_defs.process_scan_scope import ProcessScanScope
from src.core.model_defs.process_scanner_link import ProcessScannerLink
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.model_defs.value_streams import BusinessService, ValueStream
from src.core.models import Organization, User
from src.core.services.discovery_command_service import utcnow
from src.core.services.discovery_execution_cancellation_service import cancel_execution_plan
from src.core.services.discovery_execution_command_service import (
    handle_provider_execution_acknowledgement,
    record_provider_execution_result,
)
from src.core.services.discovery_execution_plan_service import generate_execution_plan
from src.core.services.discovery_execution_retry_service import (
    handle_job_failure,
    reconcile_expired_leases,
)
from src.core.services.discovery_execution_scheduler_service import (
    advance_stage_completion,
    dispatch_ready_jobs,
)
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
from src.core.services.process_scan_scope_service import (
    approve_process_scan_scope,
    create_process_scan_scope_draft,
    submit_process_scan_scope,
)
from src.core.services.process_scanner_link_service import link_scanner_to_process
from discovery_boundary_fixture import approve_test_boundary


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
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
            ValueStream.__table__,
            BusinessService.__table__,
            ProcessScannerLink.__table__,
            ProcessScanScope.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(
                id=1, name="Org", slug="org", country="DK", technical_setup_owner_user_id=1
            ),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _plan_for_profile(
    db: Session, *, profile: str, business_process_id: str | None = None
) -> DiscoveryExecutionPlan:
    source = create_evidence_source(
        db, organization_id=1, name="Scanner", source_type=EvidenceSourceType.SCANNER
    )
    db.commit()
    result = install_scanner(
        db, source, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value
    )
    db.commit()
    instance = result.instance
    record_heartbeat(db, instance)
    select_scan_profile(db, instance, profile=profile)
    record_tool_validation(
        db,
        instance,
        tool_status={
            "nmap": "available",
            "subfinder": "available",
            "nuclei": "available",
            "nuclei_templates": "available",
        },
    )
    db.commit()
    target = add_domain_target(db, source, domain="example.com")
    approve_domain_target(db, target, approved_by_user_id=1)
    db.commit()

    if business_process_id is not None:
        db.add(ValueStream(id=business_process_id, organization_id=1, name="Order to cash"))
        db.commit()
        link_scanner_to_process(
            db, organization_id=1, scanner_instance_id=instance.id, business_process_id=business_process_id
        )
        db.commit()
        scope = create_process_scan_scope_draft(
            db, organization_id=1, business_process_id=business_process_id, checks=["nmap"]
        )
        db.flush()
        scope = submit_process_scan_scope(db, scope, submitted_by_user_id=1)
        approve_process_scan_scope(db, scope, approved_by_user_id=1)
        db.commit()

    approve_test_boundary(db, organization_id=1, evidence_source_id=source.id)
    organization = db.query(Organization).filter(Organization.id == 1).first()
    run = create_discovery_run(
        db, organization=organization, instance=instance, requested_by_user_id=1, business_process_id=business_process_id
    )
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
    return (
        db.query(ProviderExecution).filter(ProviderExecution.execution_stage_id == stage.id).all()
    )


def _resolve_all_jobs(db: Session, stage: ExecutionStage, status: str) -> None:
    """CA-04.3 — EXTERNAL_DISCOVERY now has two real jobs (nmap,
    subfinder); a stage-level assertion needs every one of them terminal,
    not just _jobs(db, stage)[0]."""
    for job in _jobs(db, stage):
        job.status = status
        db.add(job)


def _events(db: Session, event_type: str) -> list[AuditEvent]:
    return (
        db.query(AuditEvent)
        .filter(AuditEvent.organization_id == 1, AuditEvent.event_type == event_type)
        .all()
    )


def test_dispatch_writes_leased_and_stage_started_audit(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)

    dispatch_ready_jobs(db)
    db.commit()

    started_events = _events(db, EXECUTION_STAGE_AUDIT_STARTED)
    assert any(e.metadata_json["executionStageId"] == external.id for e in started_events)

    leased_events = _events(db, PROVIDER_EXECUTION_AUDIT_LEASED)
    job = _jobs(db, external)[0]
    leased_event = next(
        e for e in leased_events if e.metadata_json["providerExecutionId"] == job.id
    )
    assert leased_event.metadata_json["lifecycle"] == {
        "objectType": "provider_execution",
        "objectId": job.id,
        "family": "execution",
        "transitionSource": "system_executed",
        "previousState": ProviderExecutionStatus.PENDING.value,
        "currentState": ProviderExecutionStatus.LEASED.value,
    }


def test_acknowledgement_writes_provider_execution_started_audit(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    dispatch_ready_jobs(db)
    db.commit()

    job = _jobs(db, external)[0]
    command = (
        db.query(ScannerCommand).filter(ScannerCommand.provider_execution_id == job.id).first()
    )
    handle_provider_execution_acknowledgement(db, command, accepted=True, rejection_code=None)
    db.commit()

    started_events = _events(db, PROVIDER_EXECUTION_AUDIT_STARTED)
    started_event = next(
        e for e in started_events if e.metadata_json["providerExecutionId"] == job.id
    )
    assert started_event.metadata_json["lifecycle"] == {
        "objectType": "provider_execution",
        "objectId": job.id,
        "family": "execution",
        "transitionSource": "external_provider_reported",
        "previousState": ProviderExecutionStatus.LEASED.value,
        "currentState": ProviderExecutionStatus.RUNNING.value,
    }


def test_stage_and_plan_completion_audit_written(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
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
    _resolve_all_jobs(db, fingerprinting, ProviderExecutionStatus.COMPLETED.value)
    db.commit()
    advance_stage_completion(db, fingerprinting.id)
    db.commit()

    stage_completed = _events(db, EXECUTION_STAGE_AUDIT_COMPLETED)
    assert len(stage_completed) == 3  # external, internal, fingerprinting

    plan_completed = _events(db, EXECUTION_PLAN_AUDIT_COMPLETED)
    assert any(e.metadata_json["executionPlanId"] == plan.id for e in plan_completed)


def test_stage_and_plan_failed_audit_written(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    internal = _stage(db, plan, DiscoveryStage.INTERNAL_DISCOVERY.value)

    for stage in (external, internal):
        # CA-04.3 — external has two jobs (nmap, subfinder); all of them
        # must fail for the stage itself to fail outright.
        for job in _jobs(db, stage):
            handle_job_failure(db, job, failure_code="credentials_invalid", failure_message="bad creds")
        db.commit()
        advance_stage_completion(db, stage.id)
        db.commit()

    failed_stage_events = _events(db, EXECUTION_STAGE_AUDIT_FAILED)
    assert {e.metadata_json["executionStageId"] for e in failed_stage_events} == {
        external.id,
        internal.id,
    }


def test_completed_with_warnings_audit_written_when_optional_stage_fails(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    internal = _stage(db, plan, DiscoveryStage.INTERNAL_DISCOVERY.value)
    fingerprinting = _stage(db, plan, DiscoveryStage.SERVICE_FINGERPRINTING.value)

    internal.required = False
    db.add(internal)
    db.commit()

    # CA-04.3 — external has two jobs (nmap, subfinder); both must
    # complete for the stage itself to complete.
    _resolve_all_jobs(db, external, ProviderExecutionStatus.COMPLETED.value)
    _resolve_all_jobs(db, internal, ProviderExecutionStatus.FAILED.value)
    db.commit()
    advance_stage_completion(db, external.id)
    advance_stage_completion(db, internal.id)
    db.commit()

    _resolve_all_jobs(db, fingerprinting, ProviderExecutionStatus.COMPLETED.value)
    db.commit()
    advance_stage_completion(db, fingerprinting.id)
    db.commit()

    warnings_events = _events(db, EXECUTION_PLAN_AUDIT_COMPLETED_WITH_WARNINGS)
    assert any(e.metadata_json["executionPlanId"] == plan.id for e in warnings_events)
    assert _events(db, EXECUTION_PLAN_AUDIT_FAILED) == []
    assert _events(db, EXECUTION_PLAN_AUDIT_COMPLETED) == []


def test_lease_reclaimed_and_retry_queued_audit_written(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    dispatch_ready_jobs(db)
    db.commit()

    job = _jobs(db, external)[0]
    lease = db.query(WorkerLease).filter(WorkerLease.provider_execution_id == job.id).first()
    lease.lease_expires_at = utcnow() - timedelta(minutes=1)
    db.add(lease)
    db.commit()

    reconcile_expired_leases(db)
    db.commit()

    reclaimed_events = _events(db, PROVIDER_EXECUTION_AUDIT_LEASE_RECLAIMED)
    assert any(e.metadata_json["providerExecutionId"] == job.id for e in reclaimed_events)

    retry_queued_events = _events(db, PROVIDER_EXECUTION_AUDIT_RETRY_QUEUED)
    assert any(e.metadata_json["providerExecutionId"] == job.id for e in retry_queued_events)


def test_cancellation_writes_stage_and_job_audit(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    job = _jobs(db, external)[0]
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == plan.discovery_run_id).first()

    cancel_execution_plan(db, run)
    db.commit()

    stage_cancelled = _events(db, EXECUTION_STAGE_AUDIT_CANCELLED)
    assert any(e.metadata_json["executionStageId"] == external.id for e in stage_cancelled)

    job_cancelled = _events(db, PROVIDER_EXECUTION_AUDIT_CANCELLED)
    assert any(e.metadata_json["providerExecutionId"] == job.id for e in job_cancelled)


def test_evidence_storage_failure_writes_audit(db: Session, monkeypatch):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    dispatch_ready_jobs(db)
    db.commit()

    job = _jobs(db, external)[0]
    command = (
        db.query(ScannerCommand).filter(ScannerCommand.provider_execution_id == job.id).first()
    )
    handle_provider_execution_acknowledgement(db, command, accepted=True, rejection_code=None)
    db.commit()

    from src.core.services import evidence_storage_backend as backend_module
    from src.core.services.evidence_storage_backend import EvidenceStorageError

    class _FailingBackend:
        backend_id = "failing"

        def store(self, **kwargs):
            raise EvidenceStorageError("disk full")

        def retrieve(self, **kwargs):
            raise EvidenceStorageError("disk full")

    monkeypatch.setattr(backend_module, "_BACKENDS_BY_ID", {"failing": _FailingBackend()})
    monkeypatch.setattr(
        backend_module,
        "get_evidence_storage_backend",
        lambda: backend_module._BACKENDS_BY_ID["failing"],
    )
    # record_provider_execution_result imports get_evidence_storage_backend
    # by name into its own module namespace — patch it there too.
    import src.core.services.discovery_execution_command_service as command_service_module

    monkeypatch.setattr(
        command_service_module, "get_evidence_storage_backend", lambda: _FailingBackend()
    )

    from src.core.services.discovery_command_service import DiscoveryCommandError

    instance = db.query(ScannerInstance).first()
    with pytest.raises(DiscoveryCommandError):
        record_provider_execution_result(
            db,
            instance,
            command.id,
            status=ProviderExecutionStatus.COMPLETED.value,
            evidence_format="nmap_xml",
            raw_evidence_payload="<nmaprun/>",
            schema_version="1.0",
            checkpoint=None,
            failure_code=None,
            failure_message=None,
        )
    db.commit()

    storage_failed_events = _events(db, EVIDENCE_PACKAGE_AUDIT_STORAGE_FAILED)
    assert any(e.metadata_json["providerExecutionId"] == job.id for e in storage_failed_events)


# --- CA-04.8: process-aware progress/audit events ---------------------------------------


def test_dispatch_audit_events_carry_process_context(db: Session):
    """AC2 — progress events carry business-process/service IDs where
    set, plus a slot_instance_id-equivalent placeholder that stays null
    (CA-09A's own job to ever populate, never inferred here)."""
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value, business_process_id="process-1")
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)

    dispatch_ready_jobs(db)
    db.commit()

    started_events = _events(db, EXECUTION_STAGE_AUDIT_STARTED)
    stage_event = next(e for e in started_events if e.metadata_json["executionStageId"] == external.id)
    assert stage_event.metadata_json["businessProcessId"] == "process-1"
    assert stage_event.metadata_json["businessServiceId"] is None
    assert stage_event.metadata_json["slotInstanceId"] is None

    job = _jobs(db, external)[0]
    leased_events = _events(db, PROVIDER_EXECUTION_AUDIT_LEASED)
    leased_event = next(e for e in leased_events if e.metadata_json["providerExecutionId"] == job.id)
    assert leased_event.metadata_json["businessProcessId"] == "process-1"


def test_dispatch_audit_events_carry_no_process_context_for_an_unscoped_run(db: Session):
    """The pre-existing org-wide path — omitting business_process_id
    entirely must remain zero behavior change, not silently fabricate a
    value where none was set."""
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)

    dispatch_ready_jobs(db)
    db.commit()

    job = _jobs(db, external)[0]
    leased_events = _events(db, PROVIDER_EXECUTION_AUDIT_LEASED)
    leased_event = next(e for e in leased_events if e.metadata_json["providerExecutionId"] == job.id)
    assert leased_event.metadata_json["businessProcessId"] is None


def test_acknowledgement_audit_carries_process_context(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value, business_process_id="process-1")
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    dispatch_ready_jobs(db)
    db.commit()

    job = _jobs(db, external)[0]
    command = db.query(ScannerCommand).filter(ScannerCommand.provider_execution_id == job.id).first()
    assert command.business_process_id == "process-1"  # CA-04.7's own snapshot, sanity-checked here
    handle_provider_execution_acknowledgement(db, command, accepted=True, rejection_code=None)
    db.commit()

    started_events = _events(db, PROVIDER_EXECUTION_AUDIT_STARTED)
    started_event = next(e for e in started_events if e.metadata_json["providerExecutionId"] == job.id)
    assert started_event.metadata_json["businessProcessId"] == "process-1"


def test_stage_and_plan_completion_audit_carries_process_context(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value, business_process_id="process-1")
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
    _resolve_all_jobs(db, fingerprinting, ProviderExecutionStatus.COMPLETED.value)
    db.commit()
    advance_stage_completion(db, fingerprinting.id)
    db.commit()

    stage_completed = _events(db, EXECUTION_STAGE_AUDIT_COMPLETED)
    assert all(e.metadata_json["businessProcessId"] == "process-1" for e in stage_completed)

    plan_completed = _events(db, EXECUTION_PLAN_AUDIT_COMPLETED)
    plan_event = next(e for e in plan_completed if e.metadata_json["executionPlanId"] == plan.id)
    assert plan_event.metadata_json["businessProcessId"] == "process-1"


def test_cancellation_audit_carries_process_context(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value, business_process_id="process-1")
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    job = _jobs(db, external)[0]
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == plan.discovery_run_id).first()

    cancel_execution_plan(db, run)
    db.commit()

    stage_cancelled = _events(db, EXECUTION_STAGE_AUDIT_CANCELLED)
    stage_event = next(e for e in stage_cancelled if e.metadata_json["executionStageId"] == external.id)
    assert stage_event.metadata_json["businessProcessId"] == "process-1"

    job_cancelled = _events(db, PROVIDER_EXECUTION_AUDIT_CANCELLED)
    job_event = next(e for e in job_cancelled if e.metadata_json["providerExecutionId"] == job.id)
    assert job_event.metadata_json["businessProcessId"] == "process-1"


def test_lease_reclaimed_and_retry_queued_audit_carries_process_context(db: Session):
    plan = _plan_for_profile(db, profile=ScannerProfile.SAFE_DISCOVERY.value, business_process_id="process-1")
    external = _stage(db, plan, DiscoveryStage.EXTERNAL_DISCOVERY.value)
    dispatch_ready_jobs(db)
    db.commit()

    job = _jobs(db, external)[0]
    lease = db.query(WorkerLease).filter(WorkerLease.provider_execution_id == job.id).first()
    lease.lease_expires_at = utcnow() - timedelta(minutes=1)
    db.add(lease)
    db.commit()

    reconcile_expired_leases(db)
    db.commit()

    reclaimed_events = _events(db, PROVIDER_EXECUTION_AUDIT_LEASE_RECLAIMED)
    reclaimed_event = next(e for e in reclaimed_events if e.metadata_json["providerExecutionId"] == job.id)
    assert reclaimed_event.metadata_json["businessProcessId"] == "process-1"

    retry_queued_events = _events(db, PROVIDER_EXECUTION_AUDIT_RETRY_QUEUED)
    retry_event = next(e for e in retry_queued_events if e.metadata_json["providerExecutionId"] == job.id)
    assert retry_event.metadata_json["businessProcessId"] == "process-1"
