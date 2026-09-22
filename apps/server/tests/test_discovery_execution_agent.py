"""Step 4.2 Part 2 — DiscoveryProvider abstraction (NmapProvider, delegated
mode), the per-job command lifecycle (create/acknowledge/result), and the
regression guarantee that Step 4.1's original whole-run command path is
completely unaffected by any of it."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.routes import discovery_command_agent as command_agent_routes
from src.api.routes import discovery_execution_agent as execution_agent_routes
from src.core.constants.discovery_execution_enums import (
    EvidenceNormalizationStatus,
    EvidencePackageProcessingStatus,
    ExecutionPlanStatus,
    ExecutionStageStatus,
    ProviderExecutionStatus,
)
from src.core.constants.discovery_run_enums import DiscoveryRunStatus, DiscoveryStage
from src.core.constants.evidence_scanner_enums import ScannerInstallationMethod, ScannerProfile
from src.core.constants.evidence_source_enums import EvidenceSourceType
from src.core.database import Base
from src.core.exceptions import ValidationError
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
from src.core.model_defs.evidence_scanner import (
    CollectorReadinessReport,
    ScannerCredential,
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
from src.core.services import evidence_storage_backend
from src.core.services.discovery_command_service import acknowledge_command
from src.core.services.discovery_providers import get_provider, get_registered_providers
from src.core.services.discovery_run_service import create_discovery_run
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
            ScannerCredential.__table__,
            ScannerDomainTarget.__table__,
            ScannerNetworkTarget.__table__,
            DiscoveryRun.__table__,
            DiscoveryScopeProposal.__table__,
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
            Organization(id=1, name="Org", slug="org", country="DK", technical_setup_owner_user_id=1),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
        ]
    )
    session.commit()
    yield session
    session.close()


@pytest.fixture()
def local_evidence_dir(monkeypatch, tmp_path):
    """Point the evidence storage backend at a real temp dir instead of the
    dev-default var/discovery-evidence — isolates test runs from each other
    and from a developer's own local disk."""
    backend = evidence_storage_backend.LocalFilesystemBackend(base_dir=str(tmp_path))
    monkeypatch.setitem(evidence_storage_backend._BACKENDS_BY_ID, backend.backend_id, backend)
    return tmp_path


def _fake_request(token: str | None) -> Request:
    headers = [(b"authorization", f"Bearer {token}".encode())] if token else []
    return Request({"type": "http", "headers": headers})


def _running_run_with_job(
    db: Session,
    *,
    profile: str = ScannerProfile.SAFE_DISCOVERY.value,
    provider_id: str = "nmap",
    business_process_id: str | None = None,
):
    """A real installed+online scanner, an approved domain, a discovery run
    forced to RUNNING (simulating its DiscoveryExecutionPlan already having
    started it — DISC-21/24's job, not built yet), and one real
    DiscoveryExecutionPlan/ExecutionStage/ProviderExecution chain."""
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

    organization = db.query(Organization).filter(Organization.id == 1).first()
    run = create_discovery_run(
        db, organization=organization, instance=instance, requested_by_user_id=1, business_process_id=business_process_id
    )
    if run.status == DiscoveryRunStatus.AWAITING_APPROVAL.value:
        from src.core.services.discovery_run_service import approve_discovery_run

        approve_discovery_run(db, run, approved_by_user_id=1)
    run.status = DiscoveryRunStatus.RUNNING.value  # simulates the plan having already started the run
    db.add(run)
    db.commit()

    plan = DiscoveryExecutionPlan(
        organization_id=1,
        discovery_run_id=run.id,
        plan_definition={"concurrency": {"maxParallelJobs": 1}},
        status=ExecutionPlanStatus.EXECUTING.value,
    )
    db.add(plan)
    db.flush()
    stage = ExecutionStage(
        execution_plan_id=plan.id,
        stage_key=DiscoveryStage.EXTERNAL_DISCOVERY.value,
        status=ExecutionStageStatus.RUNNING.value,
    )
    db.add(stage)
    db.flush()
    provider_execution = ProviderExecution(
        execution_stage_id=stage.id,
        provider_id=provider_id,
        status=ProviderExecutionStatus.PENDING.value,
    )
    db.add(provider_execution)
    db.commit()
    db.refresh(instance)
    db.refresh(run)
    db.refresh(provider_execution)
    return result.activation_token, run, provider_execution


# --- NmapProvider.execute() (delegated mode) ---------------------------------------------


def test_nmap_provider_execute_creates_signed_command_and_leases_job(db: Session):
    _, run, provider_execution = _running_run_with_job(db)
    provider = get_provider("nmap")

    outcome = provider.execute(db, run=run, provider_execution=provider_execution)
    db.commit()

    assert outcome.mode == "delegated"
    assert outcome.delegated_command_id is not None
    command = db.query(ScannerCommand).filter(ScannerCommand.id == outcome.delegated_command_id).first()
    assert command is not None
    assert command.provider_execution_id == provider_execution.id
    assert command.discovery_run_id == run.id
    assert command.signature  # a real HMAC, not empty

    db.refresh(provider_execution)
    assert provider_execution.status == ProviderExecutionStatus.LEASED.value
    lease = db.query(WorkerLease).filter(WorkerLease.provider_execution_id == provider_execution.id).first()
    assert lease is not None
    assert lease.worker_id == f"scanner:{run.scanner_instance_id}"
    assert lease.released_at is None

    # The whole-run status must be untouched by a per-job command's creation.
    db.refresh(run)
    assert run.status == DiscoveryRunStatus.RUNNING.value
    # CA-04.2 — a real, closed check-key vocabulary, not left unset.
    assert command.check_key == "nmap"


# --- SubfinderProvider.execute() (CA-04.3, delegated mode) -------------------------------


def test_subfinder_is_registered_with_external_discovery_only():
    provider = get_provider("subfinder")
    assert provider.provider_id == "subfinder"
    capabilities = provider.capabilities()
    assert capabilities.execution_mode == "delegated"
    assert capabilities.supported_discovery_stages == frozenset({DiscoveryStage.EXTERNAL_DISCOVERY.value})
    assert capabilities.dependency_requirements == {"requiresTool": "subfinder"}
    provider_ids = {p.provider_id for p in get_registered_providers()}
    assert {"nmap", "subfinder"} <= provider_ids


def test_subfinder_provider_execute_creates_signed_command_and_leases_job(db: Session):
    _, run, provider_execution = _running_run_with_job(db, provider_id="subfinder")
    provider = get_provider("subfinder")

    outcome = provider.execute(db, run=run, provider_execution=provider_execution)
    db.commit()

    assert outcome.mode == "delegated"
    command = db.query(ScannerCommand).filter(ScannerCommand.id == outcome.delegated_command_id).first()
    assert command is not None
    assert command.provider_execution_id == provider_execution.id
    assert command.check_key == "subfinder"
    assert command.signature  # a real HMAC, not empty

    db.refresh(provider_execution)
    assert provider_execution.status == ProviderExecutionStatus.LEASED.value
    lease = db.query(WorkerLease).filter(WorkerLease.provider_execution_id == provider_execution.id).first()
    assert lease is not None
    assert lease.released_at is None


# --- NucleiProvider.execute() (CA-04.4, delegated mode) ----------------------------------


def test_nuclei_is_registered_with_vulnerability_discovery_only():
    provider = get_provider("nuclei")
    assert provider.provider_id == "nuclei"
    capabilities = provider.capabilities()
    assert capabilities.execution_mode == "delegated"
    assert capabilities.supported_discovery_stages == frozenset({DiscoveryStage.VULNERABILITY_DISCOVERY.value})
    # CA-02.3 slice 3 — both, not just the binary. Nuclei without its template
    # pack is an engine with nothing to run, and naming only the binary let a
    # Collector missing the pack still be planned for vulnerability work.
    assert capabilities.dependency_requirements == {
        "requiresTools": ["nuclei", "nuclei_templates"]
    }
    provider_ids = {p.provider_id for p in get_registered_providers()}
    assert {"nmap", "subfinder", "nuclei"} <= provider_ids


def test_nuclei_provider_execute_creates_signed_command_and_leases_job(db: Session):
    _, run, provider_execution = _running_run_with_job(db, provider_id="nuclei")
    provider = get_provider("nuclei")

    outcome = provider.execute(db, run=run, provider_execution=provider_execution)
    db.commit()

    assert outcome.mode == "delegated"
    command = db.query(ScannerCommand).filter(ScannerCommand.id == outcome.delegated_command_id).first()
    assert command is not None
    assert command.provider_execution_id == provider_execution.id
    assert command.check_key == "nuclei"
    assert command.signature  # a real HMAC, not empty

    db.refresh(provider_execution)
    assert provider_execution.status == ProviderExecutionStatus.LEASED.value
    lease = db.query(WorkerLease).filter(WorkerLease.provider_execution_id == provider_execution.id).first()
    assert lease is not None
    assert lease.released_at is None


def test_create_command_for_provider_execution_rejects_unknown_check_key(db: Session):
    """CA-04.2 — provider_execution.provider_id can only ever be a
    registered id in practice (discovery_execution_plan_service only ever
    sets it from get_registered_providers()), so this bypasses that path
    directly to prove the rejection itself is real, not inferred from the
    fact that the normal flow happens to never produce a bad value."""
    from src.core.services.discovery_command_service import DiscoveryCommandError
    from src.core.services.discovery_execution_command_service import create_command_for_provider_execution

    _, run, provider_execution = _running_run_with_job(db)
    provider_execution.provider_id = "not_a_registered_check"
    db.add(provider_execution)
    db.commit()

    with pytest.raises(DiscoveryCommandError) as exc_info:
        create_command_for_provider_execution(db, run, provider_execution)
    assert exc_info.value.code == "check_key_unknown"

    # No half-created command must survive the rejection.
    assert db.query(ScannerCommand).filter(ScannerCommand.provider_execution_id == provider_execution.id).first() is None


# --- acknowledge (per-job branch) --------------------------------------------------------


def test_acknowledge_provider_execution_command_transitions_job_not_run(db: Session):
    token, run, provider_execution = _running_run_with_job(db)
    command_id = get_provider("nmap").execute(db, run=run, provider_execution=provider_execution).delegated_command_id
    db.commit()

    command = command_agent_routes.acknowledge_command_route(
        command_id,
        command_agent_routes.AcknowledgeCommandRequest(accepted=True, scanner_runtime_version="1.0.0"),
        _fake_request(token),
        db,
    )
    assert command.status == "acknowledged"

    db.refresh(provider_execution)
    assert provider_execution.status == ProviderExecutionStatus.RUNNING.value
    assert provider_execution.started_at is not None

    # Still untouched — the whole run's own status is not this command's concern.
    db.refresh(run)
    assert run.status == DiscoveryRunStatus.RUNNING.value


def test_reject_provider_execution_command_fails_job_and_releases_lease(db: Session):
    token, run, provider_execution = _running_run_with_job(db)
    command_id = get_provider("nmap").execute(db, run=run, provider_execution=provider_execution).delegated_command_id
    db.commit()

    command_agent_routes.acknowledge_command_route(
        command_id,
        command_agent_routes.AcknowledgeCommandRequest(accepted=False, rejection_code="scanner_busy"),
        _fake_request(token),
        db,
    )

    db.refresh(provider_execution)
    assert provider_execution.status == ProviderExecutionStatus.FAILED.value
    assert provider_execution.failure_code == "scanner_busy"
    lease = db.query(WorkerLease).filter(WorkerLease.provider_execution_id == provider_execution.id).first()
    assert lease.released_at is not None

    # This fixture's plan has exactly one stage with exactly one job, so
    # rejecting that job correctly terminates the stage, the plan, and (as
    # of DISC-24) cascades all the way up to the run itself — a real,
    # intended cascade for a single-stage plan, not a bug. Multi-stage
    # partial-failure isolation (a rejected job that must NOT prematurely
    # fail sibling stages/the whole run) is covered explicitly by
    # test_discovery_execution_scheduler_service.py's own DAG tests.
    db.refresh(run)
    assert run.status == DiscoveryRunStatus.FAILED.value
    assert run.failed_at is not None


def test_existing_whole_run_acknowledgement_is_unaffected(db: Session):
    """Regression guard: a Step 4.1 whole-run command (provider_execution_id
    is NULL) must still transition the run itself, exactly as before this
    ticket's changes to acknowledge_command."""
    from src.core.services.discovery_command_service import create_command_for_run
    from src.core.services.discovery_run_service import approve_discovery_run

    token, run, _ = _running_run_with_job(db)
    run.status = DiscoveryRunStatus.APPROVED.value
    db.add(run)
    db.commit()
    whole_run_command = create_command_for_run(db, run)
    db.commit()
    assert whole_run_command.provider_execution_id is None

    command = command_agent_routes.acknowledge_command_route(
        whole_run_command.id,
        command_agent_routes.AcknowledgeCommandRequest(accepted=True),
        _fake_request(token),
        db,
    )
    assert command.status == "acknowledged"
    db.refresh(run)
    assert run.status == DiscoveryRunStatus.ACKNOWLEDGED.value


# --- result reporting ---------------------------------------------------------------------


def test_nmap_provider_execute_snapshots_process_context_onto_the_delegated_command(db: Session):
    """CA-04.7 — the per-job path (create_command_for_provider_execution)
    snapshots the same process/service context as the whole-run path."""
    _, run, provider_execution = _running_run_with_job(db, business_process_id="process-1")
    provider = get_provider("nmap")

    outcome = provider.execute(db, run=run, provider_execution=provider_execution)
    db.commit()

    command = db.query(ScannerCommand).filter(ScannerCommand.id == outcome.delegated_command_id).first()
    assert command.business_process_id == "process-1"
    assert command.business_service_id is None


def test_result_route_evidence_package_carries_process_context(db: Session, local_evidence_dir):
    """Evidence retains this context without making artefacts
    process-exclusive: provenance_metadata carries the same context the
    command was snapshotted with, alongside its existing fields."""
    token, run, provider_execution = _running_run_with_job(db, business_process_id="process-1")
    command_id = get_provider("nmap").execute(db, run=run, provider_execution=provider_execution).delegated_command_id
    db.commit()
    command_agent_routes.acknowledge_command_route(
        command_id, command_agent_routes.AcknowledgeCommandRequest(accepted=True), _fake_request(token), db
    )
    db.commit()

    execution_agent_routes.provider_execution_result_route(
        command_id,
        execution_agent_routes.ProviderExecutionResultRequest(
            status=ProviderExecutionStatus.COMPLETED.value,
            evidence_format="nmap_xml",
            raw_evidence_payload="<nmaprun><host>127.0.0.1 open 22</host></nmaprun>",
        ),
        _fake_request(token),
        db,
    )

    package = db.query(EvidencePackage).filter(EvidencePackage.provider_execution_id == provider_execution.id).first()
    assert package.provenance_metadata["businessProcessId"] == "process-1"
    assert package.provenance_metadata["businessServiceId"] is None
    # Existing provenance fields are untouched by this addition.
    assert package.provenance_metadata["providerId"] == "nmap"


def test_result_route_audit_events_carry_process_context(db: Session, local_evidence_dir):
    """CA-04.8 — the result route's own EVIDENCE_PACKAGE_AUDIT_RECEIVED/
    PROVIDER_EXECUTION_AUDIT_COMPLETED events, resolved via a fresh
    ScannerCommand lookup by command_id (neither command nor run was
    otherwise in scope at this route)."""
    from src.core.model_defs.tenant_identity import AuditEvent

    token, run, provider_execution = _running_run_with_job(db, business_process_id="process-1")
    command_id = get_provider("nmap").execute(db, run=run, provider_execution=provider_execution).delegated_command_id
    db.commit()
    command_agent_routes.acknowledge_command_route(
        command_id, command_agent_routes.AcknowledgeCommandRequest(accepted=True), _fake_request(token), db
    )
    db.commit()

    execution_agent_routes.provider_execution_result_route(
        command_id,
        execution_agent_routes.ProviderExecutionResultRequest(
            status=ProviderExecutionStatus.COMPLETED.value,
            evidence_format="nmap_xml",
            raw_evidence_payload="<nmaprun><host>127.0.0.1 open 22</host></nmaprun>",
        ),
        _fake_request(token),
        db,
    )

    received_event = (
        db.query(AuditEvent).filter(AuditEvent.event_type == "evidence_package.received").first()
    )
    assert received_event.metadata_json["businessProcessId"] == "process-1"
    completed_event = (
        db.query(AuditEvent).filter(AuditEvent.event_type == "provider_execution.completed").first()
    )
    assert completed_event.metadata_json["businessProcessId"] == "process-1"


def test_result_route_completed_stores_evidence_package(db: Session, local_evidence_dir):
    token, run, provider_execution = _running_run_with_job(db)
    command_id = get_provider("nmap").execute(db, run=run, provider_execution=provider_execution).delegated_command_id
    db.commit()
    command_agent_routes.acknowledge_command_route(
        command_id, command_agent_routes.AcknowledgeCommandRequest(accepted=True), _fake_request(token), db
    )
    db.commit()

    response = execution_agent_routes.provider_execution_result_route(
        command_id,
        execution_agent_routes.ProviderExecutionResultRequest(
            status=ProviderExecutionStatus.COMPLETED.value,
            evidence_format="nmap_xml",
            raw_evidence_payload="<nmaprun><host>127.0.0.1 open 22</host></nmaprun>",
        ),
        _fake_request(token),
        db,
    )
    assert response.status == ProviderExecutionStatus.COMPLETED.value

    db.refresh(provider_execution)
    assert provider_execution.status == ProviderExecutionStatus.COMPLETED.value
    assert provider_execution.completed_at is not None

    package = db.query(EvidencePackage).filter(EvidencePackage.provider_execution_id == provider_execution.id).first()
    assert package is not None
    assert package.discovery_run_id == run.id
    assert package.provider_id == "nmap"
    assert package.evidence_format == "nmap_xml"
    assert package.processing_status == EvidencePackageProcessingStatus.STORED.value
    assert package.normalization_status == EvidenceNormalizationStatus.PENDING.value
    assert package.integrity_hash is not None
    assert Path(package.raw_evidence_reference).read_text() == "<nmaprun><host>127.0.0.1 open 22</host></nmaprun>"

    lease = db.query(WorkerLease).filter(WorkerLease.provider_execution_id == provider_execution.id).first()
    assert lease.released_at is not None


def test_result_route_recovers_gracefully_when_a_package_already_exists_for_the_attempt(db: Session, local_evidence_dir):
    """DISC-34: the terminal-status guard in record_provider_execution_result
    (DISC-31) already stops a *sequential* duplicate report once the job's
    own status reflects the first report's outcome, but a genuine
    concurrent race (two requests both observing a not-yet-terminal job
    before either commits) — or a crash between creating the
    EvidencePackage and persisting the job's own status update, the exact
    window DISC-32's own docstring discloses — can still reach the
    package-creation code a second time for the same attempt. Simulates
    that by resetting the job back to a non-terminal status right after
    the first real report already created its package (so the guard
    doesn't short-circuit the replay), then replaying the same result —
    uq_evidence_package_provider_execution is what actually catches the
    duplicate at the database, and the function must recover without
    raising rather than surface a 500 or a duplicate package."""
    token, run, provider_execution = _running_run_with_job(db)
    command_id = get_provider("nmap").execute(db, run=run, provider_execution=provider_execution).delegated_command_id
    db.commit()
    command_agent_routes.acknowledge_command_route(
        command_id, command_agent_routes.AcknowledgeCommandRequest(accepted=True), _fake_request(token), db
    )
    db.commit()

    request_body = execution_agent_routes.ProviderExecutionResultRequest(
        status=ProviderExecutionStatus.COMPLETED.value,
        evidence_format="nmap_xml",
        raw_evidence_payload="<nmaprun><host>127.0.0.1 open 22</host></nmaprun>",
    )
    first = execution_agent_routes.provider_execution_result_route(command_id, request_body, _fake_request(token), db)
    assert first.status == ProviderExecutionStatus.COMPLETED.value
    assert db.query(EvidencePackage).filter(EvidencePackage.provider_execution_id == provider_execution.id).count() == 1

    # Simulate the race/crash window: the job's own status update never
    # persisted, even though its package already did.
    db.refresh(provider_execution)
    provider_execution.status = ProviderExecutionStatus.LEASED.value
    provider_execution.completed_at = None
    db.add(provider_execution)
    db.commit()

    replayed = execution_agent_routes.provider_execution_result_route(
        command_id, request_body, _fake_request(token), db
    )
    assert replayed.provider_execution_id == provider_execution.id  # no crash

    assert db.query(EvidencePackage).filter(EvidencePackage.provider_execution_id == provider_execution.id).count() == 1


def test_result_route_failed_records_failure_without_evidence_package(db: Session, local_evidence_dir):
    token, run, provider_execution = _running_run_with_job(db)
    command_id = get_provider("nmap").execute(db, run=run, provider_execution=provider_execution).delegated_command_id
    db.commit()
    command_agent_routes.acknowledge_command_route(
        command_id, command_agent_routes.AcknowledgeCommandRequest(accepted=True), _fake_request(token), db
    )
    db.commit()

    execution_agent_routes.provider_execution_result_route(
        command_id,
        execution_agent_routes.ProviderExecutionResultRequest(
            status=ProviderExecutionStatus.FAILED.value,
            failure_code="target_unreachable",
            failure_message="Host did not respond",
        ),
        _fake_request(token),
        db,
    )

    db.refresh(provider_execution)
    assert provider_execution.status == ProviderExecutionStatus.FAILED.value
    assert provider_execution.failure_code == "target_unreachable"
    assert db.query(EvidencePackage).filter(EvidencePackage.provider_execution_id == provider_execution.id).count() == 0


def test_result_route_rejects_command_from_other_scanner_instance(db: Session, local_evidence_dir):
    token, run, provider_execution = _running_run_with_job(db)
    command_id = get_provider("nmap").execute(db, run=run, provider_execution=provider_execution).delegated_command_id
    db.commit()

    other_source = create_evidence_source(db, organization_id=1, name="Second scanner", source_type=EvidenceSourceType.SCANNER)
    db.commit()
    other_result = install_scanner(db, other_source, name="Second", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()

    with pytest.raises(ValidationError):
        execution_agent_routes.provider_execution_result_route(
            command_id,
            execution_agent_routes.ProviderExecutionResultRequest(status=ProviderExecutionStatus.COMPLETED.value),
            _fake_request(other_result.activation_token),
            db,
        )


def test_result_route_rejects_command_from_a_different_organizations_scanner(db: Session, local_evidence_dir):
    """DISC-35: adversarial cross-tenant check — a scanner instance
    belonging to an entirely different organization, with its own
    genuinely valid Bearer credential, must not be able to report a
    result for another organization's command."""
    token, run, provider_execution = _running_run_with_job(db)
    command_id = get_provider("nmap").execute(db, run=run, provider_execution=provider_execution).delegated_command_id
    db.commit()

    db.add(Organization(id=2, name="Other Org", slug="other-org", country="DK"))
    db.add(User(id=2, organization_id=2, email="other-admin@example.com", role="org_admin"))
    db.commit()
    other_org_source = create_evidence_source(
        db, organization_id=2, name="Other org scanner", source_type=EvidenceSourceType.SCANNER, owner_user_id=2
    )
    db.commit()
    other_org_result = install_scanner(
        db, other_org_source, name="Other org instance", installation_method=ScannerInstallationMethod.DOCKER.value
    )
    db.commit()

    with pytest.raises(ValidationError):
        execution_agent_routes.provider_execution_result_route(
            command_id,
            execution_agent_routes.ProviderExecutionResultRequest(status=ProviderExecutionStatus.COMPLETED.value),
            _fake_request(other_org_result.activation_token),
            db,
        )

    # Confirm this wasn't a false negative from some unrelated error — the
    # job under attack is genuinely untouched by the rejected attempt.
    db.refresh(provider_execution)
    assert provider_execution.status == ProviderExecutionStatus.LEASED.value
