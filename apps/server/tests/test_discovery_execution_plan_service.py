"""Step 4.2 Part 2 — DISC-21: execution plan generation. Stage derivation
from profile capability flags, DAG dependency wiring, provider-execution
job creation, and the small set of preconditions (approved-only, one plan
per run, at least one registered provider)."""

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
    ExecutionStage,
    ExecutionStageDependency,
    ProviderExecution,
)
from src.core.model_defs.discovery_run import DiscoveryRun, ScannerCommand
from src.core.model_defs.discovery_scope_proposal import DiscoveryScopeProposal
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.model_defs.evidence_scanner import ScannerDomainTarget, ScannerInstance, ScannerNetworkTarget
from src.core.model_defs.evidence_scanner import CollectorReadinessReport
from src.core.services.collector_readiness_service import record_readiness_report
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.models import Organization, User
from src.core.services.discovery_execution_plan_service import (
    DiscoveryExecutionPlanError,
    generate_execution_plan,
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


def _approved_run(db: Session, *, profile: str) -> DiscoveryRun:
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
    assert run.status == DiscoveryRunStatus.APPROVED.value
    return run


def test_generates_plan_with_dag_and_nmap_jobs_for_safe_discovery(db: Session):
    run = _approved_run(db, profile=ScannerProfile.SAFE_DISCOVERY.value)

    plan = generate_execution_plan(db, run)
    db.commit()

    assert plan.discovery_run_id == run.id
    assert plan.organization_id == run.organization_id
    assert plan.status == ExecutionPlanStatus.EXECUTING.value
    assert plan.plan_definition["stagePolicies"]

    # DISC-24: generating the plan moves the run straight to RUNNING,
    # skipping the original Step 4.1 whole-run QUEUED/COMMAND_AVAILABLE/
    # ACKNOWLEDGED handshake entirely.
    db.refresh(run)
    assert run.status == DiscoveryRunStatus.RUNNING.value
    assert run.started_at is not None

    stages = db.query(ExecutionStage).filter(ExecutionStage.execution_plan_id == plan.id).all()
    stage_by_key = {s.stage_key: s for s in stages}
    # SAFE_DISCOVERY enables external/internal/fingerprinting, not vulnerability.
    assert set(stage_by_key) == {
        DiscoveryStage.EXTERNAL_DISCOVERY.value,
        DiscoveryStage.INTERNAL_DISCOVERY.value,
        DiscoveryStage.SERVICE_FINGERPRINTING.value,
    }
    assert stage_by_key[DiscoveryStage.EXTERNAL_DISCOVERY.value].status == ExecutionStageStatus.READY.value
    assert stage_by_key[DiscoveryStage.INTERNAL_DISCOVERY.value].status == ExecutionStageStatus.READY.value
    # Fingerprinting depends on both discovery stages, so it starts PENDING.
    assert stage_by_key[DiscoveryStage.SERVICE_FINGERPRINTING.value].status == ExecutionStageStatus.PENDING.value

    fingerprinting_deps = (
        db.query(ExecutionStageDependency)
        .filter(ExecutionStageDependency.execution_stage_id == stage_by_key[DiscoveryStage.SERVICE_FINGERPRINTING.value].id)
        .all()
    )
    depended_on_ids = {d.depends_on_stage_id for d in fingerprinting_deps}
    assert depended_on_ids == {
        stage_by_key[DiscoveryStage.EXTERNAL_DISCOVERY.value].id,
        stage_by_key[DiscoveryStage.INTERNAL_DISCOVERY.value].id,
    }

    # CA-04.3 — EXTERNAL_DISCOVERY now has two registered providers (nmap,
    # subfinder); internal/fingerprinting still have only nmap, since
    # SubfinderProvider only declares EXTERNAL_DISCOVERY (passive
    # subdomain enumeration, never internal or fingerprinting).
    expected_provider_ids_by_stage = {
        DiscoveryStage.EXTERNAL_DISCOVERY.value: {"nmap", "subfinder"},
        DiscoveryStage.INTERNAL_DISCOVERY.value: {"nmap"},
        DiscoveryStage.SERVICE_FINGERPRINTING.value: {"nmap"},
    }
    for stage in stages:
        jobs = db.query(ProviderExecution).filter(ProviderExecution.execution_stage_id == stage.id).all()
        assert {job.provider_id for job in jobs} == expected_provider_ids_by_stage[stage.stage_key]
        for job in jobs:
            assert job.status == ProviderExecutionStatus.PENDING.value


def test_vulnerability_stage_included_now_that_nuclei_is_registered(db: Session):
    """CA-04.4 — VULNERABILITY_ASSESSMENT enables all four stages by
    profile; vulnerability_discovery was previously excluded as an orphan
    stage with zero registered providers (see git history for that prior
    behavior), but NucleiProvider now registers for exactly that stage, so
    it must appear with one real job, not be silently dropped."""
    run = _approved_run(db, profile=ScannerProfile.VULNERABILITY_ASSESSMENT.value)

    plan = generate_execution_plan(db, run)
    db.commit()

    stages = db.query(ExecutionStage).filter(ExecutionStage.execution_plan_id == plan.id).all()
    stage_by_key = {s.stage_key: s for s in stages}
    assert set(stage_by_key) == {
        DiscoveryStage.EXTERNAL_DISCOVERY.value,
        DiscoveryStage.INTERNAL_DISCOVERY.value,
        DiscoveryStage.SERVICE_FINGERPRINTING.value,
        DiscoveryStage.VULNERABILITY_DISCOVERY.value,
    }
    vulnerability_stage = stage_by_key[DiscoveryStage.VULNERABILITY_DISCOVERY.value]
    jobs = db.query(ProviderExecution).filter(ProviderExecution.execution_stage_id == vulnerability_stage.id).all()
    assert {job.provider_id for job in jobs} == {"nuclei"}


def test_rejects_a_second_plan_for_the_same_run(db: Session):
    run = _approved_run(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    generate_execution_plan(db, run)
    db.commit()

    with pytest.raises(DiscoveryExecutionPlanError) as exc_info:
        generate_execution_plan(db, run)
    assert exc_info.value.code == "plan_already_exists"


def test_rejects_a_run_that_is_not_approved(db: Session):
    run = _approved_run(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    run.status = DiscoveryRunStatus.DRAFT.value
    db.add(run)
    db.commit()

    with pytest.raises(DiscoveryExecutionPlanError) as exc_info:
        generate_execution_plan(db, run)
    assert exc_info.value.code == "run_not_approved"


def test_rejects_when_profile_enables_no_stage_with_a_registered_provider(db: Session, monkeypatch):
    run = _approved_run(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    monkeypatch.setattr(
        "src.core.services.discovery_execution_plan_service.get_registered_providers", lambda: ()
    )

    with pytest.raises(DiscoveryExecutionPlanError) as exc_info:
        generate_execution_plan(db, run)
    assert exc_info.value.code == "no_provider_registered"


def _report_components(db: Session, run: DiscoveryRun, statuses: dict[str, str] | None) -> None:
    """Set what this run's Collector has reported about its own components.

    None means it has never reported at all — a genuinely different state from
    reporting a failure, and the one where nothing may be gated.
    """
    instance = db.query(ScannerInstance).filter(ScannerInstance.id == run.scanner_instance_id).first()
    db.query(CollectorReadinessReport).filter(
        CollectorReadinessReport.scanner_instance_id == instance.id
    ).delete()
    if statuses is not None:
        record_readiness_report(
            db,
            instance,
            report={
                "schemaVersion": "1",
                "components": [
                    {"componentKey": key, "status": value} for key, value in statuses.items()
                ],
                "platformConnectivityStatus": "ready",
                "evidenceStorageStatus": "ready",
            },
        )
    db.commit()


def _plan_stage_keys(db: Session, plan) -> set[str]:
    return {
        stage.stage_key
        for stage in db.query(ExecutionStage).filter(ExecutionStage.execution_plan_id == plan.id)
    }


def _planned_providers(db: Session, plan) -> set[str]:
    """The real unit of gating. A stage survives as long as *any* provider can
    still serve it — nmap covers external discovery as well as Subfinder — so
    asserting on stages alone would miss a job that was correctly dropped."""
    stage_ids = [
        stage.id
        for stage in db.query(ExecutionStage).filter(ExecutionStage.execution_plan_id == plan.id)
    ]
    return {
        job.provider_id
        for job in db.query(ProviderExecution).filter(ProviderExecution.execution_stage_id.in_(stage_ids))
    }


class TestCapabilityGatingAtExecutionTime:
    """CA-02.3 slice 3 — what the profile allows and what this machine can
    actually do are different questions, and the plan must answer both.

    Before this, the plan was built purely from the profile, so a job was
    dispatched to a Collector that had already reported it could not run it,
    and the failure surfaced as a provider error mid-execution rather than as a
    capability the Collector plainly does not have.
    """

    def test_a_missing_component_drops_its_own_job_and_nothing_else(self, db: Session):
        # The whole point: a Collector without Subfinder loses domain
        # enumeration and keeps everything else.
        #
        # Asserted on jobs, not stages, because nmap *also* serves external
        # discovery — so that stage correctly survives with one provider fewer.
        # A stage-level assertion would have looked like gating was not working.
        run = _approved_run(db, profile=ScannerProfile.STANDARD_DISCOVERY.value)
        _report_components(
            db, run,
            {"nmap": "ready", "subfinder": "unavailable", "nuclei": "ready", "nuclei_templates": "ready"},
        )

        plan = generate_execution_plan(db, run)

        assert "subfinder" not in _planned_providers(db, plan)
        assert "nmap" in _planned_providers(db, plan)
        assert "nuclei" in _planned_providers(db, plan)
        # The stage stays, because something can still serve it.
        assert DiscoveryStage.EXTERNAL_DISCOVERY.value in _plan_stage_keys(db, plan)

    def test_the_template_pack_gates_vulnerability_work_not_just_the_binary(self, db: Session):
        # Nuclei without its templates is an engine with nothing to run. The
        # provider declared only `requiresTool: nuclei`, so a Collector missing
        # the pack was still planned for vulnerability checks.
        run = _approved_run(db, profile=ScannerProfile.STANDARD_DISCOVERY.value)
        _report_components(
            db, run,
            {"nmap": "ready", "subfinder": "ready", "nuclei": "ready", "nuclei_templates": "unavailable"},
        )

        plan = generate_execution_plan(db, run)

        # Nuclei is the only provider for this stage, so the stage goes too.
        assert "nuclei" not in _planned_providers(db, plan)
        assert DiscoveryStage.VULNERABILITY_DISCOVERY.value not in _plan_stage_keys(db, plan)
        assert DiscoveryStage.INTERNAL_DISCOVERY.value in _plan_stage_keys(db, plan)

    def test_a_collector_that_never_reported_is_not_gated(self, db: Session):
        # Absence of evidence is not evidence of failure. Silently planning
        # less work because a Collector has been quiet is a worse failure than
        # planning work it then cannot do.
        run = _approved_run(db, profile=ScannerProfile.STANDARD_DISCOVERY.value)
        _report_components(db, run, None)

        planned = _planned_providers(db, generate_execution_plan(db, run))

        assert {"nmap", "subfinder", "nuclei"} <= planned

    def test_a_collector_that_can_run_nothing_says_so_specifically(self, db: Session):
        # Same empty stage list as "no provider registered", completely
        # different remedy. Telling an operator no provider is registered would
        # send them looking in entirely the wrong place.
        run = _approved_run(db, profile=ScannerProfile.STANDARD_DISCOVERY.value)
        _report_components(
            db, run,
            {"nmap": "unavailable", "subfinder": "unavailable", "nuclei": "unavailable", "nuclei_templates": "unavailable"},
        )

        with pytest.raises(DiscoveryExecutionPlanError) as excinfo:
            generate_execution_plan(db, run)

        assert excinfo.value.code == "collector_cannot_run_any_stage"
