"""Step 4.2 Part 3 — DISC-38: the customer execution-summary shape.

Unit-level coverage for the three resolvers discovery_run.py composes onto
DiscoveryRunResponse: collector status, action-required, and evidence
counts. The most important case here is resolve_action_required's
pipeline-failure branch — a run that failed via the execution pipeline
never populates DiscoveryRun.failure_code (only the original Step 4.1
pre-execution BLOCKED path does), so the naive "check run.failure_code"
approach would silently miss every real execution failure."""

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
    DiscoveryCollectorStatus,
    EvidenceFormat,
    EvidenceNormalizationStatus,
    EvidencePackageProcessingStatus,
    ExecutionPlanStatus,
    ExecutionStageStatus,
    ProviderExecutionStatus,
)
from src.core.constants.evidence_scanner_enums import ScannerInstanceStatus
from src.core.database import Base
from src.core.model_defs.discovery_execution import DiscoveryExecutionPlan, EvidencePackage, ExecutionStage, ProviderExecution
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.model_defs.evidence_scanner import CollectorReadinessReport
from src.core.models import Organization, User
from src.core.constants.discovery_execution_enums import (
    NON_RETRYABLE_PROVIDER_FAILURE_CODES,
    RETRYABLE_PROVIDER_FAILURE_CODES,
)
from src.core.constants.discovery_failure_language import (
    DISCOVERY_FAILURE_UNKNOWN_STATEMENT,
    PROVIDER_FAILURE_STATEMENTS,
    RUN_FAILURE_STATEMENTS,
)
from src.core.constants.discovery_run_enums import (
    NON_RETRYABLE_FAILURE_CODES,
    RETRYABLE_FAILURE_CODES,
)
from src.core.services.discovery_execution_summary_service import (
    resolve_action_required,
    resolve_collector_view,
    resolve_evidence_view,
)


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    tables = [
        Organization.__table__,
        User.__table__,
        ScannerInstance.__table__,
        CollectorReadinessReport.__table__,
        DiscoveryRun.__table__,
        DiscoveryExecutionPlan.__table__,
        ExecutionStage.__table__,
        ProviderExecution.__table__,
        EvidencePackage.__table__,
    ]
    for table in tables:
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=tables)
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Org", slug="org", country="DK", technical_setup_owner_user_id=1))
    session.commit()
    yield session
    session.close()


def _instance(
    db: Session, *, status: str, heartbeat_age_seconds: float | None = 30
) -> ScannerInstance:
    """Liveness is derived from last_heartbeat_at (BUG-DISC-05), so a fixture
    that sets only `status` describes a Collector that has never reported —
    which is a real state, but not the one most of these tests mean. The default
    is a recent beat; pass a large age for a Collector that has stopped, or None
    for one that never started."""
    from datetime import timedelta

    from src.core.model_defs.common import utcnow

    instance = ScannerInstance(
        organization_id=1,
        evidence_source_id="src-1",
        name="Primary scanner",
        installation_method="docker",
        status=status,
        activation_token_hash="hash",
        last_heartbeat_at=(
            None
            if heartbeat_age_seconds is None
            else utcnow().replace(tzinfo=None) - timedelta(seconds=heartbeat_age_seconds)
        ),
    )
    db.add(instance)
    db.commit()
    db.refresh(instance)
    return instance


def _run(db: Session, instance: ScannerInstance, *, status: str = "running", failure_code: str | None = None, failure_message: str | None = None) -> DiscoveryRun:
    run = DiscoveryRun(
        organization_id=1,
        evidence_source_id=instance.evidence_source_id,
        scanner_instance_id=instance.id,
        status=status,
        current_stage="external_discovery",
        approval_status="not_required",
        request_source="onboarding",
        discovery_purpose="first_organisation_discovery",
        requested_by_user_id=1,
        target_ids=[],
        target_snapshot=[],
        profile_snapshot={},
        failure_code=failure_code,
        failure_message=failure_message,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _plan_with_nmap_job(db: Session, run: DiscoveryRun, *, plan_status: str, stage_status: str, job_status: str, failure_code: str | None = None, failure_message: str | None = None) -> DiscoveryExecutionPlan:
    plan = DiscoveryExecutionPlan(organization_id=1, discovery_run_id=run.id, plan_definition={}, status=plan_status)
    db.add(plan)
    db.commit()
    db.refresh(plan)

    stage = ExecutionStage(execution_plan_id=plan.id, stage_key="external_discovery", status=stage_status, required=True)
    db.add(stage)
    db.commit()
    db.refresh(stage)

    job = ProviderExecution(execution_stage_id=stage.id, provider_id="nmap", status=job_status, attempt_number=1, failure_code=failure_code, failure_message=failure_message)
    db.add(job)
    db.commit()

    return plan


# --- resolve_collector_view -------------------------------------------------


def test_collector_required_true_for_a_delegated_nmap_plan(db: Session):
    instance = _instance(db, status=ScannerInstanceStatus.ONLINE.value)
    run = _run(db, instance)
    plan = _plan_with_nmap_job(db, run, plan_status=ExecutionPlanStatus.EXECUTING.value, stage_status=ExecutionStageStatus.RUNNING.value, job_status=ProviderExecutionStatus.RUNNING.value)

    view = resolve_collector_view(db, instance, plan)

    assert view.required is True
    assert view.status == DiscoveryCollectorStatus.READY.value
    assert view.display_name == "Primary scanner"


def test_collector_offline_maps_directly(db: Session):
    # A Collector goes offline by ceasing to report, not by someone writing
    # "offline" — so the stale heartbeat is what makes this case real.
    instance = _instance(
        db, status=ScannerInstanceStatus.ONLINE.value, heartbeat_age_seconds=11 * 60
    )
    run = _run(db, instance)

    view = resolve_collector_view(db, instance, None)

    assert view.status == DiscoveryCollectorStatus.OFFLINE.value
    assert view.safe_message


def test_an_offline_collector_carries_how_to_start_it(db: Session):
    # UX-DISC-06: the one failure a user cannot diagnose from the screen. Being
    # told "Offline" and nothing else leaves them exactly as stuck.
    instance = _instance(
        db, status=ScannerInstanceStatus.ONLINE.value, heartbeat_age_seconds=11 * 60
    )

    view = resolve_collector_view(db, instance, None)

    assert view.restart_command == "docker start risklence-scanner"
    assert view.restart_host_label
    assert view.restart_self_service is True


def test_a_healthy_collector_carries_no_restart_advice(db: Session):
    # Guidance attached to a working Collector is noise, and noise is how people
    # learn to stop reading the panel.
    instance = _instance(db, status=ScannerInstanceStatus.ONLINE.value)

    view = resolve_collector_view(db, instance, None)

    assert view.restart_command is None
    assert view.restart_host_label is None


def test_a_collector_someone_deliberately_paused_is_not_told_to_restart(db: Session):
    # PAUSED/REVOKED/RETIRED are decisions a person made. Telling them to start
    # a Collector they chose to stop contradicts their own decision back at
    # them, and would be the platform overruling a human.
    instance = _instance(db, status=ScannerInstanceStatus.PAUSED.value)

    view = resolve_collector_view(db, instance, None)

    assert view.status == DiscoveryCollectorStatus.UNAVAILABLE.value
    assert view.restart_command is None


def test_collector_degraded_falls_back_to_unavailable_not_a_fabricated_state(db: Session):
    instance = _instance(db, status=ScannerInstanceStatus.DEGRADED.value)

    view = resolve_collector_view(db, instance, None)

    # No version-comparison concept exists to derive upgrade_required, and
    # no access-scope concept to derive permission_required — must never
    # be guessed.
    assert view.status == DiscoveryCollectorStatus.UNAVAILABLE.value
    assert view.required_version is None


# --- resolve_action_required -------------------------------------------------


def test_no_failure_produces_no_action_required(db: Session):
    instance = _instance(db, status=ScannerInstanceStatus.ONLINE.value)
    run = _run(db, instance)

    assert resolve_action_required(db, run, None) is None


def test_run_level_blocked_failure_is_reported_with_run_failure_code(db: Session):
    instance = _instance(db, status=ScannerInstanceStatus.ONLINE.value)
    run = _run(db, instance, status="blocked", failure_code="scope_not_approved", failure_message="Targets not approved yet.")

    action_required = resolve_action_required(db, run, None)

    assert action_required is not None
    assert action_required.code == "scope_not_approved"
    assert action_required.affected_stage_key is None
    assert action_required.can_retry is False  # scope_not_approved is non-retryable
    assert action_required.support_recommended is True
    assert action_required.provider_execution_id is None  # no job to retry at run level


def test_pipeline_failure_is_found_even_though_run_failure_code_is_empty(db: Session):
    """The real gap this ticket closes: a pipeline-driven failure never
    sets DiscoveryRun.failure_code, so the resolver must fall back to the
    plan/stage/job level to find it."""
    instance = _instance(db, status=ScannerInstanceStatus.ONLINE.value)
    run = _run(db, instance, status="failed")
    assert run.failure_code is None
    plan = _plan_with_nmap_job(
        db, run,
        plan_status=ExecutionPlanStatus.FAILED.value,
        stage_status=ExecutionStageStatus.FAILED.value,
        job_status=ProviderExecutionStatus.FAILED.value,
        failure_code="provider_timeout",
        failure_message="Nmap did not respond in time.",
    )

    action_required = resolve_action_required(db, run, plan)

    assert action_required is not None
    assert action_required.code == "provider_timeout"
    assert action_required.affected_stage_key == "external_discovery"
    assert action_required.can_retry is True  # provider_timeout is job-level retryable
    assert action_required.support_recommended is False
    assert action_required.provider_execution_id is not None


def test_pipeline_failure_with_non_retryable_job_code_recommends_support(db: Session):
    instance = _instance(db, status=ScannerInstanceStatus.ONLINE.value)
    run = _run(db, instance, status="failed")
    plan = _plan_with_nmap_job(
        db, run,
        plan_status=ExecutionPlanStatus.FAILED.value,
        stage_status=ExecutionStageStatus.FAILED.value,
        job_status=ProviderExecutionStatus.FAILED.value,
        failure_code="credentials_invalid",
        failure_message="Invalid credentials.",
    )

    action_required = resolve_action_required(db, run, plan)

    assert action_required is not None
    assert action_required.can_retry is False
    assert action_required.support_recommended is True


# --- UX-DISC-02 (#128): the message never carries the stored text ------------


def test_run_level_message_is_composed_from_the_code_not_the_stored_message(db: Session):
    """command.rejection_message is free text the Collector supplied. The
    platform did not author it and cannot vouch for it, and it was being
    rendered verbatim in the customer-facing panel."""
    instance = _instance(db, status=ScannerInstanceStatus.ONLINE.value)
    run = _run(
        db,
        instance,
        status="blocked",
        failure_code="scope_not_approved",
        failure_message="panic: goroutine 42 [running]",
    )

    action_required = resolve_action_required(db, run, None)

    assert action_required is not None
    assert action_required.message == RUN_FAILURE_STATEMENTS["scope_not_approved"]
    assert "panic" not in action_required.message


def test_provider_message_never_repeats_the_lease_wording_that_was_reported(db: Session):
    """discovery_execution_retry_service writes "Worker lease expired before
    the job reported a result." — the literal sentence that put queue
    mechanics in front of an executive."""
    instance = _instance(db, status=ScannerInstanceStatus.ONLINE.value)
    run = _run(db, instance, status="failed")
    plan = _plan_with_nmap_job(
        db, run,
        plan_status=ExecutionPlanStatus.FAILED.value,
        stage_status=ExecutionStageStatus.FAILED.value,
        job_status=ProviderExecutionStatus.FAILED.value,
        failure_code="worker_lease_expired",
        failure_message="Worker lease expired before the job reported a result.",
    )

    action_required = resolve_action_required(db, run, plan)

    assert action_required is not None
    assert action_required.message == PROVIDER_FAILURE_STATEMENTS["worker_lease_expired"]
    assert "lease" not in action_required.message.lower()


def test_provider_message_for_a_raw_exception_is_replaced_entirely(db: Session):
    """discovery_execution_scheduler_service stores failure_message=str(exc)."""
    instance = _instance(db, status=ScannerInstanceStatus.ONLINE.value)
    run = _run(db, instance, status="failed")
    plan = _plan_with_nmap_job(
        db, run,
        plan_status=ExecutionPlanStatus.FAILED.value,
        stage_status=ExecutionStageStatus.FAILED.value,
        job_status=ProviderExecutionStatus.FAILED.value,
        failure_code="provider_execution_error",
        failure_message="KeyError: 'ports'",
    )

    action_required = resolve_action_required(db, run, plan)

    assert action_required is not None
    assert "KeyError" not in action_required.message
    assert action_required.message == PROVIDER_FAILURE_STATEMENTS["provider_execution_error"]


def test_a_code_with_no_statement_falls_back_to_safe_wording_not_the_stored_text(db: Session):
    """A fallback to failure_message is how the raw string returns the first
    time a new code appears — so there is no such fallback."""
    instance = _instance(db, status=ScannerInstanceStatus.ONLINE.value)
    run = _run(db, instance, status="failed")
    plan = _plan_with_nmap_job(
        db, run,
        plan_status=ExecutionPlanStatus.FAILED.value,
        stage_status=ExecutionStageStatus.FAILED.value,
        job_status=ProviderExecutionStatus.FAILED.value,
        failure_code="a_code_invented_after_this_build",
        failure_message="stderr: segmentation fault",
    )

    action_required = resolve_action_required(db, run, plan)

    assert action_required is not None
    assert action_required.message == DISCOVERY_FAILURE_UNKNOWN_STATEMENT
    assert "segmentation" not in action_required.message
    # The code itself is still reported — the frontend needs it, and it is
    # never the thing rendered.
    assert action_required.code == "a_code_invented_after_this_build"


def test_every_code_the_platform_can_produce_has_a_statement():
    """A code with no wording degrades safely, but it should not happen by
    accident: this fails the day someone adds a code and no sentence."""
    for code in RETRYABLE_FAILURE_CODES | NON_RETRYABLE_FAILURE_CODES:
        assert code in RUN_FAILURE_STATEMENTS, code
    for code in RETRYABLE_PROVIDER_FAILURE_CODES | NON_RETRYABLE_PROVIDER_FAILURE_CODES:
        assert code in PROVIDER_FAILURE_STATEMENTS, code


# --- resolve_evidence_view ---------------------------------------------------


def test_evidence_counts_map_one_to_one_onto_normalization_status(db: Session):
    instance = _instance(db, status=ScannerInstanceStatus.ONLINE.value)
    run = _run(db, instance)
    plan = DiscoveryExecutionPlan(organization_id=1, discovery_run_id=run.id, plan_definition={}, status=ExecutionPlanStatus.EXECUTING.value)
    db.add(plan)
    db.commit()
    db.refresh(plan)
    stage = ExecutionStage(execution_plan_id=plan.id, stage_key="external_discovery", status=ExecutionStageStatus.RUNNING.value, required=True)
    db.add(stage)
    db.commit()
    db.refresh(stage)

    statuses = [
        EvidenceNormalizationStatus.PENDING.value,
        EvidenceNormalizationStatus.QUEUED.value,
        EvidenceNormalizationStatus.NORMALIZED.value,
        EvidenceNormalizationStatus.NORMALIZED.value,
        EvidenceNormalizationStatus.NORMALIZATION_FAILED.value,
    ]
    for index, status in enumerate(statuses):
        job = ProviderExecution(execution_stage_id=stage.id, provider_id="nmap", status=ProviderExecutionStatus.COMPLETED.value, attempt_number=1)
        db.add(job)
        db.commit()
        db.refresh(job)
        db.add(
            EvidencePackage(
                discovery_run_id=run.id,
                execution_plan_id=plan.id,
                execution_stage_id=stage.id,
                provider_execution_id=job.id,
                organization_id=1,
                provider_id="nmap",
                schema_version="1",
                raw_evidence_reference=f"s3://bucket/{index}",
                evidence_format=EvidenceFormat.NMAP_XML.value,
                execution_metadata={},
                provenance_metadata={},
                processing_status=EvidencePackageProcessingStatus.STORED.value,
                normalization_status=status,
            )
        )
    db.commit()

    view = resolve_evidence_view(db, run)

    assert view.packages_received == 5
    assert view.packages_awaiting_processing == 1
    assert view.packages_processing == 1
    assert view.packages_processed == 2
    assert view.packages_failed_processing == 1


def test_no_packages_reports_all_zero(db: Session):
    instance = _instance(db, status=ScannerInstanceStatus.ONLINE.value)
    run = _run(db, instance)

    view = resolve_evidence_view(db, run)

    assert view.packages_received == 0
    assert view.packages_awaiting_processing == 0
