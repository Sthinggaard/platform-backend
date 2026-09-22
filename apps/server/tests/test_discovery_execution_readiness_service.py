"""Step 4.2 Part 3 — DISC-39: technical-readiness / downstream-readiness.

Verifies the three layers stay independently derived — execution
completing never implies evidence processing is done, and evidence
processing completing never implies technicalFoundationReady — which is now
derived from the organisation's artefacts rather than hardcoded False
(BUG-DISC-16), but is still never inferred from the other two layers."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.discovery_execution_enums import EvidenceFormat, EvidenceNormalizationStatus, EvidencePackageProcessingStatus, ExecutionPlanStatus
from src.core.database import Base
from src.core.model_defs.assets_runtime import Asset, AssetLifecycleState
from src.core.model_defs.discovery_execution import DiscoveryExecutionPlan, EvidencePackage
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.models import Organization, User
from src.core.services.discovery_execution_readiness_service import resolve_discovery_readiness_layers


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    tables = [
        Organization.__table__,
        User.__table__,
        DiscoveryRun.__table__,
        DiscoveryExecutionPlan.__table__,
        EvidencePackage.__table__,
        Asset.__table__,
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


def _run(db: Session) -> DiscoveryRun:
    run = DiscoveryRun(
        organization_id=1,
        evidence_source_id="src",
        scanner_instance_id="inst",
        status="running",
        current_stage="external_discovery",
        approval_status="not_required",
        request_source="onboarding",
        discovery_purpose="first_organisation_discovery",
        requested_by_user_id=1,
        target_ids=[],
        target_snapshot=[],
        profile_snapshot={},
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _plan(db: Session, run: DiscoveryRun, status: str) -> DiscoveryExecutionPlan:
    plan = DiscoveryExecutionPlan(organization_id=1, discovery_run_id=run.id, plan_definition={}, status=status)
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan


def _package(db: Session, run: DiscoveryRun, plan: DiscoveryExecutionPlan, normalization_status: str) -> EvidencePackage:
    package = EvidencePackage(
        discovery_run_id=run.id,
        execution_plan_id=plan.id,
        execution_stage_id="stage-1",
        provider_execution_id=f"job-{normalization_status}-{db.query(EvidencePackage).count()}",
        organization_id=1,
        provider_id="nmap",
        schema_version="1",
        raw_evidence_reference="s3://bucket/key",
        evidence_format=EvidenceFormat.NMAP_XML.value,
        execution_metadata={},
        provenance_metadata={},
        processing_status=EvidencePackageProcessingStatus.STORED.value,
        normalization_status=normalization_status,
    )
    db.add(package)
    db.commit()
    return package


def test_no_plan_yet_reports_nothing_complete(db: Session):
    run = _run(db)
    layers = resolve_discovery_readiness_layers(db, run, None)

    assert layers.execution_complete is False
    assert layers.evidence_processing_complete is False
    assert layers.technical_foundation_ready is False
    assert layers.next_step_label == "Discovery is still running."


def test_executing_plan_is_not_execution_complete(db: Session):
    run = _run(db)
    plan = _plan(db, run, ExecutionPlanStatus.EXECUTING.value)

    layers = resolve_discovery_readiness_layers(db, run, plan)

    assert layers.execution_complete is False


def test_completed_plan_with_no_packages_is_vacuously_evidence_complete(db: Session):
    run = _run(db)
    plan = _plan(db, run, ExecutionPlanStatus.COMPLETED.value)

    layers = resolve_discovery_readiness_layers(db, run, plan)

    assert layers.execution_complete is True
    assert layers.evidence_processing_complete is True
    # Vacuously evidence-complete, but nothing was found, so the copy says that
    # rather than asking the user to review evidence that does not exist.
    assert "without finding anything" in (layers.next_step_label or "")


def test_completed_plan_with_pending_package_is_not_evidence_complete(db: Session):
    run = _run(db)
    plan = _plan(db, run, ExecutionPlanStatus.COMPLETED.value)
    _package(db, run, plan, EvidenceNormalizationStatus.NORMALIZED.value)
    _package(db, run, plan, EvidenceNormalizationStatus.PENDING.value)

    layers = resolve_discovery_readiness_layers(db, run, plan)

    assert layers.execution_complete is True
    assert layers.evidence_processing_complete is False
    assert layers.next_step_label == "Risklence is processing the evidence collected during discovery."


def test_a_failed_normalization_still_counts_as_processing_finished(db: Session):
    run = _run(db)
    plan = _plan(db, run, ExecutionPlanStatus.COMPLETED.value)
    _package(db, run, plan, EvidenceNormalizationStatus.NORMALIZATION_FAILED.value)

    layers = resolve_discovery_readiness_layers(db, run, plan)

    assert layers.evidence_processing_complete is True


def _asset(db: Session, *, lifecycle_state: AssetLifecycleState, name: str = "host-1") -> Asset:
    asset = Asset(
        organization_id=1,
        type="Service",
        provider="collector",
        display_name=name,
        layer="Application",
        lifecycle_state=lifecycle_state,
    )
    db.add(asset)
    db.flush()
    return asset


def test_technical_foundation_ready_when_discovery_produced_confirmed_artefacts(db: Session):
    """The BUG-DISC-16 case: a fully successful run used to leave this layer
    spinning forever, because the value was a literal False no evidence could
    move. Replaces test_technical_foundation_ready_is_never_derived_true."""
    run = _run(db)
    plan = _plan(db, run, ExecutionPlanStatus.COMPLETED.value)
    _package(db, run, plan, EvidenceNormalizationStatus.NORMALIZED.value)
    _asset(db, lifecycle_state=AssetLifecycleState.ACTIVE)

    layers = resolve_discovery_readiness_layers(db, run, plan)

    assert layers.evidence_processing_complete is True
    assert layers.technical_foundation_ready is True
    assert layers.next_step_label is None


def test_unconfirmed_artefacts_are_reported_without_blocking_the_foundation(db: Session):
    """An ambiguous match must never hold the step open, because nothing in this
    codebase can move an Asset out of UNCONFIRMED — no route, no service, no
    screen. Blocking on it would recreate the very defect BUG-DISC-16 is about:
    a step the user is told to complete and cannot. The uncertainty is stated
    instead, and the copy must not ask the user to act on it."""
    run = _run(db)
    plan = _plan(db, run, ExecutionPlanStatus.COMPLETED.value)
    _package(db, run, plan, EvidenceNormalizationStatus.NORMALIZED.value)
    _asset(db, lifecycle_state=AssetLifecycleState.ACTIVE)
    _asset(db, lifecycle_state=AssetLifecycleState.UNCONFIRMED, name="ambiguous-1")

    layers = resolve_discovery_readiness_layers(db, run, plan)

    assert layers.technical_foundation_ready is True
    label = layers.next_step_label or ""
    assert "1 item could not be matched with confidence" in label
    assert "kept separate rather than merged" in label
    # The whole point: no instruction the user has no way to follow.
    assert "Confirm" not in label


def test_technical_foundation_is_never_inferred_from_the_layers_above_it(db: Session):
    """The original boundary rule still holds: evidence processing completing
    must not imply a foundation. With no artefacts at all, the layer stays
    false and the copy states the real outcome instead of pretending to work."""
    run = _run(db)
    plan = _plan(db, run, ExecutionPlanStatus.COMPLETED.value)
    _package(db, run, plan, EvidenceNormalizationStatus.NORMALIZED.value)

    layers = resolve_discovery_readiness_layers(db, run, plan)

    assert layers.evidence_processing_complete is True
    assert layers.technical_foundation_ready is False
    assert "without finding anything" in (layers.next_step_label or "")


def test_technical_foundation_stays_false_while_evidence_is_still_processing(db: Session):
    run = _run(db)
    plan = _plan(db, run, ExecutionPlanStatus.COMPLETED.value)
    _package(db, run, plan, EvidenceNormalizationStatus.PENDING.value)
    _asset(db, lifecycle_state=AssetLifecycleState.ACTIVE)

    layers = resolve_discovery_readiness_layers(db, run, plan)

    assert layers.evidence_processing_complete is False
    assert layers.technical_foundation_ready is False
