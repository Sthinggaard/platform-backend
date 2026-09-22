"""Step 4.2 Part 3 — DISC-41: the first-ever audit-event read API.

Verifies the timeline resolver correctly branches between the two
metadata-key conventions this domain's writers actually use (snake_case
discovery_run_id on discovery_run.* events, camelCase execution*/provider*
ids everywhere else — a real, pre-existing inconsistency this module works
around rather than fixes), and that it never leaks another run's or
another organisation's events."""

from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.database import Base
from src.core.model_defs.discovery_execution import DiscoveryExecutionPlan, EvidencePackage, ExecutionStage, ProviderExecution
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.models import Organization, User
from src.core.services.discovery_execution_audit_timeline_service import resolve_discovery_run_timeline


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    tables = [
        Organization.__table__,
        User.__table__,
        DiscoveryRun.__table__,
        DiscoveryExecutionPlan.__table__,
        ExecutionStage.__table__,
        ProviderExecution.__table__,
        EvidencePackage.__table__,
        AuditEvent.__table__,
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


def _run(db: Session, *, organization_id: int = 1) -> DiscoveryRun:
    run = DiscoveryRun(
        organization_id=organization_id,
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


def test_run_level_event_matched_by_snake_case_discovery_run_id(db: Session):
    run = _run(db)
    db.add(AuditEvent(organization_id=1, actor_user_id=1, event_type="discovery_run.requested", metadata_json={"discovery_run_id": run.id}))
    db.add(AuditEvent(organization_id=1, actor_user_id=1, event_type="discovery_run.requested", metadata_json={"discovery_run_id": "some-other-run"}))
    db.commit()

    timeline = resolve_discovery_run_timeline(db, 1, run, None)

    assert len(timeline) == 1
    assert timeline[0].label == "Discovery requested"


def test_plan_stage_job_events_matched_by_camel_case_ids(db: Session):
    run = _run(db)
    plan = DiscoveryExecutionPlan(organization_id=1, discovery_run_id=run.id, plan_definition={}, status="executing")
    db.add(plan)
    db.commit()
    db.refresh(plan)
    stage = ExecutionStage(execution_plan_id=plan.id, stage_key="external_discovery", status="running", required=True)
    db.add(stage)
    db.commit()
    db.refresh(stage)
    job = ProviderExecution(execution_stage_id=stage.id, provider_id="nmap", status="running", attempt_number=1)
    db.add(job)
    db.commit()
    db.refresh(job)

    db.add(AuditEvent(organization_id=1, event_type="discovery_execution_plan.generated", metadata_json={"executionPlanId": plan.id}))
    db.add(AuditEvent(organization_id=1, event_type="execution_stage.started", metadata_json={"executionStageId": stage.id, "stageKey": "external_discovery"}))
    db.add(AuditEvent(organization_id=1, event_type="provider_execution.started", metadata_json={"providerExecutionId": job.id}))
    # A plan-level event for a *different* plan must not leak in.
    db.add(AuditEvent(organization_id=1, event_type="discovery_execution_plan.generated", metadata_json={"executionPlanId": "other-plan"}))
    db.commit()

    timeline = resolve_discovery_run_timeline(db, 1, run, plan)

    labels = {entry.label for entry in timeline}
    assert labels == {"Execution plan generated", "A discovery stage started", "A discovery job started"}


def test_plan_generated_event_matched_despite_snake_case_key(db: Session):
    """discovery_run.py's own _advance_if_approved writes
    discovery_execution_plan.generated with a snake_case execution_plan_id
    key, unlike every other discovery_execution_plan.* event (written by
    the scheduler service with camelCase executionPlanId) — both must
    resolve to the same plan."""
    run = _run(db)
    plan = DiscoveryExecutionPlan(organization_id=1, discovery_run_id=run.id, plan_definition={}, status="executing")
    db.add(plan)
    db.commit()
    db.refresh(plan)

    db.add(AuditEvent(organization_id=1, actor_user_id=1, event_type="discovery_execution_plan.generated", metadata_json={"discovery_run_id": run.id, "execution_plan_id": plan.id}))
    db.commit()

    timeline = resolve_discovery_run_timeline(db, 1, run, plan)

    assert len(timeline) == 1
    assert timeline[0].label == "Execution plan generated"


def test_customer_triggered_retry_gets_its_own_label(db: Session):
    run = _run(db)
    plan = DiscoveryExecutionPlan(organization_id=1, discovery_run_id=run.id, plan_definition={}, status="executing")
    db.add(plan)
    db.commit()
    db.refresh(plan)
    stage = ExecutionStage(execution_plan_id=plan.id, stage_key="external_discovery", status="ready", required=True)
    db.add(stage)
    db.commit()
    db.refresh(stage)
    job = ProviderExecution(execution_stage_id=stage.id, provider_id="nmap", status="failed", attempt_number=1)
    db.add(job)
    db.commit()
    db.refresh(job)

    db.add(AuditEvent(organization_id=1, event_type="provider_execution.retry_queued", metadata_json={"providerExecutionId": job.id, "trigger": "customer"}))
    db.add(AuditEvent(organization_id=1, event_type="provider_execution.retry_queued", metadata_json={"providerExecutionId": job.id, "nextRetryAt": "2030-01-01T00:00:00"}))
    db.commit()

    timeline = resolve_discovery_run_timeline(db, 1, run, plan)

    labels = [entry.label for entry in timeline]
    assert "A discovery job was retried" in labels
    assert "A discovery job was queued for retry" in labels


def test_cancellation_with_a_reason_code_gets_a_business_language_label(db: Session):
    """DISC-46 — the timeline surfaces *why* a cancellation was requested,
    never the raw enum value (Ledger's own rule)."""
    run = _run(db)
    db.add(
        AuditEvent(
            organization_id=1,
            event_type="discovery_run.cancellation_requested",
            metadata_json={"discovery_run_id": run.id, "reason_code": "scope_changed"},
        )
    )
    db.commit()

    timeline = resolve_discovery_run_timeline(db, 1, run, None)

    assert len(timeline) == 1
    assert timeline[0].label == "Cancellation requested — the approved scope changed"


def test_cancellation_without_a_reason_code_gets_the_plain_label(db: Session):
    run = _run(db)
    db.add(AuditEvent(organization_id=1, event_type="discovery_run.cancellation_requested", metadata_json={"discovery_run_id": run.id}))
    db.commit()

    timeline = resolve_discovery_run_timeline(db, 1, run, None)

    assert len(timeline) == 1
    assert timeline[0].label == "Cancellation requested"


def test_cross_organization_events_never_leak(db: Session):
    db.add(Organization(id=2, name="Other Org", slug="other-org", country="DK", technical_setup_owner_user_id=1))
    db.commit()
    run = _run(db, organization_id=1)
    other_org_run = _run(db, organization_id=2)

    db.add(AuditEvent(organization_id=2, event_type="discovery_run.requested", metadata_json={"discovery_run_id": other_org_run.id}))
    db.commit()

    timeline = resolve_discovery_run_timeline(db, 1, run, None)

    assert timeline == []


def test_unknown_event_type_gets_a_readable_fallback_label(db: Session):
    run = _run(db)
    db.add(AuditEvent(organization_id=1, event_type="discovery_run.some_future_event", metadata_json={"discovery_run_id": run.id}))
    db.commit()

    timeline = resolve_discovery_run_timeline(db, 1, run, None)

    assert timeline[0].label == "Discovery run some future event"


def test_non_discovery_event_types_are_ignored(db: Session):
    run = _run(db)
    db.add(AuditEvent(organization_id=1, event_type="business_context_refined", metadata_json={"answer_count": 3}))
    db.commit()

    timeline = resolve_discovery_run_timeline(db, 1, run, None)

    assert timeline == []


def test_occurred_at_says_it_is_utc(db: Session):
    """Søren, at 15:25 CEST, reading `2026-08-14T13:25:10.877799` on the
    activity feed. The instant was right; the string never said which zone it
    was in, and ECMAScript parses an offset-less date-time as *local*, so every
    browser outside UTC rendered it hours off — silently, and invisibly to a
    UTC-based test suite.

    Pinned on the serialised string rather than the datetime, because that is
    the part clients actually consume.
    """
    run = _run(db)
    db.add(AuditEvent(organization_id=1, event_type="discovery_run.requested", metadata_json={"discovery_run_id": run.id}))
    db.commit()

    timeline = resolve_discovery_run_timeline(db, 1, run, None)

    occurred_at = timeline[0].occurred_at
    assert occurred_at.endswith("+00:00"), occurred_at
    # And it must still be parseable as an aware instant, not just suffixed.
    assert datetime.fromisoformat(occurred_at).tzinfo is not None
