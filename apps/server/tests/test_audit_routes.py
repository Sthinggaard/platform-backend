"""Epic A3 — route-level tests for the new /api/v1/audit-trail surface:
permission gate, tenant-safe 404 shape (never a 403 leak), happy-path smoke
per route, and cursor-tampering-across-tenants safety."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import audit as audit_routes
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ResourceNotFoundError
from src.core.model_defs.discovery_execution import DiscoveryExecutionPlan, EvidencePackage, ExecutionStage, ProviderExecution
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.tenant_identity import AuditEvent, User
from src.core.model_defs.tenant_org import Organization
from src.core.model_defs.value_streams import DecisionRecord, RecoveryAction, Threat
from src.core.services.audit_cursor import encode_cursor

_TABLES = [
    Organization.__table__,
    User.__table__,
    DiscoveryRun.__table__,
    DiscoveryExecutionPlan.__table__,
    ExecutionStage.__table__,
    ProviderExecution.__table__,
    EvidencePackage.__table__,
    AuditEvent.__table__,
    Threat.__table__,
    RecoveryAction.__table__,
    DecisionRecord.__table__,
]


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in _TABLES:
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=_TABLES)
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org", country="DK"),
            Organization(id=2, name="Other Org", slug="other-org", country="DK"),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
            User(id=2, organization_id=1, email="inactive@example.com", role="member", is_active=False),
            User(
                id=3,
                organization_id=1,
                email="expired@example.com",
                role="consultant",
                access_expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
            ),
            User(id=4, organization_id=2, email="other-org-admin@example.com", role="org_admin"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _ctx(user_id: int, organization_id: int = 1) -> TenantContext:
    return TenantContext(user_id=user_id, organization_id=organization_id, email="x@example.com", roles=["org_admin"], permissions=[])


def _seed_discovery_graph(db: Session, *, organization_id: int = 1) -> dict:
    run = DiscoveryRun(
        id="run-1",
        organization_id=organization_id,
        evidence_source_id="src-1",
        scanner_instance_id="scanner-1",
        requested_by_user_id=1,
        request_source="onboarding",
        discovery_purpose="first_organisation_discovery",
        profile_snapshot={},
        target_ids=[],
        target_snapshot=[],
        status="completed",
        current_stage="completed",
        approval_status="not_required",
    )
    plan = DiscoveryExecutionPlan(
        id="plan-1", organization_id=organization_id, discovery_run_id="run-1", plan_definition={}, status="completed"
    )
    stage = ExecutionStage(id="stage-1", execution_plan_id="plan-1", stage_key="external_discovery", status="completed")
    job = ProviderExecution(id="job-1", execution_stage_id="stage-1", provider_id="nmap", status="completed")
    package = EvidencePackage(
        id="package-1",
        discovery_run_id="run-1",
        execution_plan_id="plan-1",
        execution_stage_id="stage-1",
        provider_execution_id="job-1",
        organization_id=organization_id,
        provider_id="nmap",
        schema_version="1.0",
        raw_evidence_reference="s3://evidence/package-1",
        evidence_format="json",
        execution_metadata={},
        provenance_metadata={},
        processing_status="completed",
        normalization_status="normalized",
    )
    db.add_all([run, plan, stage, job, package])
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=1,
            event_type="discovery_run.requested",
            metadata_json={"discovery_run_id": "run-1"},
        )
    )
    db.commit()
    return {"run": run, "plan": plan, "stage": stage, "job": job, "package": package}


def _seed_decision(db: Session, *, organization_id: int = 1) -> dict:
    threat = Threat(
        id="threat-1",
        organization_id=organization_id,
        status="detected",
        severity="high",
        source="glic",
        asset="Payment Gateway",
        tier="mission-critical",
        signal="Packet loss rising.",
        what_it_means="Payments may fail.",
        recommendation="jira",
    )
    record = DecisionRecord(
        id="dr-1",
        organization_id=organization_id,
        recommendation_id="rec-1",
        threat_id="threat-1",
        selected_action="jira",
        decision_type="followed-recommendation",
        rationale="Fastest remediation path.",
        decided_by="Anna Jensen",
        decided_role="org_admin",
        stale=False,
        recommendation_snapshot={"problem": "Packet loss rising."},
        reasoning_snapshot={"confidence": 91},
    )
    db.add_all([threat, record])
    db.commit()
    return {"threat": threat, "record": record}


# --- permission gate --------------------------------------------------------


def test_inactive_user_is_denied_read_access(db: Session):
    _seed_discovery_graph(db)
    with pytest.raises(AuthorizationError):
        audit_routes.get_discovery_run_audit_timeline("run-1", cursor=None, limit=50, ctx=_ctx(2), db=db)


def test_expired_access_user_is_denied_read_access(db: Session):
    _seed_discovery_graph(db)
    with pytest.raises(AuthorizationError):
        audit_routes.get_discovery_run_audit_timeline("run-1", cursor=None, limit=50, ctx=_ctx(3), db=db)


# --- tenant-safe 404 shape: cross-tenant and nonexistent must look identical -


def test_discovery_run_timeline_cross_tenant_and_nonexistent_both_404(db: Session):
    _seed_discovery_graph(db, organization_id=1)

    with pytest.raises(ResourceNotFoundError):
        audit_routes.get_discovery_run_audit_timeline("run-1", cursor=None, limit=50, ctx=_ctx(4, organization_id=2), db=db)
    with pytest.raises(ResourceNotFoundError):
        audit_routes.get_discovery_run_audit_timeline("run-does-not-exist", cursor=None, limit=50, ctx=_ctx(1), db=db)


def test_decision_trace_cross_tenant_and_nonexistent_both_404(db: Session):
    _seed_decision(db, organization_id=1)

    with pytest.raises(ResourceNotFoundError):
        audit_routes.get_decision_trace("dr-1", ctx=_ctx(4, organization_id=2), db=db)
    with pytest.raises(ResourceNotFoundError):
        audit_routes.get_decision_trace("dr-does-not-exist", ctx=_ctx(1), db=db)


def test_threat_decision_list_cross_tenant_and_nonexistent_both_404(db: Session):
    _seed_decision(db, organization_id=1)

    with pytest.raises(ResourceNotFoundError):
        audit_routes.get_decision_trace_list_for_threat(
            "threat-1", cursor=None, limit=50, ctx=_ctx(4, organization_id=2), db=db
        )
    with pytest.raises(ResourceNotFoundError):
        audit_routes.get_decision_trace_list_for_threat(
            "threat-does-not-exist", cursor=None, limit=50, ctx=_ctx(1), db=db
        )


# --- happy path smoke, one per route ----------------------------------------


def test_discovery_run_timeline_happy_path(db: Session):
    _seed_discovery_graph(db)
    page = audit_routes.get_discovery_run_audit_timeline("run-1", cursor=None, limit=50, ctx=_ctx(1), db=db)
    assert len(page.entries) == 1
    assert page.entries[0].eventType == "discovery_run.requested"


def test_execution_plan_timeline_happy_path(db: Session):
    _seed_discovery_graph(db)
    db.add(AuditEvent(organization_id=1, event_type="discovery_execution_plan.completed", metadata_json={"executionPlanId": "plan-1"}))
    db.commit()
    page = audit_routes.get_execution_plan_audit_timeline("plan-1", cursor=None, limit=50, ctx=_ctx(1), db=db)
    assert len(page.entries) == 1


def test_provider_execution_timeline_happy_path(db: Session):
    _seed_discovery_graph(db)
    db.add(AuditEvent(organization_id=1, event_type="provider_execution.completed", metadata_json={"providerExecutionId": "job-1"}))
    db.commit()
    page = audit_routes.get_provider_execution_audit_timeline("job-1", cursor=None, limit=50, ctx=_ctx(1), db=db)
    assert len(page.entries) == 1


def test_evidence_package_timeline_happy_path(db: Session):
    _seed_discovery_graph(db)
    db.add(AuditEvent(organization_id=1, event_type="evidence_package.normalized", metadata_json={"evidencePackageId": "package-1"}))
    db.commit()
    page = audit_routes.get_evidence_package_audit_timeline("package-1", cursor=None, limit=50, ctx=_ctx(1), db=db)
    assert len(page.entries) == 1


def test_decision_trace_happy_path(db: Session):
    _seed_decision(db)
    trace = audit_routes.get_decision_trace("dr-1", ctx=_ctx(1), db=db)
    assert trace.decisionRecordId == "dr-1"
    assert trace.threat is not None


def test_threat_decision_list_happy_path(db: Session):
    _seed_decision(db)
    page = audit_routes.get_decision_trace_list_for_threat("threat-1", cursor=None, limit=50, ctx=_ctx(1), db=db)
    assert [e.decisionRecordId for e in page.entries] == ["dr-1"]


# --- pagination edge cases and cursor safety --------------------------------


def test_invalid_cursor_returns_clean_400(db: Session):
    _seed_discovery_graph(db)
    with pytest.raises(HTTPException) as exc_info:
        audit_routes.get_discovery_run_audit_timeline("run-1", cursor="not-a-valid-cursor!!!", limit=50, ctx=_ctx(1), db=db)
    assert exc_info.value.status_code == 400


def test_cursor_replayed_under_a_different_tenant_cannot_leak_rows(db: Session):
    """A cursor is only ever a keyset constraint applied on top of an
    already organization_id-scoped query — replaying org 1's cursor under
    org 2's tenant context must 404 on the object check before the cursor
    is ever evaluated, the same as any other cross-tenant request."""
    _seed_discovery_graph(db, organization_id=1)
    cursor = encode_cursor(datetime.now(timezone.utc), 1)

    with pytest.raises(ResourceNotFoundError):
        audit_routes.get_discovery_run_audit_timeline(
            "run-1", cursor=cursor, limit=50, ctx=_ctx(4, organization_id=2), db=db
        )
