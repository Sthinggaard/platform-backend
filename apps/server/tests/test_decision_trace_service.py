"""Epic A3 — decision trace assembly: snapshots, threat/recovery-action
linkage, cross-tenant isolation, and threat-scoped decision history."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.database import Base
from src.core.model_defs.tenant_org import Organization
from src.core.model_defs.value_streams import DecisionRecord, RecoveryAction, Threat
from src.core.services.audit_cursor import decode_cursor
from src.core.services.decision_trace_service import resolve_decision_trace, resolve_decision_trace_list_for_threat

_TABLES = [Organization.__table__, Threat.__table__, RecoveryAction.__table__, DecisionRecord.__table__]
_BASE = datetime(2026, 7, 27, 10, 0, 0)


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
        ]
    )
    session.commit()
    yield session
    session.close()


def _threat(db: Session, *, organization_id: int = 1, threat_id: str = "threat-1") -> Threat:
    threat = Threat(
        id=threat_id,
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
    db.add(threat)
    db.commit()
    return threat


def _recovery_action(db: Session, *, organization_id: int = 1, threat_id: str, action_id: int = 1) -> RecoveryAction:
    action = RecoveryAction(
        id=action_id,
        organization_id=organization_id,
        threat_id=threat_id,
        title="Failover to secondary region",
        issue="Primary region degraded",
        action="Trigger failover runbook",
        status="in-progress",
        progress=40,
        ref="RISK-4821",
    )
    db.add(action)
    db.commit()
    return action


def _decision_record(
    db: Session,
    *,
    organization_id: int = 1,
    record_id: str = "dr-1",
    threat_id: str | None = "threat-1",
    recovery_action_id: int | None = None,
    offset_seconds: int = 0,
) -> DecisionRecord:
    record = DecisionRecord(
        id=record_id,
        organization_id=organization_id,
        recommendation_id="rec-1",
        threat_id=threat_id,
        selected_action="jira",
        decision_type="followed-recommendation",
        rationale="Fastest remediation path.",
        decided_by="Anna Jensen",
        decided_role="org_admin",
        stale=False,
        recommendation_snapshot={"problem": "Packet loss rising."},
        reasoning_snapshot={"confidence": 91},
        forecast_snapshot=None,
        recovery_action_id=recovery_action_id,
        created_at=_BASE + timedelta(seconds=offset_seconds),
    )
    db.add(record)
    db.commit()
    return record


# --- trace assembly ------------------------------------------------------


def test_trace_includes_threat_and_recovery_action_when_linked(db: Session):
    _threat(db)
    _recovery_action(db, threat_id="threat-1")
    _decision_record(db, threat_id="threat-1", recovery_action_id=1)

    trace = resolve_decision_trace(db, 1, "dr-1")

    assert trace is not None
    assert trace.recommendationSnapshot == {"problem": "Packet loss rising."}
    assert trace.reasoningSnapshot == {"confidence": 91}
    assert trace.threat is not None and trace.threat.id == "threat-1"
    assert trace.recoveryAction is not None and trace.recoveryAction.title == "Failover to secondary region"


def test_trace_returns_null_threat_and_recovery_action_when_not_linked_not_an_error(db: Session):
    _decision_record(db, threat_id=None, recovery_action_id=None)

    trace = resolve_decision_trace(db, 1, "dr-1")

    assert trace is not None
    assert trace.threat is None
    assert trace.recoveryAction is None


def test_trace_never_conflates_live_threat_decision_with_the_frozen_snapshot(db: Session):
    """The trace must never expose Threat.decision (the weaker, unversioned,
    overwritable view) — only the DecisionRecord's own frozen snapshots."""
    _threat(db)
    _decision_record(db, threat_id="threat-1")

    trace = resolve_decision_trace(db, 1, "dr-1")

    assert not hasattr(trace.threat, "decision")


# --- cross-tenant isolation ------------------------------------------------


def test_trace_is_not_readable_across_tenants(db: Session):
    _decision_record(db, organization_id=1, record_id="dr-1")

    assert resolve_decision_trace(db, 2, "dr-1") is None


def test_trace_returns_none_for_a_nonexistent_id_in_any_org(db: Session):
    assert resolve_decision_trace(db, 1, "dr-does-not-exist") is None


# --- threat-scoped decision history ----------------------------------------


def test_decision_list_for_threat_is_newest_first_and_paginated(db: Session):
    _threat(db)
    for i in range(3):
        _decision_record(db, record_id=f"dr-{i}", threat_id="threat-1", offset_seconds=i)

    page1 = resolve_decision_trace_list_for_threat(db, 1, "threat-1", limit=2)
    assert [e.decisionRecordId for e in page1.entries] == ["dr-2", "dr-1"]
    assert page1.hasMore is True

    cursor = decode_cursor(page1.nextCursor)
    page2 = resolve_decision_trace_list_for_threat(db, 1, "threat-1", cursor=cursor, limit=2)
    assert [e.decisionRecordId for e in page2.entries] == ["dr-0"]
    assert page2.hasMore is False


def test_decision_list_for_threat_is_tenant_scoped(db: Session):
    _decision_record(db, organization_id=1, record_id="dr-org1", threat_id="threat-1")
    _decision_record(db, organization_id=2, record_id="dr-org2", threat_id="threat-1")

    page = resolve_decision_trace_list_for_threat(db, 1, "threat-1")

    assert [e.decisionRecordId for e in page.entries] == ["dr-org1"]
