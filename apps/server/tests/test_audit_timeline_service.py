"""Epic A3 — cross-tenant isolation, pagination, and derivation for the new
general audit timeline service (independent of DISC-41's own service)."""

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
from src.core.model_defs.tenant_identity import AuditEvent, User
from src.core.model_defs.tenant_org import Organization
from src.core.services.audit_cursor import decode_cursor
from src.core.services.audit_timeline_service import (
    resolve_discovery_run_timeline_page,
    resolve_evidence_package_timeline_page,
    resolve_execution_plan_timeline_page,
    resolve_provider_execution_timeline_page,
)

_BASE = datetime(2026, 7, 27, 10, 0, 0)


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in (Organization.__table__, User.__table__, AuditEvent.__table__):
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=[Organization.__table__, User.__table__, AuditEvent.__table__])
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org", country="DK"),
            Organization(id=2, name="Other Org", slug="other-org", country="DK"),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _write_event(
    db: Session,
    *,
    organization_id: int,
    event_type: str,
    metadata: dict,
    actor_user_id: int | None = None,
    offset_seconds: int = 0,
) -> AuditEvent:
    event = AuditEvent(
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type=event_type,
        metadata_json=metadata,
        created_at=_BASE + timedelta(seconds=offset_seconds),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


# --- cross-tenant isolation -------------------------------------------------


def test_discovery_run_timeline_only_returns_the_requesting_org_events(db: Session):
    _write_event(
        db, organization_id=1, event_type="discovery_run.requested", metadata={"discovery_run_id": "run-shared"}
    )
    _write_event(
        db, organization_id=2, event_type="discovery_run.requested", metadata={"discovery_run_id": "run-shared"}
    )

    page = resolve_discovery_run_timeline_page(db, 1, "run-shared")

    assert len(page.entries) == 1
    assert page.entries[0].eventType == "discovery_run.requested"


def test_discovery_run_timeline_for_nonexistent_run_is_empty_not_an_error(db: Session):
    _write_event(db, organization_id=1, event_type="discovery_run.requested", metadata={"discovery_run_id": "run-a"})

    page = resolve_discovery_run_timeline_page(db, 1, "run-does-not-exist")

    assert page.entries == []
    assert page.hasMore is False


# --- pagination --------------------------------------------------------------


def test_discovery_run_timeline_pagination_is_newest_first_with_no_duplicate_or_skipped_entries(db: Session):
    for i in range(5):
        _write_event(
            db,
            organization_id=1,
            event_type="discovery_run.stage_changed",
            metadata={"discovery_run_id": "run-a"},
            offset_seconds=i,
        )

    page1 = resolve_discovery_run_timeline_page(db, 1, "run-a", limit=2)
    assert len(page1.entries) == 2
    assert page1.hasMore is True
    assert page1.nextCursor is not None
    # newest first: offsets 4, 3
    assert [e.occurredAt for e in page1.entries] == [
        _BASE + timedelta(seconds=4),
        _BASE + timedelta(seconds=3),
    ]
    # #281/#284 — and it leaves the API as an unambiguous instant. The entry
    # used to carry a pre-stringified timestamp with no offset, which every
    # browser outside UTC read as local time.
    assert "+00:00" in page1.entries[0].model_dump_json()

    cursor2 = decode_cursor(page1.nextCursor)
    page2 = resolve_discovery_run_timeline_page(db, 1, "run-a", cursor=cursor2, limit=2)
    assert len(page2.entries) == 2
    assert page2.hasMore is True
    assert {e.id for e in page2.entries}.isdisjoint({e.id for e in page1.entries})

    cursor3 = decode_cursor(page2.nextCursor)
    page3 = resolve_discovery_run_timeline_page(db, 1, "run-a", cursor=cursor3, limit=2)
    assert len(page3.entries) == 1
    assert page3.hasMore is False
    assert page3.nextCursor is None

    all_ids = {e.id for e in page1.entries} | {e.id for e in page2.entries} | {e.id for e in page3.entries}
    assert len(all_ids) == 5


# --- category / actor_type / correlation derivation --------------------------


def test_category_actor_type_and_correlation_id_derivation(db: Session):
    _write_event(
        db,
        organization_id=1,
        event_type="discovery_run.requested",
        metadata={"discovery_run_id": "run-a", "lifecycle": {"correlationId": "corr-1"}},
        actor_user_id=1,
    )
    _write_event(
        db,
        organization_id=1,
        event_type="discovery_run.completed",
        metadata={"discovery_run_id": "run-a"},
        actor_user_id=None,
        offset_seconds=1,
    )

    page = resolve_discovery_run_timeline_page(db, 1, "run-a")
    by_type = {e.eventType: e for e in page.entries}

    requested = by_type["discovery_run.requested"]
    assert requested.category == "LIFECYCLE"
    assert requested.actorType == "human"
    assert requested.correlationId == "corr-1"

    completed = by_type["discovery_run.completed"]
    assert completed.actorType == "system"
    assert completed.correlationId is None


# --- execution plan: snake_case / camelCase metadata-key inconsistency -------


def test_execution_plan_timeline_matches_both_metadata_key_conventions(db: Session):
    _write_event(
        db, organization_id=1, event_type="discovery_execution_plan.generated", metadata={"execution_plan_id": "plan-a"}
    )
    _write_event(
        db,
        organization_id=1,
        event_type="discovery_execution_plan.completed",
        metadata={"executionPlanId": "plan-a"},
        offset_seconds=1,
    )
    _write_event(
        db,
        organization_id=1,
        event_type="execution_stage.completed",
        metadata={"executionStageId": "stage-a"},
        offset_seconds=2,
    )
    _write_event(
        db,
        organization_id=1,
        event_type="execution_stage.completed",
        metadata={"executionStageId": "stage-unrelated"},
        offset_seconds=3,
    )

    page = resolve_execution_plan_timeline_page(db, 1, "plan-a", {"stage-a"})

    event_types = {e.eventType for e in page.entries}
    assert event_types == {"discovery_execution_plan.generated", "discovery_execution_plan.completed", "execution_stage.completed"}
    assert len(page.entries) == 3  # the unrelated-stage event must not appear


# --- provider execution -------------------------------------------------------


def test_provider_execution_timeline_scoped_to_one_attempt(db: Session):
    _write_event(db, organization_id=1, event_type="provider_execution.started", metadata={"providerExecutionId": "job-a"})
    _write_event(
        db,
        organization_id=1,
        event_type="provider_execution.completed",
        metadata={"providerExecutionId": "job-a"},
        offset_seconds=1,
    )
    _write_event(
        db,
        organization_id=1,
        event_type="provider_execution.started",
        metadata={"providerExecutionId": "job-b-different-retry-attempt"},
        offset_seconds=2,
    )

    page = resolve_provider_execution_timeline_page(db, 1, "job-a")

    assert len(page.entries) == 2
    assert all("job-b" not in str(e.eventType) for e in page.entries)


# --- evidence package: providerExecutionId fallback for pre-package-id writes -


def test_evidence_package_timeline_falls_back_to_provider_execution_id_when_package_id_not_yet_assigned(db: Session):
    # DISC-34: a storage_failed event can be written before any package row
    # (and therefore any evidencePackageId) exists — only the owning
    # attempt's id is available at that point.
    _write_event(
        db,
        organization_id=1,
        event_type="evidence_package.storage_failed",
        metadata={"providerExecutionId": "job-a"},
    )
    _write_event(
        db,
        organization_id=1,
        event_type="evidence_package.normalized",
        metadata={"evidencePackageId": "package-a"},
        offset_seconds=1,
    )
    _write_event(
        db,
        organization_id=1,
        event_type="evidence_package.normalized",
        metadata={"evidencePackageId": "package-unrelated"},
        offset_seconds=2,
    )

    page = resolve_evidence_package_timeline_page(db, 1, "package-a", "job-a")

    assert len(page.entries) == 2
    assert {e.eventType for e in page.entries} == {"evidence_package.storage_failed", "evidence_package.normalized"}
