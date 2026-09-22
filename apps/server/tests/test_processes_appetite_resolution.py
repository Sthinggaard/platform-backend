"""BPS-38: a Business Service's appetite completeness (`ProcessServiceRow.appetite_complete`)
resolves through the RiskAppetitePolicy cascade + ServiceAppetiteReassessment overlay,
not the retired per-service `BusinessServiceAppetiteConfig` flat record."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.routes import processes
from src.core.constants import SERVICE_TIER_BUSINESS_CRITICAL
from src.core.database import Base
from src.core.model_defs.org_access import (
    OrgMandateRoleAssignment,
    OrgMandateScopeBinding,
)
from src.core.model_defs.risk_appetite_policy import RiskAppetitePolicy
from src.core.model_defs.service_appetite_reassessment import ServiceAppetiteReassessment
from src.core.models import BusinessService, DependencyBundle, Organization, ValueStream
from src.core.services.risk_appetite_resolution_service import resolve_process_appetite

_ANSWERS = {
    "downtime": 3,
    "dataLoss": 3,
    "regulatory": 3,
    "financial": 3,
    "reputational": 3,
    "security": 3,
}


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
            ValueStream.__table__,
            BusinessService.__table__,
            DependencyBundle.__table__,
            RiskAppetitePolicy.__table__,
            ServiceAppetiteReassessment.__table__,
            # A service row now names who is ACCOUNTABLE, resolved through the
            # mandate model rather than read from the legacy owner column
            # (2026-09-04), so the row builder reads these two.
            OrgMandateRoleAssignment.__table__,
            OrgMandateScopeBinding.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org"),
            ValueStream(id="process-1", organization_id=1, name="Order to cash"),
            BusinessService(
                id="svc-1",
                organization_id=1,
                name="Checkout",
                tier=SERVICE_TIER_BUSINESS_CRITICAL,
                trading_impact="",
                value_stream_ids=["process-1"],
                l1=[],
                l2=[],
                l3=[],
            ),
        ]
    )
    session.commit()
    yield session
    session.close()


def _service_row(db: Session, process: ValueStream | None) -> processes.ProcessServiceRow:
    service = db.query(BusinessService).filter(BusinessService.id == "svc-1").first()
    process_appetite = (
        resolve_process_appetite(db, organization_id=1, process_id=process.id) if process else None
    )
    return processes._build_service_row(service, db, process, process_appetite=process_appetite)


def test_appetite_incomplete_when_no_process_policy_exists(db: Session):
    process = db.query(ValueStream).filter(ValueStream.id == "process-1").first()
    row = _service_row(db, process)
    assert row.appetite_complete is False
    assert row.appetite_answers is None


def test_appetite_complete_via_organisation_fallback(db: Session):
    """The fork this task exists to fix: a service inherits from an active
    *organisation* policy even with no process-level override at all."""
    db.add(
        RiskAppetitePolicy(
            id="org-policy", organization_id=1, scope="organisation", answers=_ANSWERS, status="active", version=1
        )
    )
    db.commit()

    process = db.query(ValueStream).filter(ValueStream.id == "process-1").first()
    row = _service_row(db, process)

    assert row.appetite_complete is True
    assert row.appetite_answers == _ANSWERS
    assert row.appetite_provenance["downtime"] == "inherited"


def test_appetite_complete_via_process_override(db: Session):
    overridden = dict(_ANSWERS, downtime=1)
    db.add(
        RiskAppetitePolicy(
            id="process-policy",
            organization_id=1,
            scope="business_process",
            process_id="process-1",
            answers=overridden,
            status="active",
            version=1,
        )
    )
    db.commit()

    process = db.query(ValueStream).filter(ValueStream.id == "process-1").first()
    row = _service_row(db, process)

    assert row.appetite_complete is True
    assert row.appetite_answers["downtime"] == 1


def test_pending_reassessment_keeps_the_step_incomplete(db: Session):
    """A pending category change is an open question for the Process Owner —
    matches the frontend's existing rule (`useServiceSetup.ts`'s
    `appetiteComplete`): only "inherited"/"reassessed" count as complete,
    "pending_reassessment" does not, even though `answers` is still populated
    from the process policy underneath it."""
    db.add(
        RiskAppetitePolicy(
            id="org-policy", organization_id=1, scope="organisation", answers=_ANSWERS, status="active", version=1
        )
    )
    db.add(
        ServiceAppetiteReassessment(
            id="reassessment-1",
            organization_id=1,
            business_service_id="svc-1",
            process_id="process-1",
            category="downtime",
            requested_level=1,
            reason="Shorter MTD for this service.",
            requested_by="2",
            status="pending",
            version=1,
        )
    )
    db.commit()

    process = db.query(ValueStream).filter(ValueStream.id == "process-1").first()
    row = _service_row(db, process)

    assert row.appetite_complete is False
    assert row.appetite_answers is not None
    assert row.appetite_provenance["downtime"] == "inherited"


def test_approved_reassessment_overrides_the_process_answer(db: Session):
    db.add(
        RiskAppetitePolicy(
            id="org-policy", organization_id=1, scope="organisation", answers=_ANSWERS, status="active", version=1
        )
    )
    db.add(
        ServiceAppetiteReassessment(
            id="reassessment-1",
            organization_id=1,
            business_service_id="svc-1",
            process_id="process-1",
            category="downtime",
            requested_level=0,
            reason="Shorter MTD for this service.",
            requested_by="2",
            status="approved",
            version=1,
            reviewed_by="1",
            reviewed_at=datetime.now(timezone.utc),
            effective_from=datetime.now(timezone.utc),
            review_at=datetime.now(timezone.utc) + timedelta(days=90),
        )
    )
    db.commit()

    process = db.query(ValueStream).filter(ValueStream.id == "process-1").first()
    row = _service_row(db, process)

    assert row.appetite_complete is True
    assert row.appetite_answers["downtime"] == 0
    assert row.appetite_provenance["downtime"] == "reassessed"


def test_unassigned_service_with_no_process_has_no_appetite():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            BusinessService.__table__,
            DependencyBundle.__table__,
            RiskAppetitePolicy.__table__,
            ServiceAppetiteReassessment.__table__,
            # A service row now names who is ACCOUNTABLE, resolved through the
            # mandate model rather than read from the legacy owner column
            # (2026-09-04), so the row builder reads these two.
            OrgMandateRoleAssignment.__table__,
            OrgMandateScopeBinding.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org"),
            BusinessService(
                id="svc-orphan",
                organization_id=1,
                name="Orphaned Service",
                tier=SERVICE_TIER_BUSINESS_CRITICAL,
                trading_impact="",
                value_stream_ids=[],
                l1=[],
                l2=[],
                l3=[],
            ),
        ]
    )
    session.commit()

    service = session.query(BusinessService).filter(BusinessService.id == "svc-orphan").first()
    row = processes._build_service_row(service, session, None)

    assert row.appetite_complete is False
    assert row.appetite_answers is None
    session.close()
