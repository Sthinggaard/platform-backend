"""CA-04.6/CA-10 — ProcessScannerLink lifecycle, and the CA-10 wiring that
makes a link start PENDING without an approved ProcessScanScope and
self-heal to ACTIVE once one is approved.

No dedicated test file existed for this service before CA-10 — its only
prior coverage was indirect, through test_discovery_run.py's process-context
fixtures. `ProcessScannerLink` itself was also not registered anywhere in
`model_defs/__init__.py`/`models.py`, so no migration for it existed either;
both gaps were closed as part of this ticket (see
alembic/versions/20260922_process_scan_scopes.py's docstring).
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.process_scanner_link_enums import ProcessScannerLinkStatus
from src.core.database import Base
from src.core.model_defs.process_scan_scope import ProcessScanScope
from src.core.model_defs.process_scanner_link import ProcessScannerLink
from src.core.model_defs.tenant_org import Organization
from src.core.model_defs.value_streams import BusinessService, ValueStream
from src.core.models import User
from src.core.services.process_scan_scope_service import approve_process_scan_scope, create_process_scan_scope_draft, submit_process_scan_scope
from src.core.services.process_scanner_link_service import (
    activate_pending_links_for_process,
    link_scanner_to_process,
)


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    tables = [
        Organization.__table__,
        User.__table__,
        ValueStream.__table__,
        BusinessService.__table__,
        ProcessScannerLink.__table__,
        ProcessScanScope.__table__,
    ]
    for table in tables:
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=tables)
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org", country="DK"),
            User(id=1, organization_id=1, email="owner@example.com", role="member"),
            ValueStream(id="process-1", organization_id=1, name="Order to cash"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _approve_scope(db: Session, *, process_id: str = "process-1") -> None:
    scope = create_process_scan_scope_draft(db, organization_id=1, business_process_id=process_id, checks=["nmap"])
    db.flush()
    scope = submit_process_scan_scope(db, scope, submitted_by_user_id=1)
    approve_process_scan_scope(db, scope, approved_by_user_id=1)
    db.commit()


def test_link_starts_pending_with_no_approved_scope(db: Session):
    link = link_scanner_to_process(
        db, organization_id=1, scanner_instance_id="scanner-1", business_process_id="process-1"
    )
    assert link.status == ProcessScannerLinkStatus.PENDING.value


def test_link_starts_active_when_a_scope_is_already_approved(db: Session):
    _approve_scope(db)
    link = link_scanner_to_process(
        db, organization_id=1, scanner_instance_id="scanner-1", business_process_id="process-1"
    )
    assert link.status == ProcessScannerLinkStatus.ACTIVE.value


def test_approving_a_scope_self_heals_pending_links_for_that_process(db: Session):
    link = link_scanner_to_process(
        db, organization_id=1, scanner_instance_id="scanner-1", business_process_id="process-1"
    )
    db.commit()
    assert link.status == ProcessScannerLinkStatus.PENDING.value

    _approve_scope(db)
    db.refresh(link)

    assert link.status == ProcessScannerLinkStatus.ACTIVE.value


def test_approving_a_scope_does_not_touch_a_different_processs_pending_link(db: Session):
    db.add(ValueStream(id="process-2", organization_id=1, name="Payroll"))
    db.commit()
    other_link = link_scanner_to_process(
        db, organization_id=1, scanner_instance_id="scanner-1", business_process_id="process-2"
    )
    db.commit()

    _approve_scope(db, process_id="process-1")
    db.refresh(other_link)

    assert other_link.status == ProcessScannerLinkStatus.PENDING.value


def test_activate_pending_links_for_process_returns_only_the_flipped_links(db: Session):
    pending = link_scanner_to_process(
        db, organization_id=1, scanner_instance_id="scanner-1", business_process_id="process-1"
    )
    db.commit()

    flipped = activate_pending_links_for_process(db, business_process_id="process-1")

    assert [row.id for row in flipped] == [pending.id]
    assert pending.status == ProcessScannerLinkStatus.ACTIVE.value
