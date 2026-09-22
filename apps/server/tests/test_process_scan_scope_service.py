"""CA-10 (#50) — ProcessScanScope service layer: derive -> submit -> approve
-> (outdated | revoke | superseded), and resolving the currently-effective
scope for a process.
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

from src.core.constants.process_scan_scope_enums import ProcessScanScopeStatus
from src.core.database import Base
from src.core.model_defs.process_scan_scope import ProcessScanScope
from src.core.model_defs.process_scanner_link import ProcessScannerLink
from src.core.model_defs.tenant_org import Organization
from src.core.model_defs.value_streams import ValueStream
from src.core.models import User
from src.core.services.process_scan_scope_service import (
    ProcessScanScopeNotFoundError,
    ProcessScanScopeValidationError,
    approve_process_scan_scope,
    create_process_scan_scope_draft,
    mark_process_scan_scope_outdated,
    require_process_scan_scope,
    resolve_effective_process_scan_scope,
    revoke_process_scan_scope,
    submit_process_scan_scope,
)


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    tables = [
        Organization.__table__,
        User.__table__,
        ValueStream.__table__,
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


def _draft(db: Session, **overrides) -> ProcessScanScope:
    kwargs = dict(organization_id=1, business_process_id="process-1", checks=["nmap"])
    kwargs.update(overrides)
    scope = create_process_scan_scope_draft(db, **kwargs)
    db.flush()
    return scope


def test_create_draft_starts_at_revision_one_and_status_draft(db: Session):
    scope = _draft(db)
    assert scope.revision == 1
    assert scope.status == ProcessScanScopeStatus.DRAFT.value
    assert scope.derived_at is not None


def test_create_draft_rejects_unknown_check_key(db: Session):
    with pytest.raises(ProcessScanScopeValidationError):
        _draft(db, checks=["not_a_real_check"])


def test_second_draft_for_the_same_process_is_the_next_revision(db: Session):
    first = _draft(db)
    db.commit()
    second = _draft(db)
    assert second.revision == first.revision + 1


def test_submit_requires_draft_status(db: Session):
    scope = _draft(db)
    submit_process_scan_scope(db, scope, submitted_by_user_id=1)
    with pytest.raises(ProcessScanScopeValidationError):
        submit_process_scan_scope(db, scope, submitted_by_user_id=1)


def test_approve_requires_submitted_status(db: Session):
    scope = _draft(db)
    with pytest.raises(ProcessScanScopeValidationError):
        approve_process_scan_scope(db, scope, approved_by_user_id=1)


def test_approve_activates_and_is_resolved_as_effective(db: Session):
    scope = _draft(db)
    submit_process_scan_scope(db, scope, submitted_by_user_id=1)
    approve_process_scan_scope(db, scope, approved_by_user_id=1)

    effective = resolve_effective_process_scan_scope(db, organization_id=1, business_process_id="process-1")

    assert effective is not None
    assert effective.id == scope.id
    assert effective.status == ProcessScanScopeStatus.ACTIVE.value
    assert effective.approved_by_user_id == 1


def test_approving_a_new_revision_supersedes_the_prior_active_one(db: Session):
    first = _draft(db)
    submit_process_scan_scope(db, first, submitted_by_user_id=1)
    approve_process_scan_scope(db, first, approved_by_user_id=1)
    db.commit()

    second = _draft(db)
    submit_process_scan_scope(db, second, submitted_by_user_id=1)
    approve_process_scan_scope(db, second, approved_by_user_id=1)
    db.flush()
    db.refresh(first)

    assert first.status == ProcessScanScopeStatus.SUPERSEDED.value
    assert first.superseded_by_scope_id == second.id
    effective = resolve_effective_process_scan_scope(db, organization_id=1, business_process_id="process-1")
    assert effective.id == second.id


def test_resolve_effective_returns_none_with_no_active_scope(db: Session):
    _draft(db)  # never submitted/approved
    assert resolve_effective_process_scan_scope(db, organization_id=1, business_process_id="process-1") is None


def test_mark_outdated_requires_active_status(db: Session):
    scope = _draft(db)
    with pytest.raises(ProcessScanScopeValidationError):
        mark_process_scan_scope_outdated(db, scope, reason="dependency bundle republished")


def test_mark_outdated_does_not_remove_authorization(db: Session):
    """Under-claiming is the safe direction (same reasoning
    process_activation_readiness_service.py uses for a stale BIA snapshot):
    an outdated scope keeps authorizing until a human re-approves, rather
    than silently going dark."""
    scope = _draft(db)
    submit_process_scan_scope(db, scope, submitted_by_user_id=1)
    approve_process_scan_scope(db, scope, approved_by_user_id=1)

    mark_process_scan_scope_outdated(db, scope, reason="dependency bundle republished")

    assert scope.outdated_at is not None
    assert scope.outdated_reason == "dependency bundle republished"
    assert scope.status == ProcessScanScopeStatus.ACTIVE.value
    effective = resolve_effective_process_scan_scope(db, organization_id=1, business_process_id="process-1")
    assert effective is not None and effective.id == scope.id


def test_revoke_removes_authorization(db: Session):
    scope = _draft(db)
    submit_process_scan_scope(db, scope, submitted_by_user_id=1)
    approve_process_scan_scope(db, scope, approved_by_user_id=1)

    revoke_process_scan_scope(db, scope, revoked_by_user_id=1)

    assert scope.status == ProcessScanScopeStatus.REVOKED.value
    assert scope.revoked_by_user_id == 1
    assert resolve_effective_process_scan_scope(db, organization_id=1, business_process_id="process-1") is None


def test_revoke_twice_raises(db: Session):
    scope = _draft(db)
    submit_process_scan_scope(db, scope, submitted_by_user_id=1)
    approve_process_scan_scope(db, scope, approved_by_user_id=1)
    revoke_process_scan_scope(db, scope, revoked_by_user_id=1)
    with pytest.raises(ProcessScanScopeValidationError):
        revoke_process_scan_scope(db, scope, revoked_by_user_id=1)


def test_require_process_scan_scope_raises_when_missing(db: Session):
    with pytest.raises(ProcessScanScopeNotFoundError):
        require_process_scan_scope(db, organization_id=1, scope_id="does-not-exist")


def test_require_process_scan_scope_is_tenant_scoped(db: Session):
    db.add(Organization(id=2, name="Other", slug="other", country="DK"))
    db.commit()
    scope = _draft(db)
    with pytest.raises(ProcessScanScopeNotFoundError):
        require_process_scan_scope(db, organization_id=2, scope_id=scope.id)
