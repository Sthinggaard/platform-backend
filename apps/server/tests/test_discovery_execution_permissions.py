"""Step 4.2 Part 3 — DISC-37: shared permission projection.

Verifies the projection combines the role gate with the same run-state
eligibility discovery_run.py's own DiscoveryRunActionState already uses,
rather than exposing state alone (the real gap this ticket closes)."""

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

from src.core.constants.discovery_run_enums import DiscoveryRunStatus
from src.core.database import Base
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.models import Organization, User
from src.core.services.discovery_execution_permissions import resolve_can_start_discovery, resolve_discovery_execution_permissions


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in (Organization.__table__, User.__table__, DiscoveryRun.__table__):
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=[Organization.__table__, User.__table__, DiscoveryRun.__table__])
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org", country="DK", technical_setup_owner_user_id=1),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
            User(id=2, organization_id=1, email="member@example.com", role="member"),
            User(id=3, organization_id=1, email="inactive-admin@example.com", role="org_admin", is_active=False),
            User(
                id=4,
                organization_id=1,
                email="consultant@example.com",
                role="consultant",
                access_expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            ),
            User(
                id=5,
                organization_id=1,
                email="expired-consultant@example.com",
                role="consultant",
                access_expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            ),
        ]
    )
    session.commit()
    yield session
    session.close()


def _run(status: str, *, failure_code: str | None = None) -> DiscoveryRun:
    return DiscoveryRun(
        organization_id=1,
        evidence_source_id="src",
        scanner_instance_id="inst",
        status=status,
        current_stage="preparing",
        approval_status="not_required",
        request_source="onboarding",
        discovery_purpose="first_organisation_discovery",
        requested_by_user_id=1,
        target_ids=[],
        target_snapshot=[],
        profile_snapshot={},
        failure_code=failure_code,
    )


def test_admin_gets_full_permissions_on_a_running_run(db: Session):
    admin = db.query(User).filter(User.id == 1).first()
    permissions = resolve_discovery_execution_permissions(admin, _run(DiscoveryRunStatus.RUNNING.value))

    assert permissions.can_start is False  # not terminal yet
    assert permissions.can_cancel is True
    assert permissions.can_retry is False  # not failed
    assert permissions.can_view_diagnostics is True


def test_member_can_view_diagnostics_but_cannot_mutate(db: Session):
    member = db.query(User).filter(User.id == 2).first()
    permissions = resolve_discovery_execution_permissions(member, _run(DiscoveryRunStatus.RUNNING.value))

    assert permissions.can_start is False
    assert permissions.can_cancel is False
    assert permissions.can_retry is False
    assert permissions.can_view_diagnostics is True


def test_admin_can_retry_only_a_retryable_failure(db: Session):
    admin = db.query(User).filter(User.id == 1).first()

    retryable = resolve_discovery_execution_permissions(
        admin, _run(DiscoveryRunStatus.FAILED.value, failure_code="scanner_offline")
    )
    assert retryable.can_retry is True
    assert retryable.can_start is True  # failed is terminal

    non_retryable = resolve_discovery_execution_permissions(
        admin, _run(DiscoveryRunStatus.FAILED.value, failure_code="permission_denied")
    )
    assert non_retryable.can_retry is False
    assert non_retryable.can_start is True


def test_inactive_admin_gets_no_permissions_at_all(db: Session):
    inactive_admin = db.query(User).filter(User.id == 3).first()
    permissions = resolve_discovery_execution_permissions(inactive_admin, _run(DiscoveryRunStatus.FAILED.value, failure_code="scanner_offline"))

    assert permissions.can_start is False
    assert permissions.can_cancel is False
    assert permissions.can_retry is False
    assert permissions.can_view_diagnostics is False


def test_missing_user_gets_no_permissions(db: Session):
    permissions = resolve_discovery_execution_permissions(None, _run(DiscoveryRunStatus.RUNNING.value))

    assert permissions.can_start is False
    assert permissions.can_cancel is False
    assert permissions.can_retry is False
    assert permissions.can_view_diagnostics is False


def test_blocked_run_cannot_be_cancelled_even_by_an_admin(db: Session):
    admin = db.query(User).filter(User.id == 1).first()
    permissions = resolve_discovery_execution_permissions(admin, _run(DiscoveryRunStatus.BLOCKED.value))

    assert permissions.can_cancel is False


def test_consultant_can_view_diagnostics_start_and_retry_but_never_cancel(db: Session):
    """Step 4.2 Part 3 spec §15/§46 — a consultant may start or retry
    execution (customer-authorised implementation path = having been
    explicitly invited as a consultant into this org) but may never
    cancel — cancellation is a customer-scope decision, closer to
    "approval" than to running/retrying what's already approved, and the
    spec never lists it as a consultant capability."""
    consultant = db.query(User).filter(User.id == 4).first()

    permissions = resolve_discovery_execution_permissions(
        consultant, _run(DiscoveryRunStatus.FAILED.value, failure_code="scanner_offline")
    )

    assert permissions.can_view_diagnostics is True
    assert permissions.can_start is True  # failed is terminal
    assert permissions.can_retry is True  # scanner_offline is retryable
    assert permissions.can_cancel is False

    running = resolve_discovery_execution_permissions(consultant, _run(DiscoveryRunStatus.RUNNING.value))
    assert running.can_cancel is False


def test_expired_consultant_loses_even_read_only_access(db: Session):
    """The core DISC-44 guarantee: an already-issued session can't outlive
    its grant, because this is re-derived fresh on every request rather
    than cached from token issuance."""
    expired_consultant = db.query(User).filter(User.id == 5).first()

    permissions = resolve_discovery_execution_permissions(
        expired_consultant, _run(DiscoveryRunStatus.FAILED.value, failure_code="scanner_offline")
    )

    assert permissions.can_view_diagnostics is False
    assert permissions.can_start is False
    assert permissions.can_retry is False


def test_resolve_can_start_discovery_reuses_the_same_role_gate(db: Session):
    """DISC-52 — the pre-execution confirmation screen's own permission
    check (no DiscoveryRun exists yet to resolve the full projection
    against), same role rule as can_start/can_retry above."""
    admin = db.query(User).filter(User.id == 1).first()
    member = db.query(User).filter(User.id == 2).first()
    inactive_admin = db.query(User).filter(User.id == 3).first()
    consultant = db.query(User).filter(User.id == 4).first()
    expired_consultant = db.query(User).filter(User.id == 5).first()

    assert resolve_can_start_discovery(admin) is True
    assert resolve_can_start_discovery(member) is False
    assert resolve_can_start_discovery(inactive_admin) is False
    assert resolve_can_start_discovery(consultant) is True
    assert resolve_can_start_discovery(expired_consultant) is False
    assert resolve_can_start_discovery(None) is False
