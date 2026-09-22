"""
Pytest configuration for server tests.
Ensures the server root is on sys.path for `src` imports.
"""

import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) in sys.path:
    sys.path.remove(str(SRC))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

LOCAL_TEST_POSTGRES_URL = (
    "postgresql://risklence:risklence_dev_password@localhost:5433/risklence_test_db"
)
LOCAL_TEST_DB_HOSTS = {"localhost", "127.0.0.1", "::1", "postgres"}


def _is_safe_test_database_url(database_url: str) -> bool:
    parsed = urlparse(database_url)

    if parsed.scheme.startswith("sqlite"):
        return True

    return parsed.hostname in LOCAL_TEST_DB_HOSTS


def _bootstrap_test_environment() -> None:
    os.environ["PYTEST_RUNNING"] = "true"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["DEBUG"] = "false"
    os.environ["AUTH_JWT_SECRET"] = "risklence-dev-only-jwt-secret-do-not-use-in-prod"
    os.environ["SECRET_KEY"] = "risklence-dev-only-jwt-secret-do-not-use-in-prod"

    allow_remote = os.getenv("ALLOW_REMOTE_TEST_DATABASE", "").strip().lower() == "true"
    test_db_url = os.getenv("TEST_POSTGRES_URL", LOCAL_TEST_POSTGRES_URL)

    if not allow_remote and not _is_safe_test_database_url(test_db_url):
        raise RuntimeError(
            "Refusing to run tests against a non-local TEST_POSTGRES_URL. "
            "Set TEST_POSTGRES_URL to localhost/127.0.0.1/postgres or sqlite, "
            "or explicitly acknowledge the risk with ALLOW_REMOTE_TEST_DATABASE=true."
        )

    # Force pytest onto the dedicated local test database even if .env.local contains
    # a live DATABASE__DATABASE_URL. Tests must never hit production data by default.
    os.environ["TEST_POSTGRES_URL"] = test_db_url
    os.environ["DATABASE__DATABASE_URL"] = test_db_url


_bootstrap_test_environment()


def _snapshot_metadata_types() -> dict:
    from src.core.database import Base  # noqa: PLC0415
    return {
        (tname, col.key): col.type
        for tname, table in Base.metadata.tables.items()
        for col in table.columns
    }


_ORIGINAL_COLUMN_TYPES: dict = {}


def pytest_configure(config):  # noqa: ARG001
    _ORIGINAL_COLUMN_TYPES.update(_snapshot_metadata_types())


@pytest.fixture(autouse=True)
def _restore_metadata_column_types():
    """Restore Base.metadata column types after each test.

    SQLite-based fixtures mutate the global Base.metadata to replace JSONB/ARRAY
    columns with SQLite-compatible types. Without restoration, tests that run
    afterwards with a real Postgres engine see the wrong column types and fail
    (e.g. ix_assets_intent_gin GIN index creation fails because the column
    appears as json instead of jsonb).
    """
    yield
    from src.core.database import Base  # noqa: PLC0415
    for tname, table in Base.metadata.tables.items():
        for col in table.columns:
            original = _ORIGINAL_COLUMN_TYPES.get((tname, col.key))
            if original is not None and col.type is not original:
                col.type = original


# --- Shared database fixtures (#228) -------------------------------------
#
# Moved here from the repository root's `tests/conftest.py` when that orphan
# directory was deleted (Søren, 2026-08-18: no orphan folders, clear ownership).
# The split is what let a whole suite fall out of CI unnoticed, so there is now
# one server test root and one conftest.
#
# These build a real Postgres session; every fixture below is opt-in — nothing
# here is autouse, so suites that never request `db_session` are unaffected.

from typing import Generator
from uuid import uuid4

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from src.core.database import Base
from src.core.models import (
    CloudAsset,
    ComplianceControl,
    ComplianceFramework,
    Finding,
    Organization,
    PolicyRule,
    ScanRun,
)

@pytest.fixture(scope="session")
def test_db_url() -> str:
    """Get test database URL."""
    return os.getenv(
        "TEST_POSTGRES_URL",
        "postgresql://risklence:risklence_dev_password@127.0.0.1:5433/risklence_test_db",
    )


@pytest.fixture(scope="session")
def test_engine(test_db_url: str):  # type: ignore
    """Create test database engine."""
    engine = create_engine(test_db_url, echo=False)

    # Create all tables
    Base.metadata.create_all(bind=engine)

    yield engine

    # Drop all tables after tests
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def db_session(test_engine) -> Generator[Session, None, None]:  # type: ignore
    """Create a database session for testing."""
    connection = test_engine.connect()
    transaction = connection.begin()
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=connection)
    session = TestSessionLocal()
    session.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def restart_savepoint(session_: Session, transaction_: Session) -> None:
        if transaction_.nested and not transaction_._parent.nested:
            session_.begin_nested()

    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def sample_organization(db_session: Session) -> Organization:
    """Create a sample organization for FK relationships."""
    org = Organization(name="Test Org", slug=f"test-org-{uuid4().hex[:8]}")
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)
    return org


@pytest.fixture
def sample_framework(db_session: Session, sample_organization: Organization) -> ComplianceFramework:
    """Create a sample compliance framework."""
    framework = ComplianceFramework(
        organization_id=sample_organization.id,
        name=f"CIS Azure Foundations Benchmark {uuid4().hex[:6]}",
        version="1.5.0",
        description="CIS Azure security benchmark",
    )
    db_session.add(framework)
    db_session.commit()
    db_session.refresh(framework)
    return framework


@pytest.fixture
def sample_control(
    db_session: Session,
    sample_framework: ComplianceFramework,
    sample_organization: Organization,
) -> ComplianceControl:
    """Create a sample compliance control."""
    from src.core.models import SeverityLevel

    control = ComplianceControl(
        organization_id=sample_organization.id,
        framework_id=sample_framework.id,
        control_id="1.1",
        title="Ensure MFA is enabled",
        description="Multi-factor authentication should be enabled for all users",
        severity=SeverityLevel.HIGH,
        remediation="Enable MFA in Azure AD",
        references={"url": "https://example.com/docs"},
    )
    db_session.add(control)
    db_session.commit()
    db_session.refresh(control)
    return control


@pytest.fixture
def sample_rule(db_session: Session, sample_control: ComplianceControl) -> PolicyRule:
    """Create a sample policy rule."""
    rule = PolicyRule(
        organization_id=sample_control.organization_id,
        control_id=sample_control.id,
        name="Check MFA enabled",
        description="Verify MFA is enabled for users",
        rule_definition={
            "property": "mfaEnabled",
            "operator": "equals",
            "value": True,
        },
        cloud_provider="azure",
        resource_type="user",
        enabled=True,
    )
    db_session.add(rule)
    db_session.commit()
    db_session.refresh(rule)
    return rule


@pytest.fixture
def sample_asset(db_session: Session, sample_organization: Organization) -> CloudAsset:
    """Create a sample cloud asset."""
    asset = CloudAsset(
        organization_id=sample_organization.id,
        asset_id=f"/subscriptions/{uuid4()}/resourceGroups/test",
        asset_type="storage_account",
        cloud_provider="azure",
        region="eastus",
        name="test-storage-account",
        asset_metadata={"encryption": "enabled"},
    )
    db_session.add(asset)
    db_session.commit()
    db_session.refresh(asset)
    return asset


@pytest.fixture
def sample_scan_run(db_session: Session, sample_organization: Organization) -> ScanRun:
    """Create a sample scan run."""
    from src.core.models import ScanStatus

    scan = ScanRun(
        organization_id=sample_organization.id,
        scan_type="compliance",
        status=ScanStatus.COMPLETED,
        cloud_provider="azure",
        scope={"subscription_id": "abc123"},
        total_assets=10,
        total_findings=5,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    return scan


@pytest.fixture
def sample_finding(
    db_session: Session,
    sample_scan_run: ScanRun,
    sample_asset: CloudAsset,
    sample_rule: PolicyRule,
) -> Finding:
    """Create a sample finding."""
    from src.core.models import FindingStatus, SeverityLevel

    finding = Finding(
        organization_id=sample_scan_run.organization_id,
        scan_run_id=sample_scan_run.id,
        asset_id=sample_asset.id,
        rule_id=sample_rule.id,
        severity=SeverityLevel.HIGH,
        title="MFA not enabled",
        description="User does not have MFA enabled",
        evidence={"mfaEnabled": False},
        risk_score=8.5,
        business_impact_score=7.0,
        status=FindingStatus.OPEN,
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)
    return finding


# Environment variable fixtures
@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clean environment variables for testing."""
    env_vars = [
        "POSTGRES_HOST",
        "POSTGRES_PASSWORD",
        "AZURE_TENANT_ID",
        "AWS_ACCESS_KEY_ID",
        "JIRA_URL",
    ]
    for var in env_vars:
        monkeypatch.delenv(var, raising=False)
