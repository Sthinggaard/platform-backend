"""Scanner agent routes: per-instance credential auth, heartbeat,
tool-validation and test-scan reporting from the standalone scanner
process — never a logged-in browser user."""

from __future__ import annotations

import hashlib

import pytest
from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from datetime import timedelta

from src.api.routes import scanner_agent as scanner_agent_routes
from src.core.constants.evidence_scanner_enums import ScannerInstallationMethod
from src.core.constants.evidence_source_enums import EvidenceSourceType
from src.core.model_defs.discovery_run import DiscoveryRun
from src.core.model_defs.discovery_execution import (
    DiscoveryExecutionPlan,
    ExecutionStage,
    ProviderExecution,
    WorkerLease,
)
from src.core.database import Base
from src.core.exceptions import AuthenticationError
from src.core.model_defs.common import utcnow
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.model_defs.evidence_scanner import (
    CollectorReadinessReport,
    ScannerCredential,
    ScannerDomainTarget,
    ScannerInstance,
    ScannerNetworkTarget,
)
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.models import Organization, User
from src.core.services.evidence_scanner_service import create_credential, install_scanner, pause_credential, revoke_credential
from src.core.services.evidence_source_service import create_evidence_source


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
            User.__table__,
            EvidenceSource.__table__,
            ScannerInstance.__table__,
            ScannerDomainTarget.__table__,
            ScannerNetworkTarget.__table__,
            ScannerCredential.__table__,
            # CA-02.3 — the agent's self-check now records a readiness report
            # and audits it, so both tables are part of this route's world.
            CollectorReadinessReport.__table__,
            # The heartbeat route renews the leases a Collector is holding,
            # so these must exist or every heartbeat test dies on a missing
            # table. Same reasoning as the #248 note in the sibling fixtures.
            DiscoveryRun.__table__,
            DiscoveryExecutionPlan.__table__,
            ExecutionStage.__table__,
            ProviderExecution.__table__,
            WorkerLease.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org", country="DK", technical_setup_owner_user_id=1),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _fake_request(token: str | None) -> Request:
    headers = [(b"authorization", f"Bearer {token}".encode())] if token else []
    scope = {"type": "http", "headers": headers}
    return Request(scope)


def _installed_instance(db: Session) -> tuple[ScannerInstance, str]:
    source = create_evidence_source(
        db, organization_id=1, name="Scanner", source_type=EvidenceSourceType.SCANNER
    )
    db.commit()
    result = install_scanner(
        db, source, name="Primary scanner", installation_method=ScannerInstallationMethod.DOCKER.value
    )
    db.commit()
    return result.instance, result.activation_token


def test_heartbeat_rejects_missing_credential(db: Session):
    with pytest.raises(AuthenticationError):
        scanner_agent_routes.heartbeat_route(_fake_request(None), db=db)


def test_heartbeat_rejects_unknown_token(db: Session):
    with pytest.raises(AuthenticationError):
        scanner_agent_routes.heartbeat_route(_fake_request("not-a-real-token"), db=db)


def test_heartbeat_succeeds_with_real_token_and_flips_online(db: Session):
    instance, token = _installed_instance(db)
    assert instance.status == "registered"
    result = scanner_agent_routes.heartbeat_route(_fake_request(token), db=db)
    assert result.scanner_instance_id == instance.id
    assert result.status == "online"


def test_heartbeat_rejects_revoked_instance(db: Session):
    instance, token = _installed_instance(db)
    instance.status = "revoked"
    db.add(instance)
    db.commit()
    with pytest.raises(AuthenticationError):
        scanner_agent_routes.heartbeat_route(_fake_request(token), db=db)


def test_tools_validate_records_status_and_version(db: Session):
    instance, token = _installed_instance(db)
    result = scanner_agent_routes.tools_validate_route(
        scanner_agent_routes.ToolValidationRequest(
            tool_status={"nmap": "available", "subfinder": "available"}, scanner_version="1.0.0"
        ),
        _fake_request(token),
        db=db,
    )
    assert result.tool_status == {"nmap": "available", "subfinder": "available"}
    db.refresh(instance)
    assert instance.scanner_version == "1.0.0"
    assert instance.last_heartbeat_at is not None


def test_test_scan_records_result_and_connection_verified(db: Session):
    instance, token = _installed_instance(db)
    result = scanner_agent_routes.test_scan_route(
        scanner_agent_routes.TestScanRequest(status="completed", connection_verified=True),
        _fake_request(token),
        db=db,
    )
    assert result.test_scan_status == "completed"
    db.refresh(instance)
    assert instance.connection_verified_at is not None


def test_a_token_only_authenticates_its_own_instance(db: Session):
    instance_a, token_a = _installed_instance(db)
    source_b = create_evidence_source(
        db, organization_id=1, name="Second scanner", source_type=EvidenceSourceType.SCANNER
    )
    db.commit()
    result_b = install_scanner(
        db, source_b, name="Second", installation_method=ScannerInstallationMethod.DOCKER.value
    )
    db.commit()

    heartbeat_a = scanner_agent_routes.heartbeat_route(_fake_request(token_a), db=db)
    heartbeat_b = scanner_agent_routes.heartbeat_route(_fake_request(result_b.activation_token), db=db)
    assert heartbeat_a.scanner_instance_id == instance_a.id
    assert heartbeat_b.scanner_instance_id == result_b.instance.id
    assert heartbeat_a.scanner_instance_id != heartbeat_b.scanner_instance_id


def test_activation_token_hash_is_sha256_of_raw_token(db: Session):
    instance, token = _installed_instance(db)
    assert instance.activation_token_hash == hashlib.sha256(token.encode("utf-8")).hexdigest()


# --- Named credentials (TENANT-83/84/86): the actual enforcement point ------------------


def test_named_credential_authenticates_its_scanner(db: Session):
    instance, _ = _installed_instance(db)
    result = create_credential(db, instance, name="Backup key", validity_policy="one_month")
    db.commit()
    heartbeat = scanner_agent_routes.heartbeat_route(_fake_request(result.activation_token), db=db)
    assert heartbeat.scanner_instance_id == instance.id


def test_paused_named_credential_cannot_authenticate(db: Session):
    instance, _ = _installed_instance(db)
    result = create_credential(db, instance, name="Key", validity_policy="one_month")
    db.commit()
    pause_credential(db, result.credential)
    db.commit()
    with pytest.raises(AuthenticationError):
        scanner_agent_routes.heartbeat_route(_fake_request(result.activation_token), db=db)


def test_revoked_named_credential_cannot_authenticate(db: Session):
    instance, _ = _installed_instance(db)
    result = create_credential(db, instance, name="Key", validity_policy="one_month")
    db.commit()
    revoke_credential(db, result.credential)
    db.commit()
    with pytest.raises(AuthenticationError):
        scanner_agent_routes.heartbeat_route(_fake_request(result.activation_token), db=db)


def test_expired_named_credential_cannot_authenticate(db: Session):
    instance, _ = _installed_instance(db)
    result = create_credential(db, instance, name="Key", validity_policy="custom", custom_days=1)
    db.commit()
    result.credential.expires_at = utcnow() - timedelta(days=1)
    db.add(result.credential)
    db.commit()
    with pytest.raises(AuthenticationError):
        scanner_agent_routes.heartbeat_route(_fake_request(result.activation_token), db=db)


def test_one_time_credential_authenticates_once_then_is_rejected(db: Session):
    instance, _ = _installed_instance(db)
    result = create_credential(db, instance, name="Bootstrap key", validity_policy="one_time")
    db.commit()
    first = scanner_agent_routes.heartbeat_route(_fake_request(result.activation_token), db=db)
    assert first.scanner_instance_id == instance.id
    with pytest.raises(AuthenticationError):
        scanner_agent_routes.heartbeat_route(_fake_request(result.activation_token), db=db)


def test_named_credential_and_instance_level_token_both_still_work_independently(db: Session):
    instance, instance_token = _installed_instance(db)
    result = create_credential(db, instance, name="Second key", validity_policy="one_month")
    db.commit()

    via_instance_token = scanner_agent_routes.heartbeat_route(_fake_request(instance_token), db=db)
    via_named_credential = scanner_agent_routes.heartbeat_route(_fake_request(result.activation_token), db=db)
    assert via_instance_token.scanner_instance_id == instance.id
    assert via_named_credential.scanner_instance_id == instance.id


def test_credential_scoped_to_wrong_org_scanner_still_only_authenticates_its_own_instance(db: Session):
    instance_a, _ = _installed_instance(db)
    source_b = create_evidence_source(
        db, organization_id=1, name="Second scanner", source_type=EvidenceSourceType.SCANNER
    )
    db.commit()
    result_b = install_scanner(
        db, source_b, name="Second", installation_method=ScannerInstallationMethod.DOCKER.value
    )
    db.commit()
    credential_a = create_credential(db, instance_a, name="A key", validity_policy="one_month")
    db.commit()

    heartbeat = scanner_agent_routes.heartbeat_route(_fake_request(credential_a.activation_token), db=db)
    assert heartbeat.scanner_instance_id == instance_a.id
    assert heartbeat.scanner_instance_id != result_b.instance.id
