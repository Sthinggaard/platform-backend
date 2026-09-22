"""Step 4.1 — scanner-facing command delivery/acknowledgement/status
routes: tenant-safe command retrieval, signature integrity, expiry,
idempotent acknowledgement, and stage/profile-capability validation."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.routes import discovery_command_agent as agent_routes
from src.core.constants.discovery_run_enums import DiscoveryRunStatus, DiscoveryStage
from src.core.constants.evidence_scanner_enums import ScannerInstallationMethod, ScannerProfile
from src.core.constants.evidence_source_enums import EvidenceSourceType
from src.core.model_defs.discovery_execution import (
    DiscoveryExecutionPlan,
    ExecutionStage,
    ProviderExecution,
    WorkerLease,
)
from src.core.database import Base
from src.core.exceptions import ValidationError
from src.core.model_defs.common import utcnow
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.artefact_access_lifecycle import ArtefactAccessLifecycle
from src.core.model_defs.assets_runtime import Asset
from src.core.model_defs.verification_inspection_command import VerificationInspectionCommand
from src.core.model_defs.verification_run import VerificationRun
from src.core.model_defs.discovery_run import DiscoveryRun, ScannerCommand
from src.core.model_defs.discovery_scope_proposal import DiscoveryScopeProposal
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.model_defs.evidence_scanner import (
    CollectorReadinessReport,
    ScannerCredential,
    ScannerDomainTarget,
    ScannerInstance,
    ScannerNetworkTarget,
)
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.model_defs.process_scan_scope import ProcessScanScope
from src.core.model_defs.process_scanner_link import ProcessScannerLink
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.model_defs.value_streams import BusinessService, ValueStream
from src.core.models import Organization, User
from src.core.services.discovery_command_service import create_command_for_run, verify_command_signature
from src.core.services.discovery_run_service import create_discovery_run
from src.core.services.evidence_scanner_service import (
    add_domain_target,
    approve_domain_target,
    exclude_domain_target,
    install_scanner,
    record_heartbeat,
    record_tool_validation,
    select_scan_profile,
)
from src.core.services.evidence_source_service import create_evidence_source
from discovery_boundary_fixture import approve_test_boundary
from src.core.services.process_scan_scope_service import (
    approve_process_scan_scope,
    create_process_scan_scope_draft,
    submit_process_scan_scope,
)
from src.core.services.process_scanner_link_service import link_scanner_to_process


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
            CollectorReadinessReport.__table__,
            ScannerCredential.__table__,
            ScannerDomainTarget.__table__,
            ScannerNetworkTarget.__table__,
            DiscoveryRun.__table__,
            DiscoveryScopeProposal.__table__,
            # #248 — the proposal points at a PermissionProfile now, and a
            # profile hangs off a PermissionSubject. Both must exist or every
            # test touching a proposal dies on a missing table.
            PermissionSubject.__table__,
            PermissionProfile.__table__,
            ScannerCommand.__table__,
            # CA-08.2 — the poll now also looks for deep-verification work when
            # no discovery command is waiting, so these must exist or every
            # "nothing pending" test dies on a missing table. Same reasoning as
            # the #248 note above.
            Asset.__table__,
            ArtefactAccessLifecycle.__table__,
            AccessConnector.__table__,
            VerificationRun.__table__,
            VerificationInspectionCommand.__table__,
            # The heartbeat route renews the leases a Collector is holding,
            # so these must exist or every heartbeat test dies on a missing
            # table. Same reasoning as the #248 note in the sibling fixtures.
            DiscoveryExecutionPlan.__table__,
            ExecutionStage.__table__,
            ProviderExecution.__table__,
            WorkerLease.__table__,
            AuditEvent.__table__,
            ValueStream.__table__,
            BusinessService.__table__,
            ProcessScannerLink.__table__,
            ProcessScanScope.__table__,
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
    return Request({"type": "http", "headers": headers})


def _ready_command(
    db: Session, *, profile: str = ScannerProfile.SAFE_DISCOVERY.value, business_process_id: str | None = None
) -> tuple[str, ScannerCommand, DiscoveryRun]:
    """A real, delivered-ready command: installed+online scanner, approved
    domain, a discovery run at COMMAND_AVAILABLE with a signed command."""
    source = create_evidence_source(db, organization_id=1, name="Scanner", source_type=EvidenceSourceType.SCANNER)
    db.commit()
    result = install_scanner(db, source, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    instance = result.instance
    record_heartbeat(db, instance)
    select_scan_profile(db, instance, profile=profile)
    record_tool_validation(db, instance, tool_status={"nmap": "available", "subfinder": "available", "nuclei": "available", "nuclei_templates": "available"})
    db.commit()
    target = add_domain_target(db, source, domain="example.com")
    approve_domain_target(db, target, approved_by_user_id=1)
    db.commit()
    approve_test_boundary(db, organization_id=1, evidence_source_id=source.id)

    if business_process_id is not None:
        db.add(ValueStream(id=business_process_id, organization_id=1, name="Order to cash"))
        db.commit()
        link_scanner_to_process(
            db, organization_id=1, scanner_instance_id=instance.id, business_process_id=business_process_id
        )
        db.commit()
        scope = create_process_scan_scope_draft(
            db, organization_id=1, business_process_id=business_process_id, checks=["nmap"]
        )
        db.flush()
        scope = submit_process_scan_scope(db, scope, submitted_by_user_id=1)
        approve_process_scan_scope(db, scope, approved_by_user_id=1)
        db.commit()

    organization = db.query(Organization).filter(Organization.id == 1).first()
    run = create_discovery_run(
        db, organization=organization, instance=instance, requested_by_user_id=1, business_process_id=business_process_id
    )
    if run.status == DiscoveryRunStatus.AWAITING_APPROVAL.value:
        # e.g. VULNERABILITY_ASSESSMENT — requires approval before a command exists.
        from src.core.services.discovery_run_service import approve_discovery_run

        approve_discovery_run(db, run, approved_by_user_id=1)
    assert run.status == DiscoveryRunStatus.APPROVED.value
    command = create_command_for_run(db, run)
    db.commit()
    db.refresh(instance)
    db.refresh(command)
    db.refresh(run)
    return result.activation_token, command, run


def _ready_command_with_domains(db: Session, domains: list[str]):
    """CA-04.2 — same shape as _ready_command but with N approved domain
    targets, so a test can revoke one after run creation and prove the
    others still deliver."""
    source = create_evidence_source(db, organization_id=1, name="Scanner", source_type=EvidenceSourceType.SCANNER)
    db.commit()
    result = install_scanner(db, source, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    instance = result.instance
    record_heartbeat(db, instance)
    select_scan_profile(db, instance, profile=ScannerProfile.SAFE_DISCOVERY.value)
    record_tool_validation(db, instance, tool_status={"nmap": "available", "subfinder": "available", "nuclei": "available", "nuclei_templates": "available"})
    db.commit()
    targets = []
    for domain in domains:
        target = add_domain_target(db, source, domain=domain)
        approve_domain_target(db, target, approved_by_user_id=1)
        targets.append(target)
    db.commit()
    approve_test_boundary(db, organization_id=1, evidence_source_id=source.id)

    organization = db.query(Organization).filter(Organization.id == 1).first()
    run = create_discovery_run(db, organization=organization, instance=instance, requested_by_user_id=1)
    assert run.status == DiscoveryRunStatus.APPROVED.value
    command = create_command_for_run(db, run)
    db.commit()
    db.refresh(command)
    db.refresh(run)
    for target in targets:
        db.refresh(target)
    return result.activation_token, command, run, targets


# --- commands/next -----------------------------------------------------------------------


def test_next_command_returns_none_when_no_pending(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Scanner", source_type=EvidenceSourceType.SCANNER)
    db.commit()
    result = install_scanner(db, source, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    response = agent_routes.next_command_route(_fake_request(result.activation_token), db)
    assert response.has_command is False


def test_next_command_returns_pending_and_marks_delivered(db: Session):
    token, command, run = _ready_command(db)
    response = agent_routes.next_command_route(_fake_request(token), db)
    assert response.has_command is True
    assert response.command.command_id == command.id
    assert response.command.profile["profileType"] == ScannerProfile.SAFE_DISCOVERY.value
    db.refresh(command)
    assert command.status == "delivered"


def test_next_command_envelope_carries_process_context(db: Session):
    """CA-04.7 — job payload carries this context, auditable end-to-end:
    the delivered wire envelope itself surfaces business_process_id, not
    just the underlying DiscoveryRun/ScannerCommand rows."""
    token, command, run = _ready_command(db, business_process_id="process-1")
    response = agent_routes.next_command_route(_fake_request(token), db)
    assert response.has_command is True
    assert response.command.business_process_id == "process-1"
    assert response.command.business_service_id is None


def test_next_command_envelope_has_no_process_context_for_an_unscoped_run(db: Session):
    token, command, run = _ready_command(db)
    response = agent_routes.next_command_route(_fake_request(token), db)
    assert response.has_command is True
    assert response.command.business_process_id is None


def test_next_command_excludes_other_scanner_instances(db: Session):
    token_a, command_a, _ = _ready_command(db)
    other_source = create_evidence_source(db, organization_id=1, name="Second scanner", source_type=EvidenceSourceType.SCANNER)
    db.commit()
    other_result = install_scanner(db, other_source, name="Second", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    response = agent_routes.next_command_route(_fake_request(other_result.activation_token), db)
    assert response.has_command is False


def test_next_command_skips_and_expires_stale_command(db: Session):
    token, command, run = _ready_command(db)
    command.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    response = agent_routes.next_command_route(_fake_request(token), db)
    assert response.has_command is False
    db.refresh(command)
    db.refresh(run)
    assert command.status == "expired"
    assert run.status == DiscoveryRunStatus.EXPIRED.value


def test_command_signature_is_verifiable(db: Session):
    _, command, _ = _ready_command(db)
    assert verify_command_signature(db, command) is True
    command.signature = "tampered"
    assert verify_command_signature(db, command) is False


def test_command_signing_key_is_real_per_instance_not_shared_secret(db: Session):
    """CA-04.1 — install_scanner must provision a real per-instance signing
    key (not leave commands signed by the platform's shared JWT secret,
    which the Collector never has a copy of and so could never verify)."""
    token, command, _ = _ready_command(db)
    instance = db.query(ScannerInstance).filter(ScannerInstance.id == command.scanner_instance_id).first()
    assert instance.command_signing_key_encrypted is not None

    from src.core.crypto import decrypt_command_signing_key, derive_command_signing_key

    expected_key = derive_command_signing_key(token, instance.id)
    assert decrypt_command_signing_key(instance.id, instance.command_signing_key_encrypted) == expected_key


def test_command_signing_key_differs_per_instance(db: Session):
    """Two instances' signing keys must not collide even for byte-identical
    raw tokens — the salt is the instance id, not a shared constant."""
    from src.core.crypto import derive_command_signing_key

    key_a = derive_command_signing_key("same-raw-token", "instance-a")
    key_b = derive_command_signing_key("same-raw-token", "instance-b")
    assert key_a != key_b


def test_regenerate_activation_token_rotates_signing_key(db: Session):
    from src.core.crypto import decrypt_command_signing_key
    from src.core.services.evidence_scanner_service import regenerate_activation_token

    token, command, _ = _ready_command(db)
    instance = db.query(ScannerInstance).filter(ScannerInstance.id == command.scanner_instance_id).first()
    old_encrypted_key = instance.command_signing_key_encrypted

    result = regenerate_activation_token(db, instance)
    db.commit()
    db.refresh(instance)

    assert instance.command_signing_key_encrypted != old_encrypted_key
    new_key = decrypt_command_signing_key(instance.id, instance.command_signing_key_encrypted)
    old_key = decrypt_command_signing_key(instance.id, old_encrypted_key)
    assert new_key != old_key
    assert result.activation_token != token


def test_sign_command_falls_back_to_shared_secret_when_no_instance_key(db: Session):
    """An instance that predates CA-04.1 (no stored signing key yet) must
    keep signing/verifying under the legacy shared-secret scheme rather
    than crashing or silently producing an unverifiable signature."""
    _, command, _ = _ready_command(db)
    instance = db.query(ScannerInstance).filter(ScannerInstance.id == command.scanner_instance_id).first()
    instance.command_signing_key_encrypted = None
    db.add(instance)
    db.commit()

    from src.core.services.discovery_command_service import sign_command

    resigned = sign_command(db, command)
    command.signature = resigned
    assert verify_command_signature(db, command) is True


def test_next_command_rejects_tampered_stored_signature(db: Session):
    """CA-04.1 — verify_command_signature now has a real production caller:
    get_next_command_for_scanner must reject (not deliver) a command whose
    stored signature no longer matches its payload, as a server-side
    integrity check independent of whatever the Collector checks itself."""
    token, command, run = _ready_command(db)
    command.signature = "tampered-in-storage"
    db.commit()

    response = agent_routes.next_command_route(_fake_request(token), db)

    assert response.has_command is False
    db.refresh(command)
    db.refresh(run)
    assert command.status == "rejected"
    assert command.rejection_code == "command_signature_invalid"
    assert run.status == DiscoveryRunStatus.FAILED.value
    assert run.failure_code == "command_signature_invalid"


def test_next_command_rejects_a_field_tampered_command_without_resigning(db: Session):
    """CA-04.5 — a stronger proof than the existing
    test_next_command_rejects_tampered_stored_signature (which only
    replaces the signature field with a garbage string): this mutates a
    signed field itself while leaving the stored signature untouched,
    proving the HMAC genuinely covers the command's real content, not just
    an opaque token the server happens to compare byte-for-byte."""
    token, command, run = _ready_command(db)
    assert verify_command_signature(db, command) is True
    command.command_type = "run_discovery_tampered"
    db.commit()

    response = agent_routes.next_command_route(_fake_request(token), db)

    assert response.has_command is False
    db.refresh(command)
    db.refresh(run)
    assert command.status == "rejected"
    assert command.rejection_code == "command_signature_invalid"
    assert run.status == DiscoveryRunStatus.FAILED.value
    assert run.failure_code == "command_signature_invalid"


def test_next_command_excludes_a_different_organizations_scanner(db: Session):
    """CA-04.5 — closes the one real cross-tenant gap this story's own
    repo-first finding identified for this whole-run command path:
    cross-instance-same-org isolation was already proven
    (test_next_command_excludes_other_scanner_instances), but nothing
    proved it also holds across organizations entirely."""
    _, command_a, _ = _ready_command(db)
    db.add(Organization(id=2, name="Other Org", slug="other-org", country="DK"))
    db.add(User(id=2, organization_id=2, email="other-admin@example.com", role="org_admin"))
    db.commit()
    other_org_source = create_evidence_source(
        db, organization_id=2, name="Other org scanner", source_type=EvidenceSourceType.SCANNER, owner_user_id=2
    )
    db.commit()
    other_org_result = install_scanner(
        db, other_org_source, name="Other org instance", installation_method=ScannerInstallationMethod.DOCKER.value
    )
    db.commit()

    response = agent_routes.next_command_route(_fake_request(other_org_result.activation_token), db)

    assert response.has_command is False


def test_next_command_excludes_a_target_revoked_after_run_creation(db: Session):
    """CA-04.2 — target scope is re-validated against live approval state
    at delivery, not trusted from the frozen run.target_snapshot alone: a
    target excluded after run creation must not still appear in what is
    actually delivered to the Collector."""
    token, command, run, targets = _ready_command_with_domains(db, ["one.example.com", "two.example.com"])
    exclude_domain_target(db, targets[0])
    db.commit()

    response = agent_routes.next_command_route(_fake_request(token), db)

    assert response.has_command is True
    delivered_domains = {target["approvedValue"] for target in response.command.targets}
    assert delivered_domains == {"two.example.com"}
    db.refresh(command)
    assert command.status == "delivered"


def test_next_command_rejects_when_every_target_is_revoked_after_run_creation(db: Session):
    """CA-04.2 — if nothing frozen into the run is still approved, there is
    nothing left this command could legitimately discover; it is rejected
    outright with the previously-unused TARGET_NOT_LOCALLY_APPROVED code,
    not delivered with an empty scope."""
    token, command, run, targets = _ready_command_with_domains(db, ["only.example.com"])
    exclude_domain_target(db, targets[0])
    db.commit()

    response = agent_routes.next_command_route(_fake_request(token), db)

    assert response.has_command is False
    db.refresh(command)
    db.refresh(run)
    assert command.status == "rejected"
    assert command.rejection_code == "target_not_locally_approved"
    assert run.status == DiscoveryRunStatus.FAILED.value
    assert run.failure_code == "target_not_locally_approved"


def test_acknowledge_command_rejects_when_target_revoked_since_delivery(db: Session):
    """CA-04.2 — re-checked again at acknowledgement, closing the window
    between delivery and acknowledgement: the Collector's own
    accepted=True is not the last word if nothing it was approved to touch
    is still approved by the time it reports back."""
    token, command, run, targets = _ready_command_with_domains(db, ["only.example.com"])
    response = agent_routes.next_command_route(_fake_request(token), db)
    assert response.has_command is True

    exclude_domain_target(db, targets[0])
    db.commit()

    body = agent_routes.AcknowledgeCommandRequest(accepted=True, scanner_runtime_version="0.1.0")
    ack_response = agent_routes.acknowledge_command_route(command.id, body, _fake_request(token), db)

    assert ack_response.accepted is False
    db.refresh(command)
    assert command.rejection_code == "target_not_locally_approved"


# --- acknowledge -------------------------------------------------------------------------


def test_acknowledge_command_accepted_transitions_run_to_acknowledged(db: Session):
    token, command, run = _ready_command(db)
    body = agent_routes.AcknowledgeCommandRequest(accepted=True, scanner_runtime_version="0.1.0")
    response = agent_routes.acknowledge_command_route(command.id, body, _fake_request(token), db)
    assert response.status == "acknowledged"
    db.refresh(run)
    assert run.status == DiscoveryRunStatus.ACKNOWLEDGED.value
    assert run.acknowledged_at is not None


def test_acknowledge_command_rejected_transitions_run_to_failed(db: Session):
    token, command, run = _ready_command(db)
    body = agent_routes.AcknowledgeCommandRequest(accepted=False, rejection_code="scanner_busy", rejection_message="Busy")
    response = agent_routes.acknowledge_command_route(command.id, body, _fake_request(token), db)
    assert response.status == "rejected"
    db.refresh(run)
    assert run.status == DiscoveryRunStatus.FAILED.value
    assert run.failure_code == "scanner_busy"


def test_acknowledge_command_writes_audit_event(db: Session):
    """Step 4.1D — this route wrote zero audit events before; confirms the
    real, system-actor (no user session) event is now recorded."""
    token, command, run = _ready_command(db)
    body = agent_routes.AcknowledgeCommandRequest(accepted=True)
    agent_routes.acknowledge_command_route(command.id, body, _fake_request(token), db)

    event = db.query(AuditEvent).filter(AuditEvent.event_type == "discovery_run.command_acknowledged").one()
    assert event.actor_user_id is None
    assert event.organization_id == 1
    assert event.metadata_json["commandId"] == command.id
    assert event.metadata_json["discoveryRunId"] == run.id


def test_acknowledge_command_rejected_writes_rejected_audit_event(db: Session):
    token, command, run = _ready_command(db)
    body = agent_routes.AcknowledgeCommandRequest(accepted=False, rejection_code="scanner_busy")
    agent_routes.acknowledge_command_route(command.id, body, _fake_request(token), db)

    event = db.query(AuditEvent).filter(AuditEvent.event_type == "discovery_run.command_rejected").one()
    assert event.metadata_json["rejectionCode"] == "scanner_busy"


def test_acknowledge_command_duplicate_is_idempotent(db: Session):
    token, command, run = _ready_command(db)
    body = agent_routes.AcknowledgeCommandRequest(accepted=True)
    first = agent_routes.acknowledge_command_route(command.id, body, _fake_request(token), db)
    second = agent_routes.acknowledge_command_route(command.id, body, _fake_request(token), db)
    assert first.status == second.status == "acknowledged"


def test_acknowledge_command_wrong_scanner_instance_rejected(db: Session):
    _, command, _ = _ready_command(db)
    other_source = create_evidence_source(db, organization_id=1, name="Second scanner", source_type=EvidenceSourceType.SCANNER)
    db.commit()
    other_result = install_scanner(db, other_source, name="Second", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    body = agent_routes.AcknowledgeCommandRequest(accepted=True)
    with pytest.raises(ValidationError):
        agent_routes.acknowledge_command_route(command.id, body, _fake_request(other_result.activation_token), db)


def test_acknowledge_command_rejected_for_a_different_organizations_scanner(db: Session):
    """CA-04.5 — the acknowledge-route half of the same cross-tenant gap
    closed by test_next_command_excludes_a_different_organizations_scanner."""
    _, command, _ = _ready_command(db)
    db.add(Organization(id=2, name="Other Org", slug="other-org", country="DK"))
    db.add(User(id=2, organization_id=2, email="other-admin@example.com", role="org_admin"))
    db.commit()
    other_org_source = create_evidence_source(
        db, organization_id=2, name="Other org scanner", source_type=EvidenceSourceType.SCANNER, owner_user_id=2
    )
    db.commit()
    other_org_result = install_scanner(
        db, other_org_source, name="Other org instance", installation_method=ScannerInstallationMethod.DOCKER.value
    )
    db.commit()
    body = agent_routes.AcknowledgeCommandRequest(accepted=True)
    with pytest.raises(ValidationError):
        agent_routes.acknowledge_command_route(command.id, body, _fake_request(other_org_result.activation_token), db)


def test_acknowledge_command_expired_rejected(db: Session):
    token, command, run = _ready_command(db)
    command.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    body = agent_routes.AcknowledgeCommandRequest(accepted=True)
    with pytest.raises(ValidationError):
        agent_routes.acknowledge_command_route(command.id, body, _fake_request(token), db)
    db.refresh(run)
    assert run.status == DiscoveryRunStatus.EXPIRED.value


# --- status updates ------------------------------------------------------------------------


def test_status_update_route_transitions_run(db: Session):
    token, command, run = _ready_command(db)
    agent_routes.acknowledge_command_route(command.id, agent_routes.AcknowledgeCommandRequest(accepted=True), _fake_request(token), db)
    body = agent_routes.StatusUpdateRequest(status=DiscoveryRunStatus.RUNNING.value, stage=DiscoveryStage.EXTERNAL_DISCOVERY.value)
    response = agent_routes.discovery_run_status_route(run.id, body, _fake_request(token), db)
    assert response.status == DiscoveryRunStatus.RUNNING.value
    assert response.current_stage == DiscoveryStage.EXTERNAL_DISCOVERY.value
    db.refresh(run)
    assert run.started_at is not None


def test_status_update_writes_stage_changed_audit_event(db: Session):
    token, command, run = _ready_command(db)
    agent_routes.acknowledge_command_route(command.id, agent_routes.AcknowledgeCommandRequest(accepted=True), _fake_request(token), db)
    body = agent_routes.StatusUpdateRequest(status=DiscoveryRunStatus.RUNNING.value, stage=DiscoveryStage.EXTERNAL_DISCOVERY.value)
    agent_routes.discovery_run_status_route(run.id, body, _fake_request(token), db)

    stage_event = db.query(AuditEvent).filter(AuditEvent.event_type == "discovery_run.stage_changed").one()
    assert stage_event.metadata_json["stage"] == DiscoveryStage.EXTERNAL_DISCOVERY.value
    # RUNNING has no dedicated terminal-status constant (Step 4.1's own
    # DISC-01 vocabulary never defined one) — only the stage event fires.
    assert db.query(AuditEvent).filter(AuditEvent.event_type == "discovery_run.completed").count() == 0


def test_status_update_stage_changed_audit_carries_process_context(db: Session):
    """CA-04.8 — the "process-execution lifecycle" half of AC3: this
    pre-existing DiscoveryRun audit event now also carries
    business_process_id, camelCase matching this file's own sibling keys."""
    token, command, run = _ready_command(db, business_process_id="process-1")
    agent_routes.acknowledge_command_route(command.id, agent_routes.AcknowledgeCommandRequest(accepted=True), _fake_request(token), db)
    body = agent_routes.StatusUpdateRequest(status=DiscoveryRunStatus.RUNNING.value, stage=DiscoveryStage.EXTERNAL_DISCOVERY.value)
    agent_routes.discovery_run_status_route(run.id, body, _fake_request(token), db)

    stage_event = db.query(AuditEvent).filter(AuditEvent.event_type == "discovery_run.stage_changed").one()
    assert stage_event.metadata_json["businessProcessId"] == "process-1"
    assert stage_event.metadata_json["slotInstanceId"] is None


def test_status_update_rejects_invalid_transition(db: Session):
    token, command, run = _ready_command(db)
    # Run is still COMMAND_AVAILABLE — RUNNING is not a valid direct target.
    body = agent_routes.StatusUpdateRequest(status=DiscoveryRunStatus.RUNNING.value, stage=None)
    with pytest.raises(ValidationError):
        agent_routes.discovery_run_status_route(run.id, body, _fake_request(token), db)


def test_status_update_rejects_stage_not_enabled_by_profile(db: Session):
    token, command, run = _ready_command(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    agent_routes.acknowledge_command_route(command.id, agent_routes.AcknowledgeCommandRequest(accepted=True), _fake_request(token), db)
    body = agent_routes.StatusUpdateRequest(status=None, stage=DiscoveryStage.VULNERABILITY_DISCOVERY.value)
    with pytest.raises(ValidationError):
        agent_routes.discovery_run_status_route(run.id, body, _fake_request(token), db)


def test_status_update_allows_stage_enabled_by_profile(db: Session):
    token, command, run = _ready_command(db, profile=ScannerProfile.VULNERABILITY_ASSESSMENT.value)
    agent_routes.acknowledge_command_route(command.id, agent_routes.AcknowledgeCommandRequest(accepted=True), _fake_request(token), db)
    body = agent_routes.StatusUpdateRequest(status=None, stage=DiscoveryStage.VULNERABILITY_DISCOVERY.value)
    response = agent_routes.discovery_run_status_route(run.id, body, _fake_request(token), db)
    assert response.current_stage == DiscoveryStage.VULNERABILITY_DISCOVERY.value


def test_status_update_to_completed_writes_completed_audit_event(db: Session):
    token, command, run = _ready_command(db)
    agent_routes.acknowledge_command_route(command.id, agent_routes.AcknowledgeCommandRequest(accepted=True), _fake_request(token), db)
    agent_routes.discovery_run_status_route(
        run.id,
        agent_routes.StatusUpdateRequest(status=DiscoveryRunStatus.RUNNING.value, stage=DiscoveryStage.EXTERNAL_DISCOVERY.value),
        _fake_request(token),
        db,
    )
    agent_routes.discovery_run_status_route(
        run.id,
        agent_routes.StatusUpdateRequest(status=DiscoveryRunStatus.COMPLETED.value, stage=DiscoveryStage.COMPLETE.value),
        _fake_request(token),
        db,
    )

    event = db.query(AuditEvent).filter(AuditEvent.event_type == "discovery_run.completed").one()
    assert event.metadata_json["status"] == DiscoveryRunStatus.COMPLETED.value


# --- cancellation acknowledgement ------------------------------------------------------------


def test_cancellation_acknowledgement_route(db: Session):
    token, command, run = _ready_command(db)
    agent_routes.acknowledge_command_route(command.id, agent_routes.AcknowledgeCommandRequest(accepted=True), _fake_request(token), db)
    run.status = DiscoveryRunStatus.CANCELLATION_REQUESTED.value
    db.commit()
    body = agent_routes.CancellationAcknowledgementRequest(status=DiscoveryRunStatus.CANCELLED.value)
    response = agent_routes.discovery_run_cancellation_ack_route(run.id, body, _fake_request(token), db)
    assert response.status == DiscoveryRunStatus.CANCELLED.value


def test_cancellation_acknowledgement_writes_cancelled_audit_event(db: Session):
    token, command, run = _ready_command(db)
    agent_routes.acknowledge_command_route(command.id, agent_routes.AcknowledgeCommandRequest(accepted=True), _fake_request(token), db)
    run.status = DiscoveryRunStatus.CANCELLATION_REQUESTED.value
    db.commit()
    body = agent_routes.CancellationAcknowledgementRequest(status=DiscoveryRunStatus.CANCELLED.value)
    agent_routes.discovery_run_cancellation_ack_route(run.id, body, _fake_request(token), db)

    event = db.query(AuditEvent).filter(AuditEvent.event_type == "discovery_run.cancelled").one()
    assert event.metadata_json["discoveryRunId"] == run.id
    assert event.actor_user_id is None


# --- BUG-DISC-04: one expired command must not disable a Collector -------------------------
# The old expiry path pushed the run to EXPIRED whenever a command expired,
# guarded only by "is the run already cancelled/expired". EXPIRED is illegal from
# RUNNING — the Step 4.2 pipeline's own state — so transition_discovery_run
# raised out of an agent-facing route with no handler, and commands/next returned
# 500 on every poll from then on. The Collector could not drain past the poisoned
# command, so one stale command disabled discovery for that scanner permanently.


def _running_run_with_expired_command(db: Session):
    """Walk the run to RUNNING through legal transitions rather than assigning
    the status, so the state under test is one the system can actually reach."""
    from src.core.services.discovery_run_service import transition_discovery_run

    token, command, run = _ready_command(db)
    transition_discovery_run(run, DiscoveryRunStatus.ACKNOWLEDGED.value)
    transition_discovery_run(run, DiscoveryRunStatus.RUNNING.value)
    db.commit()
    db.refresh(run)
    assert run.status == DiscoveryRunStatus.RUNNING.value

    command.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    return token, command, run


def test_polling_a_running_run_with_an_expired_command_does_not_raise(db: Session):
    token, command, run = _running_run_with_expired_command(db)

    # This is the call that used to 500, forever.
    response = agent_routes.next_command_route(_fake_request(token), db)

    assert response.has_command is False
    db.refresh(command)
    db.refresh(run)
    assert command.status == "expired"
    # The run is driven by its execution plan, not by this stale envelope —
    # expiring the command must not kill a healthy run.
    assert run.status == DiscoveryRunStatus.RUNNING.value


def test_acknowledging_an_expired_command_on_a_running_run_is_a_clean_refusal(db: Session):
    from src.core.exceptions import ValidationError

    token, command, run = _running_run_with_expired_command(db)

    # A refusal the route turns into a 4xx — not the unhandled
    # DiscoveryRunValidationError that used to escape before it and 500.
    with pytest.raises(ValidationError):
        agent_routes.acknowledge_command_route(
            command.id,
            agent_routes.AcknowledgeCommandRequest(accepted=True),
            _fake_request(token),
            db,
        )

    db.refresh(run)
    assert run.status == DiscoveryRunStatus.RUNNING.value


def test_transition_predicate_reads_the_table_rather_than_a_copy_of_it(db: Session):
    from src.core.services.discovery_run_service import can_transition_discovery_run

    _, _, run = _ready_command(db)

    # Legal from a run still waiting on its command…
    assert run.status == DiscoveryRunStatus.COMMAND_AVAILABLE.value
    assert can_transition_discovery_run(run, DiscoveryRunStatus.EXPIRED.value) is True

    # …and not once the execution pipeline owns it.
    run.status = DiscoveryRunStatus.RUNNING.value
    assert can_transition_discovery_run(run, DiscoveryRunStatus.EXPIRED.value) is False


# --- Cancelling a run, as a sequence rather than a single call ----------------------------
# Søren's stress test, and his own diagnosis: the tests here were exercising one
# arranged state and one call. These drive the order things actually happen in —
# cancel, then a scheduler tick, then a Collector still holding a command — which
# is where the failures lived.


def test_a_collector_still_holding_a_command_cannot_500_a_cancelling_run(db: Session):
    """The exact live failure: agent logs showed
    "…/acknowledge failed (500)" with the run in CANCELLATION_REQUESTED.
    ACKNOWLEDGED is illegal from there, and the route's only handler was for
    DiscoveryCommandError, so the transition error escaped as a 500 — which
    kills the agent's loop, because it cannot get past the command."""
    from src.core.exceptions import ValidationError
    from src.core.services.discovery_run_service import transition_discovery_run

    token, command, run = _ready_command(db)
    transition_discovery_run(run, DiscoveryRunStatus.ACKNOWLEDGED.value)
    transition_discovery_run(run, DiscoveryRunStatus.RUNNING.value)
    transition_discovery_run(run, DiscoveryRunStatus.CANCELLATION_REQUESTED.value)
    db.commit()

    with pytest.raises(ValidationError):  # a 4xx the agent can log and move past
        agent_routes.acknowledge_command_route(
            command.id,
            agent_routes.AcknowledgeCommandRequest(accepted=True),
            _fake_request(token),
            db,
        )

    db.refresh(run)
    db.refresh(command)
    # The run's own cancellation is not undone by a late acknowledgement.
    assert run.status == DiscoveryRunStatus.CANCELLATION_REQUESTED.value
    assert command.status == "rejected"
    assert command.rejection_code == "run_not_accepting_work"


def test_polling_never_returns_a_server_error_to_a_collector(db: Session):
    """A 500 on the poll route does not fail one request — it stops that
    Collector permanently, since the loop cannot get past whatever caused it."""
    from src.core.services.discovery_run_service import transition_discovery_run

    token, command, run = _ready_command(db)
    transition_discovery_run(run, DiscoveryRunStatus.ACKNOWLEDGED.value)
    transition_discovery_run(run, DiscoveryRunStatus.RUNNING.value)
    transition_discovery_run(run, DiscoveryRunStatus.CANCELLATION_REQUESTED.value)
    command.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()

    # Must not raise at all — the Collector simply gets "no work".
    response = agent_routes.next_command_route(_fake_request(token), db)

    assert response.has_command is False


# --- UX-DISC-06: downtime does not consume a command's window ----------------


def agent_routes_heartbeat(db: Session, token: str):
    """The agent's heartbeat, which is where the platform learns it is back."""
    from src.api.routes import scanner_agent as scanner_agent_routes

    return scanner_agent_routes.heartbeat_route(_fake_request(token), None, db)


def _instance_for_token(db: Session, token: str):
    from src.api.routes.scanner_agent import require_scanner_instance

    return require_scanner_instance(_fake_request(token), db)


def test_a_collector_returning_from_downtime_keeps_its_queued_work(db: Session):
    """The exact sequence that used to lose a run.

    Command expires at t+15m, the heartbeat goes stale at t+10m, and the panel
    tells the user their Collector is stopped. They read it, find the machine
    and start the agent at t+20m — and the very poll that proved they had fixed
    it was what discarded their work.
    """
    token, command, run = _ready_command(db)
    instance = _instance_for_token(db, token)
    command.expires_at = utcnow() - timedelta(minutes=5)
    instance.last_heartbeat_at = utcnow() - timedelta(minutes=20)
    db.commit()

    # The agent's own loop heartbeats first, then polls.
    agent_routes_heartbeat(db, token)
    response = agent_routes.next_command_route(_fake_request(token), db)

    assert response.has_command is True
    db.refresh(run)
    assert run.status != DiscoveryRunStatus.EXPIRED.value


def test_a_collector_that_never_went_offline_still_expires_its_stale_commands(db: Session):
    """The property expiry exists for is kept. An agent that is up and simply
    not taking its work does not get an indefinite reprieve."""
    token, command, run = _ready_command(db)
    instance = _instance_for_token(db, token)
    command.expires_at = utcnow() - timedelta(minutes=5)
    instance.last_heartbeat_at = utcnow() - timedelta(seconds=30)
    db.commit()

    agent_routes_heartbeat(db, token)
    response = agent_routes.next_command_route(_fake_request(token), db)

    assert response.has_command is False
    db.refresh(command)
    assert command.status == "expired"


def test_a_command_still_inside_its_window_is_not_silently_extended(db: Session):
    """Otherwise every reconnect would quietly push every deadline forward, and
    expiry would erode to nothing without anyone deciding that."""
    token, command, run = _ready_command(db)
    instance = _instance_for_token(db, token)
    command.expires_at = utcnow() + timedelta(minutes=10)
    instance.last_heartbeat_at = utcnow() - timedelta(minutes=30)
    db.commit()
    db.refresh(command)
    original = command.expires_at
    original_signature = command.signature

    agent_routes_heartbeat(db, token)

    db.refresh(command)
    assert command.expires_at == original
    # And nothing re-signed it either, which is how we know it was untouched.
    assert command.signature == original_signature


def test_work_is_not_revived_after_the_collector_has_been_gone_for_days(db: Session):
    """Reviving a week-old discovery because an agent came back is the
    unannounced scan expiry exists to prevent — the person who asked has long
    since moved on."""
    token, command, run = _ready_command(db)
    instance = _instance_for_token(db, token)
    command.expires_at = utcnow() - timedelta(days=6)
    instance.last_heartbeat_at = utcnow() - timedelta(days=7)
    db.commit()

    agent_routes_heartbeat(db, token)
    response = agent_routes.next_command_route(_fake_request(token), db)

    assert response.has_command is False
    db.refresh(command)
    assert command.status == "expired"


def test_revived_work_is_re_signed_so_it_is_not_refused_as_tampered(db: Session):
    """`expiresAt` is inside the signed payload. Moving the deadline without
    re-signing does not merely fail to help — `get_next_command_for_scanner`
    rejects a bad signature as *tampering*, so the user's run would be refused
    as altered instead of quietly expiring. Worse, and alarming."""
    token, command, run = _ready_command(db)
    instance = _instance_for_token(db, token)
    command.expires_at = utcnow() - timedelta(minutes=5)
    instance.last_heartbeat_at = utcnow() - timedelta(minutes=20)
    db.commit()

    agent_routes_heartbeat(db, token)
    db.refresh(command)

    assert verify_command_signature(db, command) is True
    assert command.status == "pending"


def test_the_signed_timestamps_are_the_ones_the_collector_receives(db: Session):
    """The defect that stopped every discovery, and why the suite missed it.

    ``_signable_payload`` signed ``issued_at.isoformat()`` — naive, no offset —
    while the API serialises those same fields through ``UtcTimestamp``, which
    appends ``+00:00`` (#281). The Collector signs what it *received*, so no
    signature could ever match and every provider failed with
    ``command_signature_invalid``. No discovery could execute, for anyone.

    Every existing signing test computed the expectation with the server's own
    ``_signable_payload``, so they agreed with themselves and never looked at
    the wire. This one compares the signed string against the serialised
    response value, which is the only place the two sides meet.
    """
    import json

    from src.api.schemas.timestamps import UtcTimestamp
    from src.core.services.discovery_command_service import _signable_payload
    from pydantic import BaseModel

    class _Wire(BaseModel):
        issued_at: UtcTimestamp
        expires_at: UtcTimestamp

    _token, command, _run = _ready_command(db)

    signed = json.loads(_signable_payload(command))
    on_the_wire = json.loads(
        _Wire(issued_at=command.issued_at, expires_at=command.expires_at).model_dump_json()
    )

    assert signed["issuedAt"] == on_the_wire["issued_at"]
    assert signed["expiresAt"] == on_the_wire["expires_at"]


def test_a_command_rejected_against_a_finished_run_does_not_stall_the_collector(db: Session):
    """BUG-DISC-04's twin, found by Søren's Collector polling in a loop.

    ``_reject_command_for_run`` guarded a hardcoded list — CANCELLED and
    EXPIRED — which omitted FAILED. A command rejected against an already-failed
    run attempted ``failed -> failed``, the transition raised out of an
    agent-facing route, and every subsequent poll returned 422. The Collector
    could not drain past it and discovery was disabled for that scanner
    permanently:

        Poll failed (422): This action is not valid for the discovery run's
        current state. (failed -> failed)

    A run that has already finished has nothing left to say about a command
    being rejected.
    """
    from src.core.constants.discovery_run_enums import ScannerCommandStatus
    from src.core.services.discovery_command_service import _reject_command_for_run

    _token, command, run = _ready_command(db)
    run.status = DiscoveryRunStatus.FAILED.value
    db.commit()

    # Must not raise. The whole defect was that it did.
    _reject_command_for_run(db, command, run, code="command_signature_invalid")
    db.commit()

    assert command.status == ScannerCommandStatus.REJECTED.value
    assert run.status == DiscoveryRunStatus.FAILED.value


def test_acknowledging_work_that_has_already_moved_on_is_refused_not_a_server_error(db: Session, monkeypatch):
    """Søren's Collector logged this every cycle, forever:

        acknowledge failed (500): {"detail":"Internal server error"}

    ProviderExecutionTransitionError was not caught by the acknowledge route, so
    acknowledging a job that had already moved on — reclaimed after a lease
    expiry, then retried — raised out of an agent-facing route and returned 500.
    The Collector re-sent the same acknowledgement on every cycle and could
    never drain past it.

    Acknowledging work somebody else has already taken is a race the protocol
    allows, not a server fault. The honest answer is a refusal the Collector can
    log and move past.
    """
    from src.core.exceptions import ValidationError

    from src.core.constants.lifecycle_enums import LifecycleDenialReason
    from src.core.services.provider_execution_lifecycle_service import (
        ProviderExecutionTransitionError,
    )

    token, command, _run = _ready_command(db)
    body = agent_routes.AcknowledgeCommandRequest(accepted=True)

    # Raised from the service the way a reclaimed-then-retried job raises it.
    # Tested at the boundary rather than by building a delegated per-job
    # command: what matters is that this exception cannot leave this route as a
    # 500, whatever inside it decided to raise.
    def _already_moved_on(*_args, **_kwargs):
        raise ProviderExecutionTransitionError(
            LifecycleDenialReason.INVALID_SOURCE_STATE, "running", "running"
        )

    monkeypatch.setattr(agent_routes, "acknowledge_command", _already_moved_on)

    with pytest.raises(ValidationError):
        agent_routes.acknowledge_command_route(command.id, body, _fake_request(token), db)
