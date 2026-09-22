"""Step 4.1 — Discovery Orchestration Foundation: guarded state machine,
immutable snapshots, deterministic approval policy, retry/cancellation
eligibility, concurrency, and the browser-facing discovery-run routes."""

from __future__ import annotations

from datetime import datetime

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.rate_limit import discovery_execution_rate_limiter
from src.api.middleware.tenant_context import TenantContext
from src.api.routes import discovery_run as discovery_run_routes
from src.core.constants.discovery_run_enums import ALLOWED_DISCOVERY_RUN_TRANSITIONS, CheckKey, DiscoveryRunStatus
from src.core.constants.evidence_scanner_enums import ScannerInstallationMethod, ScannerNetworkType, ScannerProfile
from src.core.constants.evidence_source_enums import EvidenceSourceType
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.discovery_execution import (
    DiscoveryExecutionPlan,
    EvidencePackage,
    ExecutionStage,
    ExecutionStageDependency,
    ProviderExecution,
    WorkerLease,
)
from src.core.model_defs.discovery_run import DiscoveryRun, ScannerCommand
from src.core.model_defs.discovery_scope_proposal import DiscoveryScopeProposal
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.model_defs.evidence_scanner import ScannerDomainTarget, ScannerInstance, ScannerNetworkTarget
from src.core.model_defs.evidence_scanner import CollectorReadinessReport
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.model_defs.process_scan_scope import ProcessScanScope
from src.core.model_defs.process_scanner_link import ProcessScannerLink
from src.core.model_defs.value_streams import BusinessService, ValueStream
from src.core.models import Asset, AuditEvent, Organization, User
from src.core.services.discovery_command_service import create_command_for_run
from src.core.services.discovery_execution_command_service import create_command_for_provider_execution
from src.core.services.discovery_run_lifecycle_service import (
    DiscoveryRunValidationError as LifecycleValidationError,
    evaluate_retry_eligibility,
    request_cancellation,
    retry_discovery_run,
)
from src.core.services.discovery_run_service import (
    DiscoveryRunValidationError,
    approve_discovery_run,
    create_discovery_run,
    evaluate_approval_requirement,
    transition_discovery_run,
)
from src.core.services.evidence_scanner_service import (
    add_domain_target,
    add_network_target,
    approve_domain_target,
    approve_network_target,
    install_scanner,
    record_heartbeat,
    record_tool_validation,
    select_scan_profile,
)
from src.core.services.evidence_source_service import create_evidence_source
from src.core.services.process_scan_scope_service import (
    approve_process_scan_scope,
    create_process_scan_scope_draft,
    submit_process_scan_scope,
)
from src.core.services.process_scanner_link_service import link_scanner_to_process, pause_link
from discovery_boundary_fixture import approve_test_boundary


@pytest.fixture(autouse=True)
def _clear_discovery_rate_limiter():
    # DISC-50 — the rate limiter is a module-level singleton; without this,
    # state leaks across the many tests in this file that all act as the
    # same (org, user), tripping the limit on later, unrelated tests
    # (matches test_auth_login_access_expiry.py's own precedent for
    # auth_rate_limiter).
    discovery_execution_rate_limiter.store.clear()
    yield
    discovery_execution_rate_limiter.store.clear()


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
            DiscoveryExecutionPlan.__table__,
            ExecutionStage.__table__,
            ExecutionStageDependency.__table__,
            ProviderExecution.__table__,
            WorkerLease.__table__,
            EvidencePackage.__table__,
            # Readiness now derives technical_foundation_ready from the
            # organisation's artefacts (BUG-DISC-16), so this service reads
            # assets as well as the discovery tables.
            Asset.__table__,
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
            Organization(id=2, name="Other Org", slug="other-org", country="DK", technical_setup_owner_user_id=3),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
            User(id=2, organization_id=1, email="member@example.com", role="member"),
            User(id=3, organization_id=2, email="admin2@example.com", role="org_admin"),
            User(
                id=4,
                organization_id=1,
                email="consultant@example.com",
                role="consultant",
                access_expires_at=datetime(2099, 1, 1),
            ),
        ]
    )
    session.commit()
    yield session
    session.close()


def _ctx(user_id: int, organization_id: int = 1, role: str = "org_admin") -> TenantContext:
    return TenantContext(
        user_id=user_id, organization_id=organization_id, email="x@example.com", roles=[role], permissions=[]
    )


def _org(db: Session, organization_id: int = 1) -> Organization:
    return db.query(Organization).filter(Organization.id == organization_id).first()


def _ready_instance(
    db: Session, *, organization_id: int = 1, profile: str = ScannerProfile.SAFE_DISCOVERY.value
) -> tuple[EvidenceSource, ScannerInstance]:
    """A scanner instance with a domain target approved, a profile
    selected, tools validated, and status flipped ONLINE — everything
    create_discovery_run's preconditions check for."""
    source = create_evidence_source(
        db, organization_id=organization_id, name="Risklence Scanner", source_type=EvidenceSourceType.SCANNER
    )
    db.commit()
    result = install_scanner(db, source, name="Primary scanner", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    instance = result.instance
    record_heartbeat(db, instance)
    select_scan_profile(db, instance, profile=profile)
    record_tool_validation(db, instance, tool_status={"nmap": "available", "subfinder": "available", "nuclei": "available", "nuclei_templates": "available"})
    db.commit()
    target = add_domain_target(db, source, domain="example.com")
    approve_domain_target(db, target, approved_by_user_id=1)
    db.commit()
    # CA-05.B — an approved boundary is a discovery precondition, same as the
    # Technical Setup Owner above. Seeded with no exclusions: these tests
    # exercise run mechanics, not the boundary itself.
    approve_test_boundary(db, organization_id=organization_id, evidence_source_id=source.id)
    db.refresh(instance)
    return source, instance


def _approve_scan_scope(db: Session, *, organization_id: int, process_id: str) -> None:
    """CA-10 — create_discovery_run additionally requires an approved,
    currently-effective ProcessScanScope for a process-scoped run. Approving
    it here also self-heals any PENDING link for the same process (created
    moments earlier by link_scanner_to_process, before this scope existed)
    to ACTIVE — the real production flow, not a test-only shortcut."""
    scope = create_process_scan_scope_draft(
        db, organization_id=organization_id, business_process_id=process_id, checks=[CheckKey.NMAP.value]
    )
    db.flush()
    scope = submit_process_scan_scope(db, scope, submitted_by_user_id=1)
    approve_process_scan_scope(db, scope, approved_by_user_id=1)
    db.commit()


def _linked_process(
    db: Session, instance: ScannerInstance, *, organization_id: int = 1, process_id: str = "process-1"
) -> str:
    """CA-04.7 — an ACTIVE ProcessScannerLink for this instance, the real
    gate create_discovery_run's own business_process_id validation checks."""
    db.add(ValueStream(id=process_id, organization_id=organization_id, name="Order to cash"))
    db.commit()
    link_scanner_to_process(db, organization_id=organization_id, scanner_instance_id=instance.id, business_process_id=process_id)
    db.commit()
    _approve_scan_scope(db, organization_id=organization_id, process_id=process_id)
    return process_id


def _linked_process_and_service(
    db: Session,
    instance: ScannerInstance,
    *,
    organization_id: int = 1,
    process_id: str = "process-1",
    service_id: str = "svc-1",
) -> tuple[str, str]:
    db.add(ValueStream(id=process_id, organization_id=organization_id, name="Order to cash"))
    db.add(BusinessService(id=service_id, organization_id=organization_id, name="Checkout", value_stream_ids=[process_id]))
    db.commit()
    link_scanner_to_process(
        db,
        organization_id=organization_id,
        scanner_instance_id=instance.id,
        business_process_id=process_id,
        business_service_id=service_id,
    )
    db.commit()
    _approve_scan_scope(db, organization_id=organization_id, process_id=process_id)
    return process_id, service_id


# --- Guarded state machine -----------------------------------------------------------


def test_transition_allows_valid_transition(db: Session):
    run = DiscoveryRun(
        organization_id=1,
        evidence_source_id="x",
        scanner_instance_id="y",
        requested_by_user_id=1,
        request_source="onboarding",
        discovery_purpose="first_organisation_discovery",
        profile_snapshot={},
        target_ids=[],
        target_snapshot=[],
        status=DiscoveryRunStatus.DRAFT.value,
        current_stage="preparing",
        approval_status="not_required",
    )
    transition_discovery_run(run, DiscoveryRunStatus.VALIDATING.value)
    assert run.status == DiscoveryRunStatus.VALIDATING.value


def test_transition_rejects_invalid_transition(db: Session):
    run = DiscoveryRun(
        organization_id=1,
        evidence_source_id="x",
        scanner_instance_id="y",
        requested_by_user_id=1,
        request_source="onboarding",
        discovery_purpose="first_organisation_discovery",
        profile_snapshot={},
        target_ids=[],
        target_snapshot=[],
        status=DiscoveryRunStatus.DRAFT.value,
        current_stage="preparing",
        approval_status="not_required",
    )
    with pytest.raises(DiscoveryRunValidationError):
        transition_discovery_run(run, DiscoveryRunStatus.RUNNING.value)


@pytest.mark.parametrize(
    "terminal_status",
    ["cancelled", "partially_completed", "completed", "failed", "expired", "blocked"],
)
def test_terminal_and_blocked_statuses_have_no_outgoing_transitions(terminal_status: str):
    assert ALLOWED_DISCOVERY_RUN_TRANSITIONS[terminal_status] == frozenset()


# --- Approval policy -------------------------------------------------------------------


def test_evaluate_approval_requirement_not_required_for_safe_discovery_non_production(db: Session):
    profile = {"profileType": ScannerProfile.SAFE_DISCOVERY.value}
    result = evaluate_approval_requirement(db, 1, profile, [{"networkType": ScannerNetworkType.CORPORATE.value}])
    assert result.required is False


def test_evaluate_approval_requirement_required_for_vulnerability_profile(db: Session):
    profile = {"profileType": ScannerProfile.VULNERABILITY_ASSESSMENT.value}
    result = evaluate_approval_requirement(db, 1, profile, [])
    assert result.required is True
    assert result.eligible_approver_user_ids == [1]


def test_evaluate_approval_requirement_required_for_production_network(db: Session):
    profile = {"profileType": ScannerProfile.SAFE_DISCOVERY.value}
    result = evaluate_approval_requirement(db, 1, profile, [{"networkType": ScannerNetworkType.PRODUCTION.value}])
    assert result.required is True


# --- create_discovery_run: preconditions / blocking -------------------------------------


def test_create_discovery_run_blocks_when_no_technical_setup_owner(db: Session):
    source, instance = _ready_instance(db)
    org = _org(db)
    org.technical_setup_owner_user_id = None
    db.commit()
    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1)
    assert run.status == DiscoveryRunStatus.BLOCKED.value
    assert run.failure_code == "technical_owner_required"


def test_create_discovery_run_blocks_when_scanner_offline(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Scanner", source_type=EvidenceSourceType.SCANNER)
    db.commit()
    result = install_scanner(db, source, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    # Never heartbeat -> stays "registered", not connected.
    run = create_discovery_run(db, organization=_org(db), instance=result.instance, requested_by_user_id=1)
    assert run.status == DiscoveryRunStatus.BLOCKED.value
    assert run.failure_code == "scanner_offline"


def test_create_discovery_run_blocks_when_no_approved_scope(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Scanner", source_type=EvidenceSourceType.SCANNER)
    db.commit()
    result = install_scanner(db, source, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    record_heartbeat(db, result.instance)
    select_scan_profile(db, result.instance, profile=ScannerProfile.SAFE_DISCOVERY.value)
    record_tool_validation(db, result.instance, tool_status={"nmap": "available", "subfinder": "available"})
    db.commit()
    run = create_discovery_run(db, organization=_org(db), instance=result.instance, requested_by_user_id=1)
    assert run.status == DiscoveryRunStatus.BLOCKED.value
    assert run.failure_code == "discovery_scope_required"


def test_create_discovery_run_requires_approval_for_vulnerability_profile(db: Session):
    org = _org(db)
    source, instance = _ready_instance(db, profile=ScannerProfile.VULNERABILITY_ASSESSMENT.value)
    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1)
    assert run.status == DiscoveryRunStatus.AWAITING_APPROVAL.value
    assert run.approval_status == "pending"


def test_create_discovery_run_approved_when_all_preconditions_met(db: Session):
    org = _org(db)
    source, instance = _ready_instance(db)
    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1)
    assert run.status == DiscoveryRunStatus.APPROVED.value
    assert run.target_snapshot[0]["displayName"] == "example.com"


def test_create_discovery_run_builds_immutable_snapshot(db: Session):
    org = _org(db)
    source, instance = _ready_instance(db)
    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1)
    # Mutate the live profile after the run was created — the snapshot must not follow.
    select_scan_profile(db, instance, profile=ScannerProfile.EXTENDED_DISCOVERY.value)
    db.commit()
    assert run.profile_snapshot["profileType"] == ScannerProfile.SAFE_DISCOVERY.value


def test_create_discovery_run_idempotent_with_same_key(db: Session):
    org = _org(db)
    source, instance = _ready_instance(db)
    first = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1, idempotency_key="abc")
    db.commit()
    second = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1, idempotency_key="abc")
    assert first.id == second.id


def test_create_discovery_run_rejects_when_active_run_exists(db: Session):
    org = _org(db)
    source, instance = _ready_instance(db)
    create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1)
    db.commit()
    with pytest.raises(DiscoveryRunValidationError):
        create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1)


# --- CA-04.7: process-aware execution context --------------------------------------------


def test_create_discovery_run_records_the_linked_business_process(db: Session):
    """AC1 — a process-scoped run records exactly one Business Process."""
    org = _org(db)
    source, instance = _ready_instance(db)
    process_id = _linked_process(db, instance)

    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1, business_process_id=process_id)

    assert run.business_process_id == process_id
    assert run.business_service_id is None


def test_create_discovery_run_records_a_validated_business_service(db: Session):
    """AC2 — service-scoped execution additionally records one validated
    (via value_stream_ids, not assumed) Business Service belonging to
    that process."""
    org = _org(db)
    source, instance = _ready_instance(db)
    process_id, service_id = _linked_process_and_service(db, instance)

    run = create_discovery_run(
        db,
        organization=org,
        instance=instance,
        requested_by_user_id=1,
        business_process_id=process_id,
        business_service_id=service_id,
    )

    assert run.business_process_id == process_id
    assert run.business_service_id == service_id


def test_create_discovery_run_rejects_a_service_not_belonging_to_the_process(db: Session):
    org = _org(db)
    source, instance = _ready_instance(db)
    process_a = _linked_process(db, instance, process_id="process-a")
    db.add(ValueStream(id="process-b", organization_id=1, name="Payroll"))
    db.add(BusinessService(id="svc-b", organization_id=1, name="Payroll svc", value_stream_ids=["process-b"]))
    db.commit()

    with pytest.raises(DiscoveryRunValidationError):
        create_discovery_run(
            db,
            organization=org,
            instance=instance,
            requested_by_user_id=1,
            business_process_id=process_a,
            business_service_id="svc-b",
        )


def test_create_discovery_run_rejects_a_service_without_a_process(db: Session):
    org = _org(db)
    source, instance = _ready_instance(db)
    db.add(ValueStream(id="process-1", organization_id=1, name="Order to cash"))
    db.add(BusinessService(id="svc-1", organization_id=1, name="Checkout", value_stream_ids=["process-1"]))
    db.commit()

    with pytest.raises(DiscoveryRunValidationError):
        create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1, business_service_id="svc-1")


def test_create_discovery_run_rejects_a_process_with_no_link_at_all(db: Session):
    org = _org(db)
    source, instance = _ready_instance(db)
    db.add(ValueStream(id="process-1", organization_id=1, name="Order to cash"))
    db.commit()

    with pytest.raises(DiscoveryRunValidationError):
        create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1, business_process_id="process-1")


def test_create_discovery_run_rejects_a_process_whose_link_is_paused(db: Session):
    """The scanner was once authorized for this process, but isn't right
    now — a paused link must not silently still authorize new runs."""
    org = _org(db)
    source, instance = _ready_instance(db)
    process_id = _linked_process(db, instance)
    link = db.query(ProcessScannerLink).filter(ProcessScannerLink.business_process_id == process_id).first()
    pause_link(db, link)
    db.commit()

    with pytest.raises(DiscoveryRunValidationError):
        create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1, business_process_id=process_id)


def test_create_discovery_run_process_context_does_not_change_if_link_is_later_paused(db: Session):
    """Execution snapshots context at creation time and does not silently
    change mid-execution if the link or a future scope changes — a run
    already created stays attributed to its process even after the link
    that authorized it is paused afterwards."""
    org = _org(db)
    source, instance = _ready_instance(db)
    process_id = _linked_process(db, instance)
    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1, business_process_id=process_id)
    db.commit()

    link = db.query(ProcessScannerLink).filter(ProcessScannerLink.business_process_id == process_id).first()
    pause_link(db, link)
    db.commit()
    db.refresh(run)

    assert run.business_process_id == process_id


def test_retry_discovery_run_carries_forward_the_same_process_context(db: Session):
    org = _org(db)
    source, instance = _ready_instance(db)
    process_id = _linked_process(db, instance)
    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1, business_process_id=process_id)
    run.status = DiscoveryRunStatus.FAILED.value
    run.failure_code = "scanner_busy"
    db.commit()

    retried = retry_discovery_run(db, run, organization=org, instance=instance, retried_by_user_id=1)

    assert retried.business_process_id == process_id


def test_retry_discovery_run_rejects_if_the_process_link_was_revoked_since(db: Session):
    """The retry re-validates against the live link, rather than blindly
    trusting the original run's now-possibly-stale attribution."""
    from src.core.services.process_scanner_link_service import revoke_link

    org = _org(db)
    source, instance = _ready_instance(db)
    process_id = _linked_process(db, instance)
    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1, business_process_id=process_id)
    run.status = DiscoveryRunStatus.FAILED.value
    run.failure_code = "scanner_busy"
    db.commit()

    link = db.query(ProcessScannerLink).filter(ProcessScannerLink.business_process_id == process_id).first()
    revoke_link(db, link)
    db.commit()

    with pytest.raises(LifecycleValidationError):
        retry_discovery_run(db, run, organization=org, instance=instance, retried_by_user_id=1)


def test_create_command_for_run_snapshots_process_context_onto_the_signed_command(db: Session):
    """Job payload carries this context, auditable end-to-end — proven at
    the ScannerCommand row itself, not just the parent run."""
    org = _org(db)
    source, instance = _ready_instance(db)
    process_id, service_id = _linked_process_and_service(db, instance)
    run = create_discovery_run(
        db, organization=org, instance=instance, requested_by_user_id=1,
        business_process_id=process_id, business_service_id=service_id,
    )
    db.commit()

    command = create_command_for_run(db, run)

    assert command.business_process_id == process_id
    assert command.business_service_id == service_id
    assert command.signature  # a real HMAC over a payload that includes this context
    # CA-04.8 — AC1: a real, not cosmetic, execution-type distinction.
    assert command.command_type == "run_process_scoped_discovery"


def test_create_discovery_run_without_process_context_is_unaffected(db: Session):
    """The pre-existing, org-wide path — omitting business_process_id
    entirely must remain zero behavior change."""
    org = _org(db)
    source, instance = _ready_instance(db)

    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1)

    assert run.business_process_id is None
    assert run.business_service_id is None
    command = create_command_for_run(db, run)
    assert command.business_process_id is None
    assert command.business_service_id is None
    # CA-04.8 — the pre-existing organisation-discovery type, not removed
    # or repurposed by the new process-scoped one.
    assert command.command_type == "run_discovery"


# --- approve / cancel / retry ------------------------------------------------------------


def test_approve_discovery_run_requires_awaiting_approval_status(db: Session):
    org = _org(db)
    source, instance = _ready_instance(db)
    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1)
    assert run.status == DiscoveryRunStatus.APPROVED.value
    with pytest.raises(DiscoveryRunValidationError):
        approve_discovery_run(db, run, approved_by_user_id=1)


def test_request_cancellation_before_command_cancels_outright(db: Session):
    org = _org(db)
    source, instance = _ready_instance(db, profile=ScannerProfile.VULNERABILITY_ASSESSMENT.value)
    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1)
    assert run.status == DiscoveryRunStatus.AWAITING_APPROVAL.value
    request_cancellation(db, run, cancelled_by_user_id=1)
    assert run.status == DiscoveryRunStatus.CANCELLED.value


def test_request_cancellation_of_command_available_run_cancels_outright_and_invalidates_command(db: Session):
    """DISC-24: create_discovery_run_route no longer triggers this original
    Step 4.1 whole-run command path (it generates an execution plan
    instead) — but create_command_for_run itself is kept, not deleted, so
    this drives it directly at the service layer to keep covering it."""
    org = _org(db)
    source, instance = _ready_instance(db)
    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1)
    assert run.status == DiscoveryRunStatus.APPROVED.value
    create_command_for_run(db, run)
    assert run.status == DiscoveryRunStatus.COMMAND_AVAILABLE.value

    request_cancellation(db, run, cancelled_by_user_id=1)

    assert run.status == DiscoveryRunStatus.CANCELLED.value
    command = db.query(ScannerCommand).filter(ScannerCommand.discovery_run_id == run.id).first()
    assert command.status == "cancelled"


def test_request_cancellation_rejects_terminal_run(db: Session):
    org = _org(db)
    source, instance = _ready_instance(db, profile=ScannerProfile.VULNERABILITY_ASSESSMENT.value)
    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1)
    request_cancellation(db, run, cancelled_by_user_id=1)
    with pytest.raises(LifecycleValidationError):
        request_cancellation(db, run, cancelled_by_user_id=1)


def test_evaluate_retry_eligibility_requires_the_previous_run_to_be_over(db: Session):
    """Was "requires FAILED". Retrying creates a brand new run rather than
    resuming the old one, so the real question is whether the previous attempt
    has finished — the old rule left a cancelled or expired run with no way
    back, while the panel's own error told the user to retry the whole run."""
    running = DiscoveryRun(status=DiscoveryRunStatus.RUNNING.value, failure_code=None)
    assert evaluate_retry_eligibility(running).allowed is False
    assert evaluate_retry_eligibility(running).reason_code == "still_running"


def test_any_finished_run_can_be_retried(db: Session):
    for status in (
        DiscoveryRunStatus.COMPLETED.value,
        DiscoveryRunStatus.PARTIALLY_COMPLETED.value,
        DiscoveryRunStatus.CANCELLED.value,
        DiscoveryRunStatus.EXPIRED.value,
    ):
        run = DiscoveryRun(status=status, failure_code=None)
        assert evaluate_retry_eligibility(run).allowed is True, status


def test_evaluate_retry_eligibility_allows_retryable_code(db: Session):
    run = DiscoveryRun(status=DiscoveryRunStatus.FAILED.value, failure_code="scanner_busy")
    assert evaluate_retry_eligibility(run).allowed is True


def test_evaluate_retry_eligibility_rejects_non_retryable_code(db: Session):
    run = DiscoveryRun(status=DiscoveryRunStatus.FAILED.value, failure_code="scope_not_approved")
    assert evaluate_retry_eligibility(run).allowed is False


def test_retry_discovery_run_creates_new_linked_run(db: Session):
    org = _org(db)
    source, instance = _ready_instance(db)
    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1)
    run.status = DiscoveryRunStatus.FAILED.value
    run.failure_code = "scanner_busy"
    db.commit()

    retried = retry_discovery_run(db, run, organization=org, instance=instance, retried_by_user_id=1)
    assert retried.id != run.id
    assert retried.retry_of_discovery_run_id == run.id
    assert retried.retry_count == 1


def test_retry_discovery_run_rejects_non_failed_run(db: Session):
    org = _org(db)
    source, instance = _ready_instance(db)
    run = create_discovery_run(db, organization=org, instance=instance, requested_by_user_id=1)
    with pytest.raises(LifecycleValidationError):
        retry_discovery_run(db, run, organization=org, instance=instance, retried_by_user_id=1)


# --- Browser-facing routes -----------------------------------------------------------------


def test_create_route_requires_org_admin(db: Session):
    source, instance = _ready_instance(db)
    body = discovery_run_routes.CreateDiscoveryRunRequest()
    with pytest.raises(AuthorizationError):
        discovery_run_routes.create_discovery_run_route(source.id, body, _ctx(2, role="member"), db)


def test_create_route_returns_running_run_and_generates_execution_plan(db: Session):
    """DISC-24: a run needing no approval reaches RUNNING in the same
    call, via a real DiscoveryExecutionPlan — not the old QUEUED/
    COMMAND_AVAILABLE whole-run command path."""
    source, instance = _ready_instance(db)
    body = discovery_run_routes.CreateDiscoveryRunRequest()
    response = discovery_run_routes.create_discovery_run_route(source.id, body, _ctx(1), db)
    assert response.status == DiscoveryRunStatus.RUNNING.value
    plan = db.query(DiscoveryExecutionPlan).filter(DiscoveryExecutionPlan.discovery_run_id == response.id).first()
    assert plan is not None
    assert plan.status == "executing"


def test_create_discovery_run_route_via_api_threads_process_context_end_to_end(db: Session):
    """CA-04.8/AC2 — the whole-run route's own discovery_run.requested
    audit event, the run response, and the generated execution plan's
    EXECUTION_PLAN_AUDIT_GENERATED event all carry the same business_process_id,
    exercised through the real HTTP-shaped request body, not just the
    service function directly."""
    source, instance = _ready_instance(db)
    process_id = _linked_process(db, instance)

    response = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(business_process_id=process_id), _ctx(1), db
    )

    assert response.business_process_id == process_id
    requested_event = (
        db.query(AuditEvent)
        .filter(AuditEvent.event_type == "discovery_run.requested", AuditEvent.organization_id == 1)
        .first()
    )
    assert requested_event.metadata_json["business_process_id"] == process_id
    assert requested_event.metadata_json["slot_instance_id"] is None
    plan_generated_event = (
        db.query(AuditEvent)
        .filter(AuditEvent.event_type == "discovery_execution_plan.generated", AuditEvent.organization_id == 1)
        .first()
    )
    assert plan_generated_event.metadata_json["business_process_id"] == process_id


def test_create_route_requiring_approval_leaves_no_command(db: Session):
    source, instance = _ready_instance(db, profile=ScannerProfile.VULNERABILITY_ASSESSMENT.value)
    body = discovery_run_routes.CreateDiscoveryRunRequest()
    response = discovery_run_routes.create_discovery_run_route(source.id, body, _ctx(1), db)
    assert response.status == DiscoveryRunStatus.AWAITING_APPROVAL.value
    assert db.query(ScannerCommand).count() == 0


def test_run_response_execution_plan_is_none_before_a_plan_exists(db: Session):
    """DISC-33: graceful degradation — a run still AWAITING_APPROVAL (no
    DiscoveryExecutionPlan generated yet) must not error, just report null."""
    source, instance = _ready_instance(db, profile=ScannerProfile.VULNERABILITY_ASSESSMENT.value)
    response = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )
    assert response.status == DiscoveryRunStatus.AWAITING_APPROVAL.value
    assert response.execution_plan is None


def test_run_response_execution_plan_reports_real_dag_state(db: Session):
    """DISC-33: the backend half of the parked DISC-25 UI ticket — the
    real DAG's stages/jobs/dependencies/required flags surface on the
    existing run-read response, not just the top-level plan status."""
    source, instance = _ready_instance(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    response = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )
    assert response.status == DiscoveryRunStatus.RUNNING.value

    plan_view = response.execution_plan
    assert plan_view is not None
    assert plan_view.status == "executing"
    assert plan_view.generated_at is not None

    stage_keys = {stage.stage_key: stage for stage in plan_view.stages}
    assert set(stage_keys) == {"external_discovery", "internal_discovery", "service_fingerprinting"}
    # CA-04.3 — external_discovery now has two registered providers
    # (nmap, subfinder); internal/fingerprinting still have only nmap.
    expected_provider_ids_by_stage = {
        "external_discovery": {"nmap", "subfinder"},
        "internal_discovery": {"nmap"},
        "service_fingerprinting": {"nmap"},
    }
    for stage in plan_view.stages:
        assert stage.required is True  # DISC-30: nothing marks a stage optional yet
        assert {job.provider_id for job in stage.jobs} == expected_provider_ids_by_stage[stage.stage_key]
        for job in stage.jobs:
            assert job.attempt_number == 1

    fingerprinting = stage_keys["service_fingerprinting"]
    assert set(fingerprinting.depends_on_stage_ids) == {
        stage_keys["external_discovery"].id,
        stage_keys["internal_discovery"].id,
    }
    assert stage_keys["external_discovery"].depends_on_stage_ids == []

    # Re-fetching the same run through GET must report the identical DAG.
    fetched = discovery_run_routes.get_discovery_run_route(source.id, response.id, _ctx(1), db)
    assert {stage.stage_key for stage in fetched.execution_plan.stages} == set(stage_keys)


def test_list_route_orders_most_recent_first(db: Session):
    source, instance = _ready_instance(db)
    first = discovery_run_routes.create_discovery_run_route(source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db)
    first_run = db.query(DiscoveryRun).filter(DiscoveryRun.id == first.id).first()
    # DISC-24: a plan-based run reaches RUNNING immediately, so a genuine
    # cancellation now goes through CANCELLATION_REQUESTED (needs a real
    # scanner-side acknowledgement — cancelling an in-flight execution
    # plan is a disclosed, not-yet-built follow-up, not this test's
    # concern). Force it terminal directly; this test is only about list
    # ordering, not cancellation semantics.
    first_run.status = DiscoveryRunStatus.CANCELLED.value
    db.add(first_run)
    db.commit()
    second = discovery_run_routes.create_discovery_run_route(source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db)
    runs = discovery_run_routes.list_discovery_runs_route(source.id, _ctx(1), db)
    assert runs[0].id == second.id


def test_get_route_cross_tenant_denied(db: Session):
    source, instance = _ready_instance(db, organization_id=1)
    response = discovery_run_routes.create_discovery_run_route(source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db)
    with pytest.raises(ResourceNotFoundError):
        discovery_run_routes.get_discovery_run_route(source.id, response.id, _ctx(3, organization_id=2), db)


def test_get_route_execution_plan_never_reachable_cross_tenant(db: Session):
    """DISC-35: adversarial check specific to DISC-33's new execution_plan
    field — org 2 must not be able to reach org 1's real DAG data by any
    route, not just the top-level run fields. The plan/stage/job query in
    _execution_plan_response is only ever reached through an already
    tenant-scoped run (_require_run), so this should already be denied at
    that earlier check — confirmed explicitly here rather than assumed."""
    source, instance = _ready_instance(db, organization_id=1)
    response = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )
    assert response.execution_plan is not None  # sanity: org 1 really does have plan data to leak

    with pytest.raises(ResourceNotFoundError):
        discovery_run_routes.get_discovery_run_route(source.id, response.id, _ctx(3, organization_id=2), db)


def test_cancel_route_cross_tenant_denied(db: Session):
    """DISC-35: adversarial check — org 2's admin must not be able to
    cancel org 1's run (and therefore not its execution plan either)."""
    source, instance = _ready_instance(db, organization_id=1)
    response = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )
    with pytest.raises(ResourceNotFoundError):
        discovery_run_routes.cancel_discovery_run_route(source.id, response.id, _ctx(3, organization_id=2, role="org_admin"), db)

    # Confirm this wasn't a false negative — org 1's run/plan are untouched.
    unaffected = discovery_run_routes.get_discovery_run_route(source.id, response.id, _ctx(1), db)
    assert unaffected.status == DiscoveryRunStatus.RUNNING.value
    assert unaffected.execution_plan.status == "executing"


def test_approve_route_advances_to_running_with_execution_plan(db: Session):
    source, instance = _ready_instance(db, profile=ScannerProfile.VULNERABILITY_ASSESSMENT.value)
    created = discovery_run_routes.create_discovery_run_route(source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db)
    approved = discovery_run_routes.approve_discovery_run_route(source.id, created.id, _ctx(1), db)
    assert approved.status == DiscoveryRunStatus.RUNNING.value
    plan = db.query(DiscoveryExecutionPlan).filter(DiscoveryExecutionPlan.discovery_run_id == approved.id).first()
    assert plan is not None


def test_cancel_route_requires_org_admin(db: Session):
    source, instance = _ready_instance(db)
    created = discovery_run_routes.create_discovery_run_route(source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db)
    with pytest.raises(AuthorizationError):
        discovery_run_routes.cancel_discovery_run_route(source.id, created.id, _ctx(2, role="member"), db)


def test_cancel_route_on_a_running_run_cancels_its_execution_plan_and_pending_jobs(db: Session):
    """DISC-31: the disclosed follow-up from DISC-24 — cancelling a RUNNING
    run must propagate into its DiscoveryExecutionPlan, not just flip
    DiscoveryRun.status while the plan keeps executing underneath."""
    source, instance = _ready_instance(db)
    created = discovery_run_routes.create_discovery_run_route(source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db)
    assert created.status == DiscoveryRunStatus.RUNNING.value
    plan = db.query(DiscoveryExecutionPlan).filter(DiscoveryExecutionPlan.discovery_run_id == created.id).first()
    assert plan is not None

    cancelled = discovery_run_routes.cancel_discovery_run_route(source.id, created.id, _ctx(1), db)
    # Was CANCELLATION_REQUESTED. That assertion encoded the defect Søren hit:
    # the run stayed there forever, because the legal transition to CANCELLED
    # existed and nothing performed it. Cancelling the plan below leaves no
    # outstanding job, so the cancellation now settles. This test's own subject
    # — that cancellation propagates into the plan — is unchanged and still
    # asserted in full.
    assert cancelled.status == DiscoveryRunStatus.CANCELLED.value

    db.refresh(plan)
    assert plan.status == "cancelled"
    stages = db.query(ExecutionStage).filter(ExecutionStage.execution_plan_id == plan.id).all()
    assert stages and all(s.status == "cancelled" for s in stages)
    jobs = (
        db.query(ProviderExecution)
        .filter(ProviderExecution.execution_stage_id.in_([s.id for s in stages]))
        .all()
    )
    assert jobs and all(j.status == "cancelled" for j in jobs)


def test_cancel_route_persists_and_returns_a_structured_reason(db: Session):
    """DISC-46 — spec §16's structured cancellation reasonCode: given, it's
    persisted on the run, returned in the response, and recorded on the
    audit event (not just on the run row)."""
    source, instance = _ready_instance(db)
    created = discovery_run_routes.create_discovery_run_route(source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db)

    cancelled = discovery_run_routes.cancel_discovery_run_route(
        source.id,
        created.id,
        _ctx(1),
        db,
        discovery_run_routes.CancelDiscoveryRunRequest(reason_code="scope_changed"),
    )
    assert cancelled.cancellation_reason_code == "scope_changed"
    assert cancelled.cancellation_reason_note is None

    audit = (
        db.query(AuditEvent)
        .filter(AuditEvent.event_type == "discovery_run.cancellation_requested", AuditEvent.organization_id == 1)
        .order_by(AuditEvent.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.metadata_json["reason_code"] == "scope_changed"


def test_cancel_route_without_a_reason_still_works(db: Session):
    """A caller (or a pre-existing client build) that never supplies a
    reason must cancel exactly as before this ticket."""
    source, instance = _ready_instance(db)
    created = discovery_run_routes.create_discovery_run_route(source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db)

    cancelled = discovery_run_routes.cancel_discovery_run_route(source.id, created.id, _ctx(1), db)
    # Settles immediately now that nothing is left outstanding — see the
    # execution-plan test above for why this changed.
    assert cancelled.status == DiscoveryRunStatus.CANCELLED.value
    assert cancelled.cancellation_reason_code is None
    assert cancelled.cancellation_reason_note is None


def test_cancel_route_rejects_an_unrecognised_reason_code(db: Session):
    source, instance = _ready_instance(db)
    created = discovery_run_routes.create_discovery_run_route(source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db)

    with pytest.raises(ValidationError):
        discovery_run_routes.cancel_discovery_run_route(
            source.id,
            created.id,
            _ctx(1),
            db,
            discovery_run_routes.CancelDiscoveryRunRequest(reason_code="not_a_real_reason"),
        )


def test_cancel_route_requires_a_note_when_reason_is_other(db: Session):
    source, instance = _ready_instance(db)
    created = discovery_run_routes.create_discovery_run_route(source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db)

    with pytest.raises(ValidationError):
        discovery_run_routes.cancel_discovery_run_route(
            source.id,
            created.id,
            _ctx(1),
            db,
            discovery_run_routes.CancelDiscoveryRunRequest(reason_code="other"),
        )

    cancelled = discovery_run_routes.cancel_discovery_run_route(
        source.id,
        created.id,
        _ctx(1),
        db,
        discovery_run_routes.CancelDiscoveryRunRequest(reason_code="other", reason_note="One-off test run"),
    )
    assert cancelled.cancellation_reason_code == "other"
    assert cancelled.cancellation_reason_note == "One-off test run"


def test_cancel_route_is_rate_limited_per_org_and_user(db: Session):
    """DISC-50 (spec §82) — every mutating discovery-execution route is
    now rate limited; exercised here via cancel (simplest to hammer
    repeatedly: the run only needs to exist, not stay in any particular
    state — a call against an already-terminal run raises the ordinary
    business-logic ValidationError, which is expected noise for this
    test, not what it's checking)."""
    source, instance = _ready_instance(db)
    created = discovery_run_routes.create_discovery_run_route(source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db)

    for _ in range(discovery_run_routes._DISCOVERY_MUTATION_RATE_LIMIT):
        try:
            discovery_run_routes.cancel_discovery_run_route(source.id, created.id, _ctx(1), db)
        except ValidationError:
            pass

    with pytest.raises(HTTPException) as exc_info:
        discovery_run_routes.cancel_discovery_run_route(source.id, created.id, _ctx(1), db)
    assert exc_info.value.status_code == 429


def test_rate_limit_is_scoped_per_organization_and_user(db: Session):
    """A noisy admin in one organisation must never be able to throttle
    an admin in a different one just by key volume — the rate-limit key
    includes both organization_id and user_id, not user_id alone."""
    source, instance = _ready_instance(db, organization_id=1)
    created = discovery_run_routes.create_discovery_run_route(source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db)

    for _ in range(discovery_run_routes._DISCOVERY_MUTATION_RATE_LIMIT):
        try:
            discovery_run_routes.cancel_discovery_run_route(source.id, created.id, _ctx(1), db)
        except ValidationError:
            pass
    # org 1's admin (user 1) is now rate-limited on this action.
    with pytest.raises(HTTPException):
        discovery_run_routes.cancel_discovery_run_route(source.id, created.id, _ctx(1), db)

    # org 2's admin (user 3) still has their own, untouched budget —
    # raises the ordinary business-logic error (this run is already
    # terminal), never a 429.
    other_source, other_instance = _ready_instance(db, organization_id=2)
    other_created = discovery_run_routes.create_discovery_run_route(
        other_source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(3, organization_id=2), db
    )
    with pytest.raises(ValidationError):
        # Cancelling twice in a row hits the ordinary "already finished"
        # business rule on the second call — not what's under test, just
        # a cheap way to get a non-429, non-2xx outcome to assert against
        # without adding a second successful cancellation's worth of setup.
        discovery_run_routes.cancel_discovery_run_route(other_source.id, other_created.id, _ctx(3, organization_id=2), db)
        discovery_run_routes.cancel_discovery_run_route(other_source.id, other_created.id, _ctx(3, organization_id=2), db)


def test_discovery_readiness_route_reports_blocking_reasons(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Scanner", source_type=EvidenceSourceType.SCANNER)
    db.commit()
    result = install_scanner(db, source, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    response = discovery_run_routes.get_discovery_readiness_route(source.id, _ctx(1), db)
    assert response.ready is False
    assert "scanner_offline" in response.blocking_reasons


def test_discovery_readiness_route_ready_when_all_preconditions_met(db: Session):
    source, instance = _ready_instance(db)
    response = discovery_run_routes.get_discovery_readiness_route(source.id, _ctx(1), db)
    assert response.ready is True
    assert response.blocking_reasons == []


def test_discovery_readiness_route_previews_scope_and_profile(db: Session):
    source, instance = _ready_instance(db)
    response = discovery_run_routes.get_discovery_readiness_route(source.id, _ctx(1), db)
    assert response.target_snapshot[0]["displayName"] == "example.com"
    assert response.profile_snapshot["profileType"] == ScannerProfile.SAFE_DISCOVERY.value
    assert response.approval_required is False


def test_discovery_readiness_route_flags_approval_required_for_vulnerability_profile(db: Session):
    source, instance = _ready_instance(db, profile=ScannerProfile.VULNERABILITY_ASSESSMENT.value)
    response = discovery_run_routes.get_discovery_readiness_route(source.id, _ctx(1), db)
    assert response.approval_required is True


def test_discovery_readiness_route_reports_collector_status(db: Session):
    """DISC-52 (spec §14) — the pre-execution confirmation screen's own
    Collector preview, resolved with no plan yet (a run hasn't been
    requested), matching resolve_collector_view's own "no plan yet
    still requires a collector" default."""
    source, instance = _ready_instance(db)
    response = discovery_run_routes.get_discovery_readiness_route(source.id, _ctx(1), db)
    assert response.collector.required is True
    assert response.collector.status == "ready"  # record_heartbeat already flipped the instance ONLINE


def test_discovery_readiness_route_reports_can_start_discovery_by_role(db: Session):
    source, instance = _ready_instance(db)

    admin_response = discovery_run_routes.get_discovery_readiness_route(source.id, _ctx(1, role="org_admin"), db)
    assert admin_response.can_start_discovery is True

    member_response = discovery_run_routes.get_discovery_readiness_route(source.id, _ctx(2, role="member"), db)
    assert member_response.can_start_discovery is False


# --- Step 4.2 Part 3: DISC-38 execution-summary fields + DISC-40 job retry ---


def test_run_response_carries_the_part_3_summary_fields(db: Session):
    source, instance = _ready_instance(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    response = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )

    assert response.permissions.can_cancel is True
    assert response.permissions.can_view_diagnostics is True
    assert response.collector.required is True
    assert response.collector.status == "ready"  # instance is ONLINE (record_heartbeat in _ready_instance)
    assert response.action_required is None
    assert response.evidence.packages_received == 0
    assert response.downstream_readiness.execution_complete is False


def test_member_gets_no_mutation_permissions_but_can_view_diagnostics(db: Session):
    source, instance = _ready_instance(db)
    created = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )
    as_member = discovery_run_routes.get_discovery_run_route(source.id, created.id, _ctx(2), db)

    assert as_member.permissions.can_cancel is False
    assert as_member.permissions.can_retry is False
    assert as_member.permissions.can_view_diagnostics is True


def test_retry_job_route_spawns_a_new_job_and_reopens_the_stage(db: Session):
    source, instance = _ready_instance(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    created = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )
    external_stage = next(s for s in created.execution_plan.stages if s.stage_key == "external_discovery")
    job = external_stage.jobs[0]

    job_row = db.query(ProviderExecution).filter(ProviderExecution.id == job.id).first()
    job_row.attempt_number = 3
    job_row.status = "failed"
    job_row.failure_code = "provider_timeout"
    job_row.failure_message = "timed out"
    db.add(job_row)
    external_row = db.query(ExecutionStage).filter(ExecutionStage.id == external_stage.id).first()
    external_row.status = "failed"
    db.add(external_row)
    db.commit()

    refreshed = discovery_run_routes.get_discovery_run_route(source.id, created.id, _ctx(1), db)
    action_required = refreshed.action_required
    assert action_required is not None
    assert action_required.code == "provider_timeout"
    assert action_required.affected_stage_key == "external_discovery"
    assert action_required.can_retry is True

    retried = discovery_run_routes.retry_provider_execution_route(source.id, created.id, job.id, _ctx(1), db)

    new_stage = next(s for s in retried.execution_plan.stages if s.stage_key == "external_discovery")
    assert new_stage.status == "ready"
    # CA-04.3 — external now starts with two real jobs (nmap, subfinder);
    # retrying nmap's failed job adds a third: the new nmap sibling.
    # subfinder's own original job is untouched by this retry.
    assert len(new_stage.jobs) == 3
    original_job = next(j for j in new_stage.jobs if j.id == job.id)
    new_job = next(j for j in new_stage.jobs if j.id != job.id and j.provider_id == original_job.provider_id)
    assert original_job.status == "failed"  # never mutated
    assert new_job.status == "pending"
    assert new_job.attempt_number == 4


def test_retry_job_route_rejects_a_non_retryable_job(db: Session):
    source, instance = _ready_instance(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    created = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )
    job_id = created.execution_plan.stages[0].jobs[0].id
    job_row = db.query(ProviderExecution).filter(ProviderExecution.id == job_id).first()
    job_row.status = "failed"
    job_row.failure_code = "credentials_invalid"
    db.add(job_row)
    db.commit()

    with pytest.raises(ValidationError):
        discovery_run_routes.retry_provider_execution_route(source.id, created.id, job_id, _ctx(1), db)


def test_retry_job_route_requires_org_admin(db: Session):
    source, instance = _ready_instance(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    created = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )
    job_id = created.execution_plan.stages[0].jobs[0].id

    with pytest.raises(AuthorizationError):
        discovery_run_routes.retry_provider_execution_route(source.id, created.id, job_id, _ctx(2), db)


def test_retry_job_route_cross_tenant_denied(db: Session):
    source, instance = _ready_instance(db, organization_id=1, profile=ScannerProfile.SAFE_DISCOVERY.value)
    created = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )
    job_id = created.execution_plan.stages[0].jobs[0].id

    with pytest.raises(ResourceNotFoundError):
        discovery_run_routes.retry_provider_execution_route(source.id, created.id, job_id, _ctx(3, organization_id=2), db)


def test_timeline_route_returns_requested_event_and_is_readable_by_a_member(db: Session):
    source, instance = _ready_instance(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    created = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )

    timeline = discovery_run_routes.get_discovery_run_timeline_route(source.id, created.id, _ctx(2), db)

    event_types = {entry.event_type for entry in timeline}
    assert "discovery_run.requested" in event_types
    assert "discovery_execution_plan.generated" in event_types


def test_timeline_route_cross_tenant_denied(db: Session):
    source, instance = _ready_instance(db, organization_id=1, profile=ScannerProfile.SAFE_DISCOVERY.value)
    created = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )

    with pytest.raises(ResourceNotFoundError):
        discovery_run_routes.get_discovery_run_timeline_route(source.id, created.id, _ctx(3, organization_id=2), db)


# --- Step 4.2 Part 3 spec §15/§46: consultant may start/retry, never approve/cancel ---


def test_consultant_can_start_a_discovery_run(db: Session):
    source, instance = _ready_instance(db, profile=ScannerProfile.SAFE_DISCOVERY.value)

    created = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(4), db
    )

    assert created.status == "running"
    audit_row = (
        db.query(AuditEvent)
        .filter(AuditEvent.event_type == "discovery_run.requested", AuditEvent.actor_user_id == 4)
        .first()
    )
    assert audit_row is not None
    assert audit_row.metadata_json["actor_role"] == "consultant"


def test_consultant_can_retry_a_failed_job(db: Session):
    source, instance = _ready_instance(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    created = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )
    external_stage = next(s for s in created.execution_plan.stages if s.stage_key == "external_discovery")
    job_id = external_stage.jobs[0].id
    job_row = db.query(ProviderExecution).filter(ProviderExecution.id == job_id).first()
    job_row.status = "failed"
    job_row.failure_code = "provider_timeout"
    db.add(job_row)
    db.commit()

    retried = discovery_run_routes.retry_provider_execution_route(source.id, created.id, job_id, _ctx(4), db)

    new_stage = next(s for s in retried.execution_plan.stages if s.stage_key == "external_discovery")
    # CA-04.3 — external now starts with two real jobs (nmap, subfinder);
    # retrying one adds a third sibling.
    assert len(new_stage.jobs) == 3
    audit_row = (
        db.query(AuditEvent)
        .filter(AuditEvent.event_type == "provider_execution.retry_queued", AuditEvent.actor_user_id == 4)
        .first()
    )
    assert audit_row is not None
    assert audit_row.metadata_json["actor_role"] == "consultant"


def test_consultant_cannot_approve(db: Session):
    source, instance = _ready_instance(db, profile=ScannerProfile.VULNERABILITY_ASSESSMENT.value)
    created = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )
    assert created.status == "awaiting_approval"

    with pytest.raises(AuthorizationError):
        discovery_run_routes.approve_discovery_run_route(source.id, created.id, _ctx(4), db)


def test_consultant_cannot_cancel(db: Session):
    source, instance = _ready_instance(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    created = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )

    with pytest.raises(AuthorizationError):
        discovery_run_routes.cancel_discovery_run_route(source.id, created.id, _ctx(4), db)


def test_expired_consultant_cannot_start(db: Session):
    source, instance = _ready_instance(db, profile=ScannerProfile.SAFE_DISCOVERY.value)
    expired = db.query(User).filter(User.id == 4).first()
    expired.access_expires_at = datetime(2000, 1, 1)
    db.add(expired)
    db.commit()

    with pytest.raises(AuthorizationError):
        discovery_run_routes.create_discovery_run_route(
            source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(4), db
        )


# --- Cancelling has to actually finish (Søren's stress test, 2026-08-13) -------------------
# Observed live: the run sat in CANCELLATION_REQUESTED indefinitely — "waiting
# for the scanner to acknowledge and stop" — and pressing Cancel a second time
# surfaced the raw state-machine message
# "(cancellation_requested -> cancellation_requested)" on an executive screen.


def test_asking_to_cancel_twice_is_not_an_error(db: Session):
    from src.core.services.discovery_run_lifecycle_service import request_cancellation
    from src.core.services.discovery_run_service import transition_discovery_run

    _source, instance = _ready_instance(db)
    run = create_discovery_run(db, organization=_org(db), instance=instance, requested_by_user_id=1)
    transition_discovery_run(run, DiscoveryRunStatus.QUEUED.value)
    transition_discovery_run(run, DiscoveryRunStatus.COMMAND_AVAILABLE.value)
    transition_discovery_run(run, DiscoveryRunStatus.ACKNOWLEDGED.value)
    transition_discovery_run(run, DiscoveryRunStatus.RUNNING.value)
    db.commit()

    request_cancellation(db, run, cancelled_by_user_id=1)
    assert run.status == DiscoveryRunStatus.CANCELLATION_REQUESTED.value

    # Pressing it again must not raise the transition error at the user.
    request_cancellation(db, run, cancelled_by_user_id=1)
    assert run.status == DiscoveryRunStatus.CANCELLATION_REQUESTED.value


def test_a_cancellation_completes_once_nothing_is_still_running(db: Session):
    """A cancellation the user cannot complete is not a cancellation. The
    transition to CANCELLED was legal all along and nothing performed it."""
    from src.core.services.discovery_execution_cancellation_service import cancel_execution_plan
    from src.core.services.discovery_run_lifecycle_service import (
        finalise_cancellation_if_settled,
        request_cancellation,
    )
    from src.core.services.discovery_run_service import transition_discovery_run

    _source, instance = _ready_instance(db)
    run = create_discovery_run(db, organization=_org(db), instance=instance, requested_by_user_id=1)
    transition_discovery_run(run, DiscoveryRunStatus.QUEUED.value)
    transition_discovery_run(run, DiscoveryRunStatus.COMMAND_AVAILABLE.value)
    transition_discovery_run(run, DiscoveryRunStatus.ACKNOWLEDGED.value)
    transition_discovery_run(run, DiscoveryRunStatus.RUNNING.value)
    db.commit()

    request_cancellation(db, run, cancelled_by_user_id=1)
    db.commit()

    # No execution plan at all — nothing outstanding, so it settles immediately.
    finalise_cancellation_if_settled(db, run)

    assert run.status == DiscoveryRunStatus.CANCELLED.value
    assert run.cancelled_at is not None


def test_finalising_is_a_no_op_for_a_run_that_was_never_cancelling(db: Session):
    from src.core.services.discovery_run_lifecycle_service import (
        finalise_cancellation_if_settled,
    )

    _source, instance = _ready_instance(db)
    run = create_discovery_run(db, organization=_org(db), instance=instance, requested_by_user_id=1)
    db.commit()

    finalise_cancellation_if_settled(db, run)

    assert run.status == DiscoveryRunStatus.APPROVED.value


def test_a_consumed_retry_schedule_does_not_deadlock_a_cancellation(db: Session):
    """process_due_retries clears next_retry_at when it spawns the next attempt
    and leaves the original RETRY_SCHEDULED as the record of that attempt. Such a
    row can never run again, so counting it as outstanding left the run waiting
    forever on work that could not happen — a cancellation that cannot settle."""
    from src.core.constants.discovery_execution_enums import ProviderExecutionStatus
    from src.core.model_defs.discovery_execution import (
        DiscoveryExecutionPlan,
        ExecutionStage,
        ProviderExecution,
    )
    from src.core.services.discovery_execution_cancellation_service import cancel_execution_plan
    from src.core.services.discovery_run_lifecycle_service import (
        finalise_cancellation_if_settled,
        request_cancellation,
    )
    from src.core.services.discovery_run_service import transition_discovery_run

    source, _instance = _ready_instance(db)
    created = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == created.id).one()
    plan = db.query(DiscoveryExecutionPlan).filter(
        DiscoveryExecutionPlan.discovery_run_id == run.id
    ).first()
    stage = db.query(ExecutionStage).filter(
        ExecutionStage.execution_plan_id == plan.id
    ).first()

    stranded = ProviderExecution(
        execution_stage_id=stage.id,
        provider_id="nmap",
        status=ProviderExecutionStatus.RETRY_SCHEDULED.value,
        attempt_number=1,
        next_retry_at=None,  # schedule already consumed — this will never run
    )
    db.add(stranded)
    db.commit()

    if run.status != DiscoveryRunStatus.RUNNING.value:
        transition_discovery_run(run, DiscoveryRunStatus.RUNNING.value)
    request_cancellation(db, run, cancelled_by_user_id=1)
    # Mirrors the cancel route: requesting stops the plan's live work, then the
    # cancellation settles if nothing is left that can still run.
    cancel_execution_plan(db, run)
    db.commit()

    finalise_cancellation_if_settled(db, run)

    assert run.status == DiscoveryRunStatus.CANCELLED.value


def test_work_that_appears_after_the_cancellation_keeps_it_open(db: Session):
    """The guard must not declare a cancellation finished while something can
    still run. Cancelling the plan cancels everything outstanding at that
    moment, so the case worth pinning is a job that appears *after* it — a
    scheduler tick racing the cancellation."""
    from datetime import timedelta

    from src.core.constants.discovery_execution_enums import ProviderExecutionStatus
    from src.core.model_defs.common import utcnow
    from src.core.model_defs.discovery_execution import (
        DiscoveryExecutionPlan,
        ExecutionStage,
        ProviderExecution,
    )
    from src.core.services.discovery_execution_cancellation_service import cancel_execution_plan
    from src.core.services.discovery_run_lifecycle_service import (
        finalise_cancellation_if_settled,
        request_cancellation,
    )
    from src.core.services.discovery_run_service import transition_discovery_run

    source, _instance = _ready_instance(db)
    created = discovery_run_routes.create_discovery_run_route(
        source.id, discovery_run_routes.CreateDiscoveryRunRequest(), _ctx(1), db
    )
    run = db.query(DiscoveryRun).filter(DiscoveryRun.id == created.id).one()
    plan = db.query(DiscoveryExecutionPlan).filter(
        DiscoveryExecutionPlan.discovery_run_id == run.id
    ).first()
    stage = db.query(ExecutionStage).filter(
        ExecutionStage.execution_plan_id == plan.id
    ).first()

    if run.status != DiscoveryRunStatus.RUNNING.value:
        transition_discovery_run(run, DiscoveryRunStatus.RUNNING.value)
    request_cancellation(db, run, cancelled_by_user_id=1)
    cancel_execution_plan(db, run)
    db.commit()

    # Slips in behind the cancellation, still genuinely due.
    due = ProviderExecution(
        execution_stage_id=stage.id,
        provider_id="nmap",
        status=ProviderExecutionStatus.RETRY_SCHEDULED.value,
        attempt_number=1,
        next_retry_at=utcnow().replace(tzinfo=None) + timedelta(minutes=5),
    )
    db.add(due)
    db.commit()

    finalise_cancellation_if_settled(db, run)

    assert run.status == DiscoveryRunStatus.CANCELLATION_REQUESTED.value
