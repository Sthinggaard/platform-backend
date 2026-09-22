"""Scanner lifecycle management: create-as-one-step, pause/resume,
regenerate activation token, retire, organisation-wide list. Added after
real operator testing showed the Step 3.5 wizard's single "install once
forever" slot was a dead end — this is the fix."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import process_ownership as process_ownership_routes
from src.api.routes import scanner_management as scanner_management_routes
from src.api.schemas.process_ownership import ProcessOwnershipInvitationRequest
from src.core.constants.evidence_scanner_enums import ScannerCredentialValidityPolicy, ScannerInstallationMethod, ScannerProfile
from src.core.constants.leadership_authorization_enums import LeadershipAuthorizationStatus
from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    MandateAssignmentSubjectType,
    MandateScopeType,
)
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.common import utcnow
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
from src.core.model_defs.leadership_authorization import LeadershipAuthorization
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.model_defs.process_scan_scope import ProcessScanScope
from src.core.model_defs.process_scanner_link import ProcessScannerLink
from src.core.model_defs.value_streams import BusinessService
from src.core.models import AuditEvent, Organization, ProcessOwnerAcceptance, User, ValueStream
from src.core.services.process_scan_scope_service import (
    approve_process_scan_scope,
    create_process_scan_scope_draft,
    submit_process_scan_scope,
)
from src.core.services.process_scanner_link_service import (
    ProcessScannerLinkNotFoundError,
    ProcessScannerLinkValidationError,
    list_links_for_instance,
)
from src.core.services.evidence_scanner_service import (
    EvidenceScannerValidationError,
    add_domain_target,
    approve_domain_target,
    confirm_scanner_scope,
    create_scanner,
    list_scanner_instances_for_org,
    pause_scanner,
    record_test_scan_result,
    record_tool_validation,
    regenerate_activation_token,
    resume_scanner,
    retire_scanner,
    select_scan_profile,
)


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
            ScannerCredential.__table__,
            # UX-SETUP-03 (#129) — setup readiness now reads the approved
            # discovery boundary, so the table it lives in has to exist here.
            DiscoveryScopeProposal.__table__,
            PermissionSubject.__table__,
            PermissionProfile.__table__,
            AuditEvent.__table__,
            BusinessService.__table__,
            ValueStream.__table__,
            OrgMandateRoleAssignment.__table__,
            OrgMandateScopeBinding.__table__,
            ProcessOwnerAcceptance.__table__,
            LeadershipAuthorization.__table__,
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
            User(id=4, organization_id=1, email="manager@example.com", role="manager"),
            User(id=5, organization_id=1, email="owner@example.com", role="member"),
            User(id=6, organization_id=1, email="stranger@example.com", role="member"),
            LeadershipAuthorization(
                id="leadership-authorization-1",
                organization_id=1,
                status=LeadershipAuthorizationStatus.ACTIVE.value,
                version=1,
                sponsor_user_id=1,
                approving_body="senior_management",
                authorized_scope="Full onboarding programme.",
                approved_by="1",
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


def _process_owner_context(user_id: int = 1, role: str = "member") -> TenantContext:
    return TenantContext(
        user_id=user_id, organization_id=1, email=f"user-{user_id}@example.com", roles=[role], permissions=[]
    )


def _make_business_service_with_process(
    db: Session, *, service_id: str = "svc-1", process_id: str = "process-1"
) -> BusinessService:
    db.add(ValueStream(id=process_id, organization_id=1, name="Order to cash"))
    service = BusinessService(id=service_id, organization_id=1, name="Checkout", value_stream_ids=[process_id])
    db.add(service)
    db.commit()
    return service


def _approve_scan_scope(db: Session, *, process_id: str = "process-1") -> None:
    """CA-10 — link_scanner_to_process now starts a link PENDING unless the
    process already has an approved ProcessScanScope; tests exercising a
    link's ACTIVE-only behaviour (pause, a plain "links scanner" assertion)
    need one approved first, same as the CA-10 test files' own fixtures."""
    scope = create_process_scan_scope_draft(db, organization_id=1, business_process_id=process_id, checks=["nmap"])
    db.flush()
    scope = submit_process_scan_scope(db, scope, submitted_by_user_id=1)
    approve_process_scan_scope(db, scope, approved_by_user_id=1)
    db.commit()


def _accept_process_ownership(db: Session, *, process_id: str, owner_user_id: int) -> None:
    """Reaches ProcessOwnerAcceptance(status=ACCEPTED) via the real invite/accept
    routes — same setup as test_process_ownership_routes.py's own _binding()
    helper, not hand-rolled rows, so this stays honest to the real gate.

    OrgMandateRoleAssignment is unique per (organization_id, canonical_role,
    user_id) — one user holds a single BPO mandate assignment, bound to
    however many processes via separate OrgMandateScopeBinding rows. Reuse
    an existing assignment for this user rather than creating a duplicate."""
    assignment = (
        db.query(OrgMandateRoleAssignment)
        .filter(
            OrgMandateRoleAssignment.organization_id == 1,
            OrgMandateRoleAssignment.canonical_role == CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
            OrgMandateRoleAssignment.user_id == owner_user_id,
        )
        .first()
    )
    if assignment is None:
        assignment = OrgMandateRoleAssignment(
            id=f"assignment-{owner_user_id}",
            organization_id=1,
            canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
            subject_type=MandateAssignmentSubjectType.USER.value,
            user_id=owner_user_id,
        )
        db.add(assignment)
        db.flush()
    binding = OrgMandateScopeBinding(
        id=f"binding-{process_id}",
        organization_id=1,
        scope_type=MandateScopeType.BUSINESS_PROCESS.value,
        value_stream_id=process_id,
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        role_assignment_id=assignment.id,
    )
    db.add(binding)
    db.commit()
    process_ownership_routes.create_process_ownership_invitation(
        ProcessOwnershipInvitationRequest(scope_binding_id=binding.id),
        ctx=_process_owner_context(1, "org_admin"),
        db=db,
    )
    process_ownership_routes.accept_process_owner_invitation(process_id, ctx=_process_owner_context(owner_user_id), db=db)


# --- Domain / service tests ------------------------------------------------------------


def test_create_scanner_creates_source_and_instance_in_one_call(db: Session):
    result = create_scanner(db, organization_id=1, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    assert result.instance.status == "registered"
    assert len(result.activation_token) > 20
    source = db.query(EvidenceSource).filter(EvidenceSource.id == result.instance.evidence_source_id).first()
    assert source.type == "scanner"


def test_create_scanner_twice_creates_two_independent_instances(db: Session):
    first = create_scanner(db, organization_id=1, name="Scanner A", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    second = create_scanner(db, organization_id=1, name="Scanner B", installation_method=ScannerInstallationMethod.LOCAL_CLI.value)
    db.commit()
    assert first.instance.id != second.instance.id
    assert first.instance.evidence_source_id != second.instance.evidence_source_id


def test_pause_and_resume_scanner(db: Session):
    result = create_scanner(db, organization_id=1, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    instance = result.instance

    pause_scanner(db, instance)
    assert instance.status == "paused"

    resume_scanner(db, instance)
    assert instance.status == "registered"


def test_resume_requires_paused_status(db: Session):
    result = create_scanner(db, organization_id=1, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    with pytest.raises(EvidenceScannerValidationError):
        resume_scanner(db, result.instance)


def test_pause_blocked_when_already_retired(db: Session):
    result = create_scanner(db, organization_id=1, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    retire_scanner(db, result.instance)
    with pytest.raises(EvidenceScannerValidationError):
        pause_scanner(db, result.instance)


def test_regenerate_activation_token_rotates_credential_and_clears_connection_proof(db: Session):
    result = create_scanner(db, organization_id=1, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    instance = result.instance
    original_hash = instance.activation_token_hash
    instance.last_heartbeat_at = None  # never connected in this test, matches the real lost-token scenario

    new_result = regenerate_activation_token(db, instance)

    assert new_result.activation_token != result.activation_token
    assert instance.activation_token_hash != original_hash
    assert instance.status == "registered"
    assert instance.connection_verified_at is None


def test_regenerate_activation_token_preserves_scope_and_profile(db: Session):
    from src.core.services.evidence_scanner_service import (
        add_domain_target,
        approve_domain_target,
        select_scan_profile,
    )

    result = create_scanner(db, organization_id=1, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    instance = result.instance
    source = db.query(EvidenceSource).filter(EvidenceSource.id == instance.evidence_source_id).first()
    target = add_domain_target(db, source, domain="example.com")
    approve_domain_target(db, target, approved_by_user_id=1)
    select_scan_profile(db, instance, profile="safe_discovery")
    db.commit()

    regenerate_activation_token(db, instance)

    assert instance.scan_profile == "safe_discovery"
    approved = db.query(ScannerDomainTarget).filter(ScannerDomainTarget.id == target.id).first()
    assert approved.status == "approved"


def test_regenerate_activation_token_blocked_when_paused(db: Session):
    result = create_scanner(db, organization_id=1, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    pause_scanner(db, result.instance)
    with pytest.raises(EvidenceScannerValidationError):
        regenerate_activation_token(db, result.instance)


def test_retire_scanner_is_idempotent_guard(db: Session):
    result = create_scanner(db, organization_id=1, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    retire_scanner(db, result.instance)
    assert result.instance.status == "retired"
    with pytest.raises(EvidenceScannerValidationError):
        retire_scanner(db, result.instance)


def test_list_scanner_instances_for_org_orders_most_recent_first(db: Session):
    first = create_scanner(db, organization_id=1, name="First", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    second = create_scanner(db, organization_id=1, name="Second", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    instances = list_scanner_instances_for_org(db, 1)
    assert instances[0].id == second.instance.id
    assert instances[1].id == first.instance.id


def test_list_scanner_instances_scoped_to_organization(db: Session):
    create_scanner(db, organization_id=1, name="Org1 scanner", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    create_scanner(db, organization_id=2, name="Org2 scanner", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    assert len(list_scanner_instances_for_org(db, 1)) == 1
    assert len(list_scanner_instances_for_org(db, 2)) == 1


# --- Route tests -------------------------------------------------------------------------


def test_create_scanner_route_requires_org_admin(db: Session):
    body = scanner_management_routes.CreateScannerRequest(name="Primary", installation_method=ScannerInstallationMethod.DOCKER)
    with pytest.raises(AuthorizationError):
        scanner_management_routes.create_scanner_route(body, _ctx(2, role="member"), db)


def test_create_scanner_route_returns_token_once(db: Session):
    body = scanner_management_routes.CreateScannerRequest(name="Primary", installation_method=ScannerInstallationMethod.DOCKER)
    response = scanner_management_routes.create_scanner_route(body, _ctx(1), db)
    assert len(response.activation_token) > 20
    assert response.instance.status == "registered"


def test_list_scanners_route_includes_approved_scope_counts(db: Session):
    from src.core.services.evidence_scanner_service import add_domain_target, approve_domain_target

    body = scanner_management_routes.CreateScannerRequest(name="Primary", installation_method=ScannerInstallationMethod.DOCKER)
    created = scanner_management_routes.create_scanner_route(body, _ctx(1), db)
    db.commit()
    source = db.query(EvidenceSource).filter(EvidenceSource.id == created.instance.evidence_source_id).first()
    target = add_domain_target(db, source, domain="example.com")
    approve_domain_target(db, target, approved_by_user_id=1)
    db.commit()

    scanners = scanner_management_routes.list_scanners_route(_ctx(1), db)
    assert scanners[0].approved_domain_count == 1


def test_get_scanner_route_returns_owner_and_approved_targets(db: Session):
    from src.core.services.evidence_scanner_service import add_network_target, approve_network_target
    from src.core.services.evidence_source_service import assign_owner

    db.add(User(id=7, organization_id=1, email="priya@example.com", first_name="Priya", last_name="Shah", role="org_admin"))
    db.commit()

    body = scanner_management_routes.CreateScannerRequest(name="Checkout & Payments", installation_method=ScannerInstallationMethod.DOCKER)
    created = scanner_management_routes.create_scanner_route(body, _ctx(1), db)
    db.commit()
    source = db.query(EvidenceSource).filter(EvidenceSource.id == created.instance.evidence_source_id).first()
    assign_owner(db, source, owner_user_id=7)

    domain = add_domain_target(db, source, domain="example.com")
    approve_domain_target(db, domain, approved_by_user_id=1)
    network_result = add_network_target(db, source, cidr="10.20.0.0/24", name="Corporate network", network_type="corporate")
    approve_network_target(db, network_result.target, approved_by_user_id=1)
    db.commit()

    detail = scanner_management_routes.get_scanner_route(created.instance.id, _ctx(1), db)
    assert detail.owner_name == "Priya Shah"
    assert detail.approved_domains == ["example.com"]
    assert len(detail.approved_networks) == 1
    assert detail.approved_networks[0].cidr == "10.20.0.0/24"
    assert detail.approved_networks[0].name == "Corporate network"
    assert detail.approved_networks[0].network_type == "corporate"


def test_get_scanner_route_owner_name_falls_back_to_email(db: Session):
    from src.core.services.evidence_source_service import assign_owner

    body = scanner_management_routes.CreateScannerRequest(name="Primary", installation_method=ScannerInstallationMethod.DOCKER)
    created = scanner_management_routes.create_scanner_route(body, _ctx(1), db)
    db.commit()
    source = db.query(EvidenceSource).filter(EvidenceSource.id == created.instance.evidence_source_id).first()
    assign_owner(db, source, owner_user_id=1)
    db.commit()

    detail = scanner_management_routes.get_scanner_route(created.instance.id, _ctx(1), db)
    assert detail.owner_name == "admin@example.com"


def test_get_scanner_route_defaults_owner_to_technical_setup_owner_with_no_approved_targets(db: Session):
    body = scanner_management_routes.CreateScannerRequest(name="Primary", installation_method=ScannerInstallationMethod.DOCKER)
    created = scanner_management_routes.create_scanner_route(body, _ctx(1), db)
    db.commit()

    detail = scanner_management_routes.get_scanner_route(created.instance.id, _ctx(1), db)
    assert detail.owner_name == "admin@example.com"  # org 1's technical_setup_owner_user_id (fixture) — the create-time default
    assert detail.approved_domains == []
    assert detail.approved_networks == []


def test_get_scanner_route_cross_tenant_denied(db: Session):
    body = scanner_management_routes.CreateScannerRequest(name="Primary", installation_method=ScannerInstallationMethod.DOCKER)
    created = scanner_management_routes.create_scanner_route(body, _ctx(1), db)
    with pytest.raises(ResourceNotFoundError):
        scanner_management_routes.get_scanner_route(created.instance.id, _ctx(3, organization_id=2), db)


def test_get_scanner_route_unknown_id_raises_not_found(db: Session):
    with pytest.raises(ResourceNotFoundError):
        scanner_management_routes.get_scanner_route("does-not-exist", _ctx(1), db)


def test_full_lifecycle_round_trip_via_routes(db: Session):
    body = scanner_management_routes.CreateScannerRequest(name="Primary", installation_method=ScannerInstallationMethod.DOCKER)
    created = scanner_management_routes.create_scanner_route(body, _ctx(1), db)
    instance_id = created.instance.id

    paused = scanner_management_routes.pause_scanner_route(instance_id, _ctx(1), db)
    assert paused.status == "paused"

    resumed = scanner_management_routes.resume_scanner_route(instance_id, _ctx(1), db)
    assert resumed.status == "registered"

    regenerated = scanner_management_routes.regenerate_token_route(instance_id, _ctx(1), db)
    assert regenerated.activation_token != created.activation_token

    revoked = scanner_management_routes.revoke_scanner_route(instance_id, _ctx(1), db)
    assert revoked.status == "revoked"

    retired = scanner_management_routes.retire_scanner_route(instance_id, _ctx(1), db)
    assert retired.status == "retired"


def test_pause_route_cross_tenant_denied(db: Session):
    body = scanner_management_routes.CreateScannerRequest(name="Primary", installation_method=ScannerInstallationMethod.DOCKER)
    created = scanner_management_routes.create_scanner_route(body, _ctx(1), db)
    with pytest.raises(ResourceNotFoundError):
        scanner_management_routes.pause_scanner_route(created.instance.id, _ctx(3, organization_id=2), db)


def test_retire_route_requires_org_admin(db: Session):
    body = scanner_management_routes.CreateScannerRequest(name="Primary", installation_method=ScannerInstallationMethod.DOCKER)
    created = scanner_management_routes.create_scanner_route(body, _ctx(1), db)
    with pytest.raises(AuthorizationError):
        scanner_management_routes.retire_scanner_route(created.instance.id, _ctx(2, role="member"), db)


def test_freshly_created_scanner_is_not_ready(db: Session):
    body = scanner_management_routes.CreateScannerRequest(name="Primary", installation_method=ScannerInstallationMethod.DOCKER)
    created = scanner_management_routes.create_scanner_route(body, _ctx(1), db)
    assert created.instance.ready is False


def test_scanner_walked_through_full_setup_is_ready_in_list(db: Session):
    body = scanner_management_routes.CreateScannerRequest(name="Primary", installation_method=ScannerInstallationMethod.DOCKER)
    created = scanner_management_routes.create_scanner_route(body, _ctx(1), db)
    db.commit()
    source = db.query(EvidenceSource).filter(EvidenceSource.id == created.instance.evidence_source_id).first()
    instance = db.query(ScannerInstance).filter(ScannerInstance.id == created.instance.id).first()

    target = add_domain_target(db, source, domain="example.com")
    approve_domain_target(db, target, approved_by_user_id=1)
    select_scan_profile(db, instance, profile=ScannerProfile.SAFE_DISCOVERY.value)
    db.commit()
    confirm_scanner_scope(db, source, instance, confirmed_by_user_id=1)
    db.commit()
    record_tool_validation(db, instance, tool_status={"nmap": "available", "subfinder": "available"})
    db.commit()
    record_test_scan_result(db, instance, status="completed", connection_verified=True)
    db.commit()
    # UX-SETUP-03 (#129) — the last step. Without an approved boundary the
    # scanner is not ready, because discovery would refuse to start.
    subject = PermissionSubject(organization_id=1, subject_kind="discovery_scope_proposal")
    db.add(subject)
    db.flush()
    profile = PermissionProfile(
        organization_id=1,
        subject_id=subject.id,
        name="Approved test discovery profile",
        capabilities=[],
        discovery_capabilities=[],
        status="active",
    )
    db.add(profile)
    db.flush()
    db.add(
        DiscoveryScopeProposal(
            organization_id=1,
            evidence_source_id=source.id,
            status="approved",
            inclusions=[],
            exclusions=[],
            checks=[],
            permission_subject_id=subject.id,
            permission_profile_id=profile.id,
            rationale="Approved in test setup.",
            decided_by_user_id=1,
            decided_at=utcnow(),
        )
    )
    db.commit()

    scanners = scanner_management_routes.list_scanners_route(_ctx(1), db)
    assert scanners[0].ready is True


# --- Named credential routes (TENANT-84) ------------------------------------------------


def _created_instance(db: Session, organization_id: int = 1, admin_user_id: int = 1) -> str:
    body = scanner_management_routes.CreateScannerRequest(name="Checkout & Payments", installation_method=ScannerInstallationMethod.DOCKER)
    created = scanner_management_routes.create_scanner_route(body, _ctx(admin_user_id, organization_id=organization_id), db)
    db.commit()
    return created.instance.id


def test_create_credential_route_returns_token_once_and_audits(db: Session):
    instance_id = _created_instance(db)
    body = scanner_management_routes.CreateCredentialRequest(
        name="Primary key", validity_policy=ScannerCredentialValidityPolicy.ONE_MONTH
    )
    result = scanner_management_routes.create_credential_route(instance_id, body, _ctx(1), db)
    assert len(result.activation_token) > 20
    assert result.activation_token in result.activation_command
    assert result.credential.status == "active"
    assert result.credential.permitted_actions == ["rotate", "pause", "revoke"]
    events = db.query(AuditEvent).filter(AuditEvent.organization_id == 1).all()
    assert any(e.event_type == "evidence_scanner.credential_created" for e in events)


def test_create_credential_route_requires_admin(db: Session):
    instance_id = _created_instance(db)
    body = scanner_management_routes.CreateCredentialRequest(
        name="Key", validity_policy=ScannerCredentialValidityPolicy.ONE_MONTH
    )
    with pytest.raises(AuthorizationError):
        scanner_management_routes.create_credential_route(instance_id, body, _ctx(2, role="member"), db)


def test_list_credentials_route(db: Session):
    instance_id = _created_instance(db)
    body = scanner_management_routes.CreateCredentialRequest(
        name="Key A", validity_policy=ScannerCredentialValidityPolicy.ONE_MONTH
    )
    scanner_management_routes.create_credential_route(instance_id, body, _ctx(1), db)
    body2 = scanner_management_routes.CreateCredentialRequest(
        name="Key B", validity_policy=ScannerCredentialValidityPolicy.SIX_MONTHS
    )
    scanner_management_routes.create_credential_route(instance_id, body2, _ctx(1), db)
    credentials = scanner_management_routes.list_credentials_route(instance_id, _ctx(1), db)
    assert {c.name for c in credentials} == {"Key A", "Key B"}


def test_rotate_credential_route_keeps_duration_by_default(db: Session):
    instance_id = _created_instance(db)
    body = scanner_management_routes.CreateCredentialRequest(
        name="Key", validity_policy=ScannerCredentialValidityPolicy.ONE_MONTH
    )
    created = scanner_management_routes.create_credential_route(instance_id, body, _ctx(1), db)
    rotate_body = scanner_management_routes.RotateCredentialRequest()
    rotated = scanner_management_routes.rotate_credential_route(instance_id, created.credential.id, rotate_body, _ctx(1), db)
    assert rotated.credential.validity_policy == "one_month"
    assert rotated.activation_token != created.activation_token
    events = db.query(AuditEvent).filter(AuditEvent.organization_id == 1).all()
    assert any(e.event_type == "evidence_scanner.credential_rotated" for e in events)


def test_rotate_credential_route_accepts_new_duration(db: Session):
    instance_id = _created_instance(db)
    body = scanner_management_routes.CreateCredentialRequest(
        name="Key", validity_policy=ScannerCredentialValidityPolicy.ONE_MONTH
    )
    created = scanner_management_routes.create_credential_route(instance_id, body, _ctx(1), db)
    rotate_body = scanner_management_routes.RotateCredentialRequest(validity_policy=ScannerCredentialValidityPolicy.SIX_MONTHS)
    rotated = scanner_management_routes.rotate_credential_route(instance_id, created.credential.id, rotate_body, _ctx(1), db)
    assert rotated.credential.validity_policy == "six_months"


def test_pause_resume_credential_route_round_trip(db: Session):
    instance_id = _created_instance(db)
    body = scanner_management_routes.CreateCredentialRequest(
        name="Key", validity_policy=ScannerCredentialValidityPolicy.ONE_MONTH
    )
    created = scanner_management_routes.create_credential_route(instance_id, body, _ctx(1), db)
    paused = scanner_management_routes.pause_credential_route(instance_id, created.credential.id, _ctx(1), db)
    assert paused.status == "paused"
    assert paused.can_authenticate is False
    resumed = scanner_management_routes.resume_credential_route(instance_id, created.credential.id, _ctx(1), db)
    assert resumed.status == "active"
    assert resumed.can_authenticate is True


def test_revoke_credential_route_is_permanent(db: Session):
    instance_id = _created_instance(db)
    body = scanner_management_routes.CreateCredentialRequest(
        name="Key", validity_policy=ScannerCredentialValidityPolicy.ONE_MONTH
    )
    created = scanner_management_routes.create_credential_route(instance_id, body, _ctx(1), db)
    revoked = scanner_management_routes.revoke_credential_route(instance_id, created.credential.id, _ctx(1), db)
    assert revoked.status == "revoked"
    assert revoked.permitted_actions == ["delete"]
    with pytest.raises(ValidationError):
        scanner_management_routes.revoke_credential_route(instance_id, created.credential.id, _ctx(1), db)


def test_delete_credential_route_blocked_while_active(db: Session):
    instance_id = _created_instance(db)
    body = scanner_management_routes.CreateCredentialRequest(
        name="Key", validity_policy=ScannerCredentialValidityPolicy.ONE_MONTH
    )
    created = scanner_management_routes.create_credential_route(instance_id, body, _ctx(1), db)
    with pytest.raises(ValidationError):
        scanner_management_routes.delete_credential_route(instance_id, created.credential.id, _ctx(1), db)


def test_delete_credential_route_succeeds_after_revoke_and_hides_from_list(db: Session):
    instance_id = _created_instance(db)
    body = scanner_management_routes.CreateCredentialRequest(
        name="Key", validity_policy=ScannerCredentialValidityPolicy.ONE_MONTH
    )
    created = scanner_management_routes.create_credential_route(instance_id, body, _ctx(1), db)
    scanner_management_routes.revoke_credential_route(instance_id, created.credential.id, _ctx(1), db)
    response = scanner_management_routes.delete_credential_route(instance_id, created.credential.id, _ctx(1), db)
    assert response.status_code == 204
    credentials = scanner_management_routes.list_credentials_route(instance_id, _ctx(1), db)
    assert created.credential.id not in {c.id for c in credentials}


def test_credential_actions_are_tenant_isolated(db: Session):
    instance_id = _created_instance(db, organization_id=1, admin_user_id=1)
    body = scanner_management_routes.CreateCredentialRequest(
        name="Key", validity_policy=ScannerCredentialValidityPolicy.ONE_MONTH
    )
    created = scanner_management_routes.create_credential_route(instance_id, body, _ctx(1), db)

    with pytest.raises(ResourceNotFoundError):
        scanner_management_routes.pause_credential_route(instance_id, created.credential.id, _ctx(3, organization_id=2), db)
    with pytest.raises(ResourceNotFoundError):
        scanner_management_routes.list_credentials_route(instance_id, _ctx(3, organization_id=2), db)


def test_credential_scoped_to_its_own_scanner_instance(db: Session):
    instance_a = _created_instance(db)
    body_b = scanner_management_routes.CreateScannerRequest(name="Vendor Onboarding", installation_method=ScannerInstallationMethod.DOCKER)
    instance_b = scanner_management_routes.create_scanner_route(body_b, _ctx(1), db).instance.id
    db.commit()

    body = scanner_management_routes.CreateCredentialRequest(
        name="Key", validity_policy=ScannerCredentialValidityPolicy.ONE_MONTH
    )
    created = scanner_management_routes.create_credential_route(instance_a, body, _ctx(1), db)

    # Same org, but the credential belongs to instance_a, not instance_b.
    with pytest.raises(ResourceNotFoundError):
        scanner_management_routes.pause_credential_route(instance_b, created.credential.id, _ctx(1), db)
# --- TENANT-79: business-process-scoped scanner evidence --------------------


def test_create_scanner_with_business_service_id_sets_scope_on_evidence_source(db: Session):
    _make_business_service_with_process(db)
    _accept_process_ownership(db, process_id="process-1", owner_user_id=5)

    body = scanner_management_routes.CreateScannerRequest(
        name="Checkout scanner", installation_method=ScannerInstallationMethod.DOCKER, business_service_id="svc-1"
    )
    created = scanner_management_routes.create_scanner_route(body, _process_owner_context(5), db)
    db.commit()

    assert created.instance.business_service_id == "svc-1"
    source = db.query(EvidenceSource).filter(EvidenceSource.id == created.instance.evidence_source_id).first()
    assert source.business_service_id == "svc-1"


def test_create_scanner_process_scoped_allows_accepted_process_owner(db: Session):
    _make_business_service_with_process(db)
    _accept_process_ownership(db, process_id="process-1", owner_user_id=5)

    body = scanner_management_routes.CreateScannerRequest(
        name="Checkout scanner", installation_method=ScannerInstallationMethod.DOCKER, business_service_id="svc-1"
    )
    created = scanner_management_routes.create_scanner_route(body, _process_owner_context(5), db)
    assert created.instance.status == "registered"


def test_create_scanner_process_scoped_denies_unaccepted_owner(db: Session):
    _make_business_service_with_process(db)
    # No acceptance recorded for user 5 — plain member, not the accepted owner.
    body = scanner_management_routes.CreateScannerRequest(
        name="Checkout scanner", installation_method=ScannerInstallationMethod.DOCKER, business_service_id="svc-1"
    )
    with pytest.raises(AuthorizationError):
        scanner_management_routes.create_scanner_route(body, _process_owner_context(5), db)


def test_create_scanner_process_scoped_denies_wrong_owner(db: Session):
    _make_business_service_with_process(db)
    _accept_process_ownership(db, process_id="process-1", owner_user_id=5)

    body = scanner_management_routes.CreateScannerRequest(
        name="Checkout scanner", installation_method=ScannerInstallationMethod.DOCKER, business_service_id="svc-1"
    )
    # User 6 is a real org member, just not the accepted owner of this process.
    with pytest.raises(AuthorizationError):
        scanner_management_routes.create_scanner_route(body, _process_owner_context(6), db)


def test_create_scanner_process_scoped_allows_manager_role(db: Session):
    _make_business_service_with_process(db)
    # No process-ownership acceptance at all — the manager role alone suffices.
    body = scanner_management_routes.CreateScannerRequest(
        name="Checkout scanner", installation_method=ScannerInstallationMethod.DOCKER, business_service_id="svc-1"
    )
    created = scanner_management_routes.create_scanner_route(body, _process_owner_context(4, "manager"), db)
    assert created.instance.business_service_id == "svc-1"


def test_create_scanner_process_scoped_allows_org_admin(db: Session):
    _make_business_service_with_process(db)
    body = scanner_management_routes.CreateScannerRequest(
        name="Checkout scanner", installation_method=ScannerInstallationMethod.DOCKER, business_service_id="svc-1"
    )
    created = scanner_management_routes.create_scanner_route(body, _ctx(1), db)
    assert created.instance.business_service_id == "svc-1"


def test_create_scanner_org_wide_path_unaffected_by_process_scoping(db: Session):
    """business_service_id omitted -> the pre-existing org-admin-only path,
    zero behavior change."""
    body = scanner_management_routes.CreateScannerRequest(name="Primary", installation_method=ScannerInstallationMethod.DOCKER)
    with pytest.raises(AuthorizationError):
        scanner_management_routes.create_scanner_route(body, _process_owner_context(5, "member"), db)


def test_link_business_service_route_links_and_unlinks(db: Session):
    _make_business_service_with_process(db)
    _accept_process_ownership(db, process_id="process-1", owner_user_id=5)
    created = scanner_management_routes.create_scanner_route(
        scanner_management_routes.CreateScannerRequest(name="Primary", installation_method=ScannerInstallationMethod.DOCKER),
        _ctx(1),
        db,
    )
    db.commit()

    linked = scanner_management_routes.link_business_service_route(
        created.instance.id,
        scanner_management_routes.LinkBusinessServiceRequest(business_service_id="svc-1"),
        _process_owner_context(5),
        db,
    )
    assert linked.business_service_id == "svc-1"

    unlinked = scanner_management_routes.link_business_service_route(
        created.instance.id,
        scanner_management_routes.LinkBusinessServiceRequest(business_service_id=None),
        _process_owner_context(5),
        db,
    )
    assert unlinked.business_service_id is None


def test_link_business_service_route_rejects_scanner_already_linked_elsewhere(db: Session):
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    _make_business_service_with_process(db, service_id="svc-2", process_id="process-2")
    _accept_process_ownership(db, process_id="process-1", owner_user_id=5)
    _accept_process_ownership(db, process_id="process-2", owner_user_id=5)

    created = scanner_management_routes.create_scanner_route(
        scanner_management_routes.CreateScannerRequest(
            name="Checkout scanner", installation_method=ScannerInstallationMethod.DOCKER, business_service_id="svc-1"
        ),
        _process_owner_context(5),
        db,
    )
    db.commit()

    with pytest.raises(ValidationError):
        scanner_management_routes.link_business_service_route(
            created.instance.id,
            scanner_management_routes.LinkBusinessServiceRequest(business_service_id="svc-2"),
            _process_owner_context(5),
            db,
        )


def test_list_scanners_route_filters_by_business_service_id_includes_unscoped(db: Session):
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    _make_business_service_with_process(db, service_id="svc-2", process_id="process-2")

    scoped = scanner_management_routes.create_scanner_route(
        scanner_management_routes.CreateScannerRequest(
            name="Scoped", installation_method=ScannerInstallationMethod.DOCKER, business_service_id="svc-1"
        ),
        _ctx(1),
        db,
    )
    other_scoped = scanner_management_routes.create_scanner_route(
        scanner_management_routes.CreateScannerRequest(
            name="Other scoped", installation_method=ScannerInstallationMethod.DOCKER, business_service_id="svc-2"
        ),
        _ctx(1),
        db,
    )
    unscoped = scanner_management_routes.create_scanner_route(
        scanner_management_routes.CreateScannerRequest(name="Unscoped", installation_method=ScannerInstallationMethod.DOCKER),
        _ctx(1),
        db,
    )
    db.commit()

    result_ids = {
        item.id
        for item in scanner_management_routes.list_scanners_route(_ctx(1), db, business_service_id="svc-1")
    }
    assert result_ids == {scoped.instance.id, unscoped.instance.id}
    assert other_scoped.instance.id not in result_ids


def test_list_scanners_route_business_service_filter_scoped_to_organization(db: Session):
    _make_business_service_with_process(db)
    scanner_management_routes.create_scanner_route(
        scanner_management_routes.CreateScannerRequest(
            name="Checkout scanner", installation_method=ScannerInstallationMethod.DOCKER, business_service_id="svc-1"
        ),
        _ctx(1),
        db,
    )
    db.commit()

    # Org 2 has no business_services row "svc-1" at all — the filter must not
    # leak org 1's scanner across the tenant boundary via the shared id string.
    other_org_results = scanner_management_routes.list_scanners_route(
        _ctx(3, organization_id=2), db, business_service_id="svc-1"
    )
    assert other_org_results == []


# --- CA-04.6: ProcessScannerLink (one scanner, many business processes) -----------------


def _scanner(db: Session, ctx: TenantContext, *, name: str = "Primary") -> ScannerInstance:
    created = scanner_management_routes.create_scanner_route(
        scanner_management_routes.CreateScannerRequest(name=name, installation_method=ScannerInstallationMethod.DOCKER),
        ctx,
        db,
    )
    db.commit()
    return created.instance


def test_create_process_link_route_links_scanner_to_process(db: Session):
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    _approve_scan_scope(db)
    instance = _scanner(db, _ctx(1))

    link = scanner_management_routes.create_process_link_route(
        instance.id,
        scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"),
        _ctx(1),
        db,
    )

    assert link.scanner_instance_id == instance.id
    assert link.business_process_id == "process-1"
    assert link.business_service_id is None
    assert link.status == "active"
    assert link.linked_by_user_id == 1


def test_create_process_link_route_allows_one_scanner_linked_to_multiple_processes(db: Session):
    """AC1 — the whole point of this story: one ScannerInstance, many
    Business Processes, each a real independent row."""
    db.add(ValueStream(id="process-1", organization_id=1, name="Order to cash"))
    db.add(ValueStream(id="process-2", organization_id=1, name="Payroll"))
    db.commit()
    instance = _scanner(db, _ctx(1))

    scanner_management_routes.create_process_link_route(
        instance.id, scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"), _ctx(1), db
    )
    scanner_management_routes.create_process_link_route(
        instance.id, scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-2"), _ctx(1), db
    )
    db.commit()

    links = list_links_for_instance(db, instance.id)
    assert {link.business_process_id for link in links} == {"process-1", "process-2"}


def test_create_process_link_route_rejects_business_service_not_in_process(db: Session):
    """AC2 — a link's optional business_service_id must belong to the
    linked business_process_id, server-enforced."""
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    _make_business_service_with_process(db, service_id="svc-2", process_id="process-2")
    instance = _scanner(db, _ctx(1))

    with pytest.raises(ValidationError):
        scanner_management_routes.create_process_link_route(
            instance.id,
            scanner_management_routes.CreateProcessScannerLinkRequest(
                business_process_id="process-1", business_service_id="svc-2"
            ),
            _ctx(1),
            db,
        )


def test_create_process_link_route_accepts_business_service_that_belongs_to_process(db: Session):
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    instance = _scanner(db, _ctx(1))

    link = scanner_management_routes.create_process_link_route(
        instance.id,
        scanner_management_routes.CreateProcessScannerLinkRequest(
            business_process_id="process-1", business_service_id="svc-1"
        ),
        _ctx(1),
        db,
    )

    assert link.business_service_id == "svc-1"


def test_create_process_link_route_rejects_duplicate_active_link(db: Session):
    """AC4 — duplicate active links prevented."""
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    instance = _scanner(db, _ctx(1))
    scanner_management_routes.create_process_link_route(
        instance.id, scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"), _ctx(1), db
    )
    db.commit()

    with pytest.raises(ValidationError):
        scanner_management_routes.create_process_link_route(
            instance.id,
            scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"),
            _ctx(1),
            db,
        )


def test_create_process_link_route_enforces_org_isolation_on_business_process(db: Session):
    """AC3 — tenant/org consistency: org 2's scanner cannot link to org 1's
    business process, which simply doesn't resolve for org 2's own
    tenant-scoped lookup."""
    db.add(ValueStream(id="process-1", organization_id=1, name="Order to cash"))
    db.commit()
    instance = _scanner(db, _ctx(3, organization_id=2))

    with pytest.raises(ResourceNotFoundError):
        scanner_management_routes.create_process_link_route(
            instance.id,
            scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"),
            _ctx(3, organization_id=2),
            db,
        )


def test_create_process_link_route_rejects_stranger_without_process_ownership(db: Session):
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    instance = _scanner(db, _ctx(1))

    with pytest.raises(AuthorizationError):
        scanner_management_routes.create_process_link_route(
            instance.id,
            scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"),
            _process_owner_context(6, "member"),
            db,
        )


def test_create_process_link_route_allows_accepted_process_owner(db: Session):
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    _accept_process_ownership(db, process_id="process-1", owner_user_id=5)
    instance = _scanner(db, _ctx(1))

    link = scanner_management_routes.create_process_link_route(
        instance.id,
        scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"),
        _process_owner_context(5),
        db,
    )

    assert link.linked_by_user_id == 5


def test_create_process_link_route_allows_manager_role(db: Session):
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    _approve_scan_scope(db)
    instance = _scanner(db, _ctx(1))

    link = scanner_management_routes.create_process_link_route(
        instance.id,
        scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"),
        _ctx(4, role="manager"),
        db,
    )

    assert link.status == "active"


def test_pause_process_link_route_pauses_active_link(db: Session):
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    _approve_scan_scope(db)
    instance = _scanner(db, _ctx(1))
    link = scanner_management_routes.create_process_link_route(
        instance.id, scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"), _ctx(1), db
    )
    db.commit()

    paused = scanner_management_routes.pause_process_link_route(instance.id, link.id, _ctx(1), db)

    assert paused.status == "paused"
    assert paused.paused_at is not None


def test_pause_process_link_route_writes_audit_with_process_context(db: Session):
    """CA-04.8 — the process-scanner-link half of AC3: the paused event
    (unlike CA-04.6's own created event) now also carries business_process_id/
    business_service_id, matching what create_process_link_route already did."""
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    _approve_scan_scope(db)
    instance = _scanner(db, _ctx(1))
    link = scanner_management_routes.create_process_link_route(
        instance.id,
        scanner_management_routes.CreateProcessScannerLinkRequest(
            business_process_id="process-1", business_service_id="svc-1"
        ),
        _ctx(1),
        db,
    )
    db.commit()

    scanner_management_routes.pause_process_link_route(instance.id, link.id, _ctx(1), db)
    db.commit()

    event = (
        db.query(AuditEvent)
        .filter(AuditEvent.event_type == "process_scanner_link.paused", AuditEvent.organization_id == 1)
        .first()
    )
    assert event.metadata_json["business_process_id"] == "process-1"
    assert event.metadata_json["business_service_id"] == "svc-1"


def test_pause_process_link_route_rejects_already_paused_link(db: Session):
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    _approve_scan_scope(db)
    instance = _scanner(db, _ctx(1))
    link = scanner_management_routes.create_process_link_route(
        instance.id, scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"), _ctx(1), db
    )
    db.commit()
    scanner_management_routes.pause_process_link_route(instance.id, link.id, _ctx(1), db)
    db.commit()

    with pytest.raises(ValidationError):
        scanner_management_routes.pause_process_link_route(instance.id, link.id, _ctx(1), db)


def test_revoke_process_link_route_revokes_and_stamps_actor(db: Session):
    """AC5 — revoked links can't authorize new work: this proves the
    terminal state and its audit fields (revoked_at/revoked_by_user_id) are
    real, not just the status string flipping."""
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    instance = _scanner(db, _ctx(1))
    link = scanner_management_routes.create_process_link_route(
        instance.id, scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"), _ctx(1), db
    )
    db.commit()

    revoked = scanner_management_routes.revoke_process_link_route(instance.id, link.id, _ctx(1), db)

    assert revoked.status == "revoked"
    assert revoked.revoked_at is not None
    assert revoked.revoked_by_user_id == 1


def test_revoke_process_link_route_writes_audit_with_process_context(db: Session):
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    instance = _scanner(db, _ctx(1))
    link = scanner_management_routes.create_process_link_route(
        instance.id,
        scanner_management_routes.CreateProcessScannerLinkRequest(
            business_process_id="process-1", business_service_id="svc-1"
        ),
        _ctx(1),
        db,
    )
    db.commit()

    scanner_management_routes.revoke_process_link_route(instance.id, link.id, _ctx(1), db)
    db.commit()

    event = (
        db.query(AuditEvent)
        .filter(AuditEvent.event_type == "process_scanner_link.revoked", AuditEvent.organization_id == 1)
        .first()
    )
    assert event.metadata_json["business_process_id"] == "process-1"
    assert event.metadata_json["business_service_id"] == "svc-1"


def test_revoke_process_link_route_rejects_already_revoked_link(db: Session):
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    instance = _scanner(db, _ctx(1))
    link = scanner_management_routes.create_process_link_route(
        instance.id, scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"), _ctx(1), db
    )
    db.commit()
    scanner_management_routes.revoke_process_link_route(instance.id, link.id, _ctx(1), db)
    db.commit()

    with pytest.raises(ValidationError):
        scanner_management_routes.revoke_process_link_route(instance.id, link.id, _ctx(1), db)


def test_revoke_process_link_route_frees_the_process_for_a_brand_new_link(db: Session):
    """A revoked link never reactivates (no resume path exists for this
    model, unlike ScannerCredential) — the only way back to ACTIVE for the
    same (scanner, process) pair is a brand-new row, proving REVOKED really
    is terminal rather than just another paused-like state."""
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    _approve_scan_scope(db)
    instance = _scanner(db, _ctx(1))
    first = scanner_management_routes.create_process_link_route(
        instance.id, scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"), _ctx(1), db
    )
    db.commit()
    scanner_management_routes.revoke_process_link_route(instance.id, first.id, _ctx(1), db)
    db.commit()

    second = scanner_management_routes.create_process_link_route(
        instance.id, scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"), _ctx(1), db
    )

    assert second.id != first.id
    assert second.status == "active"


def test_process_link_routes_reject_link_from_a_different_scanner_instance(db: Session):
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    instance_a = _scanner(db, _ctx(1), name="Scanner A")
    instance_b = _scanner(db, _ctx(1), name="Scanner B")
    link = scanner_management_routes.create_process_link_route(
        instance_a.id, scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"), _ctx(1), db
    )
    db.commit()

    with pytest.raises(ResourceNotFoundError):
        scanner_management_routes.pause_process_link_route(instance_b.id, link.id, _ctx(1), db)


def test_process_link_routes_enforce_org_isolation_on_link_lookup(db: Session):
    _make_business_service_with_process(db, service_id="svc-1", process_id="process-1")
    instance = _scanner(db, _ctx(1))
    link = scanner_management_routes.create_process_link_route(
        instance.id, scanner_management_routes.CreateProcessScannerLinkRequest(business_process_id="process-1"), _ctx(1), db
    )
    db.commit()

    with pytest.raises(ResourceNotFoundError):
        scanner_management_routes.pause_process_link_route(instance.id, link.id, _ctx(3, organization_id=2), db)


# --- Editing a Collector (Søren, 2026-08-24) --------------------------------


def _editable_scanner(db: Session, name: str = "Primary"):
    """Its own name: the file already has a `_scanner(db, ctx, *, name)` above,
    and shadowing it broke fifteen unrelated tests before this was caught."""
    body = scanner_management_routes.CreateScannerRequest(
        name=name, installation_method=ScannerInstallationMethod.DOCKER
    )
    return scanner_management_routes.create_scanner_route(body, _ctx(1), db).instance


def test_a_collector_can_be_renamed(db: Session):
    instance = _editable_scanner(db)

    updated = scanner_management_routes.update_scanner_route(
        instance.id,
        scanner_management_routes.UpdateScannerRequest(name="Head office Collector"),
        _ctx(1),
        db,
    )

    assert updated.name == "Head office Collector"




def test_the_patch_route_cannot_change_the_installation_method(db: Session):
    """Removed on Søren's call: it is not a label.

    Changing how a Collector is installed means installing it again, so it has
    its own route that rotates the credential. A PATCH field would have let the
    record assert an installation nobody performed.
    """
    assert "installation_method" not in scanner_management_routes.UpdateScannerRequest.model_fields


def test_an_empty_name_is_refused_rather_than_quietly_ignored(db: Session):
    """A caller that sent a name meant to change it.

    Accepting whitespace would leave them looking at the old name with no idea
    why their change did not take.
    """
    instance = _editable_scanner(db)

    with pytest.raises(ValidationError):
        scanner_management_routes.update_scanner_route(
            instance.id,
            scanner_management_routes.UpdateScannerRequest(name="   "),
            _ctx(1),
            db,
        )


def test_renaming_is_its_own_audit_event(db: Session):
    """"Somebody changed what this is called" and "somebody installed this" are
    different facts, and a trail that could not tell them apart would lose the
    one that identifies a person."""
    from src.core.constants.evidence_scanner_enums import SCANNER_AUDIT_UPDATED

    instance = _editable_scanner(db)
    scanner_management_routes.update_scanner_route(
        instance.id,
        scanner_management_routes.UpdateScannerRequest(name="Renamed"),
        _ctx(1),
        db,
    )

    events = [event.event_type for event in db.query(AuditEvent).all()]
    assert SCANNER_AUDIT_UPDATED in events


def test_a_request_that_changes_nothing_writes_no_audit_event(db: Session):
    """An event for a no-op makes the trail harder to read, not more complete."""
    from src.core.constants.evidence_scanner_enums import SCANNER_AUDIT_UPDATED

    instance = _editable_scanner(db, name="Primary")
    scanner_management_routes.update_scanner_route(
        instance.id,
        scanner_management_routes.UpdateScannerRequest(name="Primary"),
        _ctx(1),
        db,
    )

    events = [event.event_type for event in db.query(AuditEvent).all()]
    assert SCANNER_AUDIT_UPDATED not in events


def test_editing_a_collector_requires_org_admin(db: Session):
    instance = _editable_scanner(db)

    with pytest.raises(AuthorizationError):
        scanner_management_routes.update_scanner_route(
            instance.id,
            scanner_management_routes.UpdateScannerRequest(name="Nope"),
            _ctx(2, role="member"),
            db,
        )


def test_one_organisation_cannot_rename_anothers_collector(db: Session):
    instance = _editable_scanner(db)

    with pytest.raises((AuthorizationError, ValidationError, Exception)):
        scanner_management_routes.update_scanner_route(
            instance.id,
            scanner_management_routes.UpdateScannerRequest(name="Theirs now"),
            _ctx(1, organization_id=2),
            db,
        )


# --- The activation command has to match the install (Søren, 2026-08-24) ----


def test_a_docker_collector_is_given_a_docker_command():
    """The defect that blocked Søren at the one step with nothing to fall back on.

    A Collector installed as a Docker container has no ``risklence-scanner`` on
    the operator's PATH, so the CLI form produced ``zsh: command not found``.
    The installation method was always on the record; it simply was not
    consulted.
    """
    from src.core.services.evidence_scanner_service import generate_activation_command

    command = generate_activation_command(activation_token="TOK", installation_method="docker")

    assert command.startswith("docker run ")
    assert "ghcr.io/risklence/risklence-scanner" in command
    assert "--token TOK" in command
    # And never the bare CLI, which is the thing that failed.
    assert not command.startswith("risklence-scanner ")


def test_the_docker_command_keeps_the_credential_across_restarts():
    """Without the volume, the container activates and forgets on exit.

    The agent stores its credential in ~/.risklence-scanner; a --rm container
    with no volume would need re-activating every single run.
    """
    from src.core.services.evidence_scanner_service import generate_activation_command

    command = generate_activation_command(activation_token="TOK", installation_method="docker")
    assert "-v risklence-scanner-data:/root/.risklence-scanner" in command


def test_a_command_line_install_still_gets_the_cli_form():
    from src.core.services.evidence_scanner_service import generate_activation_command

    command = generate_activation_command(
        activation_token="TOK", installation_method="local_cli"
    )
    assert command.startswith("risklence-scanner activate ")


def test_an_unknown_install_falls_back_rather_than_guessing_docker():
    """The CLI form is the fallback for a genuinely unknown install, not a default
    anybody should be relying on — but silently emitting a docker command for a
    Collector nobody said was dockerised would be worse."""
    from src.core.services.evidence_scanner_service import generate_activation_command

    assert generate_activation_command(activation_token="TOK").startswith("risklence-scanner ")


# --- Changing the install is installing again (Søren, 2026-08-24) -----------


def test_changing_the_installation_method_rotates_the_credential(db: Session):
    """The old install's credential must stop working the moment this is called.

    It lives on a machine that is no longer the one running this Collector, and
    the signing key is derived from it — leaving it valid would let a
    decommissioned install keep accepting signed commands.
    """
    instance = _editable_scanner(db)
    before = db.query(ScannerInstance).filter_by(id=instance.id).one()
    old_hash = before.activation_token_hash
    old_key = before.command_signing_key_encrypted

    response = scanner_management_routes.change_installation_method_route(
        instance.id,
        scanner_management_routes.ChangeInstallationMethodRequest(
            installation_method=ScannerInstallationMethod.LOCAL_CLI
        ),
        _ctx(1),
        db,
    )

    after = db.query(ScannerInstance).filter_by(id=instance.id).one()
    assert after.installation_method == "local_cli"
    assert after.activation_token_hash != old_hash
    assert after.command_signing_key_encrypted != old_key
    # And a fresh token is handed back, because somebody has to install it again.
    assert len(response.activation_token) > 20


def test_changing_the_installation_method_clears_what_the_old_install_reported(db: Session):
    """Version, OS and architecture described a different machine.

    Keeping them would have the platform asserting something untrue with its own
    authority — which is the reading Søren objected to.
    """
    instance = _editable_scanner(db)
    row = db.query(ScannerInstance).filter_by(id=instance.id).one()
    row.scanner_version = "1.4.2"
    row.os_name = "Debian GNU/Linux 13"
    row.architecture = "arm64"
    db.commit()

    scanner_management_routes.change_installation_method_route(
        instance.id,
        scanner_management_routes.ChangeInstallationMethodRequest(
            installation_method=ScannerInstallationMethod.SERVER
        ),
        _ctx(1),
        db,
    )

    db.refresh(row)
    assert row.scanner_version is None
    assert row.os_name is None
    assert row.architecture is None


def test_a_reinstall_keeps_the_decisions_a_person_made(db: Session):
    """Scope and profile are somebody's decision about what this may reach.

    Being reinstalled elsewhere does not invalidate them, and silently clearing
    them would make a reinstall quietly narrow what the Collector is allowed to
    do.
    """
    instance = _editable_scanner(db)
    row = db.query(ScannerInstance).filter_by(id=instance.id).one()
    row.scan_profile = ScannerProfile.STANDARD_DISCOVERY.value
    db.commit()

    scanner_management_routes.change_installation_method_route(
        instance.id,
        scanner_management_routes.ChangeInstallationMethodRequest(
            installation_method=ScannerInstallationMethod.LOCAL_CLI
        ),
        _ctx(1),
        db,
    )

    db.refresh(row)
    assert row.scan_profile == ScannerProfile.STANDARD_DISCOVERY.value


def test_changing_to_the_method_it_already_has_is_refused(db: Session):
    """Rotating a credential for a no-op would strand a working Collector."""
    instance = _editable_scanner(db)

    with pytest.raises(ValidationError):
        scanner_management_routes.change_installation_method_route(
            instance.id,
            scanner_management_routes.ChangeInstallationMethodRequest(
                installation_method=ScannerInstallationMethod.DOCKER
            ),
            _ctx(1),
            db,
        )


def test_reinstalling_requires_org_admin(db: Session):
    instance = _editable_scanner(db)

    with pytest.raises(AuthorizationError):
        scanner_management_routes.change_installation_method_route(
            instance.id,
            scanner_management_routes.ChangeInstallationMethodRequest(
                installation_method=ScannerInstallationMethod.LOCAL_CLI
            ),
            _ctx(2, role="member"),
            db,
        )


def test_a_first_install_is_told_how_to_fetch_the_collector(db: Session):
    """Søren, 2026-08-25: rotating a credential offered only the reconnect
    command for a Collector that was never installed, so the one instruction he
    was given could not work."""
    from src.core.services.evidence_scanner_service import generate_pull_command

    assert generate_pull_command(installation_method="docker") == (
        "docker pull ghcr.io/risklence/risklence-scanner:latest"
    )


def test_no_fetch_command_is_invented_for_an_install_we_do_not_provision(db: Session):
    """A CLI or server install is fetched however that operator provisions
    software. Guessing at their estate would be worse than saying nothing."""
    from src.core.services.evidence_scanner_service import generate_pull_command

    assert generate_pull_command(installation_method="local_cli") is None
    assert generate_pull_command(installation_method="server") is None
