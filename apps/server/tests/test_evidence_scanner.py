"""Risklence Scanner setup (Step 3.5): installation/activation, domain and
network target management, profile selection, scope confirmation,
tool-validation/test-scan recording, readiness state machine, prepared
read model, tenant isolation, admin-gating."""

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
from src.api.routes import evidence_scanner as evidence_scanner_routes
from src.core.constants.evidence_scanner_enums import (
    ScannerInstallationMethod,
    ScannerNetworkType,
    ScannerProfile,
)
from src.core.constants.evidence_source_enums import EvidenceSourceType
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.common import utcnow
from src.core.model_defs.discovery_scope_proposal import DiscoveryScopeProposal
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.model_defs.evidence_scanner import (
    CollectorReadinessReport,
    ScannerDomainTarget,
    ScannerInstance,
    ScannerNetworkTarget,
)
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.model_defs.organization_identity import OrganizationDomain
from src.core.models import AuditEvent, Organization, User
from src.core.services.evidence_scanner_readiness_service import (
    build_prepared_scanner_configuration,
    evaluate_scanner_readiness,
)
from src.core.services.evidence_scanner_service import (
    EvidenceScannerValidationError,
    add_domain_target,
    add_domain_target_from_verified_identity,
    add_network_target,
    approve_domain_target,
    confirm_scanner_scope,
    install_scanner,
    list_suggested_domains,
    record_test_scan_result,
    record_tool_validation,
    select_scan_profile,
)
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
            OrganizationDomain.__table__,
            ScannerInstance.__table__,
            CollectorReadinessReport.__table__,
            ScannerDomainTarget.__table__,
            ScannerNetworkTarget.__table__,
            # UX-SETUP-03 (#129) — setup readiness now reads the approved
            # discovery boundary, so the table it lives in has to exist here.
            DiscoveryScopeProposal.__table__,
            PermissionSubject.__table__,
            PermissionProfile.__table__,
            AuditEvent.__table__,
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
        ]
    )
    session.commit()
    yield session
    session.close()


def _ctx(user_id: int, organization_id: int = 1, role: str = "org_admin") -> TenantContext:
    return TenantContext(
        user_id=user_id, organization_id=organization_id, email="x@example.com", roles=[role], permissions=[]
    )


def _scanner_source(db: Session, organization_id: int = 1) -> EvidenceSource:
    source = create_evidence_source(
        db, organization_id=organization_id, name="Risklence Scanner", source_type=EvidenceSourceType.SCANNER
    )
    db.commit()
    return source


def _installed_instance(db: Session, source: EvidenceSource) -> ScannerInstance:
    result = install_scanner(db, source, name="Primary scanner", installation_method=ScannerInstallationMethod.DOCKER.value)
    db.commit()
    return result.instance


def _approved_domain(db: Session, source: EvidenceSource) -> ScannerDomainTarget:
    target = add_domain_target(db, source, domain="example.com")
    approve_domain_target(db, target, approved_by_user_id=1)
    db.commit()
    return target


def _walk_to_ready(db: Session, source: EvidenceSource, instance: ScannerInstance) -> None:
    _approved_domain(db, source)
    select_scan_profile(db, instance, profile=ScannerProfile.SAFE_DISCOVERY.value)
    db.commit()
    confirm_scanner_scope(db, source, instance, confirmed_by_user_id=1)
    db.commit()
    record_tool_validation(
        db, instance, tool_status={"nmap": "available", "subfinder": "available"}
    )
    db.commit()
    record_test_scan_result(db, instance, status="completed", connection_verified=True)
    db.commit()
    _approve_discovery_boundary(db, source)


def _approve_discovery_boundary(db: Session, source: EvidenceSource) -> DiscoveryScopeProposal:
    """UX-SETUP-03 (#129) — the last step of setup, and the one that used to be
    missing: CA-05.B refuses every discovery run without an approved boundary,
    so a scanner is not actually ready until one exists."""
    subject = PermissionSubject(organization_id=source.organization_id, subject_kind="discovery_scope_proposal")
    db.add(subject)
    db.flush()
    profile = PermissionProfile(
        organization_id=source.organization_id,
        subject_id=subject.id,
        name="Approved test discovery profile",
        capabilities=[],
        discovery_capabilities=[],
        status="active",
    )
    db.add(profile)
    db.flush()
    proposal = DiscoveryScopeProposal(
        organization_id=source.organization_id,
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
    db.add(proposal)
    db.commit()
    return proposal


# --- Installation / activation ------------------------------------------------------


def test_install_requires_scanner_source_type(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Manual log", source_type=EvidenceSourceType.MANUAL)
    with pytest.raises(EvidenceScannerValidationError):
        install_scanner(db, source, name="x", installation_method=ScannerInstallationMethod.DOCKER.value)


def test_install_creates_instance_and_returns_token_once(db: Session):
    source = _scanner_source(db)
    result = install_scanner(db, source, name="Primary scanner", installation_method=ScannerInstallationMethod.DOCKER.value)
    assert result.instance.status == "registered"
    assert len(result.activation_token) > 20
    # only the hash is persisted
    assert result.instance.activation_token_hash != result.activation_token


def test_install_twice_fails(db: Session):
    source = _scanner_source(db)
    _installed_instance(db, source)
    with pytest.raises(EvidenceScannerValidationError):
        install_scanner(db, source, name="Second", installation_method=ScannerInstallationMethod.DOCKER.value)


# --- Domain targets --------------------------------------------------------------------


def test_add_domain_target_rejects_invalid_domain(db: Session):
    source = _scanner_source(db)
    with pytest.raises(EvidenceScannerValidationError):
        add_domain_target(db, source, domain="not a domain")


@pytest.mark.parametrize(
    "malicious_domain",
    [
        "-oX=/tmp/pwned.xml",  # argument injection — would be read as an nmap/nuclei flag, not a hostname
        "--script=vuln.example.com",
        "; rm -rf / #.example.com",
        "$(whoami).example.com",
        "example.com`id`",
    ],
)
def test_add_domain_target_rejects_command_injection_shaped_value(db: Session, malicious_domain: str):
    """CA-04.5 — the acceptance criterion's own "at least one real
    command-injection attempt provably rejected": every one of these is
    exactly the shape that would reach nmap_runner/subfinder_runner/
    nuclei_runner's subprocess.run argv verbatim if it were ever accepted
    as a target (leading-dash argument injection, or literal shell
    metacharacters) — proving _DOMAIN_PATTERN rejects it at the point of
    entry, server-side, rather than relying on the Collector to defend
    itself (the runners never validate their own target/domain argument)."""
    source = _scanner_source(db)
    with pytest.raises(EvidenceScannerValidationError):
        add_domain_target(db, source, domain=malicious_domain)


def test_add_domain_target_rejects_duplicate(db: Session):
    source = _scanner_source(db)
    add_domain_target(db, source, domain="example.com")
    db.commit()
    with pytest.raises(EvidenceScannerValidationError):
        add_domain_target(db, source, domain="EXAMPLE.com")


def test_add_domain_target_from_verified_identity_marks_verified(db: Session):
    source = _scanner_source(db)
    org_domain = OrganizationDomain(
        organization_id=1, domain="verified.example.com", domain_type="primary", verification_status="verified"
    )
    db.add(org_domain)
    db.commit()
    target = add_domain_target_from_verified_identity(db, source, organization_domain_id=org_domain.id)
    assert target.ownership_status == "verified"
    assert target.source == "verified_organisation_domain"


def test_list_suggested_domains_excludes_already_added(db: Session):
    source = _scanner_source(db)
    verified = OrganizationDomain(
        organization_id=1, domain="verified.example.com", domain_type="primary", verification_status="verified"
    )
    unverified = OrganizationDomain(
        organization_id=1, domain="pending.example.com", domain_type="secondary", verification_status="pending"
    )
    db.add_all([verified, unverified])
    db.commit()

    suggestions = list_suggested_domains(db, source)
    assert [d.domain for d in suggestions] == ["verified.example.com"]

    add_domain_target_from_verified_identity(db, source, organization_domain_id=verified.id)
    db.commit()
    assert list_suggested_domains(db, source) == []


# --- Network targets -------------------------------------------------------------------


def test_add_network_target_rejects_invalid_cidr(db: Session):
    source = _scanner_source(db)
    with pytest.raises(EvidenceScannerValidationError):
        add_network_target(db, source, cidr="not-a-cidr", name="Corp", network_type=ScannerNetworkType.CORPORATE.value)


@pytest.mark.parametrize(
    "malicious_cidr",
    [
        "-oX=/tmp/pwned.xml",
        "; rm -rf / #",
        "$(whoami)",
        "10.0.0.0/24; rm -rf /",
    ],
)
def test_add_network_target_rejects_command_injection_shaped_value(db: Session, malicious_cidr: str):
    """CA-04.5 — same acceptance criterion as the domain-target injection
    tests above, exercised on the network-target path: ipaddress.ip_network's
    own strict parsing rejects anything that isn't a syntactically valid
    CIDR, blocking argument-injection/shell-metacharacter shapes just as
    effectively as _DOMAIN_PATTERN does for domains."""
    source = _scanner_source(db)
    with pytest.raises(EvidenceScannerValidationError):
        add_network_target(db, source, cidr=malicious_cidr, name="Corp", network_type=ScannerNetworkType.CORPORATE.value)


def test_add_network_target_rejects_duplicate_cidr(db: Session):
    source = _scanner_source(db)
    add_network_target(db, source, cidr="10.20.0.0/24", name="Corp", network_type=ScannerNetworkType.CORPORATE.value)
    db.commit()
    with pytest.raises(EvidenceScannerValidationError):
        add_network_target(db, source, cidr="10.20.0.0/24", name="Corp dup", network_type=ScannerNetworkType.CORPORATE.value)


def test_add_network_target_warns_on_public_and_large_range(db: Session):
    source = _scanner_source(db)
    result = add_network_target(db, source, cidr="8.0.0.0/8", name="Public", network_type=ScannerNetworkType.CLOUD.value)
    assert "public_range" in result.warnings
    assert "large_range" in result.warnings
    assert result.estimated_address_count == 2**24


def test_add_network_target_warns_on_overlap(db: Session):
    source = _scanner_source(db)
    add_network_target(db, source, cidr="10.20.0.0/16", name="Wide", network_type=ScannerNetworkType.CORPORATE.value)
    db.commit()
    result = add_network_target(db, source, cidr="10.20.5.0/24", name="Narrow", network_type=ScannerNetworkType.CORPORATE.value)
    assert "overlapping_range" in result.warnings
    assert "public_range" not in result.warnings


def test_safe_private_range_has_no_warnings(db: Session):
    source = _scanner_source(db)
    result = add_network_target(db, source, cidr="10.20.0.0/24", name="Corp", network_type=ScannerNetworkType.CORPORATE.value)
    assert result.warnings == []
    assert result.estimated_address_count == 256


# --- Profile / scope confirmation -------------------------------------------------------


def test_confirm_scope_requires_profile_selected(db: Session):
    source = _scanner_source(db)
    instance = _installed_instance(db, source)
    _approved_domain(db, source)
    with pytest.raises(EvidenceScannerValidationError):
        confirm_scanner_scope(db, source, instance, confirmed_by_user_id=1)


def test_confirm_scope_requires_approved_target(db: Session):
    source = _scanner_source(db)
    instance = _installed_instance(db, source)
    select_scan_profile(db, instance, profile=ScannerProfile.SAFE_DISCOVERY.value)
    db.commit()
    with pytest.raises(EvidenceScannerValidationError):
        confirm_scanner_scope(db, source, instance, confirmed_by_user_id=1)


def test_confirm_scope_succeeds_with_approved_domain(db: Session):
    source = _scanner_source(db)
    instance = _installed_instance(db, source)
    _approved_domain(db, source)
    select_scan_profile(db, instance, profile=ScannerProfile.SAFE_DISCOVERY.value)
    db.commit()
    confirm_scanner_scope(db, source, instance, confirmed_by_user_id=1)
    db.commit()
    assert instance.scope_confirmed_at is not None


def test_changing_profile_invalidates_prior_scope_confirmation(db: Session):
    source = _scanner_source(db)
    instance = _installed_instance(db, source)
    _approved_domain(db, source)
    select_scan_profile(db, instance, profile=ScannerProfile.SAFE_DISCOVERY.value)
    confirm_scanner_scope(db, source, instance, confirmed_by_user_id=1)
    db.commit()
    assert instance.scope_confirmed_at is not None

    select_scan_profile(db, instance, profile=ScannerProfile.STANDARD_DISCOVERY.value)
    db.commit()
    assert instance.scope_confirmed_at is None


# --- Readiness state machine ------------------------------------------------------------


def test_readiness_missing_when_no_instance(db: Session):
    source = _scanner_source(db)
    result = evaluate_scanner_readiness(db, source)
    assert result.ready is False
    assert result.readiness.value == "missing"
    assert result.state.value == "activation_required"


def test_readiness_domain_or_network_scope_required_after_install(db: Session):
    source = _scanner_source(db)
    _installed_instance(db, source)
    result = evaluate_scanner_readiness(db, source)
    assert result.ready is False
    assert result.state.value == "domain_or_network_scope_required"


def test_readiness_scan_profile_required(db: Session):
    source = _scanner_source(db)
    _installed_instance(db, source)
    _approved_domain(db, source)
    result = evaluate_scanner_readiness(db, source)
    assert result.state.value == "scan_profile_required"


def test_readiness_scope_confirmation_required(db: Session):
    source = _scanner_source(db)
    instance = _installed_instance(db, source)
    _approved_domain(db, source)
    select_scan_profile(db, instance, profile=ScannerProfile.SAFE_DISCOVERY.value)
    db.commit()
    result = evaluate_scanner_readiness(db, source)
    assert result.state.value == "scope_confirmation_required"


def test_readiness_tool_validation_only_requires_capabilities_the_profile_enables(db: Session):
    source = _scanner_source(db)
    instance = _installed_instance(db, source)
    _approved_domain(db, source)
    select_scan_profile(db, instance, profile=ScannerProfile.SAFE_DISCOVERY.value)
    db.commit()
    confirm_scanner_scope(db, source, instance, confirmed_by_user_id=1)
    db.commit()

    # safe_discovery never enables vulnerability scanning — nuclei must not
    # be required to move past tool validation.
    result = evaluate_scanner_readiness(db, source)
    assert result.state.value == "tool_validation_required"

    record_tool_validation(db, instance, tool_status={"nmap": "available", "subfinder": "available"})
    db.commit()
    result = evaluate_scanner_readiness(db, source)
    assert result.state.value == "target_test_required"


def test_readiness_standard_discovery_requires_nuclei(db: Session):
    source = _scanner_source(db)
    instance = _installed_instance(db, source)
    _approved_domain(db, source)
    select_scan_profile(db, instance, profile=ScannerProfile.STANDARD_DISCOVERY.value)
    db.commit()
    confirm_scanner_scope(db, source, instance, confirmed_by_user_id=1)
    db.commit()

    record_tool_validation(db, instance, tool_status={"nmap": "available", "subfinder": "available"})
    db.commit()
    result = evaluate_scanner_readiness(db, source)
    assert result.state.value == "tool_validation_required"

    record_tool_validation(
        db,
        instance,
        tool_status={
            "nmap": "available",
            "subfinder": "available",
            "nuclei": "available",
            "nuclei_templates": "available",
        },
    )
    db.commit()
    result = evaluate_scanner_readiness(db, source)
    assert result.state.value == "target_test_required"


def test_readiness_ready_after_full_walk(db: Session):
    source = _scanner_source(db)
    instance = _installed_instance(db, source)
    _walk_to_ready(db, source, instance)

    result = evaluate_scanner_readiness(db, source)
    assert result.ready is True
    assert result.readiness.value == "ready"
    assert result.state.value == "scanner_ready"


def test_readiness_stops_at_the_boundary_step_when_none_is_approved(db: Session):
    """UX-SETUP-03 (#129) — the defect, stated as a test.

    Every earlier step passes and the old ladder went straight to
    SCANNER_READY, so setup reported a Collector that could start nothing:
    discovery_run_service refuses any run without an approved boundary.
    """
    source = _scanner_source(db)
    instance = _installed_instance(db, source)
    _approved_domain(db, source)
    select_scan_profile(db, instance, profile=ScannerProfile.SAFE_DISCOVERY.value)
    db.commit()
    confirm_scanner_scope(db, source, instance, confirmed_by_user_id=1)
    db.commit()
    record_tool_validation(db, instance, tool_status={"nmap": "available", "subfinder": "available"})
    db.commit()
    record_test_scan_result(db, instance, status="completed", connection_verified=True)
    db.commit()

    result = evaluate_scanner_readiness(db, source)

    assert result.ready is False
    assert result.state.value == "discovery_boundary_approval_required"
    assert result.blocking_reasons == ["discovery_boundary_not_approved"]


def test_readiness_reaches_ready_once_the_boundary_is_approved(db: Session):
    """And the other half: finishing setup now means discovery can start."""
    source = _scanner_source(db)
    instance = _installed_instance(db, source)
    _walk_to_ready(db, source, instance)

    result = evaluate_scanner_readiness(db, source)

    assert result.ready is True
    assert result.state.value == "scanner_ready"


def test_a_rejected_boundary_does_not_count_as_approved(db: Session):
    """A decision that went the other way is still a decision, and it must not
    read as consent — the boundary gate only ever recognises `approved`."""
    source = _scanner_source(db)
    instance = _installed_instance(db, source)
    _approved_domain(db, source)
    select_scan_profile(db, instance, profile=ScannerProfile.SAFE_DISCOVERY.value)
    db.commit()
    confirm_scanner_scope(db, source, instance, confirmed_by_user_id=1)
    db.commit()
    record_tool_validation(db, instance, tool_status={"nmap": "available", "subfinder": "available"})
    db.commit()
    record_test_scan_result(db, instance, status="completed", connection_verified=True)
    db.commit()
    subject = PermissionSubject(organization_id=source.organization_id, subject_kind="discovery_scope_proposal")
    db.add(subject)
    db.flush()
    profile = PermissionProfile(
        organization_id=source.organization_id,
        subject_id=subject.id,
        name="Rejected test discovery profile",
        capabilities=[],
        discovery_capabilities=[],
        status="withdrawn",
    )
    db.add(profile)
    db.flush()
    db.add(
        DiscoveryScopeProposal(
            organization_id=source.organization_id,
            evidence_source_id=source.id,
            status="rejected",
            inclusions=[],
            exclusions=[],
            checks=[],
            permission_subject_id=subject.id,
            permission_profile_id=profile.id,
            rationale="Rejected in test setup.",
            decided_by_user_id=1,
            decided_at=utcnow(),
        )
    )
    db.commit()

    result = evaluate_scanner_readiness(db, source)

    assert result.ready is False
    assert result.state.value == "discovery_boundary_approval_required"


def test_readiness_blocked_when_revoked(db: Session):
    source = _scanner_source(db)
    instance = _installed_instance(db, source)
    _walk_to_ready(db, source, instance)
    instance.status = "revoked"
    db.commit()

    result = evaluate_scanner_readiness(db, source)
    assert result.ready is False
    assert result.readiness.value == "blocked"


def test_prepared_configuration_reflects_readiness(db: Session):
    source = _scanner_source(db)
    instance = _installed_instance(db, source)
    _walk_to_ready(db, source, instance)

    prepared = build_prepared_scanner_configuration(db, source)
    assert prepared.ready is True
    assert prepared.scan_profile == "safe_discovery"
    assert prepared.capabilities["vulnerabilityScanningEnabled"] is False
    assert len(prepared.approved_domains) == 1
    assert prepared.connection_verified is True
    assert prepared.test_scan_passed is True


# --- Route-level authorisation / tenant isolation ---------------------------------------


def test_only_org_admin_can_install_scanner(db: Session):
    source = _scanner_source(db)
    with pytest.raises(AuthorizationError):
        evidence_scanner_routes.install_scanner_route(
            source.id,
            evidence_scanner_routes.InstallScannerRequest(
                name="Scanner", installation_method=ScannerInstallationMethod.DOCKER
            ),
            ctx=_ctx(2, role="member"),
            db=db,
        )


def test_scanner_lookup_is_tenant_isolated(db: Session):
    source = _scanner_source(db)
    _installed_instance(db, source)
    with pytest.raises(ResourceNotFoundError):
        evidence_scanner_routes.get_scanner_route(source.id, ctx=_ctx(3, organization_id=2), db=db)


def test_install_route_end_to_end_returns_token(db: Session):
    source = _scanner_source(db)
    response = evidence_scanner_routes.install_scanner_route(
        source.id,
        evidence_scanner_routes.InstallScannerRequest(
            name="Scanner", installation_method=ScannerInstallationMethod.DOCKER
        ),
        ctx=_ctx(1),
        db=db,
    )
    assert response.instance.status == "registered"
    assert len(response.activation_token) > 20
    events = db.query(AuditEvent).filter(AuditEvent.organization_id == 1).all()
    assert any(e.event_type == "evidence_scanner.activated" for e in events)


def test_network_target_route_rejects_invalid_cidr_as_validation_error(db: Session):
    source = _scanner_source(db)
    with pytest.raises(ValidationError):
        evidence_scanner_routes.add_network_target_route(
            source.id,
            evidence_scanner_routes.AddNetworkTargetRequest(
                cidr="garbage", name="Corp", network_type=ScannerNetworkType.CORPORATE
            ),
            ctx=_ctx(1),
            db=db,
        )


def test_readiness_route_reflects_service_state(db: Session):
    source = _scanner_source(db)
    result = evidence_scanner_routes.get_scanner_readiness_route(source.id, ctx=_ctx(1), db=db)
    assert result.state == "activation_required"
    assert result.ready is False


def test_suggested_domains_route_rejects_non_scanner_source_cleanly(db: Session):
    # Regression: a stale/mismatched source id (e.g. a frontend resume bug
    # pointing at the wrong evidence source) must fail as a clean 4xx, not
    # an unhandled 500 — this route previously let
    # EvidenceScannerValidationError propagate uncaught.
    source = create_evidence_source(db, organization_id=1, name="Manual log", source_type=EvidenceSourceType.MANUAL)
    db.commit()
    with pytest.raises(ValidationError):
        evidence_scanner_routes.list_suggested_domains_route(source.id, ctx=_ctx(1), db=db)


# --- BUG-DISC-05: a stopped Collector must stop reporting Connected -----------------------
# record_heartbeat raises status to ONLINE and nothing ever lowers it, so a
# Collector that has stopped kept showing "Connected" with a green tick while a
# run waited on it forever — pointing the user at the platform when the problem
# was their own agent.


def _instance_with_heartbeat(db: Session, *, age_seconds: float, status: str = "online"):
    from datetime import timedelta

    from src.core.model_defs.common import utcnow

    source = create_evidence_source(db, organization_id=1, name="Scanner", source_type=EvidenceSourceType.SCANNER)
    db.commit()
    instance = install_scanner(
        db, source, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value
    ).instance
    instance.status = status
    instance.last_heartbeat_at = utcnow().replace(tzinfo=None) - timedelta(seconds=age_seconds)
    db.commit()
    return instance


def test_a_recently_reporting_collector_is_still_online(db: Session):
    from src.core.services.evidence_scanner_service import resolve_scanner_liveness

    instance = _instance_with_heartbeat(db, age_seconds=60)

    assert resolve_scanner_liveness(instance) == "online"


def test_one_missed_cycle_does_not_flap_a_healthy_collector_offline(db: Session):
    """The tolerance is two cycles, not one — a slow network or a restart must
    not make a working Collector look dead."""
    from src.core.constants.evidence_scanner_enums import SCANNER_POLL_INTERVAL_SECONDS
    from src.core.services.evidence_scanner_service import resolve_scanner_liveness

    instance = _instance_with_heartbeat(db, age_seconds=SCANNER_POLL_INTERVAL_SECONDS + 5)

    assert resolve_scanner_liveness(instance) == "online"


def test_a_collector_that_stopped_reporting_is_offline(db: Session):
    """Søren's own case: heartbeat ~11 minutes old, agent could not even start,
    and the platform still said Connected."""
    from src.core.services.evidence_scanner_service import resolve_scanner_liveness

    instance = _instance_with_heartbeat(db, age_seconds=11 * 60)

    assert resolve_scanner_liveness(instance) == "offline"


def test_a_collector_that_never_reported_reads_as_registered_not_offline(db: Session):
    """"Never started" and "stopped" are different things to tell someone."""
    from src.core.services.evidence_scanner_service import resolve_scanner_liveness

    source = create_evidence_source(db, organization_id=1, name="Scanner", source_type=EvidenceSourceType.SCANNER)
    db.commit()
    instance = install_scanner(
        db, source, name="Primary", installation_method=ScannerInstallationMethod.DOCKER.value
    ).instance
    db.commit()

    assert instance.last_heartbeat_at is None
    assert resolve_scanner_liveness(instance) == "registered"


def test_a_stale_heartbeat_never_overrides_a_decision_a_person_made(db: Session):
    """Paused/revoked/retired are choices. Inferring "offline" over them would
    erase the decision and misreport why the Collector is not running."""
    from src.core.services.evidence_scanner_service import resolve_scanner_liveness

    for decided in ("paused", "revoked", "retired"):
        instance = _instance_with_heartbeat(db, age_seconds=60 * 60, status=decided)
        assert resolve_scanner_liveness(instance) == decided
