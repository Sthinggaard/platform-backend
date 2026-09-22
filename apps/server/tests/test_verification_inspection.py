"""CA-08.3 (#291) — an inspection cannot exceed the approved permission profile.

The criterion is a claim about capability, not intention, so these tests are
written to try to exceed the boundary rather than to confirm the happy path.
The two that matter most:

- ``test_a_capability_outside_the_profile_never_reaches_a_command`` — the whole
  epic's claim. Permission is asked *before* a template is resolved, so a
  refusal is never a template problem wearing a policy's name.
- ``test_ca_08_introduces_no_second_place_that_decides_what_is_permitted`` —
  #248's structural assertion, extended to this epic's code as the criterion
  requires.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.access_connector_enums import (
    AccessConnectorStatus,
    AccessConnectorType,
    ConnectorCredentialModel,
)
from src.core.constants.artefact_access_lifecycle_enums import ArtefactAccessState
from src.core.constants.leadership_authorization_enums import LeadershipAuthorizationStatus
from src.core.constants.permission_profile_enums import (
    PermissionSubjectKind,
    ConnectorCapability,
)
from src.core.constants.verification_command_templates import (
    COMMAND_TEMPLATES,
    SERVICE_CONFIG_TARGETS,
)
from src.core.constants.verification_inspection_enums import (
    VERIFICATION_COMMAND_SIGNATURE_VERSION,
    VERIFICATION_INSPECTION_AUDIT_AUTHORISED,
    VERIFICATION_INSPECTION_AUDIT_REFUSED,
    VerificationPlatform,
)
from src.core.constants.verification_run_enums import (
    VerificationApprovalSource,
    VerificationRunStatus,
)
from src.core.crypto import encrypt_command_signing_key
from src.core.database import Base
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.artefact_access_lifecycle import ArtefactAccessLifecycle
from src.core.model_defs.assets_runtime import (
    AssetStatus,
    ConnectivityStatus,
    Criticality,
    Environment,
    ScanStartMode,
    SetupConfidence,
)
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.model_defs.leadership_authorization import LeadershipAuthorization
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.model_defs.verification_run import VerificationRun
from src.core.models import Asset, AuditEvent, Organization, User
from src.core.services.permission_enforcement_service import CapabilityNotPermittedError
from src.core.services.permission_profile_service import (
    approve_profile,
    approve_service_config,
    create_profile_draft,
    submit_profile,
)
from src.core.services.permission_subject_service import register_permission_subject
from src.core.services.verification_inspection_service import (
    InspectionRefusedError,
    authorise_inspection,
)

ORG_ID = 1
ADMIN_USER_ID = 1
SPONSOR_USER_ID = 2
ASSET_ID = 10
INSTANCE_ID = "scanner-1"

OS_VERSION = ConnectorCapability.READ_OS_VERSION.value
PACKAGES = ConnectorCapability.READ_INSTALLED_PACKAGES.value
SOCKET_OWNER = ConnectorCapability.READ_LISTENING_SOCKET_OWNER.value
SERVICE_CONFIG = ConnectorCapability.READ_SERVICE_CONFIG.value
INSPECT_CONTAINER = ConnectorCapability.INSPECT_CONTAINER.value
API_INVENTORY = ConnectorCapability.READ_API_INVENTORY.value


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            User.__table__,
            Asset.__table__,
            LeadershipAuthorization.__table__,
            ScannerInstance.__table__,
            AccessConnector.__table__,
            PermissionSubject.__table__,
            PermissionProfile.__table__,
            ArtefactAccessLifecycle.__table__,
            VerificationRun.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=ORG_ID, name="Org", slug="org"),
            User(id=ADMIN_USER_ID, organization_id=ORG_ID, email="a@example.com", role="org_admin"),
            User(id=SPONSOR_USER_ID, organization_id=ORG_ID, email="s@example.com", role="org_admin"),
            Asset(
                id=ASSET_ID,
                organization_id=ORG_ID,
                type="Service",
                provider="collector",
                display_name="db-01",
                layer="Application",
                environment=Environment.PROD,
                criticality=Criticality.MEDIUM,
                status=AssetStatus.PARTIALLY_OBSERVED,
                connectivity_status=ConnectivityStatus.PENDING_VERIFICATION,
                setup_confidence=SetupConfidence.LOW,
                scan_start_mode=ScanStartMode.AUDIT_ONLY,
                findings_count=0,
                risk_score=0.0,
                confidence=0.4,
            ),
            LeadershipAuthorization(
                id="auth-1",
                organization_id=ORG_ID,
                status=LeadershipAuthorizationStatus.ACTIVE.value,
                sponsor_user_id=SPONSOR_USER_ID,
                approving_body="board_risk_committee",
                authorized_scope="Programme.",
            ),
            ScannerInstance(
                id=INSTANCE_ID,
                organization_id=ORG_ID,
                evidence_source_id="src-1",
                name="collector-1",
                installation_method="docker",
                activation_token_hash="x" * 64,
                command_signing_key_encrypted=encrypt_command_signing_key(
                    INSTANCE_ID, b"0" * 32
                ),
            ),
        ]
    )
    session.commit()
    yield session
    session.close()


def _connector(db: Session) -> AccessConnector:
    subject = register_permission_subject(
        db, organization_id=ORG_ID, subject_kind=PermissionSubjectKind.ACCESS_CONNECTOR
    )
    connector = AccessConnector(
        organization_id=ORG_ID,
        permission_subject_id=subject.id,
        scanner_instance_id=INSTANCE_ID,
        connector_type=AccessConnectorType.SSH_RESTRICTED.value,
        credential_model=ConnectorCredentialModel.OPERATOR_SUPPLIED.value,
        target_host="db-01.internal",
        status=AccessConnectorStatus.CONFIGURED.value,
    )
    db.add(connector)
    db.commit()
    return connector


def _approved(db: Session, connector: AccessConnector, capabilities: list[str]) -> PermissionProfile:
    profile = create_profile_draft(
        db,
        subject=connector,
        name="Deep verification",
        capabilities=capabilities,
        prepared_by_user_id=ADMIN_USER_ID,
    )
    submit_profile(db, profile, submitted_by_user_id=ADMIN_USER_ID)
    approve_profile(db, profile, approved_by_user_id=SPONSOR_USER_ID)
    db.commit()
    return profile


def _run(db: Session, profile: PermissionProfile, *, status: str = VerificationRunStatus.RUNNING.value) -> VerificationRun:
    lifecycle = ArtefactAccessLifecycle(
        organization_id=ORG_ID,
        asset_id=ASSET_ID,
        state=ArtefactAccessState.RUNNING.value,
        requested_choice="deep_verification",
        requested_at=datetime.now(timezone.utc),
        # The database refuses a running lifecycle with no approval stamped on
        # it (ck_artefact_access_run_requires_approval, #289). Satisfied rather
        # than worked around: a fixture that dodged the constraint would be
        # testing a state the product cannot reach.
        verification_approved_at=datetime.now(timezone.utc),
        verification_approved_by_user_id=SPONSOR_USER_ID,
        verification_approved_source=VerificationApprovalSource.PER_ARTEFACT.value,
        running_at=datetime.now(timezone.utc),
    )
    db.add(lifecycle)
    db.commit()
    run = VerificationRun(
        organization_id=ORG_ID,
        asset_id=ASSET_ID,
        lifecycle_id=lifecycle.id,
        approval_source=VerificationApprovalSource.PER_ARTEFACT.value,
        approved_by_user_id=SPONSOR_USER_ID,
        approved_at=datetime.now(timezone.utc),
        permission_profile_id=profile.id,
        status=status,
    )
    db.add(run)
    db.commit()
    return run


def _events(db: Session) -> list[str]:
    return [e.event_type for e in db.query(AuditEvent).all()]


# --- The criterion: an inspection cannot exceed the profile -----------------


def test_a_permitted_capability_produces_the_approved_command(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)

    inspection = authorise_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )

    assert inspection.argv == ("cat", "/etc/os-release")
    assert inspection.permission_profile_id == profile.id
    assert VERIFICATION_INSPECTION_AUDIT_AUTHORISED in _events(db)


def test_a_capability_outside_the_profile_never_reaches_a_command(db: Session):
    """The epic's central claim, and the reason for the order inside the service.

    The profile grants the OS version only. Asking for the package list must be
    refused by *policy* — not by anything about templates — and the refusal must
    be the enforcement point's, so the audit trail says what actually happened.
    """
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)

    with pytest.raises(CapabilityNotPermittedError):
        authorise_inspection(
            db,
            run=run,
            connector=connector,
            capability=PACKAGES,
            platform=VerificationPlatform.DEBIAN.value,
        )

    assert "permission_profile_capability_denied" in _events(db)
    assert VERIFICATION_INSPECTION_AUDIT_AUTHORISED not in _events(db)


def test_enforcement_fails_closed_when_no_profile_exists(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    # Take the profile out of force; nothing else changes.
    profile.status = "withdrawn"
    db.commit()

    with pytest.raises(CapabilityNotPermittedError):
        authorise_inspection(
            db, run=run, connector=connector, capability=OS_VERSION, platform=None
        )


def test_a_finished_run_cannot_inspect_anything_further(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile, status=VerificationRunStatus.COMPLETED.value)

    with pytest.raises(InspectionRefusedError):
        authorise_inspection(
            db, run=run, connector=connector, capability=OS_VERSION, platform=None
        )
    assert VERIFICATION_INSPECTION_AUDIT_REFUSED in _events(db)


def test_a_refusal_is_audited_because_the_attempt_is_the_record(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [API_INVENTORY])
    run = _run(db, profile)

    with pytest.raises(InspectionRefusedError):
        authorise_inspection(
            db, run=run, connector=connector, capability=API_INVENTORY, platform=None
        )

    refusals = [
        e for e in db.query(AuditEvent).all()
        if e.event_type == VERIFICATION_INSPECTION_AUDIT_REFUSED
    ]
    assert len(refusals) == 1
    assert refusals[0].metadata_json["capability"] == API_INVENTORY


# --- Option C: the command is the server's, not the Collector's -------------


def test_the_platform_decides_the_command_where_it_genuinely_differs(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [PACKAGES])
    run = _run(db, profile)

    debian = authorise_inspection(
        db, run=run, connector=connector, capability=PACKAGES,
        platform=VerificationPlatform.DEBIAN.value,
    )
    alpine = authorise_inspection(
        db, run=run, connector=connector, capability=PACKAGES,
        platform=VerificationPlatform.ALPINE.value,
    )

    assert debian.argv[0] == "dpkg-query"
    assert alpine.argv[0] == "apk"


def test_an_undetermined_platform_is_refused_rather_than_guessed(db: Session):
    """No fallback command. A guess would be an inspection nobody bounded."""
    connector = _connector(db)
    profile = _approved(db, connector, [PACKAGES])
    run = _run(db, profile)

    with pytest.raises(InspectionRefusedError, match="never determined"):
        authorise_inspection(
            db, run=run, connector=connector, capability=PACKAGES, platform=None
        )


def test_a_capability_that_is_not_a_host_read_has_no_command(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [API_INVENTORY])
    run = _run(db, profile)

    with pytest.raises(InspectionRefusedError, match="not something read by inspecting a host"):
        authorise_inspection(
            db, run=run, connector=connector, capability=API_INVENTORY, platform=None
        )


def test_a_parameter_outside_its_approved_shape_is_refused(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [INSPECT_CONTAINER])
    run = _run(db, profile)
    profile.docker_socket_approved_at = datetime.now(timezone.utc)
    db.commit()

    with pytest.raises(InspectionRefusedError):
        authorise_inspection(
            db, run=run, connector=connector, capability=INSPECT_CONTAINER, platform=None,
            parameters={"container_id": "abc; rm -rf /"},
        )


def test_a_parameter_the_template_never_declared_is_refused(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)

    with pytest.raises(InspectionRefusedError):
        authorise_inspection(
            db, run=run, connector=connector, capability=OS_VERSION, platform=None,
            parameters={"path": "/etc/shadow"},
        )


def test_every_command_is_an_argv_list_and_every_placeholder_is_a_whole_element():
    """The property that actually makes substitution safe.

    Not "no metacharacters": ``dpkg-query``'s ``-f=${Package}`` legitimately
    contains ``$``, and it is harmless because there is no shell for it to mean
    anything to. The real invariants are that a template is a list of arguments
    rather than a sentence, and that a placeholder occupies a **whole** element.

    The second one is the trap this test exists to catch. ``parameter_names``
    matches ``{name}`` only as a complete element, so a template written as
    ``--file={config_path}`` would never be recognised as taking a parameter —
    and would ship the literal text ``--file={config_path}`` to the host. Worse,
    a caller-controlled value spliced into a larger argument is the one shape
    where substitution could widen what a command reaches.
    """
    for capability, by_platform in COMMAND_TEMPLATES.items():
        for platform, argv in by_platform.items():
            assert isinstance(argv, tuple), f"{capability}/{platform}"
            assert len(argv) >= 1, f"{capability}/{platform}"

            # The program itself is never parameterised and never a path.
            assert re.fullmatch(r"[a-z][a-z0-9-]*", argv[0]), f"{capability}/{platform}: {argv[0]}"

            for element in argv:
                assert isinstance(element, str)
                for placeholder in re.findall(r"\{[a-z_]+\}", element):
                    assert element == placeholder, (
                        f"{capability}/{platform}: {placeholder} must be its own argv element, "
                        f"not embedded in {element!r}"
                    )


def test_every_placeholder_in_a_template_has_a_declared_shape():
    """A placeholder with no pattern is refused at runtime; catch it at import.

    The runtime default is refusal, which is right, but a template shipped with
    an undeclared parameter would be a capability that can never run — a defect
    that would only surface the first time somebody tried to use it.
    """
    from src.core.constants.verification_command_templates import (
        parameter_names,
        parameter_pattern,
    )

    for capability, by_platform in COMMAND_TEMPLATES.items():
        for platform, argv in by_platform.items():
            for name in parameter_names(argv):
                assert parameter_pattern(name) is not None, (
                    f"{capability}/{platform}: '{name}' has no declared shape"
                )


# --- read_service_config: its own approval, and never a caller's path -------


def test_approving_the_profile_does_not_grant_reading_configuration(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [SERVICE_CONFIG])
    run = _run(db, profile)

    with pytest.raises(CapabilityNotPermittedError, match="its own explicit approval"):
        authorise_inspection(
            db, run=run, connector=connector, capability=SERVICE_CONFIG, platform=None,
            config_target="nginx",
        )


def test_reading_configuration_works_only_after_its_own_approval(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [SERVICE_CONFIG])
    approve_service_config(db, profile, approved_by_user_id=SPONSOR_USER_ID)
    db.commit()
    run = _run(db, profile)

    inspection = authorise_inspection(
        db, run=run, connector=connector, capability=SERVICE_CONFIG, platform=None,
        config_target="nginx",
    )

    assert inspection.argv == ("cat", SERVICE_CONFIG_TARGETS["nginx"])
    assert "permission_profile_service_config_approved" in _events(db)


def test_a_caller_cannot_choose_which_file_is_read(db: Session):
    """Søren's condition on keeping this capability at all.

    A caller names a target from the approved set. Supplying a path directly —
    even alongside a valid target — must not reach the command, or a bounded
    capability becomes an arbitrary file read wearing its name.
    """
    connector = _connector(db)
    profile = _approved(db, connector, [SERVICE_CONFIG])
    approve_service_config(db, profile, approved_by_user_id=SPONSOR_USER_ID)
    db.commit()
    run = _run(db, profile)

    inspection = authorise_inspection(
        db, run=run, connector=connector, capability=SERVICE_CONFIG, platform=None,
        parameters={"config_path": "/etc/shadow"},
        config_target="nginx",
    )
    assert inspection.argv == ("cat", SERVICE_CONFIG_TARGETS["nginx"])
    assert "/etc/shadow" not in inspection.argv

    with pytest.raises(InspectionRefusedError, match="not a configuration file"):
        authorise_inspection(
            db, run=run, connector=connector, capability=SERVICE_CONFIG, platform=None,
            config_target="/etc/shadow",
        )


def test_every_approved_config_target_is_an_absolute_path():
    for name, path in SERVICE_CONFIG_TARGETS.items():
        assert path.startswith("/"), name
        assert ".." not in path, name


# --- Signing: the boundary is enforced by something the Collector checks ----


def test_the_signature_covers_the_command_and_its_own_domain(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)

    inspection = authorise_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )

    assert inspection.signature_version == VERIFICATION_COMMAND_SIGNATURE_VERSION
    assert len(inspection.signature) == 64


def test_two_different_commands_do_not_share_a_signature(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [PACKAGES])
    run = _run(db, profile)

    debian = authorise_inspection(
        db, run=run, connector=connector, capability=PACKAGES,
        platform=VerificationPlatform.DEBIAN.value,
    )
    rhel = authorise_inspection(
        db, run=run, connector=connector, capability=PACKAGES,
        platform=VerificationPlatform.RHEL.value,
    )
    assert debian.signature != rhel.signature


def test_a_collector_with_no_signing_key_is_refused(db: Session):
    """No inheriting discovery's shared-secret fallback.

    A new capability starting life with a legacy weakness is how a compatibility
    shim becomes permanent.
    """
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    instance = db.query(ScannerInstance).filter(ScannerInstance.id == INSTANCE_ID).first()
    instance.command_signing_key_encrypted = None
    db.commit()

    with pytest.raises(InspectionRefusedError, match="no signing key"):
        authorise_inspection(
            db, run=run, connector=connector, capability=OS_VERSION, platform=None
        )


# --- Criterion 4: no second place decides what is permitted ----------------


def test_ca_08_introduces_no_second_place_that_decides_what_is_permitted():
    """#248's structural assertion, extended to this epic as the criterion asks.

    CA-08's code may *ask* whether a capability is permitted; it may never
    answer. A module that reads a profile's capability list is deciding, whether
    or not it calls itself an enforcement point.
    """
    source_root = Path(__file__).resolve().parents[1] / "src"
    offenders: list[str] = []

    for path in source_root.rglob("*.py"):
        if "verification" not in path.name:
            continue
        text = path.read_text()
        if re.search(r"\.capabilities\b", text) or re.search(r"\.docker_socket_approved_at\b", text):
            offenders.append(path.relative_to(source_root).as_posix())

    assert offenders == [], (
        "CA-08 code must ask assert_capability_permitted, never read a profile's "
        f"grant itself; found: {offenders}"
    )


def test_the_verification_vocabulary_stays_disjoint_from_discovery():
    """The criterion's real content: two grants must not become one answer."""
    from src.core.constants.discovery_scope_proposal_enums import DiscoveryCapability

    connector_capabilities = {member.value for member in ConnectorCapability}
    discovery_capabilities = {member.value for member in DiscoveryCapability}
    assert connector_capabilities & discovery_capabilities == set()

    # And every host-read template is keyed by a connector capability, so a
    # discovery capability can never resolve to a deep-verification command.
    assert set(COMMAND_TEMPLATES) <= connector_capabilities
