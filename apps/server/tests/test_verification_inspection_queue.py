"""CA-08.2 (#290) — queueing an inspection, handing it over, taking the report.

Written after the wiring, because the wiring shipped a defect nothing could
catch: ``report_inspection`` was built without the ``/api/v1`` prefix every other
client path carries, and would have 404'd against a live server. The lesson
those tests encode is that the *shape of the contract* needs asserting, not only
the behaviour behind it.

The one that matters most is
``test_an_inspection_cannot_be_queued_outside_the_approved_profile`` — queueing
goes through ``authorise_inspection`` or the boundary is decorative.
"""

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

from src.core.constants.access_connector_enums import (
    AccessConnectorStatus,
    AccessConnectorType,
    ConnectorCredentialModel,
)
from src.core.constants.artefact_access_lifecycle_enums import ArtefactAccessState
from src.core.constants.leadership_authorization_enums import LeadershipAuthorizationStatus
from src.core.constants.permission_profile_enums import (
    ConnectorCapability,
    PermissionSubjectKind,
)
from src.core.constants.verification_inspection_enums import (
    InspectionCommandStatus,
    InspectionOutcome,
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
    AssetFinding,
    AssetFindingStatus,
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
from src.core.model_defs.verification_inspection_command import VerificationInspectionCommand
from src.core.model_defs.verification_run import VerificationRun
from src.core.models import Asset, AuditEvent, Organization, User
from src.core.services.permission_enforcement_service import CapabilityNotPermittedError
from src.core.services.permission_profile_service import (
    approve_profile,
    create_profile_draft,
    submit_profile,
)
from src.core.services.permission_subject_service import register_permission_subject
from src.core.services.verification_inspection_queue_service import (
    InspectionCommandError,
    envelope_for,
    next_inspection_for_scanner,
    queue_inspection,
    record_inspection_result,
    reject_inspection,
)

ORG_ID = 1
ADMIN_USER_ID = 1
SPONSOR_USER_ID = 2
ASSET_ID = 10
INSTANCE_ID = "scanner-1"

OS_VERSION = ConnectorCapability.READ_OS_VERSION.value
PACKAGES = ConnectorCapability.READ_INSTALLED_PACKAGES.value


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
            VerificationInspectionCommand.__table__,
            AssetFinding.__table__,
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
                command_signing_key_encrypted=encrypt_command_signing_key(INSTANCE_ID, b"0" * 32),
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


def _run(db: Session, profile: PermissionProfile) -> VerificationRun:
    now = datetime.now(timezone.utc)
    lifecycle = ArtefactAccessLifecycle(
        organization_id=ORG_ID,
        asset_id=ASSET_ID,
        state=ArtefactAccessState.RUNNING.value,
        requested_choice="deep_verification",
        requested_at=now,
        verification_approved_at=now,
        verification_approved_by_user_id=SPONSOR_USER_ID,
        verification_approved_source=VerificationApprovalSource.PER_ARTEFACT.value,
        running_at=now,
    )
    db.add(lifecycle)
    db.commit()
    run = VerificationRun(
        organization_id=ORG_ID,
        asset_id=ASSET_ID,
        lifecycle_id=lifecycle.id,
        approval_source=VerificationApprovalSource.PER_ARTEFACT.value,
        approved_by_user_id=SPONSOR_USER_ID,
        approved_at=now,
        permission_profile_id=profile.id,
        status=VerificationRunStatus.RUNNING.value,
    )
    db.add(run)
    db.commit()
    return run


def _events(db: Session) -> list[str]:
    return [event.event_type for event in db.query(AuditEvent).all()]


# --- Queueing goes through the boundary ------------------------------------


def test_an_inspection_cannot_be_queued_outside_the_approved_profile(db: Session):
    """The boundary is decorative if the queue can go around it.

    Queueing calls ``authorise_inspection``, which is the only caller of
    ``assert_capability_permitted``. A command reaching the queue without it
    would be an approved-looking instruction nobody authorised.
    """
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)

    with pytest.raises(CapabilityNotPermittedError):
        queue_inspection(
            db, run=run, connector=connector, capability=PACKAGES, platform="debian"
        )

    assert db.query(VerificationInspectionCommand).count() == 0


def test_a_queued_inspection_records_what_authorised_it(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)

    command = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()

    assert command.argv == ["cat", "/etc/os-release"]
    assert command.permission_profile_id == profile.id
    assert command.status == InspectionCommandStatus.PENDING.value
    assert len(command.signature) == 64


# --- Delivery ---------------------------------------------------------------


def test_the_collector_is_given_the_oldest_pending_inspection_once(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    first = queue_inspection(db, run=run, connector=connector, capability=OS_VERSION, platform=None)
    first.issued_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=60)
    queue_inspection(db, run=run, connector=connector, capability=OS_VERSION, platform=None)
    db.commit()

    claimed = next_inspection_for_scanner(db, scanner_instance_id=INSTANCE_ID)
    db.commit()

    assert claimed.id == first.id
    assert claimed.status == InspectionCommandStatus.DELIVERED.value

    # Handed over once. A second poll must not return the same work again, or
    # one approved read becomes two.
    second = next_inspection_for_scanner(db, scanner_instance_id=INSTANCE_ID)
    db.commit()
    assert second.id != first.id


def test_expired_work_is_retired_rather_than_handed_over(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    command.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=1)
    db.commit()

    assert next_inspection_for_scanner(db, scanner_instance_id=INSTANCE_ID) is None
    db.commit()
    db.refresh(command)
    assert command.status == InspectionCommandStatus.EXPIRED.value


def test_another_collector_is_never_given_this_work(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    queue_inspection(db, run=run, connector=connector, capability=OS_VERSION, platform=None)
    db.commit()

    assert next_inspection_for_scanner(db, scanner_instance_id="scanner-2") is None


def test_the_envelope_carries_the_signature_as_issued(db: Session):
    """Rebuilt from the row, never re-signed.

    Re-deriving the signature at delivery time would sign whatever the row says
    *now*, so a tampered argv would verify perfectly — which is the one thing
    the signature exists to prevent.
    """
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()

    envelope = envelope_for(command, run=run)
    assert envelope["signature"] == command.signature
    assert envelope["argv"] == ["cat", "/etc/os-release"]
    assert envelope["command_id"] == command.id
    assert envelope["scanner_instance_id"] == INSTANCE_ID


def test_the_envelope_has_nowhere_to_put_a_credential(db: Session):
    """CA-07.2, at the wire. Asserted on both sides — its twin is in the agent suite."""
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()

    envelope = envelope_for(command, run=run)
    for forbidden in ("password", "private_key", "identity_file", "username", "credential", "token"):
        assert forbidden not in envelope, forbidden


# --- The report -------------------------------------------------------------


def test_the_engine_reads_what_the_collector_reported(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()

    record_inspection_result(
        db, command=command, exit_code=255, stderr="Permission denied (publickey)."
    )
    db.commit()

    assert command.outcome == InspectionOutcome.AUTHENTICATION_FAILED.value
    assert command.status == InspectionCommandStatus.COMPLETED.value
    assert "verification_inspection_reported" in [e.event_type for e in db.query(AuditEvent).all()]


def test_a_second_report_cannot_overwrite_the_first(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()
    record_inspection_result(db, command=command, exit_code=0, stderr="")
    db.commit()

    with pytest.raises(InspectionCommandError):
        record_inspection_result(db, command=command, exit_code=255, stderr="Permission denied")


def test_a_refusal_by_the_collector_is_not_a_fact_about_the_host(db: Session):
    """Two different failures that must not look alike.

    "The Collector would not run this instruction" says something about us;
    "the host refused this command" says something about the customer's estate.
    Only the second belongs in what an organisation reads.
    """
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()

    reject_inspection(db, command=command, reason="command_signature_invalid")
    db.commit()

    assert command.status == InspectionCommandStatus.REJECTED.value
    assert command.outcome is None


def test_stderr_is_bounded_before_it_is_stored(db: Session):
    """It arrives from a customer's host, and it is not evidence.

    An unbounded column filled from a far side is somewhere a very large or very
    sensitive string can quietly come to rest.
    """
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()

    record_inspection_result(db, command=command, exit_code=1, stderr="x" * 10_000)
    db.commit()
    assert len(command.stderr) == 4000


def test_the_command_row_has_nowhere_to_store_output(db: Session):
    """Evidence goes to the evidence services, not onto the command.

    A ``stdout`` column here would be a second place a credential read out of a
    configuration file could come to rest, and #296 exists because that output
    can contain one.
    """
    columns = {column.name for column in VerificationInspectionCommand.__table__.columns}
    assert "stdout" not in columns
    assert not [name for name in columns if "output" in name or "payload" in name]


def test_a_queued_envelope_still_verifies_against_the_agents_own_rules(db: Session):
    """The regression that #281's timestamp test caught, asserted end to end.

    ``verification_inspection_commands`` columns are ``timestamp without time
    zone``, so they read back naive — while the signature was computed over an
    *aware* ``isoformat()`` ending ``+00:00``. Rebuilding the envelope from the
    naive value produced a different payload string from the one that was
    signed, and **every** inspection delivered from this queue would have failed
    verification on the Collector.

    Recomputed here the way ``scanner_agent.command_signing`` does, rather than
    by importing it: the agent bundle is deliberately dependency-free from the
    server, so the two mirror each other and this is the test that proves the
    mirror still lines up.
    """
    import hashlib
    import hmac
    import json

    from src.core.crypto import decrypt_command_signing_key

    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()

    # Round-trip through the database, so the naive-column read is real.
    db.expire_all()
    command = db.query(VerificationInspectionCommand).filter_by(id=command.id).first()
    envelope = envelope_for(command, run=run)

    payload = json.dumps(
        {
            "signatureVersion": envelope["signature_version"],
            "runId": envelope["run_id"],
            "organizationId": envelope["organization_id"],
            "assetId": envelope["asset_id"],
            "connectorId": envelope["connector_id"],
            "capability": envelope["capability"],
            "argv": list(envelope["argv"]),
            "issuedAt": envelope["issued_at"],
            "expiresAt": envelope["expires_at"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    instance = db.query(ScannerInstance).filter_by(id=INSTANCE_ID).first()
    key = decrypt_command_signing_key(instance.id, instance.command_signing_key_encrypted)
    expected = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    assert expected == envelope["signature"], (
        "a queued envelope no longer matches its own signature — check that the "
        "timestamps carry their UTC offset"
    )


# --- CA-08.4: what the run established -------------------------------------


def test_a_successful_inspection_records_what_it_identified(db: Session):
    """The epic's payoff: the artefact stops being "http-proxy" and gets a name."""
    import json

    from src.core.constants.artefact_identity_evidence_enums import ArtefactIdentityBasis

    connector = _connector(db)
    profile = _approved(db, connector, [ConnectorCapability.INSPECT_CONTAINER.value])
    profile.docker_socket_approved_at = datetime.now(timezone.utc)
    db.commit()
    run = _run(db, profile)
    command = queue_inspection(
        db,
        run=run,
        connector=connector,
        capability=ConnectorCapability.INSPECT_CONTAINER.value,
        platform=None,
        parameters={"container_id": "a" * 12},
    )
    db.commit()

    record_inspection_result(
        db,
        command=command,
        exit_code=0,
        stderr="",
        stdout=json.dumps([{"Config": {"Image": "makeplane/plane-frontend:v0.23.1"}}]),
    )
    db.commit()

    assert command.identity_name == "makeplane/plane-frontend:v0.23.1"
    assert command.identity_basis == ArtefactIdentityBasis.CONTAINER_IMAGE.value

    # And the artefact itself now reads as that, rather than as an address.
    asset = db.query(Asset).filter_by(id=ASSET_ID).first()
    assert asset.display_name == "makeplane/plane-frontend:v0.23.1"
    assert "verification_identity_determined" in _events(db)


def test_an_inspection_that_identified_nothing_records_a_finding(db: Session):
    """An empty result is a finding, not a gap — so it is audited, not skipped."""
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()

    record_inspection_result(db, command=command, exit_code=0, stderr="", stdout="   ")
    db.commit()

    assert command.identity_name is None
    assert "verification_identity_undetermined" in _events(db)
    asset = db.query(Asset).filter_by(id=ASSET_ID).first()
    assert asset.display_name == "db-01"  # unchanged


def test_output_that_cannot_be_redacted_is_refused_and_the_refusal_is_recorded(db: Session):
    """The allow-list still holds something back, and says so when it does.

    This was ``read_service_config`` until #296 gave it a redactor. It is now
    ``read_running_processes``: ``ps`` output is command lines, and anything
    started with ``--password=…`` is visible there — which is not the decidable
    key-based problem a configuration file is.

    Dropping it silently would leave a person looking at a successful run that
    established nothing, unable to tell the platform chose not to look.
    """
    connector = _connector(db)
    profile = _approved(db, connector, [ConnectorCapability.READ_RUNNING_PROCESSES.value])
    db.commit()
    run = _run(db, profile)
    command = queue_inspection(
        db,
        run=run,
        connector=connector,
        capability=ConnectorCapability.READ_RUNNING_PROCESSES.value,
        platform=None,
    )
    db.commit()

    record_inspection_result(
        db, command=command, exit_code=0, stderr="",
        stdout="1234 1 java --password=hunter2",
    )
    db.commit()

    assert command.identity_name is None
    assert "verification_identity_output_withheld" in _events(db)
    # And nothing resembling the output was stored anywhere on the row.
    assert "hunter2" not in (command.stderr or "")


def test_weaker_later_evidence_does_not_downgrade_a_verified_name(db: Session):
    """A run that cost a person a decision must not be undone by a lesser one."""
    import json

    connector = _connector(db)
    profile = _approved(
        db,
        connector,
        [ConnectorCapability.INSPECT_CONTAINER.value, OS_VERSION],
    )
    profile.docker_socket_approved_at = datetime.now(timezone.utc)
    db.commit()
    run = _run(db, profile)

    strong = queue_inspection(
        db, run=run, connector=connector,
        capability=ConnectorCapability.INSPECT_CONTAINER.value, platform=None,
        parameters={"container_id": "b" * 12},
    )
    db.commit()
    record_inspection_result(
        db, command=strong, exit_code=0, stderr="",
        stdout=json.dumps([{"Config": {"Image": "grafana/grafana:11.1.0"}}]),
    )
    db.commit()

    weak = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()
    record_inspection_result(
        db, command=weak, exit_code=0, stderr="",
        stdout='PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"',
    )
    db.commit()

    asset = db.query(Asset).filter_by(id=ASSET_ID).first()
    assert asset.display_name == "grafana/grafana:11.1.0"


def test_a_failed_inspection_establishes_nothing(db: Session):
    """No login, no evidence. The outcome is the finding."""
    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()

    record_inspection_result(
        db, command=command, exit_code=255, stderr="Permission denied (publickey).",
        stdout="",
    )
    db.commit()

    assert command.identity_name is None
    assert "verification_identity_determined" not in _events(db)


# --- CA-08.6 (#294): the surface a person reads ----------------------------
#
# Kept in this file rather than its own: the surface reads exactly the rows the
# tests above create, and duplicating a 229-line fixture to assert on them would
# be the DRY failure the repo's own rules forbid.


def test_an_artefact_nobody_examined_reads_differently_from_one_that_found_nothing(db: Session):
    """CA-08.6's criterion, and the distinction the whole surface exists for.

    They are opposite facts: one is an argument for granting access, the other
    is the record that access was granted and spent. A surface that renders them
    alike invites asking for an approval somebody already gave.
    """
    from src.core.services.verification_surface_service import (
        build_artefact_verification_view,
    )

    never = build_artefact_verification_view(db, organization_id=ORG_ID, asset_id=ASSET_ID)
    assert never.ever_verified is False
    assert "never been examined" in never.summary

    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()
    record_inspection_result(db, command=command, exit_code=0, stderr="", stdout="")
    db.commit()

    examined = build_artefact_verification_view(db, organization_id=ORG_ID, asset_id=ASSET_ID)
    assert examined.ever_verified is True
    assert "never been examined" not in examined.summary
    assert examined.summary != never.summary


def test_the_surface_says_what_was_established_and_who_approved_it(db: Session):
    import json

    from src.core.services.verification_surface_service import (
        build_artefact_verification_view,
    )

    connector = _connector(db)
    profile = _approved(db, connector, [ConnectorCapability.INSPECT_CONTAINER.value])
    profile.docker_socket_approved_at = datetime.now(timezone.utc)
    db.commit()
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector,
        capability=ConnectorCapability.INSPECT_CONTAINER.value, platform=None,
        parameters={"container_id": "c" * 12},
    )
    db.commit()
    record_inspection_result(
        db, command=command, exit_code=0, stderr="",
        stdout=json.dumps([{"Config": {"Image": "makeplane/plane-frontend:v0.23.1"}}]),
    )
    db.commit()

    view = build_artefact_verification_view(db, organization_id=ORG_ID, asset_id=ASSET_ID)

    assert view.identity_name == "makeplane/plane-frontend:v0.23.1"
    assert view.identity_explanation == "read from the container image it was built from"
    assert view.runs[0].approved_by == "s@example.com"
    # Business language, not a capability id.
    assert view.runs[0].inspections[0].what_was_read == "What one container is built from"
    assert "exit" not in view.runs[0].inspections[0].what_it_means


def test_no_field_on_this_surface_can_carry_secret_material(db: Session):
    """CA-08.6's redaction criterion, asserted rather than assumed.

    ``stderr`` arrives verbatim from a customer's host, and nothing about its
    shape stops a credential appearing in it. Redaction is applied at CA-07.6's
    one choke point over the whole payload, so a field added later is covered
    without anybody remembering to cover it.
    """
    from src.core.constants.secret_redaction import REDACTED
    from src.core.services.verification_surface_service import (
        build_artefact_verification_view,
        view_as_dict,
    )

    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()
    record_inspection_result(db, command=command, exit_code=0, stderr="", stdout="")
    db.commit()

    payload = view_as_dict(
        build_artefact_verification_view(db, organization_id=ORG_ID, asset_id=ASSET_ID)
    )

    def _walk(value):
        if isinstance(value, dict):
            for key, inner in value.items():
                # Any secret-bearing key must already read as redacted.
                from src.core.constants.secret_redaction import is_secret_key

                if is_secret_key(str(key)):
                    assert inner == REDACTED, key
                _walk(inner)
        elif isinstance(value, list):
            for item in value:
                _walk(item)

    _walk(payload)


def test_every_timestamp_leaves_this_surface_with_an_offset(db: Session):
    """#281, on a route that returns a plain dict.

    ``UtcTimestamp`` never sees these values, so the timestamp-boundary test
    cannot scan them. Left naive they serialise as ``2026-08-24T16:37:27`` and a
    browser outside UTC renders the event at its own local hour.
    """
    from src.core.services.verification_surface_service import (
        build_artefact_verification_view,
        view_as_dict,
    )

    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()
    record_inspection_result(db, command=command, exit_code=0, stderr="", stdout="")
    db.commit()

    payload = view_as_dict(
        build_artefact_verification_view(db, organization_id=ORG_ID, asset_id=ASSET_ID)
    )
    stamps = [payload["runs"][0]["began_at"], payload["runs"][0]["inspections"][0]["completed_at"]]
    for stamp in stamps:
        assert stamp is not None
        assert stamp.endswith("+00:00"), stamp


def test_one_organisations_verification_is_unreachable_from_another(db: Session):
    """CA-08.6's tenant-isolation criterion."""
    from src.core.services.verification_surface_service import (
        build_artefact_verification_view,
    )

    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    queue_inspection(db, run=run, connector=connector, capability=OS_VERSION, platform=None)
    db.commit()

    other = build_artefact_verification_view(db, organization_id=999, asset_id=ASSET_ID)
    assert other.ever_verified is False
    assert other.runs == []


# --- #296: a credential in the open is a finding about the customer ---------


def test_a_stored_credential_becomes_a_finding_the_organisation_can_act_on(db: Session):
    """Søren's point, and the half redaction alone does not cover.

    Redaction protects *us* — it keeps the platform inside CA-07.2. It does
    nothing for the customer, whose credential is still in a readable file. A
    platform that knew and said nothing would be the wrong kind of quiet.
    """
    from src.core.services.permission_profile_service import approve_service_config

    connector = _connector(db)
    profile = _approved(db, connector, [ConnectorCapability.READ_SERVICE_CONFIG.value])
    approve_service_config(db, profile, approved_by_user_id=SPONSOR_USER_ID)
    db.commit()
    run = _run(db, profile)
    command = queue_inspection(
        db, run=run, connector=connector,
        capability=ConnectorCapability.READ_SERVICE_CONFIG.value, platform=None,
        config_target="nginx",
    )
    db.commit()

    record_inspection_result(
        db, command=command, exit_code=0, stderr="",
        stdout="user = admin\npassword = [redacted]\n",
        credential_findings=[
            {"target": "nginx", "setting": "password", "kind": "secret_setting"}
        ],
    )
    db.commit()

    finding = db.query(AssetFinding).filter_by(asset_id=ASSET_ID).one()
    assert finding.status is AssetFindingStatus.OPEN
    assert "nginx" in finding.title
    # Business language: what it means for them, not what the file contained.
    assert "plain text" in finding.description
    assert "rotate" in finding.description or "rotated" in finding.description


def test_the_finding_holds_no_value_and_no_file_path(db: Session):
    """The tension #296 exists to resolve, asserted.

    Reporting the finding is proof we read the thing we promised never to hold,
    so the report has to stand without it. And no path: a report naming exact
    paths across an estate is a map for anyone who later gets into Risklence.
    """
    from src.core.services.credential_exposure_service import record_credential_exposure

    record_credential_exposure(
        db, organization_id=ORG_ID, asset_id=ASSET_ID,
        findings=[{"target": "nginx", "setting": "password", "kind": "secret_setting"}],
    )
    db.commit()

    finding = db.query(AssetFinding).filter_by(asset_id=ASSET_ID).one()
    blob = f"{finding.title} {finding.description} {finding.evidence_refs}"
    assert "hunter2" not in blob
    assert "/etc/" not in blob
    assert ".conf" not in blob


def test_reading_the_same_file_again_does_not_pile_up_findings(db: Session):
    """A weekly schedule would otherwise turn one real problem into a growing pile."""
    from src.core.services.credential_exposure_service import record_credential_exposure

    for _ in range(3):
        record_credential_exposure(
            db, organization_id=ORG_ID, asset_id=ASSET_ID,
            findings=[{"target": "nginx", "setting": "password", "kind": "secret_setting"}],
        )
        db.commit()

    assert db.query(AssetFinding).filter_by(asset_id=ASSET_ID).count() == 1


def test_a_resolved_finding_is_not_reopened_by_seeing_it_again(db: Session):
    """Somebody decided it was handled. Overruling that is not ours to do."""
    from src.core.services.credential_exposure_service import record_credential_exposure

    record_credential_exposure(
        db, organization_id=ORG_ID, asset_id=ASSET_ID,
        findings=[{"target": "nginx", "setting": "password", "kind": "secret_setting"}],
    )
    db.commit()
    finding = db.query(AssetFinding).filter_by(asset_id=ASSET_ID).one()
    finding.status = AssetFindingStatus.RESOLVED
    db.commit()

    record_credential_exposure(
        db, organization_id=ORG_ID, asset_id=ASSET_ID,
        findings=[{"target": "nginx", "setting": "password", "kind": "secret_setting"}],
    )
    db.commit()
    db.refresh(finding)
    assert finding.status is AssetFindingStatus.RESOLVED


def test_configuration_output_is_carried_now_that_redaction_exists(db: Session):
    """The allow-list entry #296 earned.

    Before it, this capability's output stayed on the Collector and a run that
    succeeded established nothing. A test guards the entry because it depends on
    code running somewhere else entirely.
    """
    from src.core.constants.verification_command_templates import (
        OUTPUT_SAFE_BEFORE_REDACTION,
    )

    assert ConnectorCapability.READ_SERVICE_CONFIG.value in OUTPUT_SAFE_BEFORE_REDACTION
    # And the one still held back, for a reason redaction does not solve: ps
    # output is command lines, which is not a decidable key-based problem.
    assert (
        ConnectorCapability.READ_RUNNING_PROCESSES.value not in OUTPUT_SAFE_BEFORE_REDACTION
    )


# --- CA-08.5 (#293): stopping, failing, and not being stranded --------------


def _lifecycle_for(db: Session, run: VerificationRun) -> ArtefactAccessLifecycle:
    return db.query(ArtefactAccessLifecycle).filter_by(id=run.lifecycle_id).one()


def test_a_failed_run_no_longer_strands_the_artefact(db: Session):
    """#289 left the lifecycle in RUNNING on purpose, and left it stranded.

    Moving a failure to COMPLETE would make it indistinguishable from a success
    — that part was right. What was missing was any other way out: RUNNING had
    one exit and it was the wrong one. It goes back to APPROVED, because the run
    broke and the approval did not.
    """
    from src.core.services.verification_run_service import fail_verification_run

    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    lifecycle = _lifecycle_for(db, run)

    fail_verification_run(db, run, reason="Something broke", lifecycle=lifecycle)
    db.commit()

    assert run.status == VerificationRunStatus.FAILED.value
    assert lifecycle.state == ArtefactAccessState.APPROVED.value
    # Never COMPLETE — that was the point of #289's original decision.
    assert lifecycle.completed_at is None
    # And nothing claims a run is under way.
    assert lifecycle.running_at is None


def test_a_cancelled_run_reads_differently_from_a_failed_one(db: Session):
    """"We stopped it" and "it broke" are different facts about the organisation.

    Only one of them is a defect worth anybody's attention, and a surface that
    rendered both as "failed" would send somebody looking for a fault that was
    a decision.
    """
    from src.core.services.verification_run_service import cancel_verification_run

    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    lifecycle = _lifecycle_for(db, run)

    cancel_verification_run(db, run, lifecycle=lifecycle, actor_user_id=SPONSOR_USER_ID)
    db.commit()

    assert run.status == VerificationRunStatus.CANCELLED.value
    assert run.status != VerificationRunStatus.FAILED.value
    assert "verification_run_cancelled" in _events(db)
    assert lifecycle.state == ArtefactAccessState.APPROVED.value


def test_cancelling_takes_back_work_a_collector_has_not_run_yet(db: Session):
    """Otherwise a Collector polling afterwards runs it and reports evidence
    gathered for a run somebody stopped."""
    from src.core.services.verification_run_service import cancel_verification_run

    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    queued = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()

    cancel_verification_run(db, run, lifecycle=_lifecycle_for(db, run))
    db.commit()
    db.refresh(queued)

    assert queued.status == InspectionCommandStatus.EXPIRED.value


def test_cancelling_does_not_rewrite_what_already_happened(db: Session):
    """A completed inspection describes something that genuinely ran on a host.

    Rewriting it to hide it would be falsifying the record rather than
    cancelling work.
    """
    from src.core.services.verification_run_service import cancel_verification_run

    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    done = queue_inspection(
        db, run=run, connector=connector, capability=OS_VERSION, platform=None
    )
    db.commit()
    record_inspection_result(db, command=done, exit_code=0, stderr="", stdout="")
    db.commit()

    cancel_verification_run(db, run, lifecycle=_lifecycle_for(db, run))
    db.commit()
    db.refresh(done)

    assert done.status == InspectionCommandStatus.COMPLETED.value
    assert done.outcome == InspectionOutcome.SUCCEEDED.value


def test_a_run_whose_collector_has_stopped_is_reported_as_stalled(db: Session):
    """The failure this is for: a Collector dies mid-run.

    It sends no result and no failure, because it is not there to send
    anything. The run stays RUNNING and the surface shows an examination in
    progress that will never end — and nobody is told, because nothing happened.
    """
    from src.core.services.verification_run_liveness_service import assess_run_liveness

    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    queue_inspection(db, run=run, connector=connector, capability=OS_VERSION, platform=None)
    # Last heard from days ago. Derived from the heartbeat, never swept.
    instance = db.query(ScannerInstance).filter_by(id=INSTANCE_ID).one()
    instance.last_heartbeat_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=3)
    db.commit()

    liveness = assess_run_liveness(db, run=run)

    assert liveness.stalled is True
    # Business language, per the platform's own rule.
    assert "Collector stopped reporting" in liveness.explanation
    assert "heartbeat" not in liveness.explanation.lower()


def test_a_healthy_collector_is_not_reported_as_stalled(db: Session):
    """A slow scan and a dead Collector look identical on a clock.

    Guessing between them from elapsed time is how a healthy long-running job
    gets killed, so silence is the signal — not duration.
    """
    from src.core.services.verification_run_liveness_service import assess_run_liveness

    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    queue_inspection(db, run=run, connector=connector, capability=OS_VERSION, platform=None)
    instance = db.query(ScannerInstance).filter_by(id=INSTANCE_ID).one()
    instance.status = "online"
    instance.last_heartbeat_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()

    assert assess_run_liveness(db, run=run).stalled is False


def test_a_stalled_run_says_so_on_the_surface(db: Session):
    """As visible as a success, which is CA-08.5's own criterion."""
    from src.core.services.verification_surface_service import (
        build_artefact_verification_view,
    )

    connector = _connector(db)
    profile = _approved(db, connector, [OS_VERSION])
    run = _run(db, profile)
    queue_inspection(db, run=run, connector=connector, capability=OS_VERSION, platform=None)
    instance = db.query(ScannerInstance).filter_by(id=INSTANCE_ID).one()
    instance.last_heartbeat_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=3)
    db.commit()

    view = build_artefact_verification_view(db, organization_id=ORG_ID, asset_id=ASSET_ID)

    assert view.runs[0].stalled is True
    assert "Collector stopped reporting" in view.runs[0].outcome_explanation
