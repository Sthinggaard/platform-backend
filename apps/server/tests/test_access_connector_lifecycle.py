"""CA-07.4 — pause, revoke and disconnect behave distinctly, and revocation bites.

Two things are being asserted here, and the second is the one that matters.

The first is that the three withdrawal verbs are genuinely different: pause is
reversible and the grant stands, revocation is permanent and needs a reason,
disconnection is operational and does not withdraw anything. A story that shipped
three buttons writing the same column would pass a demo and fail an auditor.

The second is that a revoked Connector **cannot be used**. Until CA-07.4, a
revoked Connector holding an approved profile still passed
``assert_capability_permitted``, because the profile and the Connector are
separate records and only the profile was consulted. A revocation that does not
stop access is not a revocation, so the enforcement tests below are the story's
real acceptance criterion.
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

from src.core.constants.access_connector_enums import (
    CONNECTOR_AUDIT_DISCONNECTED,
    CONNECTOR_AUDIT_PAUSED,
    CONNECTOR_AUDIT_RESUMED,
    CONNECTOR_AUDIT_REVOKED,
    AccessConnectorStatus,
    AccessConnectorType,
    ConnectorCredentialModel,
)
from src.core.constants.leadership_authorization_enums import LeadershipAuthorizationStatus
from src.core.constants.permission_profile_enums import (
    PROFILE_AUDIT_CAPABILITY_DENIED,
    ConnectorCapability,
    PermissionSubjectKind,
)
from src.core.database import Base
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.leadership_authorization import LeadershipAuthorization
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.models import AuditEvent, Organization, User
from src.core.services.access_connector_lifecycle_service import (
    disconnect_connector,
    pause_connector,
    resume_connector,
    revoke_connector,
)
from src.core.services.access_connector_service import AccessConnectorValidationError
from src.core.services.permission_enforcement_service import (
    CapabilityNotPermittedError,
    assert_capability_permitted,
)
from src.core.services.permission_profile_service import (
    approve_profile,
    create_profile_draft,
    submit_profile,
)
from src.core.services.permission_subject_service import register_permission_subject

ORG_ID = 1
ADMIN_USER_ID = 1
SPONSOR_USER_ID = 2
READ = ConnectorCapability.READ_INSTALLED_PACKAGES.value


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
            LeadershipAuthorization.__table__,
            AccessConnector.__table__,
            PermissionSubject.__table__,
            PermissionProfile.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=ORG_ID, name="Org", slug="org"),
            User(id=ADMIN_USER_ID, organization_id=ORG_ID, email="a@example.com", role="org_admin"),
            User(
                id=SPONSOR_USER_ID, organization_id=ORG_ID, email="s@example.com", role="org_admin"
            ),
            LeadershipAuthorization(
                id="auth-1",
                organization_id=ORG_ID,
                status=LeadershipAuthorizationStatus.ACTIVE.value,
                sponsor_user_id=SPONSOR_USER_ID,
                approving_body="board_risk_committee",
                authorized_scope="Programme.",
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
        scanner_instance_id="scanner-1",
        connector_type=AccessConnectorType.SSH_RESTRICTED.value,
        credential_model=ConnectorCredentialModel.OPERATOR_SUPPLIED.value,
        target_host="db-01.internal",
        status=AccessConnectorStatus.CONFIGURED.value,
    )
    db.add(connector)
    db.commit()
    return connector


def _with_approved_profile(db: Session) -> AccessConnector:
    connector = _connector(db)
    profile = create_profile_draft(
        db,
        subject=connector,
        name="Read-only inventory",
        capabilities=[READ],
        prepared_by_user_id=ADMIN_USER_ID,
    )
    submit_profile(db, profile, submitted_by_user_id=ADMIN_USER_ID)
    approve_profile(db, profile, approved_by_user_id=SPONSOR_USER_ID)
    db.commit()
    return connector


def _events(db: Session) -> list[str]:
    return [e.event_type for e in db.query(AuditEvent).all()]


# --- The three verbs are distinct -----------------------------------------


def test_pause_is_reversible_and_leaves_the_grant_standing(db: Session):
    connector = _with_approved_profile(db)

    pause_connector(db, connector, paused_by_user_id=ADMIN_USER_ID)
    db.commit()
    assert connector.status == AccessConnectorStatus.PAUSED.value
    assert connector.paused_at is not None
    assert connector.revoked_at is None

    resume_connector(db, connector, resumed_by_user_id=ADMIN_USER_ID)
    db.commit()
    assert connector.status == AccessConnectorStatus.CONFIGURED.value
    assert connector.paused_at is None
    # The grant was never touched, so the Connector is usable again immediately.
    assert assert_capability_permitted(db, connector, READ) is not None


def test_revocation_is_permanent_and_cannot_be_resumed(db: Session):
    """The distinction that makes revoke worth having as its own verb."""
    connector = _connector(db)
    revoke_connector(
        db, connector, revoked_by_user_id=SPONSOR_USER_ID, revocation_reason="Supplier exited."
    )
    db.commit()

    with pytest.raises(AccessConnectorValidationError, match="revocation is permanent"):
        resume_connector(db, connector)


def test_revocation_must_say_why(db: Session):
    """An auditor reads the reason years later; a blank one answers nothing."""
    connector = _connector(db)
    with pytest.raises(AccessConnectorValidationError, match="must say why"):
        revoke_connector(db, connector, revoked_by_user_id=SPONSOR_USER_ID, revocation_reason="   ")


def test_revocation_is_not_deletion(db: Session):
    """The record of what was granted survives being withdrawn."""
    connector = _with_approved_profile(db)
    connector_id = connector.id
    revoke_connector(
        db, connector, revoked_by_user_id=SPONSOR_USER_ID, revocation_reason="Contract ended."
    )
    db.commit()

    survivor = db.get(AccessConnector, connector_id)
    assert survivor is not None
    assert survivor.revocation_reason == "Contract ended."
    assert survivor.revoked_by_user_id == SPONSOR_USER_ID
    # And the profile that was once in force is still readable.
    assert db.query(PermissionProfile).filter_by(organization_id=ORG_ID).count() == 1


def test_disconnecting_a_revoked_connector_does_not_erase_the_revocation(db: Session):
    """The operational act must not overwrite the governance one.

    Cleaning a credential off a rebuilt Collector is a different fact from
    withdrawing an authorisation, and a record that showed only the cleanup would
    misrepresent what actually happened.
    """
    connector = _connector(db)
    revoke_connector(
        db, connector, revoked_by_user_id=SPONSOR_USER_ID, revocation_reason="Access withdrawn."
    )
    disconnect_connector(db, connector, disconnected_by_user_id=ADMIN_USER_ID)
    db.commit()

    assert connector.status == AccessConnectorStatus.REVOKED.value
    assert connector.disconnected_at is not None
    assert connector.revoked_at is not None


def test_disconnection_alone_does_not_withdraw_the_grant(db: Session):
    """The reverse independence: a rebuilt Collector revokes nothing."""
    connector = _connector(db)
    disconnect_connector(db, connector, disconnected_by_user_id=ADMIN_USER_ID)
    db.commit()

    assert connector.status == AccessConnectorStatus.DISCONNECTED.value
    assert connector.revoked_at is None
    assert connector.revocation_reason is None


def test_each_verb_gets_its_own_audit_event(db: Session):
    """A shared "connector changed" event would lose the whole distinction."""
    connector = _connector(db)
    pause_connector(db, connector, paused_by_user_id=ADMIN_USER_ID)
    resume_connector(db, connector, resumed_by_user_id=ADMIN_USER_ID)
    disconnect_connector(db, connector, disconnected_by_user_id=ADMIN_USER_ID)
    revoke_connector(
        db, connector, revoked_by_user_id=SPONSOR_USER_ID, revocation_reason="Done with it."
    )
    db.commit()

    events = _events(db)
    for event in (
        CONNECTOR_AUDIT_PAUSED,
        CONNECTOR_AUDIT_RESUMED,
        CONNECTOR_AUDIT_DISCONNECTED,
        CONNECTOR_AUDIT_REVOKED,
    ):
        assert event in events
    assert len(set(events)) == 4


def test_the_revocation_reason_reaches_the_audit_trail(db: Session):
    connector = _connector(db)
    revoke_connector(
        db, connector, revoked_by_user_id=SPONSOR_USER_ID, revocation_reason="Vendor breach."
    )
    db.commit()

    event = db.query(AuditEvent).filter_by(event_type=CONNECTOR_AUDIT_REVOKED).one()
    assert event.metadata_json["revocation_reason"] == "Vendor breach."
    assert event.actor_user_id == SPONSOR_USER_ID
    # Never the fingerprint: an audit table is the wrong place for a credential
    # identifier to accumulate.
    assert "credential_fingerprint" not in event.metadata_json


def test_a_connector_in_use_cannot_be_resumed_or_double_revoked(db: Session):
    connector = _connector(db)
    with pytest.raises(AccessConnectorValidationError, match="Only a paused Connector"):
        resume_connector(db, connector)

    revoke_connector(db, connector, revoked_by_user_id=SPONSOR_USER_ID, revocation_reason="Gone.")
    with pytest.raises(AccessConnectorValidationError, match="already revoked"):
        revoke_connector(
            db, connector, revoked_by_user_id=SPONSOR_USER_ID, revocation_reason="Gone again."
        )


# --- Withdrawal actually stops access -------------------------------------


@pytest.mark.parametrize(
    "withdraw",
    [
        pytest.param(lambda db, c: pause_connector(db, c), id="paused"),
        pytest.param(
            lambda db, c: revoke_connector(
                db, c, revoked_by_user_id=SPONSOR_USER_ID, revocation_reason="Withdrawn."
            ),
            id="revoked",
        ),
        pytest.param(lambda db, c: disconnect_connector(db, c), id="disconnected"),
    ],
)
def test_a_withdrawn_connector_may_do_nothing_even_with_an_approved_profile(db: Session, withdraw):
    """The gap CA-07.4 found, closed.

    The profile is approved, active and contains the capability. Enforcement must
    still refuse, because the *subject* was withdrawn — and only the subject
    knows that.
    """
    connector = _with_approved_profile(db)
    assert assert_capability_permitted(db, connector, READ) is not None

    withdraw(db, connector)
    db.commit()

    with pytest.raises(CapabilityNotPermittedError, match="may not be used"):
        assert_capability_permitted(db, connector, READ)


def test_the_refusal_is_audited_and_says_which_state_caused_it(db: Session):
    """A denial nobody can see afterwards cannot answer "why did this return nothing?"."""
    connector = _with_approved_profile(db)
    revoke_connector(
        db, connector, revoked_by_user_id=SPONSOR_USER_ID, revocation_reason="Withdrawn."
    )
    db.commit()

    with pytest.raises(CapabilityNotPermittedError):
        assert_capability_permitted(db, connector, READ)
    db.commit()

    denial = (
        db.query(AuditEvent)
        .filter_by(event_type=PROFILE_AUDIT_CAPABILITY_DENIED)
        .order_by(AuditEvent.id.desc())
        .first()
    )
    assert denial is not None
    assert AccessConnectorStatus.REVOKED.value in denial.metadata_json["reason"]
    assert denial.metadata_json["capability"] == READ


def test_resuming_restores_access_but_revocation_never_does(db: Session):
    """Pause and revoke differ where it counts: in what enforcement does next."""
    connector = _with_approved_profile(db)
    pause_connector(db, connector)
    db.commit()
    with pytest.raises(CapabilityNotPermittedError):
        assert_capability_permitted(db, connector, READ, audit=False)

    resume_connector(db, connector)
    db.commit()
    assert assert_capability_permitted(db, connector, READ, audit=False) is not None
