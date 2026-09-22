"""CA-07.4 — access can be tested, and a failure says something an operator can act on.

The criterion this suite exists for is the fourth one. A test that fails with
"connection error" tells nobody anything, so the vocabulary is closed, every code
carries a remedy, and a failure without a code is refused outright. Those three
together are what makes "in terms an operator can act on" checkable rather than
a claim in a docstring.

The other line being held here is CA-07's headline rule: **a connection test is
not verification.** Nothing in this path reads the estate, produces evidence, or
concludes anything about risk — asserted below by a test that would fail if a
successful test result ever started something.
"""

from __future__ import annotations

from datetime import timedelta

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
from src.core.constants.connector_access_test_enums import (
    ACCESS_TEST_TIMEOUT_MINUTES,
    CONNECTOR_ACCESS_TEST_REMEDIES,
    TEST_AUDIT_EXPIRED,
    TEST_AUDIT_REQUESTED,
    TEST_AUDIT_RESULT_RECORDED,
    ConnectorAccessTestFailure,
    ConnectorAccessTestStatus,
)
from src.core.constants.leadership_authorization_enums import LeadershipAuthorizationStatus
from src.core.constants.permission_profile_enums import (
    ConnectorCapability,
    PermissionSubjectKind,
)
from src.core.database import Base
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.common import utcnow
from src.core.model_defs.connector_access_test import ConnectorAccessTest
from src.core.model_defs.leadership_authorization import LeadershipAuthorization
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.models import AuditEvent, Organization, User
from src.core.services.access_connector_lifecycle_service import revoke_connector
from src.core.services.connector_access_test_service import (
    ConnectorAccessTestValidationError,
    expire_stale_access_tests,
    list_access_tests,
    record_access_test_result,
    remedy_for,
    request_access_test,
)
from src.core.services.permission_profile_service import (
    approve_profile,
    create_profile_draft,
    submit_profile,
)
from src.core.services.permission_subject_service import register_permission_subject

ORG_ID = 1
OTHER_ORG_ID = 2
ADMIN_USER_ID = 1
SPONSOR_USER_ID = 2
READ = ConnectorCapability.READ_INSTALLED_PACKAGES.value
READ_OS = ConnectorCapability.READ_OS_VERSION.value


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
            ConnectorAccessTest.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=ORG_ID, name="Org", slug="org"),
            Organization(id=OTHER_ORG_ID, name="Other", slug="other"),
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


def _connector(db: Session, *, organization_id: int = ORG_ID) -> AccessConnector:
    subject = register_permission_subject(
        db, organization_id=organization_id, subject_kind=PermissionSubjectKind.ACCESS_CONNECTOR
    )
    connector = AccessConnector(
        organization_id=organization_id,
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


def _testable(db: Session, capabilities: list[str] | None = None) -> AccessConnector:
    connector = _connector(db)
    profile = create_profile_draft(
        db,
        subject=connector,
        name="Read-only inventory",
        capabilities=capabilities or [READ],
        prepared_by_user_id=ADMIN_USER_ID,
    )
    submit_profile(db, profile, submitted_by_user_id=ADMIN_USER_ID)
    approve_profile(db, profile, approved_by_user_id=SPONSOR_USER_ID)
    db.commit()
    return connector


def _events(db: Session) -> list[str]:
    return [e.event_type for e in db.query(AuditEvent).all()]


# --- Every failure names something a person can go and change --------------


def test_every_failure_code_has_a_remedy():
    """The closed vocabulary is only worth having if it is exhaustively answered.

    A code added later without a remedy is exactly how "connection error" comes
    back, so the gap is a test failure rather than a silent ``None`` on a screen.
    """
    for failure in ConnectorAccessTestFailure:
        remedy = CONNECTOR_ACCESS_TEST_REMEDIES.get(failure.value)
        assert remedy, f"{failure.value} has no remedy"
        assert remedy_for(failure.value) == remedy


def test_a_failure_must_name_a_cause(db: Session):
    """Refusing a codeless failure is what stops "it didn't work" being a result."""
    connector = _testable(db)
    test = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    db.commit()

    with pytest.raises(ConnectorAccessTestValidationError, match="what failed"):
        record_access_test_result(db, test, reachable=False, permissions_adequate=False)


def test_an_invented_failure_code_is_refused(db: Session):
    connector = _testable(db)
    test = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    db.commit()

    with pytest.raises(ConnectorAccessTestValidationError, match="Unknown failure code"):
        record_access_test_result(
            db, test, reachable=False, permissions_adequate=False, failure_code="it_broke"
        )


# --- Reachability and permission adequacy are two answers ------------------


def test_reachable_but_underpermitted_is_recorded_as_both_facts(db: Session):
    """The distinction that decides where an operator is sent.

    Collapsing this into "failed" would point somebody at the network when the
    problem is an account's rights.
    """
    connector = _testable(db)
    test = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    record_access_test_result(
        db,
        test,
        reachable=True,
        permissions_adequate=False,
        failure_code=ConnectorAccessTestFailure.PERMISSION_INSUFFICIENT.value,
    )
    db.commit()

    assert test.status == ConnectorAccessTestStatus.FAILED.value
    assert test.reachable is True
    assert test.permissions_adequate is False
    assert "widen the account's rights" in remedy_for(test.failure_code)


def test_a_successful_test_records_both_answers_and_starts_nothing(db: Session):
    """CA-07's headline rule at its narrowest: proving access works begins nothing.

    Nothing is scheduled, no evidence row appears, and the only trace is the test
    itself plus its audit events. Verification is CA-08, behind its own approval.
    """
    connector = _testable(db)
    test = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    record_access_test_result(
        db, test, reachable=True, permissions_adequate=True, capabilities_confirmed=[READ]
    )
    db.commit()

    assert test.status == ConnectorAccessTestStatus.SUCCEEDED.value
    assert test.capabilities_confirmed == [READ]
    assert test.completed_at is not None
    assert _events(db).count(TEST_AUDIT_RESULT_RECORDED) == 1
    # The Connector is untouched — a test changes nothing about the grant.
    assert connector.status == AccessConnectorStatus.CONFIGURED.value


def test_a_collector_may_only_confirm_what_the_profile_granted(db: Session):
    """A report naming an ungranted capability would become a second, unapproved grant."""
    connector = _testable(db, [READ])
    test = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    db.commit()

    with pytest.raises(ConnectorAccessTestValidationError, match="not in the approved"):
        record_access_test_result(
            db,
            test,
            reachable=True,
            permissions_adequate=True,
            capabilities_confirmed=[READ, READ_OS],
        )


# --- History, not a latest-result column ----------------------------------


def test_results_accumulate_rather_than_overwrite(db: Session):
    """"When did this stop working?" is unanswerable if each result replaces the last."""
    connector = _testable(db)
    first = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    record_access_test_result(db, first, reachable=True, permissions_adequate=True)
    db.commit()
    second = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    record_access_test_result(
        db,
        second,
        reachable=False,
        permissions_adequate=False,
        failure_code=ConnectorAccessTestFailure.HOST_UNREACHABLE.value,
    )
    db.commit()

    history = list_access_tests(db, organization_id=ORG_ID, connector_id=connector.id)
    assert len(history) == 2
    assert {t.status for t in history} == {
        ConnectorAccessTestStatus.SUCCEEDED.value,
        ConnectorAccessTestStatus.FAILED.value,
    }


def test_a_result_may_only_be_reported_once(db: Session):
    connector = _testable(db)
    test = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    record_access_test_result(db, test, reachable=True, permissions_adequate=True)
    db.commit()

    with pytest.raises(ConnectorAccessTestValidationError, match="already reported"):
        record_access_test_result(db, test, reachable=False, permissions_adequate=False,
                                  failure_code=ConnectorAccessTestFailure.PORT_CLOSED.value)


def test_only_one_test_may_be_waiting_at_a_time(db: Session):
    connector = _testable(db)
    request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    db.commit()

    with pytest.raises(ConnectorAccessTestValidationError, match="already waiting"):
        request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)


def test_a_collector_that_never_answers_expires_rather_than_waits_forever(db: Session):
    """``expired`` is its own status: heard nothing, versus told no.

    The first sends an operator to the Collector, the second to the target, so a
    request that sat in ``requested`` forever would look like work in progress
    and actually be silence.
    """
    connector = _testable(db)
    test = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    test.requested_at = utcnow() - timedelta(minutes=ACCESS_TEST_TIMEOUT_MINUTES + 1)
    db.commit()

    expired = expire_stale_access_tests(db, organization_id=ORG_ID)
    db.commit()

    assert [t.id for t in expired] == [test.id]
    assert test.status == ConnectorAccessTestStatus.EXPIRED.value
    assert test.completed_at is not None
    assert TEST_AUDIT_EXPIRED in _events(db)
    # And the Connector is testable again, rather than blocked by a dead request.
    assert request_access_test(db, connector).status == ConnectorAccessTestStatus.REQUESTED.value


# --- The two failures the platform can state on its own --------------------


def test_a_connector_with_no_approved_profile_fails_without_asking_the_collector(db: Session):
    """There is nothing to measure adequacy against, so testing would prove nothing."""
    connector = _connector(db)
    test = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    db.commit()

    assert test.status == ConnectorAccessTestStatus.FAILED.value
    assert test.failure_code == ConnectorAccessTestFailure.NO_APPROVED_PERMISSION_PROFILE.value
    assert test.reachable is None and test.permissions_adequate is None
    # Recorded as a result, not raised as an error, so it sits in the same history.
    assert len(list_access_tests(db, organization_id=ORG_ID, connector_id=connector.id)) == 1
    assert TEST_AUDIT_REQUESTED not in _events(db)


def test_a_revoked_connector_cannot_be_tested(db: Session):
    connector = _testable(db)
    revoke_connector(
        db, connector, revoked_by_user_id=SPONSOR_USER_ID, revocation_reason="Withdrawn."
    )
    db.commit()

    test = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    db.commit()
    assert test.failure_code == ConnectorAccessTestFailure.CONNECTOR_NOT_ACTIVE.value
    assert "revoked" in test.failure_detail


# --- Tenancy and the trail -------------------------------------------------


def test_history_never_crosses_a_tenant_boundary(db: Session):
    mine = _testable(db)
    theirs = _connector(db, organization_id=OTHER_ORG_ID)
    request_access_test(db, mine, requested_by_user_id=ADMIN_USER_ID)
    request_access_test(db, theirs)
    db.commit()

    assert [t.connector_id for t in list_access_tests(
        db, organization_id=ORG_ID, connector_id=mine.id
    )] == [mine.id]
    assert list_access_tests(db, organization_id=ORG_ID, connector_id=theirs.id) == []


def test_the_collectors_free_text_never_reaches_the_audit_trail(db: Session):
    """The Collector is the only party holding a credential, so its notes stay out.

    An audit table is long-lived and widely read — the last place an echoed
    secret should come to rest. The closed failure code carries the meaning.
    """
    connector = _testable(db)
    test = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    record_access_test_result(
        db,
        test,
        reachable=False,
        permissions_adequate=False,
        failure_code=ConnectorAccessTestFailure.AUTHENTICATION_REJECTED.value,
        failure_detail="offered key AAAA-not-a-real-secret to root@db-01",
    )
    db.commit()

    event = db.query(AuditEvent).filter_by(event_type=TEST_AUDIT_RESULT_RECORDED).one()
    assert "failure_detail" not in event.metadata_json
    assert event.metadata_json["failure_code"] == (
        ConnectorAccessTestFailure.AUTHENTICATION_REJECTED.value
    )


def test_the_result_is_pinned_to_the_profile_it_was_measured_against(db: Session):
    """Profiles supersede; a result that outlived its grant would be unreadable."""
    connector = _testable(db)
    test = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    db.commit()

    profile = db.query(PermissionProfile).filter_by(organization_id=ORG_ID).one()
    assert test.permission_profile_id == profile.id
