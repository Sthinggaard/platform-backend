"""CA-07.5 — the seven access states, and the boundary the whole epic rests on.

One test here matters more than the rest:
``test_reaching_verification_ready_schedules_nothing``. The contract's headline
rule is *"access does not start verification"*, and readiness is exactly the
moment when starting the work would feel like a favour — everything is
configured, the connection is proven, the permissions are adequate. So the test
counts rows in **every** scheduling table this platform has, before and after,
and fails if a single one appears.

The rest establish that the sequence is earned rather than claimed: a state
cannot be skipped, "tested" must name a test that actually succeeded, and there
is no path into ``RUNNING`` except through a recorded human approval.
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
    AccessConnectorStatus,
    AccessConnectorType,
    ConnectorCredentialModel,
)
from src.core.constants.artefact_access_lifecycle_enums import (
    ACCESS_LIFECYCLE_AUDIT_TRANSITIONED,
    ACCESS_LIFECYCLE_AUDIT_VERIFICATION_APPROVED,
    ARTEFACT_ACCESS_TRANSITIONS,
    ArtefactAccessState,
    VerificationApprovalSource,
)
from src.core.constants.contextual_access_enums import (
    AccessOperatingMode,
    ArtefactAccessChoice,
    ContextualAccessDecision,
    ContextualAccessPolicyStatus,
)
from src.core.constants.leadership_authorization_enums import LeadershipAuthorizationStatus
from src.core.constants.permission_profile_enums import (
    ConnectorCapability,
    PermissionSubjectKind,
)
from src.core.database import Base
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.artefact_access_lifecycle import ArtefactAccessLifecycle
from src.core.model_defs.assets_runtime import Asset
from src.core.model_defs.connector_access_test import ConnectorAccessTest
from src.core.model_defs.contextual_access_policy import ContextualAccessPolicy
from src.core.model_defs.discovery_execution import (
    DiscoveryExecutionPlan,
    ExecutionStage,
    ProviderExecution,
)
from src.core.model_defs.leadership_authorization import LeadershipAuthorization
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.model_defs.recurrence_schedule import RecurrenceOccurrence, RecurrenceSchedule
from src.core.models import AuditEvent, Organization, User
from src.core.services.access_connector_lifecycle_service import revoke_connector
from src.core.services.artefact_access_lifecycle_service import (
    ArtefactAccessLifecycleError,
    approve_verification,
    get_lifecycle,
    inherit_standing_approval,
    mark_complete,
    mark_configured,
    mark_running,
    mark_tested,
    mark_verification_ready,
    request_access,
)
from src.core.services.connector_access_test_service import (
    record_access_test_result,
    request_access_test,
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
ASSET_ID = 10
READ = ConnectorCapability.READ_INSTALLED_PACKAGES.value

#: Every table in this platform that means "work has been queued". The boundary
#: test counts all of them, so a future scheduling primitive added to any of
#: these is covered without the test needing to know it arrived.
SCHEDULING_TABLES = (
    RecurrenceSchedule,
    RecurrenceOccurrence,
    DiscoveryExecutionPlan,
    ExecutionStage,
    ProviderExecution,
)


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
            ContextualAccessPolicy.__table__,
            AccessConnector.__table__,
            PermissionSubject.__table__,
            PermissionProfile.__table__,
            ConnectorAccessTest.__table__,
            ArtefactAccessLifecycle.__table__,
            AuditEvent.__table__,
            *[model.__table__ for model in SCHEDULING_TABLES],
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
            Asset(
                id=ASSET_ID,
                organization_id=ORG_ID,
                type="host",
                display_name="db-01.internal",
                layer="l1",
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


def _successful_test(db: Session, connector: AccessConnector) -> ConnectorAccessTest:
    test = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    record_access_test_result(db, test, reachable=True, permissions_adequate=True)
    db.commit()
    return test


def _requested(db: Session) -> ArtefactAccessLifecycle:
    lifecycle = request_access(
        db,
        organization_id=ORG_ID,
        asset_id=ASSET_ID,
        choice=ArtefactAccessChoice.CONNECT_HOST.value,
        requested_by_user_id=ADMIN_USER_ID,
    )
    db.commit()
    return lifecycle


def _ready(db: Session) -> tuple[ArtefactAccessLifecycle, AccessConnector]:
    """Walk an artefact all the way to VERIFICATION_READY, the honest way."""
    connector = _connector(db)
    lifecycle = _requested(db)
    mark_configured(db, lifecycle, connector, actor_user_id=ADMIN_USER_ID)
    db.commit()
    test = _successful_test(db, connector)
    mark_tested(db, lifecycle, test, actor_user_id=ADMIN_USER_ID)
    mark_verification_ready(db, lifecycle, actor_user_id=ADMIN_USER_ID)
    db.commit()
    return lifecycle, connector


def _scheduled_row_counts(db: Session) -> dict[str, int]:
    return {model.__tablename__: db.query(model).count() for model in SCHEDULING_TABLES}


def _mode_a_policy(db: Session, *, effective_to=None) -> ContextualAccessPolicy:
    policy = ContextualAccessPolicy(
        organization_id=ORG_ID,
        decision=ContextualAccessDecision.ACCESS_OPERATING_MODE.value,
        choice=AccessOperatingMode.SCHEDULED_AUTONOMOUS.value,
        status=ContextualAccessPolicyStatus.ACTIVE.value,
        version=1,
        consequence_statement="A usable credential lives on the Collector.",
        effective_to=effective_to,
    )
    db.add(policy)
    db.commit()
    return policy


# --- The rule the whole epic rests on --------------------------------------


def test_reaching_verification_ready_schedules_nothing(db: Session):
    """The contract's headline rule, asserted rather than asserted-to.

    *"Access does not start verification."* Readiness means only that a human may
    now be asked. Nothing is queued, planned, dispatched or scheduled — and this
    counts every table in the platform that could hold such a thing, so the claim
    is checked against the system rather than against this module's intentions.
    """
    connector = _connector(db)
    lifecycle = _requested(db)
    mark_configured(db, lifecycle, connector, actor_user_id=ADMIN_USER_ID)
    db.commit()
    test = _successful_test(db, connector)
    mark_tested(db, lifecycle, test, actor_user_id=ADMIN_USER_ID)
    db.commit()

    before = _scheduled_row_counts(db)
    mark_verification_ready(db, lifecycle, actor_user_id=ADMIN_USER_ID)
    db.commit()

    assert lifecycle.state == ArtefactAccessState.VERIFICATION_READY.value
    assert lifecycle.verification_ready_at is not None
    assert _scheduled_row_counts(db) == before
    assert all(count == 0 for count in before.values())
    # And readiness is emphatically not approval.
    assert lifecycle.verification_approved_at is None


def test_the_service_module_imports_no_scheduler(db: Session):
    """A structural check, because the behavioural one can only see today's tables.

    If this module ever grows an import of a dispatcher or a recurrence
    primitive, somebody is preparing to start work from here — and that is the
    one thing it must never do.
    """
    import inspect

    from src.core.services import artefact_access_lifecycle_service as module

    source = inspect.getsource(module)
    for forbidden in (
        "dispatch",
        "recurrence",
        "celery",
        "execution_plan",
        "schedule",
        "enqueue",
    ):
        assert f"import {forbidden}" not in source.lower()
        assert f"from src.core.services.{forbidden}" not in source.lower()


def test_there_is_no_path_into_running_except_through_approval():
    """Readable as data, so the absence of a shortcut is visible at a glance."""
    into_running = [
        state
        for state, targets in ARTEFACT_ACCESS_TRANSITIONS.items()
        if ArtefactAccessState.RUNNING.value in targets
    ]
    assert into_running == [ArtefactAccessState.APPROVED.value]


def test_a_ready_artefact_cannot_be_run_without_a_human_saying_yes(db: Session):
    lifecycle, _ = _ready(db)
    with pytest.raises(ArtefactAccessLifecycleError, match="still has to say yes"):
        mark_running(db, lifecycle)


def test_approval_is_its_own_act_with_its_own_audit_event(db: Session):
    """"A human authorised verification" must never hide inside a generic event."""
    lifecycle, _ = _ready(db)
    approve_verification(db, lifecycle, approved_by_user_id=SPONSOR_USER_ID)
    db.commit()

    assert lifecycle.state == ArtefactAccessState.APPROVED.value
    assert lifecycle.verification_approved_by_user_id == SPONSOR_USER_ID
    assert (
        lifecycle.verification_approved_source == VerificationApprovalSource.PER_ARTEFACT.value
    )
    event = (
        db.query(AuditEvent)
        .filter_by(event_type=ACCESS_LIFECYCLE_AUDIT_VERIFICATION_APPROVED)
        .one()
    )
    assert event.actor_user_id == SPONSOR_USER_ID
    assert event.metadata_json["asset_id"] == ASSET_ID


def test_the_database_refuses_a_run_that_no_one_approved(db: Session):
    """Belt and braces: a writer bypassing the service still cannot record it."""
    from sqlalchemy.exc import IntegrityError

    lifecycle, _ = _ready(db)
    lifecycle.state = ArtefactAccessState.RUNNING.value
    db.add(lifecycle)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


# --- Standing approval, which is a real approval and not a bypass ----------


def test_a_standing_mode_a_decision_can_be_inherited(db: Session):
    """Søren's ruling: a human approved the cadence once, and runs inherit it."""
    lifecycle, _ = _ready(db)
    policy = _mode_a_policy(db)

    inherit_standing_approval(db, lifecycle)
    db.commit()

    assert lifecycle.state == ArtefactAccessState.APPROVED.value
    assert lifecycle.verification_approved_source == (
        VerificationApprovalSource.STANDING_OPERATING_MODE.value
    )
    # Resolves to the record somebody signed, not to the word "standing".
    assert lifecycle.verification_approval_policy_id == policy.id
    assert lifecycle.verification_approved_by_user_id is None


def test_there_is_nothing_to_inherit_without_a_live_mode_a_decision(db: Session):
    """The half that stops "standing" becoming "unapproved"."""
    lifecycle, _ = _ready(db)
    with pytest.raises(ArtefactAccessLifecycleError, match="no standing"):
        inherit_standing_approval(db, lifecycle)


def test_a_lapsed_standing_approval_cannot_be_inherited(db: Session):
    """An approval with an expiry that passed is not an approval.

    Mode A's mandatory review date exists precisely so standing permission cannot
    outlive the decision behind it, and this is where that bites.
    """
    from datetime import timedelta

    from src.core.model_defs.common import utcnow

    lifecycle, _ = _ready(db)
    _mode_a_policy(db, effective_to=utcnow() - timedelta(days=1))

    with pytest.raises(ArtefactAccessLifecycleError, match="no standing"):
        inherit_standing_approval(db, lifecycle)


# --- The sequence is earned, not claimed -----------------------------------


def test_states_cannot_be_skipped(db: Session):
    lifecycle = _requested(db)
    with pytest.raises(ArtefactAccessLifecycleError, match="cannot move from"):
        mark_verification_ready(db, lifecycle)


def test_tested_must_name_a_test_that_actually_succeeded(db: Session):
    """Otherwise "tested" is a label somebody typed."""
    from src.core.constants.connector_access_test_enums import ConnectorAccessTestFailure

    connector = _connector(db)
    lifecycle = _requested(db)
    mark_configured(db, lifecycle, connector, actor_user_id=ADMIN_USER_ID)
    db.commit()

    failed = request_access_test(db, connector, requested_by_user_id=ADMIN_USER_ID)
    record_access_test_result(
        db,
        failed,
        reachable=False,
        permissions_adequate=False,
        failure_code=ConnectorAccessTestFailure.HOST_UNREACHABLE.value,
    )
    db.commit()

    with pytest.raises(ArtefactAccessLifecycleError, match="not been proven to work"):
        mark_tested(db, lifecycle, failed)


def test_access_cannot_be_configured_through_a_withdrawn_connector(db: Session):
    connector = _connector(db)
    lifecycle = _requested(db)
    revoke_connector(
        db, connector, revoked_by_user_id=SPONSOR_USER_ID, revocation_reason="Withdrawn."
    )
    db.commit()

    with pytest.raises(ArtefactAccessLifecycleError, match="may not be used"):
        mark_configured(db, lifecycle, connector)


def test_access_cannot_be_configured_through_an_unapproved_connector(db: Session):
    """No approved profile means nobody decided what it may do."""
    subject = register_permission_subject(
        db, organization_id=ORG_ID, subject_kind=PermissionSubjectKind.ACCESS_CONNECTOR
    )
    bare = AccessConnector(
        organization_id=ORG_ID,
        permission_subject_id=subject.id,
        scanner_instance_id="scanner-1",
        connector_type=AccessConnectorType.SSH_RESTRICTED.value,
        credential_model=ConnectorCredentialModel.OPERATOR_SUPPLIED.value,
        target_host="db-01.internal",
        status=AccessConnectorStatus.CONFIGURED.value,
    )
    db.add(bare)
    lifecycle = _requested(db)
    db.commit()

    with pytest.raises(ArtefactAccessLifecycleError, match="no approved permission profile"):
        mark_configured(db, lifecycle, bare)


# --- Requesting access is a recorded decision, not a scan -------------------


@pytest.mark.parametrize(
    "choice",
    [
        ArtefactAccessChoice.NETWORK_ONLY.value,
        ArtefactAccessChoice.EXCLUDE.value,
        ArtefactAccessChoice.REVIEW_LATER.value,
    ],
)
def test_the_three_choices_that_do_not_ask_for_access_start_nothing(db: Session, choice: str):
    """Refused by name with an explanation, never by silently doing nothing."""
    with pytest.raises(ArtefactAccessLifecycleError, match="does not ask for deeper access"):
        request_access(
            db, organization_id=ORG_ID, asset_id=ASSET_ID, choice=choice
        )
    assert get_lifecycle(db, organization_id=ORG_ID, asset_id=ASSET_ID) is None


def test_departing_from_the_standing_default_needs_a_recorded_reason(db: Session):
    """The platform's existing idiom: the recommended route is free, others owe words."""
    db.add(
        ContextualAccessPolicy(
            organization_id=ORG_ID,
            decision=ContextualAccessDecision.DEEPER_ACCESS_DEFAULT.value,
            choice=ArtefactAccessChoice.NETWORK_ONLY.value,
            status=ContextualAccessPolicyStatus.ACTIVE.value,
            version=1,
            consequence_statement="Network evidence only.",
        )
    )
    db.commit()

    with pytest.raises(ArtefactAccessLifecycleError, match="recorded reason"):
        request_access(
            db,
            organization_id=ORG_ID,
            asset_id=ASSET_ID,
            choice=ArtefactAccessChoice.CONNECT_HOST.value,
        )

    lifecycle = request_access(
        db,
        organization_id=ORG_ID,
        asset_id=ASSET_ID,
        choice=ArtefactAccessChoice.CONNECT_HOST.value,
        deviation_reason="Network evidence cannot tell us what is installed on this host.",
        requested_by_user_id=ADMIN_USER_ID,
    )
    db.commit()
    assert lifecycle.deviation_reason is not None


def test_one_artefact_has_one_access_journey(db: Session):
    _requested(db)
    with pytest.raises(ArtefactAccessLifecycleError, match="already been requested"):
        request_access(
            db,
            organization_id=ORG_ID,
            asset_id=ASSET_ID,
            choice=ArtefactAccessChoice.GRANT_ACCESS.value,
        )


# --- The whole journey, and what it leaves behind --------------------------


def test_the_full_seven_state_journey_is_walkable_and_audited(db: Session):
    lifecycle, _ = _ready(db)
    approve_verification(db, lifecycle, approved_by_user_id=SPONSOR_USER_ID)
    mark_running(db, lifecycle, actor_user_id=SPONSOR_USER_ID)
    mark_complete(db, lifecycle, actor_user_id=SPONSOR_USER_ID)
    db.commit()

    assert lifecycle.state == ArtefactAccessState.COMPLETE.value
    for stamp in (
        lifecycle.configured_at,
        lifecycle.tested_at,
        lifecycle.verification_ready_at,
        lifecycle.verification_approved_at,
        lifecycle.running_at,
        lifecycle.completed_at,
    ):
        assert stamp is not None

    transitions = [
        e.metadata_json["state"]
        for e in db.query(AuditEvent).filter_by(event_type=ACCESS_LIFECYCLE_AUDIT_TRANSITIONED)
    ]
    assert transitions == [
        ArtefactAccessState.CONFIGURED.value,
        ArtefactAccessState.TESTED.value,
        ArtefactAccessState.VERIFICATION_READY.value,
        ArtefactAccessState.RUNNING.value,
        ArtefactAccessState.COMPLETE.value,
    ]


def test_a_completed_journey_survives_the_connector_being_revoked(db: Session):
    """Two independent lifecycles. Withdrawing one does not rewrite the other.

    The Connector's state answers "may this route be used now?"; the artefact's
    answers "what happened to this artefact, and who approved it?". A revocation
    today must not make last month's approved verification unreadable.
    """
    lifecycle, connector = _ready(db)
    approve_verification(db, lifecycle, approved_by_user_id=SPONSOR_USER_ID)
    mark_running(db, lifecycle)
    mark_complete(db, lifecycle)
    db.commit()

    revoke_connector(
        db, connector, revoked_by_user_id=SPONSOR_USER_ID, revocation_reason="No longer needed."
    )
    db.commit()

    assert lifecycle.state == ArtefactAccessState.COMPLETE.value
    assert lifecycle.verification_approved_by_user_id == SPONSOR_USER_ID
