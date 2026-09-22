"""CA-08.1 (#289) — a verification run begins only where a person allowed it.

The boundary test in here is the one the epic is built around. CA-07.5 drew the
line — ``VERIFICATION_READY`` means *a human may now be asked*, never that
anything is running — and this is the first code with the power to cross it.

The fixture is the lifecycle suite's, because walking an artefact to
``VERIFICATION_READY`` honestly is exactly what these tests need and a
hand-built row would prove nothing about the sequence.
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

from src.core.constants.verification_run_enums import (
    VerificationApprovalSource,
    VerificationRunStatus,
)
from src.core.model_defs.verification_run import VerificationRun
from src.core.services.artefact_access_lifecycle_service import approve_verification
from src.core.services.verification_run_service import (
    VerificationRunError,
    begin_verification_run,
    complete_verification_run,
    fail_verification_run,
    list_runs_for_asset,
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
            VerificationRun.__table__,
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

def _approved(db: Session) -> tuple[ArtefactAccessLifecycle, AccessConnector]:
    lifecycle, connector = _ready(db)
    approve_verification(db, lifecycle, approved_by_user_id=SPONSOR_USER_ID)
    db.commit()
    return lifecycle, connector


def _profile_id(db: Session, connector: AccessConnector) -> str:
    profile = (
        db.query(PermissionProfile)
        .filter(PermissionProfile.subject_id == connector.permission_subject_id)
        .one()
    )
    return profile.id


# --- The boundary this epic exists to hold ------------------------------------


def test_verification_cannot_begin_from_verification_ready(db: Session):
    """The single most important test in the epic.

    VERIFICATION_READY means *a human may now be asked*. An artefact sitting
    there has had everything access can establish established and nothing more.
    If a run could begin from it, "separately human-approved" would be a comment
    rather than a rule.
    """
    lifecycle, connector = _ready(db)
    assert lifecycle.state == ArtefactAccessState.VERIFICATION_READY.value

    with pytest.raises(VerificationRunError, match="until a person has approved"):
        begin_verification_run(
            db,
            organization_id=ORG_ID,
            lifecycle=lifecycle,
            permission_profile_id=_profile_id(db, connector),
            began_by_user_id=ADMIN_USER_ID,
        )

    assert db.query(VerificationRun).count() == 0, "and nothing was recorded either"


def test_a_run_begins_once_a_person_has_approved_it(db: Session):
    lifecycle, connector = _approved(db)

    run = begin_verification_run(
        db,
        organization_id=ORG_ID,
        lifecycle=lifecycle,
        permission_profile_id=_profile_id(db, connector),
        began_by_user_id=ADMIN_USER_ID,
    )
    db.commit()

    assert run.status == VerificationRunStatus.RUNNING.value
    # The lifecycle moved because the run reported it — the only edge into
    # RUNNING there is.
    assert lifecycle.state == ArtefactAccessState.RUNNING.value


def test_the_run_records_what_it_was_allowed_to_do_and_who_allowed_it(db: Session):
    """A state is not an account of what was done, which is why this row exists."""
    lifecycle, connector = _approved(db)
    profile_id = _profile_id(db, connector)

    run = begin_verification_run(
        db,
        organization_id=ORG_ID,
        lifecycle=lifecycle,
        permission_profile_id=profile_id,
        began_by_user_id=ADMIN_USER_ID,
    )
    db.commit()

    assert run.asset_id == ASSET_ID
    assert run.permission_profile_id == profile_id
    assert run.approved_by_user_id == SPONSOR_USER_ID
    assert run.approval_source == VerificationApprovalSource.PER_ARTEFACT.value


def test_a_run_without_a_permission_profile_is_refused(db: Session):
    """#291 bounds what a run may reach; this refuses one with no answer at all."""
    lifecycle, _ = _approved(db)

    with pytest.raises(VerificationRunError, match="approved permission profile"):
        begin_verification_run(
            db,
            organization_id=ORG_ID,
            lifecycle=lifecycle,
            permission_profile_id="",
            began_by_user_id=ADMIN_USER_ID,
        )


def test_one_artefact_cannot_be_verified_twice_at_once(db: Session):
    lifecycle, connector = _approved(db)
    profile_id = _profile_id(db, connector)
    begin_verification_run(
        db, organization_id=ORG_ID, lifecycle=lifecycle,
        permission_profile_id=profile_id, began_by_user_id=ADMIN_USER_ID,
    )
    db.commit()

    with pytest.raises(VerificationRunError, match="already being verified"):
        begin_verification_run(
            db, organization_id=ORG_ID, lifecycle=lifecycle,
            permission_profile_id=profile_id, began_by_user_id=ADMIN_USER_ID,
        )


def test_another_organisation_cannot_begin_a_run_on_this_one(db: Session):
    lifecycle, connector = _approved(db)

    with pytest.raises(VerificationRunError):
        begin_verification_run(
            db, organization_id=ORG_ID + 1, lifecycle=lifecycle,
            permission_profile_id=_profile_id(db, connector), began_by_user_id=ADMIN_USER_ID,
        )


# --- Finishing ----------------------------------------------------------------


def test_completing_a_run_completes_the_journey(db: Session):
    lifecycle, connector = _approved(db)
    run = begin_verification_run(
        db, organization_id=ORG_ID, lifecycle=lifecycle,
        permission_profile_id=_profile_id(db, connector), began_by_user_id=ADMIN_USER_ID,
    )
    db.commit()

    complete_verification_run(db, run, lifecycle=lifecycle, actor_user_id=ADMIN_USER_ID)
    db.commit()

    assert run.status == VerificationRunStatus.COMPLETED.value
    assert run.finished_at is not None
    assert lifecycle.state == ArtefactAccessState.COMPLETE.value


def test_a_failed_run_does_not_complete_the_journey(db: Session):
    """"It broke" and "it finished" must not look alike downstream."""
    lifecycle, connector = _approved(db)
    run = begin_verification_run(
        db, organization_id=ORG_ID, lifecycle=lifecycle,
        permission_profile_id=_profile_id(db, connector), began_by_user_id=ADMIN_USER_ID,
    )
    db.commit()

    fail_verification_run(db, run, reason="The collector stopped responding.", actor_user_id=ADMIN_USER_ID)
    db.commit()

    assert run.status == VerificationRunStatus.FAILED.value
    assert run.failure_reason == "The collector stopped responding."
    assert lifecycle.state == ArtefactAccessState.RUNNING.value, "not silently completed"


def test_a_finished_run_is_not_reopened(db: Session):
    lifecycle, connector = _approved(db)
    run = begin_verification_run(
        db, organization_id=ORG_ID, lifecycle=lifecycle,
        permission_profile_id=_profile_id(db, connector), began_by_user_id=ADMIN_USER_ID,
    )
    db.commit()
    fail_verification_run(db, run, reason="Timed out.", actor_user_id=ADMIN_USER_ID)
    db.commit()

    with pytest.raises(VerificationRunError, match="already finished"):
        complete_verification_run(db, run, lifecycle=lifecycle, actor_user_id=ADMIN_USER_ID)


# --- The record a reader gets --------------------------------------------------


def test_every_material_moment_is_audited_with_attribution(db: Session):
    lifecycle, connector = _approved(db)
    run = begin_verification_run(
        db, organization_id=ORG_ID, lifecycle=lifecycle,
        permission_profile_id=_profile_id(db, connector), began_by_user_id=ADMIN_USER_ID,
    )
    complete_verification_run(db, run, lifecycle=lifecycle, actor_user_id=ADMIN_USER_ID)
    db.commit()

    events = [e.event_type for e in db.query(AuditEvent).all()]
    assert "verification_run_began" in events
    assert "verification_run_completed" in events


def test_an_artefacts_runs_read_newest_first(db: Session):
    lifecycle, connector = _approved(db)
    profile_id = _profile_id(db, connector)
    first = begin_verification_run(
        db, organization_id=ORG_ID, lifecycle=lifecycle,
        permission_profile_id=profile_id, began_by_user_id=ADMIN_USER_ID,
    )
    fail_verification_run(db, first, reason="Timed out.", actor_user_id=ADMIN_USER_ID)
    db.commit()

    runs = list_runs_for_asset(db, organization_id=ORG_ID, asset_id=ASSET_ID)

    assert [r.id for r in runs] == [first.id]
