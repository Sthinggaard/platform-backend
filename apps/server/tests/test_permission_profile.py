"""CA-07.3 — permission profiles are defined, approved, and actually enforced.

The enforcement tests are the ones that matter: a profile nothing checks is
documentation. Every path through `assert_capability_permitted` must fail
closed, including the one where everything looks approved and Docker socket
access still has not been granted.
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
from src.core.constants.leadership_authorization_enums import LeadershipAuthorizationStatus
from src.core.constants.permission_profile_enums import (
    PROFILE_AUDIT_APPROVED,
    PROFILE_AUDIT_CAPABILITY_DENIED,
    PROFILE_AUDIT_DOCKER_SOCKET_APPROVED,
    ConnectorCapability,
    PermissionProfileStatus,
)
from src.core.database import Base
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.leadership_authorization import LeadershipAuthorization
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.permission_subject import PermissionSubject
from src.core.model_defs.discovery_scope_proposal import DiscoveryScopeProposal
from src.core.models import AuditEvent, Organization, User
from src.core.services.permission_enforcement_service import (
    DOCKER_SOCKET_CAPABILITIES,
    CapabilityNotPermittedError,
    assert_capability_permitted,
)
from src.core.constants.permission_profile_enums import PermissionSubjectKind
from src.core.services.permission_subject_service import register_permission_subject
from src.core.services.permission_profile_service import (
    PermissionProfileValidationError,
    approve_docker_socket,
    approve_profile,
    create_profile_draft,
    get_active_profile,
    reject_profile,
    submit_profile,
)

ORG_ID = 1
OTHER_ORG_ID = 2
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
            DiscoveryScopeProposal.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=ORG_ID, name="Org", slug="org"),
            Organization(id=OTHER_ORG_ID, name="Other", slug="other"),
            User(id=ADMIN_USER_ID, organization_id=ORG_ID, email="a@example.com", role="org_admin"),
            User(id=SPONSOR_USER_ID, organization_id=ORG_ID, email="s@example.com", role="org_admin"),
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


def _connector(db: Session, *, docker: bool = False, organization_id: int = ORG_ID) -> AccessConnector:
    subject = register_permission_subject(
        db,
        organization_id=organization_id,
        subject_kind=PermissionSubjectKind.ACCESS_CONNECTOR,
    )
    connector = AccessConnector(
        organization_id=organization_id,
        permission_subject_id=subject.id,
        scanner_instance_id="scanner-1",
        connector_type=(
            AccessConnectorType.DOCKER_READONLY.value if docker else AccessConnectorType.SSH_RESTRICTED.value
        ),
        credential_model=ConnectorCredentialModel.OPERATOR_SUPPLIED.value,
        target_host="db-01.internal",
        requires_docker_socket=docker,
        status=AccessConnectorStatus.CONFIGURED.value,
    )
    db.add(connector)
    db.commit()
    return connector


def _approved(db: Session, connector: AccessConnector, capabilities: list[str]) -> PermissionProfile:
    profile = create_profile_draft(
        db,
        subject=connector,
        name="Read-only inventory",
        capabilities=capabilities,
        prepared_by_user_id=ADMIN_USER_ID,
    )
    submit_profile(db, profile, submitted_by_user_id=ADMIN_USER_ID)
    approve_profile(db, profile, approved_by_user_id=SPONSOR_USER_ID)
    db.commit()
    return profile


def _events(db: Session) -> list[str]:
    return [e.event_type for e in db.query(AuditEvent).all()]


# --- Criterion 1: first-class, defined then approved, with attribution ------


def test_a_profile_is_approved_by_a_person_and_records_who(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [READ])

    assert profile.status == PermissionProfileStatus.ACTIVE.value
    assert profile.approved_by_user_id == SPONSOR_USER_ID
    assert profile.approved_at is not None
    assert profile.prepared_by_user_id == ADMIN_USER_ID
    assert PROFILE_AUDIT_APPROVED in _events(db)


def test_a_draft_is_not_in_force_until_approved(db: Session):
    connector = _connector(db)
    create_profile_draft(
        db, subject=connector, name="Draft", capabilities=[READ], prepared_by_user_id=ADMIN_USER_ID
    )
    db.commit()

    assert get_active_profile(db, organization_id=ORG_ID, subject_id=connector.permission_subject_id) is None
    with pytest.raises(CapabilityNotPermittedError, match="no approved permission profile"):
        assert_capability_permitted(db, connector, READ)


def test_an_empty_profile_is_refused(db: Session):
    """An empty grant would be approved as though it granted something."""
    connector = _connector(db)
    with pytest.raises(PermissionProfileValidationError, match="at least one capability"):
        create_profile_draft(db, subject=connector, name="Empty", capabilities=[])


def test_an_unknown_capability_cannot_enter_a_profile(db: Session):
    connector = _connector(db)
    with pytest.raises(PermissionProfileValidationError, match="Unknown capability"):
        create_profile_draft(
            db, subject=connector, name="Bad", capabilities=["read_everything_forever"]
        )


def test_a_rejected_profile_keeps_its_reason_and_grants_nothing(db: Session):
    connector = _connector(db)
    profile = create_profile_draft(
        db, subject=connector, name="P", capabilities=[READ], prepared_by_user_id=ADMIN_USER_ID
    )
    submit_profile(db, profile)
    reject_profile(
        db, profile, rejected_by_user_id=SPONSOR_USER_ID, rejection_reason="Too broad for this host."
    )
    db.commit()

    assert profile.status == PermissionProfileStatus.WITHDRAWN.value
    assert profile.rejection_reason == "Too broad for this host."
    assert get_active_profile(db, organization_id=ORG_ID, subject_id=connector.permission_subject_id) is None


# --- Criterion 2: a connector cannot operate outside its profile ------------


def test_a_granted_capability_is_permitted(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [READ])

    assert assert_capability_permitted(db, connector, READ).id == profile.id


def test_a_capability_outside_the_profile_is_refused_and_audited(db: Session):
    connector = _connector(db)
    _approved(db, connector, [READ])

    with pytest.raises(CapabilityNotPermittedError, match="outside this Connector"):
        assert_capability_permitted(db, connector, ConnectorCapability.READ_SERVICE_CONFIG.value)

    assert PROFILE_AUDIT_CAPABILITY_DENIED in _events(db)
    denial = next(e for e in db.query(AuditEvent).all() if e.event_type == PROFILE_AUDIT_CAPABILITY_DENIED)
    # The denial has to answer "why did this return nothing?" on its own.
    assert denial.metadata_json["capability"] == ConnectorCapability.READ_SERVICE_CONFIG.value
    # The subject, not the Connector: enforcement is given a PermissionSubjectBearer
    # and genuinely does not know which concrete kind it is. `subject_kind` on the
    # supertable says which table to join, at the cost of one indexed lookup.
    assert denial.metadata_json["subject_id"] == connector.permission_subject_id
    assert denial.metadata_json["reason"]


def test_enforcement_fails_closed_when_no_profile_exists_at_all(db: Session):
    connector = _connector(db)

    with pytest.raises(CapabilityNotPermittedError, match="may do nothing at all"):
        assert_capability_permitted(db, connector, READ)


def test_a_superseded_profile_stops_granting(db: Session):
    connector = _connector(db)
    _approved(db, connector, [READ, ConnectorCapability.READ_OS_VERSION.value])
    # A narrower replacement.
    _approved(db, connector, [READ])

    assert assert_capability_permitted(db, connector, READ) is not None
    with pytest.raises(CapabilityNotPermittedError):
        assert_capability_permitted(db, connector, ConnectorCapability.READ_OS_VERSION.value)


# --- Criterion 3: Docker socket needs its own explicit approval -------------


def test_approving_a_docker_profile_does_not_grant_socket_access(db: Session):
    """The contract's rule, and the one most likely to be lost in implementation."""
    connector = _connector(db, docker=True)
    profile = _approved(db, connector, [ConnectorCapability.LIST_CONTAINERS.value])

    # The profile is active and the capability is granted…
    assert profile.status == PermissionProfileStatus.ACTIVE.value
    assert ConnectorCapability.LIST_CONTAINERS.value in profile.capabilities
    assert profile.docker_socket_approved_at is None

    # …and it still may not run.
    with pytest.raises(CapabilityNotPermittedError, match="own explicit approval"):
        assert_capability_permitted(db, connector, ConnectorCapability.LIST_CONTAINERS.value)


def test_socket_access_works_only_after_its_own_approval(db: Session):
    connector = _connector(db, docker=True)
    profile = _approved(db, connector, [ConnectorCapability.LIST_CONTAINERS.value])

    approve_docker_socket(db, profile, connector, approved_by_user_id=SPONSOR_USER_ID)
    db.commit()

    assert profile.docker_socket_approved_by_user_id == SPONSOR_USER_ID
    assert assert_capability_permitted(db, connector, ConnectorCapability.LIST_CONTAINERS.value)
    assert PROFILE_AUDIT_DOCKER_SOCKET_APPROVED in _events(db)


def test_the_socket_approval_is_its_own_audit_event(db: Session):
    """A trail that could not tell the two approvals apart would lose the rule."""
    connector = _connector(db, docker=True)
    profile = _approved(db, connector, [ConnectorCapability.LIST_CONTAINERS.value])
    approve_docker_socket(db, profile, connector, approved_by_user_id=SPONSOR_USER_ID)
    db.commit()

    events = _events(db)
    assert PROFILE_AUDIT_APPROVED in events
    assert PROFILE_AUDIT_DOCKER_SOCKET_APPROVED in events
    assert events.count(PROFILE_AUDIT_DOCKER_SOCKET_APPROVED) == 1


def test_socket_approval_is_refused_for_a_connector_that_never_needed_it(db: Session):
    connector = _connector(db, docker=False)
    profile = _approved(db, connector, [READ])

    with pytest.raises(PermissionProfileValidationError, match="nothing to approve"):
        approve_docker_socket(db, profile, connector, approved_by_user_id=SPONSOR_USER_ID)


def test_non_container_capabilities_never_need_socket_approval(db: Session):
    connector = _connector(db, docker=True)
    _approved(db, connector, [READ])

    # Same connector, socket unapproved — a non-container capability still runs.
    assert assert_capability_permitted(db, connector, READ)
    assert READ not in DOCKER_SOCKET_CAPABILITIES


# --- Criterion 4: changing an approved profile requires re-approval ---------


def test_widening_a_profile_requires_a_new_approval_and_supersedes(db: Session):
    connector = _connector(db)
    first = _approved(db, connector, [READ])

    second = _approved(db, connector, [READ, ConnectorCapability.READ_OS_VERSION.value])

    db.refresh(first)
    assert second.version == first.version + 1
    assert first.status == PermissionProfileStatus.SUPERSEDED.value
    assert first.superseded_by_id == second.id
    # The old grant is still readable — "what was permitted then?" survives.
    assert first.capabilities == [READ]


def test_there_is_no_route_that_edits_an_approved_profile(db: Session):
    from src.api.routes import permission_profiles as routes

    methods = {m for route in routes.router.routes for m in route.methods}
    assert "PATCH" not in methods
    assert "PUT" not in methods
    assert "DELETE" not in methods


def test_an_already_approved_profile_cannot_be_approved_again(db: Session):
    connector = _connector(db)
    profile = _approved(db, connector, [READ])

    with pytest.raises(PermissionProfileValidationError, match="awaiting approval"):
        approve_profile(db, profile, approved_by_user_id=SPONSOR_USER_ID)


# --- Tenancy ---------------------------------------------------------------


def test_a_profile_does_not_leak_across_organisations(db: Session):
    connector = _connector(db)
    _approved(db, connector, [READ])

    assert get_active_profile(db, organization_id=ORG_ID, subject_id=connector.permission_subject_id) is not None
    assert get_active_profile(db, organization_id=OTHER_ORG_ID, subject_id=connector.permission_subject_id) is None


def test_the_capability_vocabulary_does_not_overlap_discovery_capabilities(db: Session):
    """Two grants that looked like one would blur two different questions."""
    from src.core.constants.discovery_scope_proposal_enums import DiscoveryCapability

    connector_caps = {c.value for c in ConnectorCapability}
    discovery_caps = {c.value for c in DiscoveryCapability}
    assert connector_caps & discovery_caps == set()


def test_discovery_profile_is_enforced_without_merging_capability_vocabularies(db: Session):
    from src.core.constants.discovery_scope_proposal_enums import DiscoveryCapability

    subject = register_permission_subject(
        db,
        organization_id=ORG_ID,
        subject_kind=PermissionSubjectKind.DISCOVERY_SCOPE_PROPOSAL,
    )
    profile = PermissionProfile(
        organization_id=ORG_ID,
        subject_id=subject.id,
        name="Backfilled discovery profile",
        capabilities=[],
        discovery_capabilities=[DiscoveryCapability.EXTERNAL_DISCOVERY.value],
        status=PermissionProfileStatus.ACTIVE.value,
    )
    db.add(profile)
    db.flush()
    proposal = DiscoveryScopeProposal(
        organization_id=ORG_ID,
        evidence_source_id="source-1",
        permission_subject_id=subject.id,
        permission_profile_id=profile.id,
        status="approved",
        inclusions=[],
        exclusions=[],
        checks=[DiscoveryCapability.EXTERNAL_DISCOVERY.value],
        rationale={},
    )
    db.add(proposal)
    db.commit()

    authorised = assert_capability_permitted(
        db, proposal, DiscoveryCapability.EXTERNAL_DISCOVERY.value
    )
    assert authorised.id == profile.id
    with pytest.raises(CapabilityNotPermittedError):
        assert_capability_permitted(db, proposal, READ)


# --- What the supertable is for (Søren's decision, 2026-08-18) --------------


def test_a_profile_reaches_its_subject_through_a_real_foreign_key(db: Session):
    """The point of the supertable, and what a subject_type/subject_id pair loses.

    `permission_profiles.subject_id` is a foreign key to a real table, so the
    database itself can still answer "does this profile point at something that
    exists?" — which a polymorphic type/id pair could never do.
    """
    fks = list(PermissionProfile.__table__.c.subject_id.foreign_keys)

    assert len(fks) == 1
    assert fks[0].column.table.name == "permission_subjects"
    # And there is no type discriminator on the profile at all — the kind lives
    # on the subject, where it is descriptive rather than load-bearing.
    assert "subject_type" not in PermissionProfile.__table__.c
    assert "connector_id" not in PermissionProfile.__table__.c


def test_a_connector_has_exactly_one_permission_subject(db: Session):
    connector = _connector(db)
    subject = db.get(PermissionSubject, connector.permission_subject_id)

    assert subject is not None
    assert subject.organization_id == connector.organization_id
    assert subject.subject_kind == PermissionSubjectKind.ACCESS_CONNECTOR.value
    # Enforced by the schema, not only by the service that happens to create it.
    assert AccessConnector.__table__.c.permission_subject_id.unique is True
    assert AccessConnector.__table__.c.permission_subject_id.nullable is False


def test_enforcement_needs_no_knowledge_of_the_subject_kind(db: Session):
    """Code polymorphism, which is the half that costs nothing.

    `assert_capability_permitted` takes anything satisfying
    `PermissionSubjectBearer`. A new kind of permissionable thing needs no branch
    here, no new column on `permission_profiles`, and no change to this path.
    """
    from src.core.services.permission_subject_service import PermissionSubjectBearer

    connector = _connector(db)
    _approved(db, connector, [READ])

    assert isinstance(connector, PermissionSubjectBearer)

    class FutureSubject:
        """Stands in for whatever C4 permissions next — a Collector, say.

        Its whole surface is the Protocol: an organisation, a subject id, and its
        own answer to "may you be used right now?". CA-07.4 added the third, and
        the cost of that to a future subject kind is this one property — in
        exchange for inheriting the withdrawal check without writing it.
        """

        def __init__(
            self,
            organization_id: int,
            permission_subject_id: str,
            inactive_reason: str | None = None,
        ) -> None:
            self.organization_id = organization_id
            self.permission_subject_id = permission_subject_id
            self.permission_subject_inactive_reason = inactive_reason

    stand_in = FutureSubject(connector.organization_id, connector.permission_subject_id)
    # Not an AccessConnector, never mentioned in the enforcement path, still works.
    assert assert_capability_permitted(db, stand_in, READ) is not None

    # And a withdrawn one is refused, with no code in the enforcement path
    # knowing what kind of thing it is or what "withdrawn" means to it.
    withdrawn = FutureSubject(
        connector.organization_id,
        connector.permission_subject_id,
        inactive_reason="This Collector was retired.",
    )
    with pytest.raises(CapabilityNotPermittedError, match="retired"):
        assert_capability_permitted(db, withdrawn, READ)


def test_exactly_one_function_decides_whether_a_capability_is_permitted():
    """#248's exit criterion, asserted structurally rather than trusted to review.

    The invariant is true today — `permission_enforcement_service` holds the only
    decision — but nothing was keeping it true. A second enforcement function
    grown in a route or a runner would look like correct code at review time, and
    the point of absorbing the JSONB bag was to stop two places answering one
    question.

    **What this catches**: a second `*_capability_permitted` function anywhere in
    `src/`. **What it does not**: an inline membership test written in a caller.
    A regex broad enough to find that also flags scanner *capability support*
    (`stage_key in p.capabilities().supported_discovery_stages`) and plain
    response building, which are different questions — so the narrow assertion
    that actually holds is the one made here, and the import test below closes
    the rest of the gap.
    """
    from pathlib import Path
    import re

    source_root = Path(__file__).resolve().parents[1] / "src"
    definition = re.compile(r"^def \w*capability_permitted\b", re.M)

    definitions = [
        f"{path.relative_to(source_root).as_posix()}:{match.group(0)}"
        for path in source_root.rglob("*.py")
        for match in definition.finditer(path.read_text())
    ]

    assert definitions == [
        "core/services/permission_enforcement_service.py:def assert_capability_permitted"
    ], f"enforcement must live in one function; found: {definitions}"


def test_only_the_permission_services_can_read_a_profile_capability_list():
    """The other half: a module that cannot see the model cannot decide on it.

    Enforcement is not a rule about behaviour alone, it is a rule about reach.
    Each module below is allowed for a stated reason; a new name appearing here
    is the review question — *why does this need to see the stored
    capabilities?* — asked automatically rather than hoped for.
    """
    from pathlib import Path
    import re

    source_root = Path(__file__).resolve().parents[1] / "src"
    imports = re.compile(r"\bPermissionProfile\b")
    allowed = {
        # The model layer itself: the model, its sibling subject, the vocabulary
        # and the two barrels that re-export them. Naming a type is not deciding
        # with it.
        "core/model_defs/permission_profile.py",
        "core/model_defs/permission_subject.py",
        "core/model_defs/__init__.py",
        "core/constants/permission_profile_enums.py",
        "core/models.py",
        # The one place that decides.
        "core/services/permission_enforcement_service.py",
        # Builds, submits and approves profiles — decides what may *enter* one,
        # which is a different question from whether an action is permitted.
        "core/services/permission_profile_service.py",
        # The profile's own surface.
        "api/routes/permission_profiles.py",
        # #248 — reads the profile a proposal now points at, in place of the
        # JSONB bag it replaced. Echoes it back; gates nothing on it.
        "api/routes/discovery_run.py",
        "core/services/discovery_scope_proposal_service.py",
        # Reports what a connector may do; asks enforcement, never re-decides.
        "core/services/connector_access_test_service.py",
    }

    reaching = sorted(
        path.relative_to(source_root).as_posix()
        for path in source_root.rglob("*.py")
        if imports.search(path.read_text())
    )

    unexpected = [name for name in reaching if name not in allowed]
    assert unexpected == [], (
        "a new module can see a profile's stored capabilities — say why, or ask "
        f"permission_enforcement_service instead: {unexpected}"
    )
