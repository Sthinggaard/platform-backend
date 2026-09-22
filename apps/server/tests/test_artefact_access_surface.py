"""CA-07.6 (#240) — readiness is visible, and no secret is visible with it.

The story's exit criterion is one sentence: *a technical owner can see access
readiness and act on it, without any screen or log ever showing them a secret.*
Four of its acceptance criteria are asserted here rather than described —
redaction, isolation, the two-states collision, and the shape of the surface —
because "no credential is exposed" is exactly the kind of claim that is true
until someone adds a field.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.artefact_access_lifecycle_enums import (
    ACCESS_STATES_AWAITING_A_PERSON,
    ArtefactAccessState,
    VerificationApprovalSource,
)
from src.core.constants.secret_redaction import REDACTED, is_secret_key, redact
from src.core.database import Base
from src.core.model_defs.artefact_access_lifecycle import ArtefactAccessLifecycle
from src.core.model_defs.assets_runtime import (
    Asset,
    AssetLifecycleState,
    AssetStatus,
    ConnectivityStatus,
    Criticality,
    Environment,
    ScanStartMode,
    SetupConfidence,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.model_defs.tenant_org import Organization
from src.api.middleware.tenant_context import TenantContext
from src.api.routes.access_connectors import require_org_admin
from src.api.routes.artefact_inventory import list_artefact_inventory_route
from src.core.exceptions import AuthorizationError
from src.core.model_defs.tenant_identity import User
from src.core.roles import UserRole
from src.core.services.artefact_inventory_service import list_inventory
from src.core.services.audit_service import append_audit_event


@pytest.fixture(scope="function")
def db():
    engine = create_engine("sqlite:///:memory:")
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine)
    session.add_all(
        [
            Organization(id=1, name="Org One", slug="org-one"),
            Organization(id=2, name="Org Two", slug="org-two"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _asset(db: Session, *, organization_id: int = 1, display_name: str = "10.0.0.15") -> Asset:
    asset = Asset(
        organization_id=organization_id,
        type="Observed host",
        provider="collector",
        display_name=display_name,
        layer="Infrastructure",
        environment=Environment.PROD,
        criticality=Criticality.MEDIUM,
        status=AssetStatus.PARTIALLY_OBSERVED,
        connectivity_status=ConnectivityStatus.PENDING_VERIFICATION,
        setup_confidence=SetupConfidence.LOW,
        scan_start_mode=ScanStartMode.AUDIT_ONLY,
        findings_count=0,
        risk_score=0.0,
        confidence=0.4,
        lifecycle_state=AssetLifecycleState.ACTIVE,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def _access(
    db: Session,
    asset: Asset,
    *,
    state: str = ArtefactAccessState.VERIFICATION_READY.value,
    connector_id: str | None = "connector-1",
) -> ArtefactAccessLifecycle:
    # Two CHECK constraints hold CA-07.5's contract rule in the schema: nothing
    # may be `running` or `complete` without an approval stamped on the row, and
    # an approval must name which kind of "yes" it was. The fixture satisfies
    # them rather than working around them — they are the rule, not an obstacle.
    approved = state in (
        ArtefactAccessState.APPROVED.value,
        ArtefactAccessState.RUNNING.value,
        ArtefactAccessState.COMPLETE.value,
    )
    lifecycle = ArtefactAccessLifecycle(
        organization_id=asset.organization_id,
        asset_id=asset.id,
        state=state,
        requested_choice="connect_host",
        requested_at=utcnow(),
        connector_id=connector_id,
        verification_approved_at=utcnow() if approved else None,
        verification_approved_source=(
            VerificationApprovalSource.PER_ARTEFACT.value if approved else None
        ),
    )
    db.add(lifecycle)
    db.commit()
    return lifecycle


# --- Redaction ---------------------------------------------------------------


def test_secret_bearing_keys_are_redacted_at_any_depth():
    """A secret one level down is still a secret in the log."""
    redacted = redact(
        {
            "username": "svc-scan",
            "password": "hunter2",
            "attempt": {"apiToken": "tok_live_123", "port": 22},
            "history": [{"client_secret": "s3cr3t"}, {"host": "10.0.0.15"}],
        }
    )

    assert redacted["password"] == REDACTED
    assert redacted["attempt"]["apiToken"] == REDACTED
    assert redacted["history"][0]["client_secret"] == REDACTED
    # Everything that is not a secret survives — a redactor that eats context is
    # a redactor people route around.
    assert redacted["username"] == "svc-scan"
    assert redacted["attempt"]["port"] == 22
    assert redacted["history"][1]["host"] == "10.0.0.15"


def test_redaction_keeps_the_key_so_the_omission_is_visible():
    """A vanished field reads as "there was nothing here", which is a different
    and more misleading fact than "something was held back"."""
    redacted = redact({"password": "hunter2"})
    assert "password" in redacted


def test_the_fields_that_make_readiness_visible_are_not_redacted():
    """The whole story is that readiness stays visible. `credential_fingerprint`
    identifies *which* key is in use without deriving from anything reversible,
    and `credential_model` says where a credential may live — redacting either
    would hide the readiness this surface exists to show."""
    for key in ("credential_fingerprint", "credential_model", "credential_username"):
        assert is_secret_key(key) is False, key

    for key in ("password", "api_key", "APIKey", "authorization", "private_key", "sessionKey"):
        assert is_secret_key(key) is True, key


def test_audit_metadata_is_redacted_at_the_choke_point(db: Session):
    """Not at each call site. Every audit event in the platform goes through
    `append_audit_event`, and a call site can forget where a choke point cannot."""
    append_audit_event(
        db,
        organization_id=1,
        event_type="artefact_access_transitioned",
        metadata={"connector": "dc-1", "password": "hunter2", "nested": {"token": "abc"}},
    )
    db.commit()

    event = db.query(AuditEvent).one()
    assert event.metadata_json["password"] == REDACTED
    assert event.metadata_json["nested"]["token"] == REDACTED
    assert event.metadata_json["connector"] == "dc-1"


def test_the_inventory_surface_has_no_field_that_could_carry_a_secret(db: Session):
    """The exit criterion, asserted against the response shape rather than
    against one example row: a field that cannot exist cannot leak."""
    from src.api.routes.artefact_inventory import InventoryEntryResponse

    leaky = [name for name in InventoryEntryResponse.model_fields if is_secret_key(name)]
    assert leaky == [], f"the inventory row exposes secret-bearing fields: {leaky}"


def test_no_rendered_access_value_is_a_secret(db: Session):
    """And against a real row, because the shape test above passes trivially if
    the surface simply stops reporting access at all."""
    asset = _asset(db)
    _access(db, asset)

    entry = list_inventory(db, organization_id=1).entries[0]

    assert entry.access_state == ArtefactAccessState.VERIFICATION_READY.value
    assert entry.access_connector_id == "connector-1"
    for value in (entry.access_state, entry.access_connector_id):
        assert REDACTED not in str(value)


# --- Isolation ---------------------------------------------------------------


def test_one_organisations_access_is_unreachable_from_another(db: Session):
    """The access loader joins on asset id, and asset ids are global. Scoping on
    them alone would be correct today and silently wrong the moment a caller
    passes ids from anywhere else."""
    theirs = _asset(db, organization_id=2, display_name="their-host")
    _access(db, theirs, state=ArtefactAccessState.APPROVED.value, connector_id="their-connector")
    ours = _asset(db, organization_id=1, display_name="our-host")

    entries = list_inventory(db, organization_id=1).entries

    assert [entry.display_name for entry in entries] == ["our-host"]
    assert entries[0].asset_id == ours.id
    assert entries[0].access_state is None
    assert entries[0].access_connector_id is None


def test_an_access_record_belonging_to_another_organisation_is_never_attached(db: Session):
    """The sharpest form: same asset id space, a lifecycle row that names our
    asset but belongs to them. It must not be picked up."""
    ours = _asset(db, organization_id=1, display_name="our-host")
    db.add(
        ArtefactAccessLifecycle(
            organization_id=2,
            asset_id=ours.id,
            state=ArtefactAccessState.APPROVED.value,
            requested_choice="connect_host",
            requested_at=utcnow(),
            connector_id="their-connector",
        )
    )
    db.commit()

    entry = list_inventory(db, organization_id=1).entries[0]

    assert entry.access_state is None
    assert entry.access_connector_id is None


# --- The two-state collision -------------------------------------------------


def test_identity_state_and_access_state_are_both_reported_and_neither_is_lost(db: Session):
    """The collision CA-07.6 was told to design around rather than discover.

    An artefact can be confirmed in the inventory with no access configured, or
    unconfirmed with access already approved. One field holding both would make
    two different questions look like one answer.
    """
    confirmed_no_access = _asset(db, display_name="a-confirmed")
    unconfirmed_with_access = _asset(db, display_name="b-unconfirmed")
    unconfirmed_with_access.lifecycle_state = AssetLifecycleState.UNCONFIRMED
    db.commit()
    _access(db, unconfirmed_with_access, state=ArtefactAccessState.APPROVED.value)

    by_name = {entry.display_name: entry for entry in list_inventory(db, organization_id=1).entries}

    assert by_name["a-confirmed"].lifecycle_state == "ACTIVE"
    assert by_name["a-confirmed"].access_state is None

    assert by_name["b-unconfirmed"].lifecycle_state == "UNCONFIRMED"
    assert by_name["b-unconfirmed"].access_state == ArtefactAccessState.APPROVED.value


def test_never_requested_access_is_distinct_from_a_journey_that_has_not_advanced(db: Session):
    """`None` and `access_requested` are different facts and must stay so."""
    never = _asset(db, display_name="a-never")
    requested = _asset(db, display_name="b-requested")
    _access(db, requested, state=ArtefactAccessState.ACCESS_REQUESTED.value, connector_id=None)

    by_name = {entry.display_name: entry for entry in list_inventory(db, organization_id=1).entries}

    assert by_name["a-never"].access_state is None
    assert by_name["b-requested"].access_state == ArtefactAccessState.ACCESS_REQUESTED.value


# --- Waiting on a person -----------------------------------------------------


@pytest.mark.parametrize(
    ("state", "awaiting"),
    [
        (ArtefactAccessState.ACCESS_REQUESTED.value, True),
        (ArtefactAccessState.CONFIGURED.value, True),
        (ArtefactAccessState.TESTED.value, False),
        (ArtefactAccessState.VERIFICATION_READY.value, True),
        (ArtefactAccessState.APPROVED.value, False),
        (ArtefactAccessState.RUNNING.value, False),
        (ArtefactAccessState.COMPLETE.value, False),
    ],
)
def test_the_surface_marks_exactly_the_states_that_wait_on_a_person(
    db: Session, state: str, awaiting: bool
):
    """`VERIFICATION_READY` is the one that matters: it means a human may now be
    asked, and unmarked it would sit there looking like progress."""
    asset = _asset(db)
    _access(db, asset, state=state)

    entry = list_inventory(db, organization_id=1).entries[0]

    assert entry.access_awaiting_person is awaiting
    assert (state in ACCESS_STATES_AWAITING_A_PERSON) is awaiting


def test_awaiting_a_person_is_derived_from_the_state_and_cannot_disagree_with_it(db: Session):
    """Computed rather than stored, so the badge and the state are one fact."""
    asset = _asset(db)
    lifecycle = _access(db, asset, state=ArtefactAccessState.VERIFICATION_READY.value)
    assert list_inventory(db, organization_id=1).entries[0].access_awaiting_person is True

    lifecycle.state = ArtefactAccessState.APPROVED.value
    lifecycle.verification_approved_at = utcnow()
    lifecycle.verification_approved_source = VerificationApprovalSource.PER_ARTEFACT.value
    db.commit()

    assert list_inventory(db, organization_id=1).entries[0].access_awaiting_person is False


# --- Permissions: viewing readiness and changing access are separate rights ---


def _user(db: Session, *, user_id: int, role: str, organization_id: int = 1) -> User:
    user = User(
        id=user_id,
        organization_id=organization_id,
        email=f"{role}-{user_id}@risklence.test",
        password_hash="x",
        first_name=role.title(),
        last_name="User",
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    return user


def _list_inventory_route(db: Session, ctx: TenantContext):
    """Called directly rather than over HTTP, so FastAPI's `Query(...)` defaults
    are never resolved — they have to be supplied here or the route receives
    Query objects where it expects values."""
    return list_artefact_inventory_route(
        lifecycle_state=[],
        asset_type=None,
        layer=None,
        review_status=None,
        candidacy=None,
        q=None,
        limit=100,
        offset=0,
        ctx=ctx,
        db=db,
    )


def _ctx(user_id: int, role: str, organization_id: int = 1) -> TenantContext:
    return TenantContext(
        user_id=user_id,
        organization_id=organization_id,
        email=f"{role}-{user_id}@risklence.test",
        roles=[role],
        permissions=[],
    )


def test_a_member_can_see_access_readiness(db: Session):
    """Seeing readiness is reading a list of your own organisation's things.
    Gating it behind admin would mean the person who has to chase an approval
    cannot see that one is outstanding."""
    _user(db, user_id=5, role=UserRole.MEMBER.value)
    asset = _asset(db)
    _access(db, asset, state=ArtefactAccessState.VERIFICATION_READY.value)

    response = _list_inventory_route(db, _ctx(5, UserRole.MEMBER.value))

    assert response.entries[0].access_state == ArtefactAccessState.VERIFICATION_READY.value
    assert response.entries[0].access_awaiting_person is True


def test_a_member_cannot_change_access(db: Session):
    """The other half of the criterion. Reading readiness and altering it are
    different authorities, and the same person holding both is a choice an
    organisation makes, not a default this platform ships."""
    _user(db, user_id=5, role=UserRole.MEMBER.value)

    with pytest.raises(AuthorizationError):
        require_org_admin(db, _ctx(5, UserRole.MEMBER.value))


def test_an_admin_can_change_access(db: Session):
    _user(db, user_id=6, role=UserRole.ORG_ADMIN.value)
    require_org_admin(db, _ctx(6, UserRole.ORG_ADMIN.value))


def test_a_consultant_can_read_but_never_change(db: Session):
    """DISC-44 defines the consultant as external, time-boxed and read-only.
    An external party widening what may be reached inside a host would weaken
    the audit argument this epic rests on."""
    _user(db, user_id=8, role=UserRole.CONSULTANT.value)
    asset = _asset(db)
    _access(db, asset)

    response = _list_inventory_route(db, _ctx(8, UserRole.CONSULTANT.value))
    assert response.entries[0].access_state == ArtefactAccessState.VERIFICATION_READY.value

    with pytest.raises(AuthorizationError):
        require_org_admin(db, _ctx(8, UserRole.CONSULTANT.value))


def test_the_inventory_refuses_someone_from_another_organisation(db: Session):
    """The route resolves the user inside the requesting organisation, so a
    context naming an organisation the user does not belong to finds nobody."""
    _user(db, user_id=9, role=UserRole.ORG_ADMIN.value, organization_id=2)

    with pytest.raises(AuthorizationError):
        _list_inventory_route(db, _ctx(9, UserRole.ORG_ADMIN.value, organization_id=1))
