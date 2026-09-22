"""One owner decision about one slot, without publishing the service.

Søren, 2026-09-02, on the mapping wizard: *"It goes through all five or so
dependencies in a fixed setup. This is too linear and it does not really help
the users."*

The wizard was linear because the API was: rejecting **one** suggestion had a
route, accepting one did not. The only way to record an acceptance was
`/slots/publish`, which takes a list, marks the bundle `bundle_published`, and
derives `coverage_score` from the request body — so a batch of one would report
a service fully published and 100% covered after the reader's first answer.

`test_a_decision_does_not_publish_the_bundle` is the test that motivated the
whole route; if it ever goes green by accident, the linearity is back.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray, JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from fastapi import HTTPException

from src.api.middleware.tenant_context import TenantContext
from src.api.routes.bundle_contracts import DecideSlotMappingRequest
from src.api.routes.bundle_mapping_decide import decide_slot_mapping
from src.core.database import Base
from src.core.models import BusinessService, DependencyBundle, Organization, SlotInstance, User, ValueStream
from src.core.roles import UserRole


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add_all([
        Organization(id=1, name="Org One", slug="org-one", plan_tier="enterprise", subscription_status="active", onboarding_completed=False),
        Organization(id=2, name="Org Two", slug="org-two", plan_tier="enterprise", subscription_status="active", onboarding_completed=False),
    ])
    session.commit()
    yield session
    session.close()


def _admin(db: Session, *, user_id: int, organization_id: int) -> User:
    """An administrator, because `require_process_editor` returns early for one.

    The reject/supersede suite next door is quarantined under #353 for exactly
    the omission this avoids: its fixture seeds no one who may edit, so
    authorisation refuses before the behaviour under test is ever reached.
    """
    user = User(
        id=user_id,
        organization_id=organization_id,
        email=f"admin{user_id}@risklence.test",
        email_verified=True,
        role=UserRole.ORG_ADMIN.value,
        is_active=True,
        status="active",
        mfa_enabled=False,
        mfa_enforced_by_policy=False,
    )
    db.add(user)
    db.flush()
    return user


def _ctx(*, organization_id: int = 1, user_id: int = 7) -> TenantContext:
    return TenantContext(
        user_id=user_id, organization_id=organization_id,
        email="admin7@risklence.test", roles=["org_admin"], permissions=[],
    )


def _seed(
    db: Session,
    *,
    organization_id: int = 1,
    service_id: str = "svc-1",
    slot_id: str = "slot-1",
    seed_admin: bool = True,
) -> DependencyBundle:
    if seed_admin:
        _admin(db, user_id=7, organization_id=organization_id)
    # The service must be linked to a process. `require_service_process_editor`
    # loops over the service's processes and the admin shortcut lives *inside*
    # that loop, so a service linked to nothing fails closed — deliberately:
    # "Services not linked to a process fail closed until an administrator
    # links them into the process map."
    process_id = f"vs-{organization_id}"
    db.add(ValueStream(id=process_id, organization_id=organization_id, name="Order to Cash"))
    db.add(BusinessService(
        id=service_id, organization_id=organization_id,
        name="Payment Processing", archetype="transactional_system",
        value_stream_ids=[process_id],
    ))
    bundle = DependencyBundle(
        id=str(uuid.uuid4()), organization_id=organization_id, service_id=service_id,
        status="draft", mode="manual_training", lifecycle_state="template_loaded", groups=[],
    )
    db.add(bundle)
    db.add(SlotInstance(
        id=str(uuid.uuid4()), organization_id=organization_id, service_id=service_id,
        slot_id=slot_id, group_key="external_providers", status="unknown",
        mapping_status="suggested", asset_id="asset-9", asset_label="Stripe",
    ))
    db.commit()
    return bundle


def _decide(db: Session, **body) -> object:
    return decide_slot_mapping(
        service_id="svc-1", slot_id="slot-1",
        body=DecideSlotMappingRequest(**body), ctx=_ctx(), db=db,
    )


def _decided_row(db: Session) -> SlotInstance:
    """The slot the test decided, not merely the only slot that exists.

    Deciding materialises every slot the service's template defines
    (`ensure_slot_instances`, 2026-09-03), so a service now has as many rows as
    its template has slots.
    """
    return (
        db.query(SlotInstance)
        .filter(SlotInstance.service_id == "svc-1", SlotInstance.slot_id == "slot-1")
        .one()
    )


def test_a_single_slot_can_be_accepted_on_its_own(db: Session):
    _seed(db)
    result = _decide(db, decision="mapped", asset_id="asset-9", asset_label="Stripe")

    assert result.slot.status == "mapped"
    assert result.slot.asset_id == "asset-9"
    # Narrowed from `.one()` on 2026-09-03: deciding now also materialises the
    # slots the service's template defines, so "the only row" stopped being a
    # way to say "the row that was decided".
    row = _decided_row(db)
    assert row.mapping_status == "approved"
    assert row.provenance == "owner_approved"
    assert row.decided_by == "7"


def test_a_decision_does_not_publish_the_bundle(db: Session):
    """The reason this route exists.

    Publishing is a different act. One answer must not report the service
    published, and must not be counted as coverage of anything.
    """
    bundle = _seed(db)
    _decide(db, decision="mapped", asset_id="asset-9", asset_label="Stripe")

    db.refresh(bundle)
    assert bundle.lifecycle_state == "template_loaded"


def test_setting_a_slot_aside_never_keeps_the_asset(db: Session):
    """An asset on a "not applicable" answer would record a decision nobody made.

    The suggestion arrives with an asset already attached, so a caller echoing
    the body back is the likely mistake — the route drops it rather than trusting
    the caller to.
    """
    _seed(db)
    result = _decide(db, decision="not_applicable", asset_id="asset-9", asset_label="Stripe")

    assert result.slot.status == "not_applicable"
    assert result.slot.asset_id is None
    assert result.slot.asset_label is None


def test_unknown_is_not_recorded_as_a_confident_answer(db: Session):
    _seed(db)
    _decide(db, decision="unknown")

    row = _decided_row(db)
    assert row.status == "unknown"
    assert row.mapping_status == "needs_review"
    # Confidence is about verification; an unanswered question has none.
    assert row.mapping_confidence is None


def test_a_slot_from_another_organisation_is_not_reachable(db: Session):
    # The whole service lives in org 2; the caller is an admin of org 1.
    _seed(db, organization_id=2, seed_admin=False)
    _admin(db, user_id=7, organization_id=1)
    db.commit()

    with pytest.raises(HTTPException) as excinfo:
        _decide(db, decision="mapped", asset_id="asset-9", asset_label="Stripe")
    assert excinfo.value.status_code == 404

    # And nothing was written to the other tenant's row.
    assert db.query(SlotInstance).one().status == "unknown"


def test_a_member_may_not_decide(db: Session):
    _seed(db)
    member = User(
        id=9, organization_id=1, email="member@risklence.test", email_verified=True,
        role=UserRole.MEMBER.value, is_active=True, status="active",
        mfa_enabled=False, mfa_enforced_by_policy=False,
    )
    db.add(member)
    db.commit()

    with pytest.raises(Exception) as excinfo:
        decide_slot_mapping(
            service_id="svc-1", slot_id="slot-1",
            body=DecideSlotMappingRequest(decision="mapped", asset_id="asset-9"),
            ctx=_ctx(user_id=9), db=db,
        )
    assert "access is required" in str(excinfo.value) or excinfo.value.__class__.__name__ == "AuthorizationError"
    assert db.query(SlotInstance).one().status == "unknown"


def test_deciding_materialises_the_slots_the_template_defines(db: Session):
    """A slot exists because the template says so, not because the engine spoke.

    Søren, 2026-09-03: *"would it not be find artefact, select the artefact and
    map the FK to the dependency so it is connected in the DB?"* It could not,
    for any dependency the suggestion engine had no candidate for: no row
    existed, and this route updates a row. Every artefact he picked did nothing
    and said nothing.
    """
    _seed(db)
    before = {row.slot_id for row in db.query(SlotInstance).all()}
    assert before == {"slot-1"}

    _decide(db, decision="mapped", asset_id="asset-9", asset_label="Stripe")

    after = {row.slot_id for row in db.query(SlotInstance).all()}
    assert after > before, "the template's own slots should now have rows"

    # The ones it created are unanswered — a row nobody decided must never
    # arrive already approved.
    for row in db.query(SlotInstance).filter(SlotInstance.slot_id != "slot-1").all():
        assert row.status == "unknown"
        assert row.mapping_status == "needs_review"
        assert row.asset_id is None
