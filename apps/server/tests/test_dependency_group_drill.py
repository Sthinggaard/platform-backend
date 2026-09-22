"""What one dependency group's drill actually returns.

⚠️ This endpoint had no live coverage: every test of it lives in
`test_bundles_routes.py`, quarantined whole under #353 because its DummyDB
fixtures predate the authorisation the routes now require. So the response shape
was free to drift, and it did — it returned one entry per **slot** while
identifying each by its **asset**, which is not an identity:

- two slots in one group can hold the same asset (a shared dependency, or a
  single point of failure reached two ways);
- every unmapped slot carries ``asset_id=""``.

React answered the collision by dropping or duplicating rows, reported on
2026-09-03 as *"Encountered two children with the same key, `92`"*. The slot id
was in hand the whole time and was not sent.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import bundle_slot_mapping_routes as routes
from src.api.routes.bundle_slot_mapping_routes import (
    get_dependency_group_drill,
    get_service_bundle_runtime,
)
from src.core.database import Base
from src.core.models import (
    BusinessService,
    DependencyBundle,
    Organization,
    SlotInstance,
    User,
    ValueStream,
)
from src.core.roles import UserRole
from src.core.services import dependency_decision_service as decisions

GROUP = {
    "key": "data",
    "label": "Data storage",
    "description": "Where the data lives.",
    "required": True,
}


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(
        Organization(
            id=1,
            name="Org One",
            slug="org-one",
            plan_tier="enterprise",
            subscription_status="active",
            onboarding_completed=False,
        )
    )
    session.commit()
    yield session
    session.close()


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=7,
        organization_id=1,
        email="admin7@risklence.test",
        roles=["org_admin"],
        permissions=[],
    )


def _seed(db: Session, *, slots: list[tuple[str, str]]) -> None:
    """`slots` is (slot_id, asset_id) — the pairing the bug was about."""
    db.add(
        User(
            id=7,
            organization_id=1,
            email="admin7@risklence.test",
            email_verified=True,
            role=UserRole.ORG_ADMIN.value,
            is_active=True,
            status="active",
            mfa_enabled=False,
            mfa_enforced_by_policy=False,
        )
    )
    db.add(ValueStream(id="vs-1", organization_id=1, name="Order to Cash"))
    # No archetype and no template key: the canonical-slot filter then has
    # nothing to narrow by and every seeded row is returned, which keeps this
    # test about the response shape rather than about template resolution.
    db.add(
        BusinessService(
            id="svc-1",
            organization_id=1,
            name="Frontend Application",
            archetype=None,
            value_stream_ids=["vs-1"],
        )
    )
    db.add(
        DependencyBundle(
            id=str(uuid.uuid4()),
            organization_id=1,
            service_id="svc-1",
            status="published",
            mode="manual_training",
            lifecycle_state="bundle_published",
            groups=[GROUP],
        )
    )
    for slot_id, asset_id in slots:
        db.add(
            SlotInstance(
                id=str(uuid.uuid4()),
                organization_id=1,
                service_id="svc-1",
                slot_id=slot_id,
                group_key="data",
                status="mapped" if asset_id else "unknown",
                mapping_status="approved" if asset_id else "needs_review",
                asset_id=asset_id or None,
                asset_label="Managed PostgreSQL" if asset_id else None,
            )
        )
    db.commit()


def _drill(db: Session):
    return get_dependency_group_drill(service_id="svc-1", group_key="data", ctx=_ctx(), db=db)


def test_every_row_carries_the_slot_it_is(db: Session) -> None:
    _seed(db, slots=[("general_data_store", "asset-92"), ("backup_data_store", "asset-93")])

    result = _drill(db)

    assert {row.slot_id for row in result.assets} == {"general_data_store", "backup_data_store"}


def test_the_order_is_the_same_every_time(db: Session) -> None:
    # The query had no ORDER BY, so the same request could hand a reader their
    # dependencies in a different order on each load and rows moved under the
    # cursor. Stable, not yet meaningful — the template's display_order is what
    # a reader should see, and that needs the slot-template join.
    _seed(db, slots=[("general_data_store", "asset-92"), ("backup_data_store", "asset-93")])

    assert [row.slot_id for row in _drill(db).assets] == [row.slot_id for row in _drill(db).assets]
    assert [row.slot_id for row in _drill(db).assets] == ["backup_data_store", "general_data_store"]


def test_two_slots_holding_one_asset_stay_distinguishable(db: Session) -> None:
    # The defect, exactly: same asset, two slots. Before the slot id was sent,
    # these two rows were indistinguishable to any client.
    _seed(db, slots=[("general_data_store", "asset-92"), ("reporting_data_store", "asset-92")])

    result = _drill(db)

    assert len({row.slot_id for row in result.assets}) == 2
    assert {row.asset_id for row in result.assets} == {"asset-92"}


def test_unmapped_slots_stay_distinguishable_too(db: Session) -> None:
    # Every unmapped slot carries an empty asset_id, so the asset could not tell
    # them apart even in principle.
    _seed(db, slots=[("general_data_store", ""), ("backup_data_store", "")])

    result = _drill(db)

    assert len({row.slot_id for row in result.assets}) == 2
    assert {row.asset_id for row in result.assets} == {""}


def test_template_group_metadata_keeps_a_stale_published_bundle_drillable(db: Session) -> None:
    """A current template group must not 404 just because bundle JSONB predates it."""
    _seed(db, slots=[])
    service = db.query(BusinessService).filter(BusinessService.id == "svc-1").one()
    service.archetype = "identity_access"
    db.add(
        SlotInstance(
            id=str(uuid.uuid4()),
            organization_id=1,
            service_id="svc-1",
            slot_id="identity_provider",
            group_key="identity_access",
            status="unknown",
            mapping_status="needs_review",
            asset_id=None,
            asset_label=None,
        )
    )
    db.commit()

    result = get_dependency_group_drill(
        service_id="svc-1",
        group_key="identity_access",
        ctx=_ctx(),
        db=db,
    )

    assert result.group_key == "identity_access"
    assert result.label == "Identity systems that make up this service"
    assert result.total_slots == 1


def test_it_counts_slots_not_assets(db: Session) -> None:
    _seed(db, slots=[("general_data_store", "asset-92"), ("backup_data_store", "")])

    result = _drill(db)

    assert result.total_slots == 2
    assert result.mapped_count == 1


def _active_template(
    monkeypatch: pytest.MonkeyPatch, slot_ids: list[str], group_key: str = "data"
) -> None:
    """Give the service an active template holding `slot_ids` in `group_key`, for both readers."""
    template = SimpleNamespace(id="template-1", version=1)
    slots = [
        SimpleNamespace(slot_id=slot_id, label=slot_id, capability_group_key=group_key)
        for slot_id in slot_ids
    ]
    for module in (routes, decisions):
        monkeypatch.setattr(module, "resolve_active_service_template", lambda *_a, **_k: template)
        monkeypatch.setattr(module, "list_slot_templates_for_service", lambda *_a, **_k: slots)


def test_a_decision_whose_slot_left_the_template_is_listed_and_flagged(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#460 (Søren, 2026-09-15): it stays live and is flagged for review (#472). The drill used to
    keep only current-template slots, so the person's answer vanished from it."""
    _seed(db, slots=[("general_data_store", "asset-92"), ("legacy_data_store", "asset-93")])
    _active_template(monkeypatch, ["general_data_store"])

    result = _drill(db)

    assert {row.slot_id: row.template_orphaned for row in result.assets} == {
        "general_data_store": False,
        "legacy_data_store": True,
    }
    assert (result.total_slots, result.mapped_count) == (2, 2)


def test_an_unanswered_row_outside_the_template_stays_out(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a live decision is kept. A row nobody answered is not a dependency."""
    _seed(db, slots=[("general_data_store", "asset-92"), ("legacy_data_store", "")])
    _active_template(monkeypatch, ["general_data_store"])

    assert [row.slot_id for row in _drill(db).assets] == ["general_data_store"]


def test_a_group_the_template_has_dropped_flags_every_decision_in_it(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Found on org 7, 2026-09-15: the template still exists but asks nothing in this group any more.
    The loader read "no slots in this group" as "no template", listed both decisions as current, and
    the drill showed them unflagged while runtime and `/slots` flagged them."""
    _seed(db, slots=[("general_data_store", "asset-92"), ("backup_data_store", "asset-93")])
    _active_template(monkeypatch, ["application_service"], group_key="application")

    result = _drill(db)

    assert {row.slot_id: row.template_orphaned for row in result.assets} == {
        "backup_data_store": True,
        "general_data_store": True,
    }
    assert (result.total_slots, result.mapped_count) == (2, 2)


def test_the_runtime_view_lists_and_flags_the_same_decision(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(db, slots=[("general_data_store", "asset-92"), ("legacy_data_store", "asset-93")])
    _active_template(monkeypatch, ["general_data_store"])

    runtime = get_service_bundle_runtime(service_id="svc-1", ctx=_ctx(), db=db)

    [group] = runtime.groups
    assert {slot.slot_id: slot.template_orphaned for slot in group.slots} == {
        "general_data_store": False,
        "legacy_data_store": True,
    }
    assert (group.total_slots, group.mapped_count) == (2, 2)
