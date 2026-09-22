"""A service's slots exist because its template says so.

Søren, 2026-09-03, after picking an artefact and watching nothing happen:
*"would it not be find artefact, select the artefact and map the FK to the
dependency so it is connected in the DB?"*

It should be. What stood in the way is that a ``SlotInstance`` was created only
where the suggestion engine had a candidate, so a slot the scanner had nothing
to say about had no row — and ``/slots/{slot_id}/decide`` updates a row. The
answer could not be recorded, and the engine was effectively deciding how many
dependencies a service has.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.database import Base
from src.core.models import BusinessService, Organization, SlotInstance
from src.core.services.slot_provisioning_service import ensure_slot_instances
from src.core.template_models import ServiceTemplate, SlotTemplate


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Organization(
        id=1, name="Org One", slug="org-one", plan_tier="enterprise",
        subscription_status="active", onboarding_completed=False,
    ))
    session.commit()
    yield session
    session.close()


def _service(db: Session, *, slots: list[tuple[str, str]]) -> BusinessService:
    """A service on a template defining `slots` as (slot_id, group_key)."""
    template_id = str(uuid.uuid4())
    db.add(ServiceTemplate(
        id=template_id, service_key="web_channel", service_name="Web Channel",
        archetype="customer_channel", version=3, status="published", is_active=True,
        capability_groups=[],
    ))
    for order, (slot_id, group_key) in enumerate(slots):
        db.add(SlotTemplate(
            id=str(uuid.uuid4()), service_template_id=template_id, slot_id=slot_id,
            label=slot_id, purpose="", capability_group_key=group_key, display_order=order,
        ))
    service = BusinessService(
        id="svc-1", organization_id=1, name="Frontend Application",
        archetype="customer_channel", template_key="web_channel",
    )
    db.add(service)
    db.commit()
    return service


def _rows(db: Session) -> dict[str, SlotInstance]:
    return {row.slot_id: row for row in db.query(SlotInstance).all()}


def test_every_template_slot_gets_a_row(db: Session) -> None:
    service = _service(db, slots=[("application_platform", "systems"), ("general_data_store", "data")])

    created = ensure_slot_instances(db, service=service)
    db.commit()

    assert {row.slot_id for row in created} == {"application_platform", "general_data_store"}
    assert set(_rows(db)) == {"application_platform", "general_data_store"}


def test_a_new_row_is_unanswered_and_not_counted_as_a_decision(db: Session) -> None:
    # `mapping_status` defaults to "approved" on the column. A row nobody has
    # decided must never arrive already approved, or the surface reads it as an
    # answer the reader never gave.
    service = _service(db, slots=[("communication_service", "external_providers")])

    ensure_slot_instances(db, service=service)
    db.commit()

    row = _rows(db)["communication_service"]
    assert row.status == "unknown"
    assert row.mapping_status == "needs_review"
    assert row.asset_id is None
    assert row.decided_by is None
    assert row.decided_at is None
    assert row.mapping_confidence is None


def test_it_carries_the_group_so_an_answer_can_find_its_row(db: Session) -> None:
    # The worklist answers by capability group; without this the row exists but
    # nothing can address it.
    service = _service(db, slots=[("general_data_store", "data")])

    ensure_slot_instances(db, service=service)
    db.commit()

    assert _rows(db)["general_data_store"].group_key == "data"
    assert _rows(db)["general_data_store"].dependency_category == "data"


def test_running_it_twice_changes_nothing(db: Session) -> None:
    service = _service(db, slots=[("application_platform", "systems")])
    ensure_slot_instances(db, service=service)
    db.commit()

    created_again = ensure_slot_instances(db, service=service)
    db.commit()

    assert created_again == []
    assert len(_rows(db)) == 1


def test_it_never_touches_an_answer_already_given(db: Session) -> None:
    service = _service(db, slots=[("general_data_store", "data")])
    db.add(SlotInstance(
        id=str(uuid.uuid4()), organization_id=1, service_id="svc-1",
        slot_id="general_data_store", group_key="data", status="mapped",
        mapping_status="approved", asset_id="asset-92", asset_label="Managed PostgreSQL",
    ))
    db.commit()

    assert ensure_slot_instances(db, service=service) == []
    db.commit()

    row = _rows(db)["general_data_store"]
    assert row.status == "mapped"
    assert row.asset_label == "Managed PostgreSQL"


def test_it_adds_the_missing_slot_beside_the_answered_one(db: Session) -> None:
    # The real shape of Søren's service: five answered, one the engine never
    # suggested for — and that one had no row to answer against.
    service = _service(db, slots=[("general_data_store", "data"), ("communication_service", "external_providers")])
    db.add(SlotInstance(
        id=str(uuid.uuid4()), organization_id=1, service_id="svc-1",
        slot_id="general_data_store", group_key="data", status="mapped",
        mapping_status="approved", asset_id="asset-92", asset_label="Managed PostgreSQL",
    ))
    db.commit()

    created = ensure_slot_instances(db, service=service)
    db.commit()

    assert [row.slot_id for row in created] == ["communication_service"]
    assert _rows(db)["general_data_store"].asset_label == "Managed PostgreSQL"


def test_a_slot_dropped_from_a_newer_template_keeps_its_answer(db: Session) -> None:
    # Adds, never removes. What happens to an answer whose question has gone is
    # a template-migration decision, not this one's.
    service = _service(db, slots=[("application_platform", "systems")])
    db.add(SlotInstance(
        id=str(uuid.uuid4()), organization_id=1, service_id="svc-1",
        slot_id="retired_slot", group_key="legacy", status="mapped",
        mapping_status="approved", asset_id="asset-1", asset_label="Old thing",
    ))
    db.commit()

    ensure_slot_instances(db, service=service)
    db.commit()

    assert "retired_slot" in _rows(db)


def test_a_service_with_no_template_is_left_alone(db: Session) -> None:
    service = BusinessService(
        id="svc-2", organization_id=1, name="Unknown", archetype=None, template_key=None,
    )
    db.add(service)
    db.commit()

    assert ensure_slot_instances(db, service=service) == []
    assert _rows(db) == {}


def test_it_stays_inside_the_tenant(db: Session) -> None:
    # Another organisation's row for the same slot id must not be mistaken for
    # this service's, or a slot would silently go unprovisioned.
    service = _service(db, slots=[("application_platform", "systems")])
    db.add(Organization(
        id=2, name="Org Two", slug="org-two", plan_tier="enterprise",
        subscription_status="active", onboarding_completed=False,
    ))
    db.add(SlotInstance(
        id=str(uuid.uuid4()), organization_id=2, service_id="svc-1",
        slot_id="application_platform", group_key="systems", status="mapped",
        mapping_status="approved", asset_id="asset-5", asset_label="Someone else's",
    ))
    db.commit()

    created = ensure_slot_instances(db, service=service)
    db.commit()

    assert [row.slot_id for row in created] == ["application_platform"]
    assert len(db.query(SlotInstance).filter(SlotInstance.organization_id == 1).all()) == 1
