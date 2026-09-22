"""CA-09A.6 (#318) — a rejection is evidence about the matching rules."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.dependency_mapping_enums import SlotMappingReasonCode
from src.core.database import Base
from src.core.models import MappingDecision, Organization
from src.core.services.slot_mapping_refutation_service import (
    REFUTING_REASON_CODES,
    load_refutations,
)


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=[Organization.__table__, MappingDecision.__table__])
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Org", slug="org"))
    session.add(Organization(id=2, name="Other", slug="other"))
    session.commit()
    yield session
    session.close()


def _rejection(db, *, org=1, slot="database", asset="42", code=SlotMappingReasonCode.WRONG_ASSET):
    db.add(
        MappingDecision(
            organization_id=org,
            service_id="svc-1",
            bundle_id="bundle-1",
            action="reject_slot_mapping",
            group_key="data",
            before_state={"slot_id": slot, "asset_id": asset, "asset_label": "thing"},
            after_state={"mapping_status": "rejected", "reason_code": str(code)},
        )
    )
    db.commit()


def test_wrong_asset_refutes_the_pairing(db):
    _rejection(db, slot="database", asset="42")

    refuted = load_refutations(db, organization_id=1)

    # #363 — read back in the one stored spelling. The fixture's "42" is how a
    # refusal was recorded before the suggestion service named assets canonically.
    assert ("database", "asset-42") in refuted
    assert refuted[("database", "asset-42")].reason_code == SlotMappingReasonCode.WRONG_ASSET.value


@pytest.mark.parametrize(
    "code",
    [
        SlotMappingReasonCode.ASSET_NOT_APPLICABLE,
        SlotMappingReasonCode.LOW_CONFIDENCE,
        SlotMappingReasonCode.OTHER,
    ],
)
def test_only_a_wrong_match_says_anything_about_the_rule(db, code):
    """The distinction this whole epic turns on, and the reason CA-09A.5 had to
    make the reason codes vary.

    `asset_not_applicable` — the artefact is real, nothing in *this* service
    uses it. True here, silent about anywhere else.
    `low_confidence` — *not a no, a not yet.* Refuting on it would silence a
    suggestion the reviewer explicitly declined to rule on.
    `other` — refused without saying why; an honest answer, and not one the
    engine may read meaning into.

    Reading any of them as refutation is the failure Søren gated this story on:
    learning from noise, and degrading the rules it was meant to improve."""
    _rejection(db, code=code)

    assert load_refutations(db, organization_id=1) == {}


def test_what_one_organisation_rules_out_never_reaches_another(db):
    """A matcher that learned across tenants would leak the shape of one
    estate into another's suggestions."""
    _rejection(db, org=2, slot="database", asset="42")

    assert load_refutations(db, organization_id=1) == {}
    assert ("database", "asset-42") in load_refutations(db, organization_id=2)


def test_a_decision_that_cannot_name_what_it_refused_refutes_nothing(db):
    """Rows written before the slot was recorded cannot say which suggestion
    was rejected. Guessing would suppress one nobody ruled out."""
    db.add(
        MappingDecision(
            organization_id=1,
            service_id="svc-1",
            bundle_id="bundle-1",
            action="reject_slot_mapping",
            group_key="data",
            before_state={"asset_id": "42"},  # no slot_id — the old shape
            after_state={"mapping_status": "rejected", "reason_code": "wrong_asset"},
        )
    )
    db.commit()

    assert load_refutations(db, organization_id=1) == {}


def test_the_artefact_is_read_from_the_state_before_the_refusal(db):
    """Rejecting clears `asset_id` from the row, so the *after* state no longer
    knows what was refused. Reading it there would refute nothing at all."""
    _rejection(db, asset="99")

    assert ("database", "asset-99") in load_refutations(db, organization_id=1)


def test_other_decisions_in_the_log_are_not_refutations(db):
    """The log holds every mapping action. Only a refusal refutes."""
    db.add(
        MappingDecision(
            organization_id=1,
            service_id="svc-1",
            bundle_id="bundle-1",
            action="supersede_slot_mapping",
            before_state={"slot_id": "database", "asset_id": "42"},
            after_state={"reason_code": "wrong_asset"},
        )
    )
    db.commit()

    assert load_refutations(db, organization_id=1) == {}


def test_widening_what_the_engine_learns_from_is_a_deliberate_act(db):
    """Asserted so that adding a code to this set is a decision somebody makes
    on purpose, with a test to change, rather than a tidy-up."""
    assert REFUTING_REASON_CODES == {SlotMappingReasonCode.WRONG_ASSET.value}
