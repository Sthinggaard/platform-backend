"""CA-02.3 slice 3 — asking a polling Collector to do something.

The rules worth pinning are the ones that decide whether a user pressing a
button can be told the truth about what happened: an instruction that was
delivered is not an instruction that was carried out, five presses are one
question, and a request nobody can act on must eventually stop being asked.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.evidence_scanner_enums import (
    CollectorInstruction,
    ScannerInstanceStatus,
)
from src.core.database import Base
from src.core.model_defs.common import utcnow
from src.core.model_defs.evidence_scanner import CollectorReadinessReport, ScannerInstance
from src.core.model_defs.tenant_org import Organization
from src.core.services.collector_instruction_service import (
    INSTRUCTION_TTL,
    clear_instruction,
    pending_instruction_for,
    request_instruction,
)


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            ScannerInstance.__table__,
            CollectorReadinessReport.__table__,
        ],
    )
    session = Session(bind=engine)
    session.add(Organization(id=1, name="Org", slug="org"))
    session.commit()
    yield session
    session.close()


def _instance(db: Session) -> ScannerInstance:
    instance = ScannerInstance(
        id="inst-1",
        organization_id=1,
        evidence_source_id="src-1",
        name="Primary",
        installation_method="docker",
        activation_token_hash="x" * 64,
        status=ScannerInstanceStatus.ONLINE.value,
        last_heartbeat_at=utcnow(),
    )
    db.add(instance)
    db.flush()
    return instance


class TestRequesting:
    def test_a_requested_instruction_is_delivered(self, db: Session):
        instance = _instance(db)

        request_instruction(
            db, instance, instruction=CollectorInstruction.SELF_CHECK, requested_by_user_id=5
        )

        assert pending_instruction_for(instance) == "self_check"

    def test_nothing_is_delivered_when_nothing_was_asked(self, db: Session):
        assert pending_instruction_for(_instance(db)) is None

    def test_the_requesting_person_is_recorded(self, db: Session):
        # The whole point: the resulting report must be attributable to someone,
        # not to "the system".
        instance = _instance(db)

        request_instruction(
            db, instance, instruction=CollectorInstruction.SELF_CHECK, requested_by_user_id=5
        )

        assert instance.pending_instruction_requested_by_user_id == 5

    def test_pressing_the_button_five_times_is_still_one_instruction(self, db: Session):
        # Coalescing by nature. A queue would faithfully deliver five checks;
        # the user asked one question.
        instance = _instance(db)

        for _ in range(5):
            request_instruction(
                db, instance, instruction=CollectorInstruction.SELF_CHECK, requested_by_user_id=5
            )

        assert pending_instruction_for(instance) == "self_check"
        assert instance.pending_instruction_requested_at is not None

    def test_the_most_recent_requester_wins_attribution(self, db: Session):
        # Whoever is now waiting on their screen is the person the answer
        # belongs to.
        instance = _instance(db)
        request_instruction(
            db, instance, instruction=CollectorInstruction.SELF_CHECK, requested_by_user_id=5
        )

        request_instruction(
            db, instance, instruction=CollectorInstruction.SELF_CHECK, requested_by_user_id=9
        )

        assert instance.pending_instruction_requested_by_user_id == 9


class TestDeliveryIsNotCompletion:
    def test_reading_the_instruction_does_not_clear_it(self, db: Session):
        # Handing it over is not evidence anything happened. A Collector that
        # receives an instruction and then dies must not silently lose it —
        # treating delivery as completion is the exact conflation this whole
        # story exists to remove.
        instance = _instance(db)
        request_instruction(
            db, instance, instruction=CollectorInstruction.SELF_CHECK, requested_by_user_id=5
        )

        pending_instruction_for(instance)
        pending_instruction_for(instance)

        assert pending_instruction_for(instance) == "self_check"

    def test_it_is_cleared_when_the_result_arrives(self, db: Session):
        instance = _instance(db)
        request_instruction(
            db, instance, instruction=CollectorInstruction.SELF_CHECK, requested_by_user_id=5
        )

        clear_instruction(db, instance)

        assert pending_instruction_for(instance) is None
        assert instance.pending_instruction_requested_by_user_id is None


class TestAnUnanswerableRequestStopsBeingAsked:
    def test_an_expired_request_is_no_longer_delivered(self, db: Session):
        # Because the flag clears on completion, an instruction the Collector
        # cannot carry out would otherwise be redelivered forever.
        instance = _instance(db)
        request_instruction(
            db, instance, instruction=CollectorInstruction.SELF_CHECK, requested_by_user_id=5
        )
        instance.pending_instruction_requested_at = utcnow() - INSTRUCTION_TTL - timedelta(minutes=1)
        db.flush()

        assert pending_instruction_for(instance) is None

    def test_a_request_inside_the_window_is_still_delivered(self, db: Session):
        instance = _instance(db)
        request_instruction(
            db, instance, instruction=CollectorInstruction.SELF_CHECK, requested_by_user_id=5
        )
        instance.pending_instruction_requested_at = utcnow() - INSTRUCTION_TTL + timedelta(minutes=1)
        db.flush()

        assert pending_instruction_for(instance) == "self_check"

    def test_expiry_does_not_mutate_on_a_read(self, db: Session):
        # pending_instruction_for runs on the heartbeat path; a read must not
        # quietly write. clear_instruction is the only writer.
        instance = _instance(db)
        request_instruction(
            db, instance, instruction=CollectorInstruction.SELF_CHECK, requested_by_user_id=5
        )
        instance.pending_instruction_requested_at = utcnow() - INSTRUCTION_TTL - timedelta(minutes=1)
        db.flush()

        pending_instruction_for(instance)

        assert instance.pending_instruction == "self_check"

    def test_a_request_with_no_timestamp_is_still_delivered(self, db: Session):
        # Cannot tell whether it is stale. A self-check is cheap and harmless;
        # dropping a real request leaves a user watching a button that did
        # nothing.
        instance = _instance(db)
        instance.pending_instruction = CollectorInstruction.SELF_CHECK.value
        instance.pending_instruction_requested_at = None
        db.flush()

        assert pending_instruction_for(instance) == "self_check"
