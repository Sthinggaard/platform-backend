"""Telling the owners who depend on a service that somebody decided about it (#375).

The two surfaces Søren described ask different questions, and these pin the
difference — because collapsing them is how a decision gets waved away unread:

- **In the business process**: what is new since I looked. Cleared by opening it.
- **Overview page**: what have I still not confirmed I was told. Cleared only by
  saying so.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray, JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.constants.org_access_enums import CanonicalMandateRole
from src.core.database import Base
from src.core.models import ServiceChangeNotice, ServiceChangeNoticeKind
from src.core.services.service_change_notice_service import (
    acknowledge_notice,
    mark_notice_viewed,
    notify_service_decision,
    unacknowledged_notices_for_recipient,
    notices_for_process,
    unresolved_notices_for_recipient,
)

import org_mandate_fixture as factories

ORG = 1


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    factories.make_organisation(session, ORG)
    session.commit()
    yield session
    session.close()


def _shared_service(db: Session):
    """One service, two processes, two owners — the case the ruling is about."""
    for uid in (7, 8):
        factories.make_user(db, uid, organization_id=ORG)
    for pid in ("p1", "p2"):
        factories.make_process(db, pid, organization_id=ORG)
    service = factories.make_service(db, "svc-1", organization_id=ORG, processes=["p1", "p2"])
    factories.grant_mandate(
        db, organization_id=ORG, user_id=7,
        role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1",
    )
    factories.grant_mandate(
        db, organization_id=ORG, user_id=8,
        role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p2",
    )
    factories.grant_mandate(
        db, organization_id=ORG, user_id=7,
        role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER, service_id="svc-1",
    )
    db.commit()
    return service


def _notify(db: Session, service, *, by: int = 7):
    written = notify_service_decision(
        db, organization_id=ORG, service=service, decided_by_user_id=by,
        title="Accepted the risk on Managed PostgreSQL",
        description="No standby will be provisioned this quarter.",
        owner_comment="We reviewed it and the cost is not justified before Q1.",
        decision_record_id="decision-1",
    )
    db.commit()
    return written


def test_every_other_affected_owner_is_written_to(db: Session):
    service = _shared_service(db)

    written = _notify(db, service, by=7)

    # 7 decided, so 7 is not informed of their own decision.
    assert [n.recipient_user_id for n in written] == [8]
    assert written[0].process_id == "p2"
    assert written[0].kind == ServiceChangeNoticeKind.UPDATE


def test_the_message_names_who_decided_and_what_they_said(db: Session):
    service = _shared_service(db)

    notice = _notify(db, service, by=7)[0]

    assert notice.actor_user_id == 7
    assert notice.owner_comment.startswith("We reviewed it")
    # Links through to the decision in full — #375's second criterion.
    assert notice.decision_record_id == "decision-1"


def test_opening_it_clears_the_map_badge_but_owes_the_same_answer(db: Session):
    """Søren, 2026-09-04: reading is "a 100% read action" — and not an answer.

    The record keeps the row either way; what opening changes is `viewed_at`,
    which is what the page reads to decide whether a marker still stands.
    """
    service = _shared_service(db)
    notice = _notify(db, service, by=7)[0]

    mark_notice_viewed(notice)
    db.commit()

    assert notice.viewed_at is not None
    assert notice.acknowledged_at is None
    # The log does not shorten as the reader catches up with it.
    assert len(notices_for_process(db, organization_id=ORG, process_id="p2", recipient_user_id=8)) == 1
    # And the duty is untouched.
    assert len(unacknowledged_notices_for_recipient(db, organization_id=ORG, recipient_user_id=8)) == 1

def test_acknowledging_is_what_discharges_it(db: Session):
    service = _shared_service(db)
    notice = _notify(db, service, by=7)[0]

    acknowledge_notice(notice, user_id=8)
    db.commit()

    assert unacknowledged_notices_for_recipient(db, organization_id=ORG, recipient_user_id=8) == []
    # Acknowledging implies it was read, so the badge goes too.
    assert notice.viewed_at is not None


def test_only_the_person_it_was_written_for_can_acknowledge_it(db: Session):
    service = _shared_service(db)
    notice = _notify(db, service, by=7)[0]

    with pytest.raises(ValueError):
        acknowledge_notice(notice, user_id=7)

    assert notice.acknowledged_at is None


def test_an_issue_stays_outstanding_however_often_it_is_read(db: Session):
    """Reading never discharges an issue — an update's marker, but never this.

    ⚠️ **Amended 2026-09-05.** It used to acknowledge as well as read and assert
    the issue still stood; acknowledging now discharges it, so that belongs in
    its own test. What this always meant to pin — that *reading* is not enough —
    is unchanged.
    """
    service = _shared_service(db)
    notice = _notify(db, service, by=7)[0]
    notice.kind = ServiceChangeNoticeKind.ISSUE
    db.commit()

    mark_notice_viewed(notice)
    mark_notice_viewed(notice)
    db.commit()

    assert len(unresolved_notices_for_recipient(db, organization_id=ORG, recipient_user_id=8)) == 1

def test_resolving_it_is_what_takes_an_issue_off_the_map(db: Session):
    """Only the owning team can resolve an issue — the reader never can.

    Resolved rows stay in the record: "you were told, and it was fixed" is
    history worth keeping. `resolved_at` is what tells the page to stop drawing.
    """
    service = _shared_service(db)
    notice = _notify(db, service, by=7)[0]
    notice.kind = ServiceChangeNoticeKind.ISSUE
    notice.resolved_at = notice.created_at
    db.commit()

    assert len(notices_for_process(db, organization_id=ORG, process_id="p2", recipient_user_id=8)) == 1
    # Gone from the overview's banner, which asks only what is still outstanding.
    assert unresolved_notices_for_recipient(db, organization_id=ORG, recipient_user_id=8) == []

def test_a_service_in_one_process_owes_nobody_a_message(db: Session):
    # The owner decided about their own service; there is nobody else to tell.
    factories.make_user(db, 7, organization_id=ORG)
    factories.make_process(db, "p1", organization_id=ORG)
    service = factories.make_service(db, "svc-1", organization_id=ORG, processes=["p1"])
    factories.grant_mandate(
        db, organization_id=ORG, user_id=7,
        role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1",
    )
    db.commit()

    assert _notify(db, service, by=7) == []
    assert db.query(ServiceChangeNotice).count() == 0


def test_the_overview_asks_the_map_question_across_every_process(db: Session):
    """The overview banner spans processes; the map's list is scoped to one.

    Søren's overview design counts "3 services across 2 business processes", so
    the read cannot be per-process — but it must still answer *what is new since
    I looked*, not *what have I never confirmed*.
    """
    service = _shared_service(db)
    _notify(db, service, by=7)

    outstanding = unresolved_notices_for_recipient(db, organization_id=ORG, recipient_user_id=8)

    assert [n.process_id for n in outstanding] == ["p2"]


def test_reading_an_update_takes_it_off_the_overview_but_not_off_the_ledger(db: Session):
    """The same rule the map follows, and the same one it does not discharge."""
    service = _shared_service(db)
    notice = _notify(db, service, by=7)[0]

    mark_notice_viewed(notice)
    db.commit()

    assert unresolved_notices_for_recipient(db, organization_id=ORG, recipient_user_id=8) == []
    # Still owed: reading is not acknowledging.
    assert len(unacknowledged_notices_for_recipient(db, organization_id=ORG, recipient_user_id=8)) == 1


def test_an_issue_stays_on_the_overview_however_often_it_is_read(db: Session):
    service = _shared_service(db)
    notice = _notify(db, service, by=7)[0]
    notice.kind = ServiceChangeNoticeKind.ISSUE
    db.commit()

    mark_notice_viewed(notice)
    db.commit()

    assert len(unresolved_notices_for_recipient(db, organization_id=ORG, recipient_user_id=8)) == 1


def test_the_overview_never_shows_another_person_a_notice(db: Session):
    """A notice is written to a person. 7 decided; 7 is owed nothing."""
    service = _shared_service(db)
    _notify(db, service, by=7)

    assert unresolved_notices_for_recipient(db, organization_id=ORG, recipient_user_id=7) == []


def test_marking_done_clears_the_strips_but_keeps_the_record(db: Session):
    """Søren, 2026-09-05, in two parts and they pull in opposite directions.

    *"When I have looked through the information and marked done the notification
    should disappear in the business process and in the overview"* — and *"the
    record of notification in the service should still be in the tab."*

    So acknowledging empties the banners and takes the markers down, and leaves
    the log exactly as long as it was.
    """
    service = _shared_service(db)
    notice = _notify(db, service, by=7)[0]

    acknowledge_notice(notice, user_id=8)
    db.commit()

    # The strips ask this, and it is now empty.
    assert unresolved_notices_for_recipient(db, organization_id=ORG, recipient_user_id=8) == []
    assert unacknowledged_notices_for_recipient(db, organization_id=ORG, recipient_user_id=8) == []
    # The tab asks this, and it is not.
    record = notices_for_process(db, organization_id=ORG, process_id="p2", recipient_user_id=8)
    assert len(record) == 1
    assert record[0].acknowledged_at is not None

def test_marking_done_clears_an_open_issue_too(db: Session):
    """The trade Søren accepted, pinned so nobody restores the old rule by accident.

    An issue outlives any amount of *reading*. Acknowledging is not reading: the
    service may still be broken afterwards, and what the reader closed is whether
    **they have been informed** — the only half of it that was ever theirs.
    """
    service = _shared_service(db)
    notice = _notify(db, service, by=7)[0]
    notice.kind = ServiceChangeNoticeKind.ISSUE
    db.commit()

    mark_notice_viewed(notice)
    db.commit()
    assert len(unresolved_notices_for_recipient(db, organization_id=ORG, recipient_user_id=8)) == 1

    acknowledge_notice(notice, user_id=8)
    db.commit()

    assert unresolved_notices_for_recipient(db, organization_id=ORG, recipient_user_id=8) == []
    # Still in the log, marked done.
    assert len(notices_for_process(db, organization_id=ORG, process_id="p2", recipient_user_id=8)) == 1

