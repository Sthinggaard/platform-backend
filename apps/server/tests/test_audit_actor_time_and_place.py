"""#284 (TZ-6) — the audit trail says when, in whose clock, and from where.

The ruling this epic came from was about the audit section specifically:
*"if the timestamp is wrong we are not professional and we will lose
customers."* These are the four ways it could still be wrong after everything
else was fixed — a record that re-resolves itself, an order that follows the
rendered string, a DST boundary nobody tested, and a null filled in with a
guess.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy.orm import Session

from src.core.models import AuditEvent, Organization, User
from src.core.services.audit_service import append_audit_event

COPENHAGEN = ZoneInfo("Europe/Copenhagen")


@pytest.fixture
def person(db_session: Session, sample_organization: Organization) -> User:
    user = User(
        organization_id=sample_organization.id,
        email=f"actor-{uuid4().hex[:8]}@example.com",
        email_verified=True,
        role="admin",
        is_active=True,
        timezone="Europe/Copenhagen",
        location_country="DK",
        location_city="Copenhagen",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_an_event_records_where_the_actor_was(db_session, sample_organization, person) -> None:
    event = append_audit_event(
        db_session,
        organization_id=sample_organization.id,
        event_type="decision_recorded",
        actor_user_id=person.id,
    )
    db_session.commit()

    assert event.actor_timezone == "Europe/Copenhagen"
    assert event.actor_location_country == "DK"
    assert event.actor_location_city == "Copenhagen"


def test_relocating_does_not_move_where_a_past_decision_was_made(
    db_session, sample_organization, person
) -> None:
    """The reason this is copied rather than joined.

    An audit trail that rewrites itself when somebody edits their profile is
    not evidence. The decision was made in Copenhagen whatever happens next.
    """
    past = append_audit_event(
        db_session,
        organization_id=sample_organization.id,
        event_type="decision_recorded",
        actor_user_id=person.id,
    )
    db_session.commit()

    person.timezone = "Asia/Singapore"
    person.location_country = "SG"
    person.location_city = "Singapore"
    db_session.commit()
    db_session.refresh(past)

    assert past.actor_timezone == "Europe/Copenhagen"
    assert past.actor_location_city == "Copenhagen"

    # And the next event correctly records the new place.
    now = append_audit_event(
        db_session,
        organization_id=sample_organization.id,
        event_type="decision_recorded",
        actor_user_id=person.id,
    )
    db_session.commit()
    assert now.actor_timezone == "Asia/Singapore"


def test_a_system_event_records_no_place_rather_than_a_default(
    db_session, sample_organization
) -> None:
    """Null means "not recorded". Inventing UTC would be the same failure the
    copied columns exist to prevent, pointed the other way."""
    event = append_audit_event(
        db_session,
        organization_id=sample_organization.id,
        event_type="recurrence_occurrence_due",
        actor_user_id=None,
    )
    db_session.commit()

    assert event.actor_timezone is None
    assert event.actor_location_country is None


def test_an_actor_from_another_organisation_is_not_read(
    db_session, sample_organization, person
) -> None:
    """Tenant isolation, on the lookup this story added.

    A new query against `users` is a new place to leak across organisations.
    """
    other = Organization(name="Other", slug=f"other-{uuid4().hex[:8]}")
    db_session.add(other)
    db_session.commit()

    event = append_audit_event(
        db_session,
        organization_id=other.id,
        event_type="decision_recorded",
        actor_user_id=person.id,
    )
    db_session.commit()

    assert event.actor_timezone is None


def test_two_events_an_hour_apart_in_the_repeated_hour_still_order_correctly(
    db_session, sample_organization, person
) -> None:
    """The October night when 02:00–03:00 happens twice.

    Both events render as "02:30" in Copenhagen. Ordering follows the stored
    instant, so the record can still say which came first — which is the whole
    reason storage stayed UTC while display became local.
    """
    # 2026-10-25 is the last Sunday in October: 03:00 CEST falls back to 02:00 CET.
    first = datetime(2026, 10, 25, 0, 30, tzinfo=ZoneInfo("UTC"))  # 02:30 CEST
    second = first + timedelta(hours=1)  # 02:30 CET, an hour later

    assert first.astimezone(COPENHAGEN).strftime("%H:%M") == "02:30"
    assert second.astimezone(COPENHAGEN).strftime("%H:%M") == "02:30"
    assert first.astimezone(COPENHAGEN).strftime("%Z") != second.astimezone(COPENHAGEN).strftime("%Z")

    events = []
    for at in (second, first):  # inserted out of order on purpose
        event = append_audit_event(
            db_session,
            organization_id=sample_organization.id,
            event_type="decision_recorded",
            actor_user_id=person.id,
        )
        event.created_at = at.replace(tzinfo=None)
        events.append(event)
    db_session.commit()

    ordered = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.organization_id == sample_organization.id)
        .order_by(AuditEvent.created_at.asc())
        .all()
    )
    assert [e.id for e in ordered] == [events[1].id, events[0].id]


def test_the_same_stored_instant_reads_as_two_clocks_and_one_moment(
    db_session, sample_organization, person
) -> None:
    """What per-user display means, asserted on a real row.

    15:21 UTC is 17:21 in Copenhagen and 20:51 in Kolkata. Both readers are
    right, and the stored instant is what makes them agree.
    """
    event = append_audit_event(
        db_session,
        organization_id=sample_organization.id,
        event_type="decision_recorded",
        actor_user_id=person.id,
    )
    event.created_at = datetime(2026, 8, 20, 15, 21)
    db_session.commit()

    stored = event.created_at.replace(tzinfo=ZoneInfo("UTC"))
    assert stored.astimezone(COPENHAGEN).strftime("%H:%M %Z") == "17:21 CEST"
    assert stored.astimezone(ZoneInfo("Asia/Kolkata")).strftime("%H:%M") == "20:51"


def test_a_summer_and_a_winter_event_are_not_the_same_offset(
    db_session, sample_organization, person
) -> None:
    """A DST transition covered by a test rather than found by a customer."""
    january = datetime(2026, 1, 20, 15, 21, tzinfo=ZoneInfo("UTC"))
    august = datetime(2026, 8, 20, 15, 21, tzinfo=ZoneInfo("UTC"))

    assert january.astimezone(COPENHAGEN).strftime("%H:%M %Z") == "16:21 CET"
    assert august.astimezone(COPENHAGEN).strftime("%H:%M %Z") == "17:21 CEST"
