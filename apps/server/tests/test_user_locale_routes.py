"""#280 (TZ-2) — a person sees and sets their own location and timezone.

The criteria that matter here are not "the field saves". They are: the screen
can tell a default from a choice, changing a zone does not touch a stored
instant, a country proposes without deciding, and the change is auditable.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy.orm import Session

from src.api.main import app
from src.core.constants.user_locale import (
    DEFAULT_TIMEZONE,
    USER_LOCALE_AUDIT_UPDATED,
)
from src.core.database import get_db
from src.core.models import AuditEvent, Organization, User
from src.core.utils.jwt_secrets import get_jwt_secret_bytes

NAMESPACE = "https://risklence.com/"


@pytest.fixture
def person(db_session: Session, sample_organization: Organization) -> User:
    user = User(
        organization_id=sample_organization.id,
        email=f"reader-{uuid4().hex[:8]}@example.com",
        email_verified=True,
        role="admin",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def client(db_session: Session) -> TestClient:
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.pop(get_db, None)


def headers(person: User) -> dict:
    token = jwt.encode(
        {
            "sub": str(person.id),
            "email": person.email,
            f"{NAMESPACE}organization_id": person.organization_id,
            f"{NAMESPACE}roles": ["admin"],
            f"{NAMESPACE}permissions": [],
        },
        get_jwt_secret_bytes(),
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def test_a_person_who_has_not_chosen_is_told_it_is_a_default(client, person) -> None:
    """The criterion a silent default would fail.

    Showing the fallback as though it were their setting is how somebody ends
    up reading an audit trail in a clock they never picked.
    """
    body = client.get("/api/v1/users/me/locale", headers=headers(person)).json()

    assert body["timezone"] is None
    assert body["effective_timezone"] == DEFAULT_TIMEZONE
    assert body["is_default"] is True


def test_setting_a_zone_makes_it_a_choice_rather_than_a_default(client, person) -> None:
    response = client.patch(
        "/api/v1/users/me/locale",
        headers=headers(person),
        json={"timezone": "Asia/Kolkata"},
    )
    assert response.status_code == 200
    body = response.json()

    assert body["timezone"] == "Asia/Kolkata"
    assert body["effective_timezone"] == "Asia/Kolkata"
    assert body["is_default"] is False


def test_the_screen_is_given_the_local_time_and_its_zone_name(client, person) -> None:
    """So a person can confirm at a glance that they picked the right one.

    Computed server-side because it must match the clock the platform will
    actually render timestamps in — a browser asked separately can disagree.
    """
    client.patch(
        "/api/v1/users/me/locale",
        headers=headers(person),
        json={"timezone": "Pacific/Auckland"},
    )
    body = client.get("/api/v1/users/me/locale", headers=headers(person)).json()

    assert body["local_time"].endswith(("+12:00", "+13:00"))  # NZ, either side of DST
    assert body["local_time_zone_abbreviation"] in {"NZST", "NZDT"}


def test_an_offset_is_refused_with_a_reason(client, person) -> None:
    response = client.patch(
        "/api/v1/users/me/locale",
        headers=headers(person),
        json={"timezone": "CET"},
    )
    assert response.status_code == 422
    assert "does not name a place" in response.text


def test_the_screen_carries_the_promise_that_nothing_is_rewritten(client, person) -> None:
    body = client.get("/api/v1/users/me/locale", headers=headers(person)).json()
    assert "does not change when anything happened" in body["note"]


def test_a_country_proposes_without_deciding(client, person) -> None:
    single = client.get(
        "/api/v1/users/me/locale/proposal?country=dk", headers=headers(person)
    ).json()
    assert single == {"country": "DK", "proposed_timezone": "Europe/Copenhagen"}

    # Greenland spans four zones, so it settles nothing and says so.
    many = client.get(
        "/api/v1/users/me/locale/proposal?country=GL", headers=headers(person)
    ).json()
    assert many == {"country": "GL", "proposed_timezone": None}


def test_a_proposal_never_writes_anything(client, person, db_session) -> None:
    """The distinction the whole story rests on: offered, not applied."""
    client.get("/api/v1/users/me/locale/proposal?country=DK", headers=headers(person))
    db_session.refresh(person)
    assert person.timezone is None


def test_location_is_recorded_and_can_be_cleared(client, person) -> None:
    set_body = client.patch(
        "/api/v1/users/me/locale",
        headers=headers(person),
        json={"location_country": "dk", "location_city": "  Copenhagen "},
    ).json()
    assert set_body["location_country"] == "DK"
    assert set_body["location_city"] == "Copenhagen"

    # Somebody who moves somewhere they would rather not state must be able to
    # remove it, not only replace it.
    cleared = client.patch(
        "/api/v1/users/me/locale",
        headers=headers(person),
        json={"clear_location": True},
    ).json()
    assert cleared["location_country"] is None
    assert cleared["location_city"] is None


def test_setting_a_location_does_not_set_a_zone(client, person, db_session) -> None:
    """Location proposes; it never determines. Asserted at the write path.

    A country that silently filled in a zone would be the derivation this epic
    refuses, arriving through the back door of a form.
    """
    client.patch(
        "/api/v1/users/me/locale",
        headers=headers(person),
        json={"location_country": "DK"},
    )
    db_session.refresh(person)
    assert person.location_country == "DK"
    assert person.timezone is None


def test_a_change_is_audited_with_what_it_was_and_what_it_became(
    client, person, db_session
) -> None:
    client.patch(
        "/api/v1/users/me/locale",
        headers=headers(person),
        json={"timezone": "Europe/Berlin", "location_country": "DE"},
    )
    events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.event_type == USER_LOCALE_AUDIT_UPDATED)
        .all()
    )
    assert len(events) == 1
    assert events[0].actor_user_id == person.id
    assert events[0].metadata_json["before"]["timezone"] is None
    assert events[0].metadata_json["after"]["timezone"] == "Europe/Berlin"


def test_saving_the_same_values_again_writes_no_audit_event(
    client, person, db_session
) -> None:
    """An audit trail that records every save is one nobody reads."""
    for _ in range(3):
        client.patch(
            "/api/v1/users/me/locale",
            headers=headers(person),
            json={"timezone": "Europe/Oslo"},
        )
    events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.event_type == USER_LOCALE_AUDIT_UPDATED)
        .all()
    )
    assert len(events) == 1


def test_changing_a_zone_leaves_every_stored_instant_untouched(
    client, person, db_session
) -> None:
    """The fear this endpoint has to answer, asserted rather than promised.

    A person changing their clock reasonably worries they are rewriting
    history. The audit event written before the change must still say what it
    said afterwards.
    """
    client.patch(
        "/api/v1/users/me/locale", headers=headers(person), json={"timezone": "Europe/Berlin"}
    )
    event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.event_type == USER_LOCALE_AUDIT_UPDATED)
        .one()
    )
    recorded_at = event.created_at

    client.patch(
        "/api/v1/users/me/locale", headers=headers(person), json={"timezone": "Pacific/Auckland"}
    )
    db_session.refresh(event)
    assert event.created_at == recorded_at
