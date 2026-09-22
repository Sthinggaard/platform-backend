"""Who must be told when someone decides about a Business Service (#375, GOV-07).

Søren, 2026-09-04: "Anyone who owns a process where there is a service which the
process does not own and will be affected by it."

⚠️ Informed is not asked. Nothing here grants a veto, and the tests say so where
it would be easy to drift — a person owed a message is never returned as an
approver.
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

from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    MandateAssignmentSubjectType,
    MandateScopeType,
)
from src.core.database import Base
from src.core.models import BusinessService, Organization, User, ValueStream
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.roles import UserRole
from src.core.services.information_duty_service import (
    InformationBasis,
    resolve_information_duty,
)
from src.core.services.service_accountability_service import resolve_service_accountability

ORG = 1


# The shared factories take the organisation explicitly; these bind it to this
# suite's default so a test reads as the case it is about, not as plumbing.
import org_mandate_fixture as factories


def make_user(db, user_id, *, organization_id=ORG):
    return factories.make_user(db, user_id, organization_id=organization_id)


def make_process(db, process_id, *, organization_id=ORG):
    return factories.make_process(db, process_id, organization_id=organization_id)


def make_service(db, service_id, *, processes, organization_id=ORG):
    return factories.make_service(
        db, service_id, organization_id=organization_id, processes=processes
    )


def grant_mandate(db, *, user_id, role, process_id=None, service_id=None, organization_id=ORG):
    return factories.grant_mandate(
        db, organization_id=organization_id, user_id=user_id, role=role,
        process_id=process_id, service_id=service_id,
    )


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
        id=ORG, name="Org One", slug="org-one", plan_tier="enterprise",
        subscription_status="active", onboarding_completed=False,
    ))
    session.commit()
    yield session
    session.close()






def _duty(db: Session, service: BusinessService, *, decided_by: int):
    accountability = resolve_service_accountability(
        db, organization_id=ORG, services=[service]
    )[service.id]
    return resolve_information_duty(
        db, organization_id=ORG, service=service,
        accountability=accountability, decided_by_user_id=decided_by,
    )


def test_the_owner_of_every_other_carrying_process_is_informed(db: Session):
    # The case Søren named: a service several processes lean on, decided by one
    # person, and the others have to hear about it.
    for uid in (7, 8, 9):
        make_user(db, uid)
    for pid in ("p1", "p2", "p3"):
        make_process(db, pid)
    service = make_service(db, "svc-1", processes=["p1", "p2", "p3"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    grant_mandate(db, user_id=8, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p2")
    grant_mandate(db, user_id=9, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p3")
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER, service_id="svc-1")
    db.commit()

    duty = _duty(db, service, decided_by=7)

    assert {p.user_id for p in duty.people} == {8, 9}
    assert duty.is_owed is True


def test_nobody_is_informed_of_their_own_decision(db: Session):
    make_user(db, 7)
    make_process(db, "p1")
    service = make_service(db, "svc-1", processes=["p1"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    db.commit()

    duty = _duty(db, service, decided_by=7)

    assert duty.people == ()
    assert duty.is_owed is False


def test_a_delegate_deciding_informs_the_process_owner(db: Session):
    # Partial delegation: the delegate acts, the owner who delegated is told.
    make_user(db, 7)
    make_user(db, 9)
    make_process(db, "p1")
    service = make_service(db, "svc-1", processes=["p1"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    grant_mandate(db, user_id=9, role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER, service_id="svc-1")
    db.commit()

    duty = _duty(db, service, decided_by=9)

    assert [(p.user_id, p.basis) for p in duty.people] == [(7, InformationBasis.DELEGATED_AWAY)]


def test_the_message_names_which_process_of_theirs_is_affected(db: Session):
    # "Your process X is affected" is the message. Without the process id it
    # would say only that something, somewhere, changed.
    make_user(db, 7)
    make_user(db, 8)
    make_process(db, "p1")
    make_process(db, "p2")
    service = make_service(db, "svc-1", processes=["p1", "p2"])
    grant_mandate(db, user_id=8, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p2")
    db.commit()

    duty = _duty(db, service, decided_by=7)

    assert [(p.user_id, p.process_id) for p in duty.people] == [(8, "p2")]


def test_one_person_owning_two_affected_processes_is_told_about_each(db: Session):
    # Two processes of theirs are affected, and a message naming only one would
    # under-report the blast radius.
    make_user(db, 7)
    make_user(db, 8)
    make_process(db, "p1")
    make_process(db, "p2")
    service = make_service(db, "svc-1", processes=["p1", "p2"])
    grant_mandate(db, user_id=8, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    grant_mandate(db, user_id=8, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p2")
    db.commit()

    duty = _duty(db, service, decided_by=7)

    assert sorted(p.process_id for p in duty.people) == ["p1", "p2"]
    assert {p.user_id for p in duty.people} == {8}


def test_a_process_with_no_owner_owes_nobody_a_message(db: Session):
    # Not an error here: an ownerless process is #376's gap to surface, not a
    # person to invent.
    make_user(db, 7)
    make_process(db, "p1")
    make_process(db, "p2")
    service = make_service(db, "svc-1", processes=["p1", "p2"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    db.commit()

    duty = _duty(db, service, decided_by=7)

    assert duty.people == ()


def test_a_service_in_no_process_owes_nobody(db: Session):
    make_user(db, 7)
    service = make_service(db, "svc-1", processes=[])
    db.commit()

    assert _duty(db, service, decided_by=7).people == ()
