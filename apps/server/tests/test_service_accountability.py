"""Who is accountable for a Business Service — Søren's ruling, 2026-08-31/09-04.

    "The service is owned by the process unless the service has been given an
    owner. [Where] the same service is used in multiple processes — who owns
    it? It is owned by the team who maintains it. In this case the assigned
    owner owns it."

Accountability is stated only where the chain cannot answer. These exercise all
four ways it fails to, because each one needs a different repair and a single
"unresolved" boolean would hide that.

⚠️ Real session, not a fake one. `test_process_access_resolution.py` next door
mocks the DB with a `_Query` whose `filter()` is a no-op — which means a
tenant-isolation assertion written against it passes without isolating anything.
AGENTS.md §11.2 and me.md both forbid mocked persistence here.
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
from src.core.services.service_accountability_service import (
    ServiceAccountabilityGap,
    ServiceAccountabilitySource,
    resolve_service_accountability,
)

ORG = 1
OTHER_ORG = 2


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
    for org_id, slug in ((ORG, "org-one"), (OTHER_ORG, "org-two")):
        session.add(Organization(
            id=org_id, name=f"Org {org_id}", slug=slug, plan_tier="enterprise",
            subscription_status="active", onboarding_completed=False,
        ))
    session.commit()
    yield session
    session.close()



def _resolve(db: Session, services: list[BusinessService], *, organization_id: int = ORG):
    return resolve_service_accountability(db, organization_id=organization_id, services=services)


# --- the chain answers ---------------------------------------------------------

def test_a_service_in_one_process_resolves_to_that_process_owner(db: Session):
    make_user(db, 7)
    make_process(db, "p1")
    service = make_service(db, "svc-1", processes=["p1"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    db.commit()

    answer = _resolve(db, [service])["svc-1"]

    assert answer.source is ServiceAccountabilitySource.PROCESS_CHAIN
    assert answer.holder_user_id == 7
    assert answer.gap is None
    assert answer.must_be_stated is False


def test_a_stated_holder_answers_even_across_several_processes(db: Session):
    # The whole point of stating one: it resolves the case the chain cannot.
    make_user(db, 7)
    make_user(db, 9)
    make_process(db, "p1")
    make_process(db, "p2")
    service = make_service(db, "svc-1", processes=["p1", "p2"])
    grant_mandate(db, user_id=9, role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER, service_id="svc-1")
    db.commit()

    answer = _resolve(db, [service])["svc-1"]

    assert answer.source is ServiceAccountabilitySource.STATED
    assert answer.holder_user_id == 9


def test_a_delegate_does_not_replace_the_process_owner(db: Session):
    """Søren, 2026-09-04: delegation is partial.

    "The team is always the process owner... The process owner can decide to
    delegate partial ownership to the services such that the accountability of
    the service not working is pinned to one in the team."

    So both people are real: the delegate answers for the service, the process
    owner remains the authority and is who #375 informs.
    """
    make_user(db, 7)
    make_user(db, 9)
    make_process(db, "p1")
    service = make_service(db, "svc-1", processes=["p1"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    grant_mandate(db, user_id=9, role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER, service_id="svc-1")
    db.commit()

    answer = _resolve(db, [service])["svc-1"]

    assert answer.holder_user_id == 9
    assert answer.is_delegated is True
    # The owner who delegated is still named, not overwritten by the delegate.
    assert answer.process_owner_user_ids == (7,)


def test_the_owners_of_every_process_are_named_when_the_chain_is_ambiguous(db: Session):
    # This is who has to agree before a holder is stated, so the answer has to
    # carry all of them rather than the first one found.
    make_user(db, 7)
    make_user(db, 8)
    make_process(db, "p1")
    make_process(db, "p2")
    service = make_service(db, "svc-1", processes=["p1", "p2"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    grant_mandate(db, user_id=8, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p2")
    db.commit()

    answer = _resolve(db, [service])["svc-1"]

    assert answer.gap is ServiceAccountabilityGap.SEVERAL_PROCESSES
    assert answer.process_owner_user_ids == (7, 8)


def test_a_stated_holder_wins_over_the_chain(db: Session):
    make_user(db, 7)
    make_user(db, 9)
    make_process(db, "p1")
    service = make_service(db, "svc-1", processes=["p1"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    grant_mandate(db, user_id=9, role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER, service_id="svc-1")
    db.commit()

    answer = _resolve(db, [service])["svc-1"]

    assert answer.source is ServiceAccountabilitySource.STATED
    assert answer.holder_user_id == 9


# --- the four ways the chain fails, each needing its own repair -----------------

def test_several_processes_with_nothing_stated_must_be_stated(db: Session):
    make_user(db, 7)
    make_process(db, "p1")
    make_process(db, "p2")
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    service = make_service(db, "svc-1", processes=["p1", "p2"])
    db.commit()

    answer = _resolve(db, [service])["svc-1"]

    # Not silently narrowed to p1's owner: "the process owner" names two people.
    assert answer.gap is ServiceAccountabilityGap.SEVERAL_PROCESSES
    assert answer.holder_user_id is None
    assert answer.must_be_stated is True


def test_a_service_in_no_process_terminates_at_nobody(db: Session):
    # 57 services are in this state today. #378 says it should not exist; until
    # then it is surfaced, never resolved to a default.
    service = make_service(db, "svc-1", processes=[])
    db.commit()

    answer = _resolve(db, [service])["svc-1"]

    assert answer.gap is ServiceAccountabilityGap.NO_PROCESS
    assert answer.must_be_stated is True


def test_one_process_with_no_owner_is_a_gap_not_a_silence(db: Session):
    make_process(db, "p1")
    service = make_service(db, "svc-1", processes=["p1"])
    db.commit()

    answer = _resolve(db, [service])["svc-1"]

    assert answer.gap is ServiceAccountabilityGap.PROCESS_HAS_NO_OWNER


def test_a_service_cannot_have_two_stated_holders_either(db: Session):
    """Søren, 2026-09-04: does one-owner-per-process cascade to services?

    It does, and the schema already said so — a matching partial unique index
    on (organisation, business_service, canonical_role). Pinned here because the
    resolver's refusal to guess only makes sense if the invariant is real.
    """
    from sqlalchemy.exc import IntegrityError

    make_user(db, 7)
    make_user(db, 8)
    make_process(db, "p1")
    make_service(db, "svc-1", processes=["p1"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER, service_id="svc-1")

    with pytest.raises(IntegrityError):
        grant_mandate(db, user_id=8, role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER, service_id="svc-1")
    db.rollback()


def test_a_process_cannot_have_two_owners_in_the_first_place(db: Session):
    """The database is what makes "which of the two?" unaskable.

    `PROCESS_HAS_SEVERAL_OWNERS` exists in the resolver as defence against data
    that reached the table around this constraint. Asserting the constraint is
    worth more than exercising a branch the schema forbids.
    """
    from sqlalchemy.exc import IntegrityError

    make_user(db, 7)
    make_user(db, 8)
    make_process(db, "p1")
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")

    with pytest.raises(IntegrityError):
        grant_mandate(db, user_id=8, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    db.rollback()


# --- what must never happen ----------------------------------------------------

def test_a_binding_without_a_matching_assignment_grants_nothing(db: Session):
    # The assignment owns eligibility, the binding owns scope. A binding whose
    # assignment names a different role is not a mandate.
    make_user(db, 7)
    make_process(db, "p1")
    service = make_service(db, "svc-1", processes=["p1"])
    assignment = OrgMandateRoleAssignment(
        id=str(uuid.uuid4()), organization_id=ORG,
        canonical_role=CanonicalMandateRole.ORG_WIDE_VISIBILITY.value,
        subject_type=MandateAssignmentSubjectType.USER.value, user_id=7,
    )
    db.add(assignment)
    db.flush()
    db.add(OrgMandateScopeBinding(
        id=str(uuid.uuid4()), organization_id=ORG,
        scope_type=MandateScopeType.BUSINESS_PROCESS.value, value_stream_id="p1",
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        role_assignment_id=assignment.id,
    ))
    db.commit()

    assert _resolve(db, [service])["svc-1"].gap is ServiceAccountabilityGap.PROCESS_HAS_NO_OWNER


def test_another_organisations_mandate_never_answers_for_this_one(db: Session):
    make_user(db, 99, organization_id=OTHER_ORG)
    make_process(db, "p1")
    service = make_service(db, "svc-1", processes=["p1"])
    # Same process id, another tenant's binding.
    grant_mandate(
        db, user_id=99, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER,
        process_id="p1", organization_id=OTHER_ORG,
    )
    db.commit()

    answer = _resolve(db, [service])["svc-1"]

    assert answer.holder_user_id is None
    assert answer.gap is ServiceAccountabilityGap.PROCESS_HAS_NO_OWNER


def test_an_archived_service_is_not_a_resting_place_for_a_decision(db: Session):
    from src.core.model_defs.common import utcnow

    service = make_service(db, "svc-1", processes=["p1"])
    service.archived_at = utcnow()
    db.commit()

    assert _resolve(db, [service]) == {}


def test_read_from_inside_a_process_a_shared_service_resolves_to_that_owner(db: Session):
    """Søren, 2026-09-04, on a map showing "No owner" for shared services.

    "If no owner has been assigned a service the process owner is the owner...
    it should just be the process owner who it defaults to."

    Asked globally, "the process owner" names three people for Data Platform.
    Asked from inside one process it names one — and that is how every
    process-scoped screen asks it.
    """
    make_user(db, 7)
    make_user(db, 8)
    make_process(db, "p1")
    make_process(db, "p2")
    service = make_service(db, "svc-1", processes=["p1", "p2"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    grant_mandate(db, user_id=8, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p2")
    db.commit()

    from_p1 = resolve_service_accountability(
        db, organization_id=ORG, services=[service], as_seen_from_process_id="p1"
    )["svc-1"]
    from_p2 = resolve_service_accountability(
        db, organization_id=ORG, services=[service], as_seen_from_process_id="p2"
    )["svc-1"]

    assert from_p1.holder_user_id == 7
    assert from_p2.holder_user_id == 8
    # ⚠️ A PROPOSAL, not a verdict. Søren, 2026-09-04: "If the service is in
    # other processes the question should be: is this service maintained in this
    # process, or by this process owner?" Three processes each showing their own
    # owner as settled fact would be three answers for one service.
    assert from_p1.source is ServiceAccountabilitySource.PROCESS_CHAIN_ASSUMED
    assert from_p1.needs_confirmation is True


def test_without_a_process_a_shared_service_stays_ambiguous(db: Session):
    # A caller with no context must not be handed one of several owners at
    # random — the standalone service list is exactly that caller.
    make_user(db, 7)
    make_process(db, "p1")
    make_process(db, "p2")
    service = make_service(db, "svc-1", processes=["p1", "p2"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    db.commit()

    answer = resolve_service_accountability(db, organization_id=ORG, services=[service])["svc-1"]

    assert answer.gap is ServiceAccountabilityGap.SEVERAL_PROCESSES


def test_a_process_the_service_is_not_in_does_not_answer_for_it(db: Session):
    # Asking from an unrelated process must not borrow its owner.
    make_user(db, 7)
    make_process(db, "p1")
    make_process(db, "p9")
    service = make_service(db, "svc-1", processes=["p1", "p2"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p9")
    db.commit()

    answer = resolve_service_accountability(
        db, organization_id=ORG, services=[service], as_seen_from_process_id="p9"
    )["svc-1"]

    assert answer.gap is ServiceAccountabilityGap.SEVERAL_PROCESSES


def test_a_delegate_still_wins_when_read_from_a_process(db: Session):
    make_user(db, 7)
    make_user(db, 9)
    make_process(db, "p1")
    make_process(db, "p2")
    service = make_service(db, "svc-1", processes=["p1", "p2"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    grant_mandate(db, user_id=9, role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER, service_id="svc-1")
    db.commit()

    answer = resolve_service_accountability(
        db, organization_id=ORG, services=[service], as_seen_from_process_id="p1"
    )["svc-1"]

    assert answer.holder_user_id == 9
    assert answer.source is ServiceAccountabilitySource.STATED


def test_a_service_in_one_process_is_settled_and_asks_nothing(db: Session):
    # The question only arises where another process could claim it.
    make_user(db, 7)
    make_process(db, "p1")
    service = make_service(db, "svc-1", processes=["p1"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    db.commit()

    answer = resolve_service_accountability(
        db, organization_id=ORG, services=[service], as_seen_from_process_id="p1"
    )["svc-1"]

    assert answer.source is ServiceAccountabilitySource.PROCESS_CHAIN
    assert answer.needs_confirmation is False


def test_answering_the_question_settles_it_everywhere(db: Session):
    # Naming a holder is the answer to "who maintains this", so it holds from
    # every process rather than being re-asked in each.
    make_user(db, 7)
    make_user(db, 9)
    make_process(db, "p1")
    make_process(db, "p2")
    service = make_service(db, "svc-1", processes=["p1", "p2"])
    grant_mandate(db, user_id=7, role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1")
    grant_mandate(db, user_id=9, role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER, service_id="svc-1")
    db.commit()

    for process_id in ("p1", "p2"):
        answer = resolve_service_accountability(
            db, organization_id=ORG, services=[service], as_seen_from_process_id=process_id
        )["svc-1"]
        assert answer.holder_user_id == 9
        assert answer.needs_confirmation is False
