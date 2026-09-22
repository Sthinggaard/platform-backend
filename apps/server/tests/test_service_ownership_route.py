"""Delegating accountability for a service (#403).

Søren, 2026-09-04: "The process owner may choose to delegate ownership of the
service to a team member, but the process owner will always be accountable."

So these assert a **delegation**, not an assignment to something ownerless — and
that clearing it returns the service to its process rather than to nobody.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray, JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import service_ownership as routes
from src.core.constants.org_access_enums import CanonicalMandateRole
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.roles import UserRole

import org_mandate_fixture as factories

ORG = 1
OTHER_ORG = 2


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
    factories.make_organisation(session, OTHER_ORG)
    session.commit()
    yield session
    session.close()


def _ctx(user_id: int, *, organization_id: int = ORG, roles: list[str] | None = None) -> TenantContext:
    return TenantContext(
        user_id=user_id, organization_id=organization_id,
        email=f"u{user_id}@risklence.test", roles=roles or ["member"], permissions=[],
    )


def _world(db: Session):
    """A process with an owner, a service in it, and a team member to delegate to."""
    owner = factories.make_user(db, 7, organization_id=ORG)
    mate = factories.make_user(db, 9, organization_id=ORG)
    mate.title = "Service Desk Analyst"
    factories.make_process(db, "p1", organization_id=ORG)
    service = factories.make_service(db, "svc-1", organization_id=ORG, processes=["p1"])
    factories.grant_mandate(
        db, organization_id=ORG, user_id=7,
        role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1",
    )
    # The binding is the offer; only an acceptance is the authority (#403's
    # "accepted process owner").
    factories.accept_process_ownership(db, organization_id=ORG, user_id=7, process_id="p1")
    db.commit()
    return owner, mate, service


def _put(db: Session, *, actor: int, user_id: int | None, service_id: str = "svc-1", roles=None):
    return routes.delegate_service_owner(
        service_id=service_id,
        body=routes.DelegateServiceOwnerRequest(user_id=user_id),
        ctx=_ctx(actor, roles=roles),
        db=db,
    )


def test_the_process_owner_may_delegate_to_a_team_member(db: Session):
    _world(db)

    response = _put(db, actor=7, user_id=9)

    assert response.holder_user_id == 9
    assert response.source == "stated"
    assert response.holder_title == "Service Desk Analyst"


def test_clearing_it_returns_the_service_to_its_process_not_to_nobody(db: Session):
    """The reason the control says "Unassigned" and never "None"."""
    _world(db)
    _put(db, actor=7, user_id=9)

    response = _put(db, actor=7, user_id=None)

    assert response.holder_user_id == 7
    assert response.source == "process_chain"


def test_delegating_twice_replaces_rather_than_joins(db: Session):
    # One holder per service — the schema's unique index says so, and a second
    # delegation must not raise on it.
    _world(db)
    factories.make_user(db, 11, organization_id=ORG)
    _put(db, actor=7, user_id=9)

    response = _put(db, actor=7, user_id=11)

    assert response.holder_user_id == 11


def test_a_member_who_owns_no_linked_process_may_not_delegate(db: Session):
    _world(db)
    factories.make_user(db, 26, organization_id=ORG)

    # The domain exception, not an HTTPException — `AuthorizationError` is what
    # the app maps to 403, and asserting the mapping here would test FastAPI.
    with pytest.raises(AuthorizationError):
        _put(db, actor=26, user_id=9)


def test_an_organisation_administrator_may_delegate(db: Session):
    # #403's decision: the accepted process owner OR an org admin — the admin
    # exists because a process owner who has left cannot delegate for themselves.
    _world(db)
    factories.make_user(db, 2, organization_id=ORG, role=UserRole.ORG_ADMIN.value)
    db.commit()

    assert _put(db, actor=2, user_id=9, roles=["org_admin"]).holder_user_id == 9


def test_a_service_in_another_organisation_is_not_found(db: Session):
    _world(db)
    factories.make_service(db, "svc-other", organization_id=OTHER_ORG, processes=[])
    db.commit()

    with pytest.raises(ResourceNotFoundError):
        _put(db, actor=7, user_id=9, service_id="svc-other")


def test_a_person_outside_the_organisation_cannot_be_delegated_to(db: Session):
    _world(db)
    factories.make_user(db, 99, organization_id=OTHER_ORG)

    with pytest.raises(ValidationError):
        _put(db, actor=7, user_id=99)


def test_an_inactive_person_cannot_be_delegated_to(db: Session):
    _, mate, _ = _world(db)
    mate.is_active = False
    db.commit()

    with pytest.raises(ValidationError):
        _put(db, actor=7, user_id=9)
