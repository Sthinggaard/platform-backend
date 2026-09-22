"""Who may record a binding decision about a threat (#374, GOV-06).

🚨 The hole this closes. `POST /api/v1/recommendations/decisions` was guarded by
`_require_non_consultant` alone, so any active non-consultant could accept risk,
escalate, or dispatch to Jira on **any** threat in the organisation. Søren found
it on 2026-08-31 testing as `viewer@risklence.com` — a member holding no mandate
at all — and was offered *Change decision* on a process he does not own.

Søren's ruling: authority follows ownership of the thing decided. A process
owner who merely *depends* on the service is refused, and informed instead
(#375) — that is the case that makes this different from "may they act on the
affected process".
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
from src.core.models import Asset
from src.core.services.threat_decision_authority_service import (
    ThreatDecisionRefusal,
    resolve_threat_decision_authority,
)

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


def _asset(db: Session, asset_id: int, name: str, *, organization_id: int = ORG) -> Asset:
    asset = Asset(
        id=asset_id, organization_id=organization_id, display_name=name,
        type="Database", layer="data", status="PARTIALLY_OBSERVED",
    )
    db.add(asset)
    db.flush()
    return asset


def _service_on(db: Session, service_id: str, *, processes: list[str], asset_ids: list[int]):
    service = factories.make_service(
        db, service_id, organization_id=ORG, processes=processes
    )
    service.l1 = [f"asset-{asset_id}" for asset_id in asset_ids]
    db.flush()
    return service


def _authority(db: Session, *, asset_name: str, actor: int | None):
    return resolve_threat_decision_authority(
        db, organization_id=ORG, threat_asset_name=asset_name, actor_user_id=actor
    )


def test_the_service_owner_may_decide(db: Session):
    factories.make_user(db, 7, organization_id=ORG)
    factories.make_process(db, "p1", organization_id=ORG)
    _asset(db, 92, "Managed PostgreSQL")
    _service_on(db, "svc-1", processes=["p1"], asset_ids=[92])
    factories.grant_mandate(
        db, organization_id=ORG, user_id=7,
        role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1",
    )
    db.commit()

    authority = _authority(db, asset_name="Managed PostgreSQL", actor=7)

    assert authority.may_decide is True
    assert authority.affected_service_ids == ("svc-1",)


def test_a_member_holding_no_mandate_may_not_decide(db: Session):
    """The reported case, exactly: viewer@risklence.com, role member, no mandate."""
    factories.make_user(db, 7, organization_id=ORG)
    factories.make_user(db, 26, organization_id=ORG)
    factories.make_process(db, "p1", organization_id=ORG)
    _asset(db, 92, "Managed PostgreSQL")
    _service_on(db, "svc-1", processes=["p1"], asset_ids=[92])
    factories.grant_mandate(
        db, organization_id=ORG, user_id=7,
        role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1",
    )
    db.commit()

    authority = _authority(db, asset_name="Managed PostgreSQL", actor=26)

    assert authority.may_decide is False
    assert authority.refusal is ThreatDecisionRefusal.NOT_THE_HOLDER
    assert authority.holder_user_ids == (7,)


def test_a_process_owner_who_merely_depends_is_refused(db: Session):
    """The case that makes this rule different from process act-eligibility.

    Two processes lean on one asset. The service is delegated to user 9, so the
    owner of the other process may not decide about it — they are informed.
    """
    for uid in (7, 8, 9):
        factories.make_user(db, uid, organization_id=ORG)
    for pid in ("p1", "p2"):
        factories.make_process(db, pid, organization_id=ORG)
    _asset(db, 92, "Managed PostgreSQL")
    _service_on(db, "svc-1", processes=["p1", "p2"], asset_ids=[92])
    factories.grant_mandate(
        db, organization_id=ORG, user_id=8,
        role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p2",
    )
    factories.grant_mandate(
        db, organization_id=ORG, user_id=9,
        role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER, service_id="svc-1",
    )
    db.commit()

    assert _authority(db, asset_name="Managed PostgreSQL", actor=9).may_decide is True
    refused = _authority(db, asset_name="Managed PostgreSQL", actor=8)
    assert refused.may_decide is False
    assert refused.refusal is ThreatDecisionRefusal.NOT_THE_HOLDER


def test_nobody_may_decide_when_nobody_is_accountable(db: Session):
    # Fails closed. The repair is to state an owner (#376), never to widen who
    # may act — a decision recorded by nobody in particular is the outcome this
    # exists to prevent.
    factories.make_user(db, 7, organization_id=ORG)
    factories.make_process(db, "p1", organization_id=ORG)
    _asset(db, 92, "Managed PostgreSQL")
    _service_on(db, "svc-1", processes=["p1"], asset_ids=[92])
    db.commit()

    authority = _authority(db, asset_name="Managed PostgreSQL", actor=7)

    assert authority.may_decide is False
    assert authority.refusal is ThreatDecisionRefusal.ACCOUNTABILITY_UNRESOLVED
    assert authority.holder_user_ids == ()


def test_an_artefact_no_service_carries_has_nobody_to_decide(db: Session):
    factories.make_user(db, 7, organization_id=ORG)
    _asset(db, 92, "Managed PostgreSQL")
    db.commit()

    assert _authority(db, asset_name="Managed PostgreSQL", actor=7).refusal is (
        ThreatDecisionRefusal.NO_SERVICE_REACHED
    )


def test_an_unknown_artefact_is_refused_rather_than_waved_through(db: Session):
    factories.make_user(db, 7, organization_id=ORG)
    db.commit()

    assert _authority(db, asset_name="Nothing We Hold", actor=7).refusal is (
        ThreatDecisionRefusal.ASSET_NOT_FOUND
    )


def test_an_anonymous_actor_may_never_decide(db: Session):
    factories.make_user(db, 7, organization_id=ORG)
    factories.make_process(db, "p1", organization_id=ORG)
    _asset(db, 92, "Managed PostgreSQL")
    _service_on(db, "svc-1", processes=["p1"], asset_ids=[92])
    factories.grant_mandate(
        db, organization_id=ORG, user_id=7,
        role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1",
    )
    db.commit()

    assert _authority(db, asset_name="Managed PostgreSQL", actor=None).may_decide is False


def test_another_tenants_artefact_of_the_same_name_grants_nothing(db: Session):
    # Names are not unique across tenants, and the link from a threat to its
    # artefact is by name — so this is the isolation that matters most here.
    factories.make_user(db, 7, organization_id=ORG)
    _asset(db, 500, "Managed PostgreSQL", organization_id=OTHER_ORG)
    db.commit()

    assert _authority(db, asset_name="Managed PostgreSQL", actor=7).refusal is (
        ThreatDecisionRefusal.ASSET_NOT_FOUND
    )


def test_the_match_ignores_case_and_padding_like_the_projection_does(db: Session):
    factories.make_user(db, 7, organization_id=ORG)
    factories.make_process(db, "p1", organization_id=ORG)
    _asset(db, 92, "Managed PostgreSQL")
    _service_on(db, "svc-1", processes=["p1"], asset_ids=[92])
    factories.grant_mandate(
        db, organization_id=ORG, user_id=7,
        role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER, process_id="p1",
    )
    db.commit()

    assert _authority(db, asset_name="  managed postgresql ", actor=7).may_decide is True
