"""GET /organisation/recommendation — Risklence's suggested Organisation Risk
Appetite for leadership to review and correct, including the real peer
benchmark query (a real SQLite session, not the lightweight FakeDB harness
used elsewhere in this file's sibling tests — org_peer_appetite_benchmark
queries a bare column and needs a real ORM session)."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import risk_appetite_policies as appetite
from src.core.database import Base
from src.core.model_defs.risk_appetite_policy import RiskAppetitePolicy
from src.core.models import Organization


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=[Organization.__table__, RiskAppetitePolicy.__table__])
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Org", slug="org", required_frameworks=["NIS2"], nace_code="62.01"))
    session.commit()
    yield session
    session.close()


def _context() -> TenantContext:
    return TenantContext(user_id=1, organization_id=1, email="user@example.com", roles=["org_admin"], permissions=[])


def test_recommendation_reads_the_organisations_own_regulatory_frameworks(db: Session):
    recommendation = appetite.get_organisation_appetite_recommendation(ctx=_context(), db=db)

    assert recommendation.answers["regulatory"] == 1
    assert recommendation.answers["security"] == 1
    assert recommendation.confidence == "high"
    assert not recommendation.missing_inputs
    assert "NIS2" in recommendation.reasons["regulatory"]


def test_recommendation_blends_in_the_real_peer_benchmark(db: Session):
    for peer_id, level in zip([2, 3, 4], [1, 1, 1]):
        db.add(Organization(id=peer_id, name=f"Peer {peer_id}", slug=f"peer-{peer_id}", nace_code="62.01"))
        db.add(
            RiskAppetitePolicy(
                id=f"peer-policy-{peer_id}",
                organization_id=peer_id,
                scope="organisation",
                answers={"downtime": level},
                status="active",
                version=1,
                approved_by=str(peer_id),
            )
        )
    db.commit()

    recommendation = appetite.get_organisation_appetite_recommendation(ctx=_context(), db=db)

    # Baseline 3, peer median 1 -> blended = round((3 + 1) / 2) = 2.
    assert recommendation.answers["downtime"] == 2
    assert "3 similar organisations" in recommendation.reasons["downtime"]


def test_recommendation_defaults_honestly_without_a_nace_code(db: Session):
    db.query(Organization).filter(Organization.id == 1).update({"nace_code": None})
    db.commit()

    recommendation = appetite.get_organisation_appetite_recommendation(ctx=_context(), db=db)

    assert recommendation.answers["downtime"] == 3
    assert "similar organisations" not in recommendation.reasons["downtime"]
