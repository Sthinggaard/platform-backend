"""Cross-org peer appetite benchmark: aggregate-only, minimum peer count, never per-org."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.database import Base
from src.core.model_defs.risk_appetite_policy import RiskAppetitePolicy
from src.core.models import Organization, ValueStream
from src.core.services.peer_appetite_benchmark_service import org_peer_appetite_benchmark, peer_appetite_benchmark


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[Organization.__table__, ValueStream.__table__, RiskAppetitePolicy.__table__],
    )
    session = sessionmaker(bind=engine)()
    session.add_all([Organization(id=i, name=f"Org {i}", slug=f"org-{i}") for i in range(1, 6)])
    session.commit()
    yield session
    session.close()


def _active_org_policy(db: Session, *, org_id: int, answers: dict) -> None:
    db.add(
        RiskAppetitePolicy(
            id=f"org-policy-{org_id}",
            organization_id=org_id,
            scope="organisation",
            answers=answers,
            status="active",
            version=1,
            approved_by="1",
        )
    )


def _peer_process(db: Session, *, org_id: int, process_id: str, library_item_id: str) -> ValueStream:
    process = ValueStream(id=process_id, organization_id=org_id, name="Order to cash", library_item_id=library_item_id)
    db.add(process)
    return process


def _active_policy(db: Session, *, org_id: int, process_id: str, answers: dict, version: int = 1) -> None:
    db.add(
        RiskAppetitePolicy(
            id=f"policy-{process_id}",
            organization_id=org_id,
            scope="business_process",
            process_id=process_id,
            answers=answers,
            status="active",
            version=version,
            approved_by="1",
        )
    )


def test_returns_no_signal_without_a_process_template(db: Session):
    assert peer_appetite_benchmark(db, library_item_id=None, exclude_organization_id=1) == {}


def test_returns_no_signal_below_the_minimum_peer_count(db: Session):
    _peer_process(db, org_id=2, process_id="peer-1", library_item_id="order_to_cash")
    _active_policy(db, org_id=2, process_id="peer-1", answers={"downtime": 2})
    _peer_process(db, org_id=3, process_id="peer-2", library_item_id="order_to_cash")
    _active_policy(db, org_id=3, process_id="peer-2", answers={"downtime": 2})
    db.commit()

    # Only 2 peers — below MIN_PEER_COUNT of 3.
    result = peer_appetite_benchmark(db, library_item_id="order_to_cash", exclude_organization_id=1)
    assert result == {}


def test_returns_the_median_once_enough_peers_exist(db: Session):
    for i, level in enumerate([1, 2, 2, 4], start=2):
        _peer_process(db, org_id=i, process_id=f"peer-{i}", library_item_id="order_to_cash")
        _active_policy(db, org_id=i, process_id=f"peer-{i}", answers={"downtime": level, "dataLoss": 1})
    db.commit()

    result = peer_appetite_benchmark(db, library_item_id="order_to_cash", exclude_organization_id=1)

    assert result["downtime"].peer_count == 4
    assert result["downtime"].median_level == 2
    assert result["dataLoss"].peer_count == 4
    assert result["dataLoss"].median_level == 1


def test_never_includes_the_requesting_organisations_own_processes(db: Session):
    _peer_process(db, org_id=1, process_id="own-process", library_item_id="order_to_cash")
    _active_policy(db, org_id=1, process_id="own-process", answers={"downtime": 0})
    for i in [2, 3, 4]:
        _peer_process(db, org_id=i, process_id=f"peer-{i}", library_item_id="order_to_cash")
        _active_policy(db, org_id=i, process_id=f"peer-{i}", answers={"downtime": 3})
    db.commit()

    result = peer_appetite_benchmark(db, library_item_id="order_to_cash", exclude_organization_id=1)

    assert result["downtime"].peer_count == 3
    assert result["downtime"].median_level == 3


def test_ignores_a_different_process_template(db: Session):
    for i in [2, 3, 4]:
        _peer_process(db, org_id=i, process_id=f"peer-{i}", library_item_id="billing")
        _active_policy(db, org_id=i, process_id=f"peer-{i}", answers={"downtime": 1})
    db.commit()

    result = peer_appetite_benchmark(db, library_item_id="order_to_cash", exclude_organization_id=1)
    assert result == {}


# --- Organisation Risk Appetite peer benchmark (comparable by NACE code, not process template) ---


def test_org_benchmark_returns_no_signal_without_a_nace_code(db: Session):
    assert org_peer_appetite_benchmark(db, nace_code=None, exclude_organization_id=1) == {}


def test_org_benchmark_returns_no_signal_below_the_minimum_peer_count(db: Session):
    db.query(Organization).filter(Organization.id.in_([2, 3])).update(
        {"nace_code": "62.01"}, synchronize_session=False
    )
    _active_org_policy(db, org_id=2, answers={"downtime": 2})
    _active_org_policy(db, org_id=3, answers={"downtime": 2})
    db.commit()

    # Only 2 peers — below MIN_PEER_COUNT of 3.
    result = org_peer_appetite_benchmark(db, nace_code="62.01", exclude_organization_id=1)
    assert result == {}


def test_org_benchmark_returns_the_median_once_enough_peers_share_the_industry(db: Session):
    db.query(Organization).filter(Organization.id.in_([2, 3, 4, 5])).update(
        {"nace_code": "62.01"}, synchronize_session=False
    )
    for org_id, level in zip([2, 3, 4, 5], [1, 2, 2, 4]):
        _active_org_policy(db, org_id=org_id, answers={"downtime": level, "regulatory": 1})
    db.commit()

    result = org_peer_appetite_benchmark(db, nace_code="62.01", exclude_organization_id=1)

    assert result["downtime"].peer_count == 4
    assert result["downtime"].median_level == 2
    assert result["regulatory"].peer_count == 4
    assert result["regulatory"].median_level == 1


def test_org_benchmark_never_includes_the_requesting_organisations_own_policy(db: Session):
    db.query(Organization).filter(Organization.id.in_([1, 2, 3, 4])).update(
        {"nace_code": "62.01"}, synchronize_session=False
    )
    _active_org_policy(db, org_id=1, answers={"downtime": 0})
    for org_id in [2, 3, 4]:
        _active_org_policy(db, org_id=org_id, answers={"downtime": 3})
    db.commit()

    result = org_peer_appetite_benchmark(db, nace_code="62.01", exclude_organization_id=1)

    assert result["downtime"].peer_count == 3
    assert result["downtime"].median_level == 3


def test_org_benchmark_ignores_a_different_industry(db: Session):
    db.query(Organization).filter(Organization.id.in_([2, 3, 4])).update(
        {"nace_code": "10.01"}, synchronize_session=False
    )
    for org_id in [2, 3, 4]:
        _active_org_policy(db, org_id=org_id, answers={"downtime": 1})
    db.commit()

    result = org_peer_appetite_benchmark(db, nace_code="62.01", exclude_organization_id=1)
    assert result == {}
