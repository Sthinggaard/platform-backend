"""BSP-02: slot-mapping lifecycle on SlotInstance."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray, JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.routes.bundle_slot_mapping_routes import _upsert_slot_instance
from src.core.database import Base
from src.core.models import Organization, SlotInstance


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
        engine, tables=[Organization.__table__, SlotInstance.__table__]
    )
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Org", slug="org"))
    session.commit()
    yield session
    session.close()


def _row(db: Session) -> SlotInstance:
    return db.query(SlotInstance).one()


def test_mapped_slot_is_owner_approved_with_full_confidence(db: Session):
    _upsert_slot_instance(
        db,
        org_id=1,
        service_id="svc-1",
        slot_id="external_provider",
        group_key="external_providers",
        status="mapped",
        asset_id="asset-9",
        asset_label="Stripe",
        template_version=1,
        decided_by="7",
    )
    db.commit()
    row = _row(db)
    assert row.mapping_status == "approved"
    assert row.mapping_confidence == 1.0
    assert row.evidence_source == "manual"
    assert row.provenance == "owner_approved"
    assert row.decided_by == "7"
    assert row.decided_at is not None


def test_unknown_slot_stays_needs_review_without_fabricated_confidence(db: Session):
    _upsert_slot_instance(
        db,
        org_id=1,
        service_id="svc-1",
        slot_id="monitoring_service",
        group_key="systems",
        status="unknown",
        asset_id=None,
        asset_label=None,
        template_version=1,
        decided_by="7",
    )
    db.commit()
    row = _row(db)
    assert row.mapping_status == "needs_review"
    assert row.mapping_confidence is None
    assert row.provenance is None
    assert row.decided_at is None


def test_reupsert_moves_lifecycle_forward(db: Session):
    common = dict(
        db=db,
        org_id=1,
        service_id="svc-1",
        slot_id="external_provider",
        group_key="external_providers",
        template_version=1,
        decided_by="7",
    )
    _upsert_slot_instance(
        common.pop("db"), status="unknown", asset_id=None, asset_label=None, **common
    )
    db.commit()
    assert _row(db).mapping_status == "needs_review"

    _upsert_slot_instance(
        db, status="mapped", asset_id="asset-9", asset_label="Stripe", **common
    )
    db.commit()
    row = _row(db)
    assert row.mapping_status == "approved"
    assert row.provenance == "owner_approved"
    assert db.query(SlotInstance).count() == 1
