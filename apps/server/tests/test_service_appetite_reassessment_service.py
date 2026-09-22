"""Service Owner requests, Process Owner approves: appetite reassessment lifecycle."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.core.database import Base
from src.core.constants import SERVICE_TIER_BUSINESS_CRITICAL
from src.core.model_defs.service_appetite_reassessment import ServiceAppetiteReassessment
from src.core.models import BusinessService, Organization, ValueStream
from src.core.services.service_appetite_reassessment_service import (
    AppetiteReassessmentValidationError,
    approve_reassessment,
    approved_answers,
    get_active_reassessments,
    reject_reassessment,
    request_reassessment,
)


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
        tables=[
            Organization.__table__,
            ValueStream.__table__,
            BusinessService.__table__,
            ServiceAppetiteReassessment.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org"),
            ValueStream(id="process-1", organization_id=1, name="Order to cash"),
            BusinessService(
                id="svc-1",
                organization_id=1,
                name="Checkout",
                tier=SERVICE_TIER_BUSINESS_CRITICAL,
                trading_impact="",
                l1=[],
                l2=[],
                l3=[],
            ),
        ]
    )
    session.commit()
    yield session
    session.close()


def test_request_then_approve_makes_the_category_effective(db: Session):
    reassessment = request_reassessment(
        db,
        organization_id=1,
        business_service_id="svc-1",
        process_id="process-1",
        category="downtime",
        requested_level=0,
        reason="Checkout is customer-facing and shorter MTD than the rest of the process.",
        requested_by="2",
    )
    db.commit()
    assert reassessment.status == "pending"

    approve_reassessment(
        db,
        reassessment,
        reviewed_by="1",
        review_at=datetime.now(timezone.utc) + timedelta(days=90),
    )
    db.commit()

    answers = approved_answers(db, organization_id=1, business_service_id="svc-1")
    assert answers == {"downtime": 0}


def test_rejected_reassessment_never_becomes_effective(db: Session):
    reassessment = request_reassessment(
        db,
        organization_id=1,
        business_service_id="svc-1",
        process_id="process-1",
        category="downtime",
        requested_level=0,
        reason="Requested reason.",
        requested_by="2",
    )
    db.commit()

    reject_reassessment(db, reassessment, reviewed_by="1", rejection_reason="Not material enough.")
    db.commit()

    assert approved_answers(db, organization_id=1, business_service_id="svc-1") == {}
    assert reassessment.status == "rejected"


def test_a_new_request_for_the_same_category_supersedes_the_previous_one(db: Session):
    first = request_reassessment(
        db,
        organization_id=1,
        business_service_id="svc-1",
        process_id="process-1",
        category="downtime",
        requested_level=1,
        reason="First reason.",
        requested_by="2",
    )
    db.commit()
    approve_reassessment(db, first, reviewed_by="1", review_at=datetime.now(timezone.utc) + timedelta(days=90))
    db.commit()

    second = request_reassessment(
        db,
        organization_id=1,
        business_service_id="svc-1",
        process_id="process-1",
        category="downtime",
        requested_level=0,
        reason="Tighter still after an incident.",
        requested_by="2",
    )
    db.commit()

    assert first.status == "superseded"
    assert first.superseded_by_id == second.id
    assert second.version == 2
    # The prior approval no longer counts once superseded by a new pending request.
    active = get_active_reassessments(db, organization_id=1, business_service_id="svc-1")
    assert active["downtime"].id == second.id
    assert active["downtime"].status == "pending"


def test_rejects_an_unknown_category_or_out_of_range_level(db: Session):
    with pytest.raises(AppetiteReassessmentValidationError):
        request_reassessment(
            db,
            organization_id=1,
            business_service_id="svc-1",
            process_id="process-1",
            category="not-a-real-category",
            requested_level=2,
            reason="reason",
            requested_by="2",
        )
    with pytest.raises(AppetiteReassessmentValidationError):
        request_reassessment(
            db,
            organization_id=1,
            business_service_id="svc-1",
            process_id="process-1",
            category="downtime",
            requested_level=9,
            reason="reason",
            requested_by="2",
        )


def test_cannot_approve_or_reject_a_non_pending_reassessment(db: Session):
    reassessment = request_reassessment(
        db,
        organization_id=1,
        business_service_id="svc-1",
        process_id="process-1",
        category="downtime",
        requested_level=0,
        reason="reason",
        requested_by="2",
    )
    db.commit()
    approve_reassessment(db, reassessment, reviewed_by="1", review_at=datetime.now(timezone.utc) + timedelta(days=90))
    db.commit()

    with pytest.raises(AppetiteReassessmentValidationError):
        approve_reassessment(db, reassessment, reviewed_by="1", review_at=datetime.now(timezone.utc) + timedelta(days=90))
    with pytest.raises(AppetiteReassessmentValidationError):
        reject_reassessment(db, reassessment, reviewed_by="1", rejection_reason="too late")
