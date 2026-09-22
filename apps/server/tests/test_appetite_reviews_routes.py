"""Org-wide appetite review dates for the Governance Control Centre (ONB-GOV-10)."""

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

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import risk_appetite_policies as appetite
from src.core.constants import SERVICE_TIER_BUSINESS_CRITICAL
from src.core.constants.appetite_reassessment_enums import AppetiteReassessmentStatus
from src.core.database import Base
from src.core.model_defs.risk_appetite_policy import APPETITE_POLICY_ACTIVE, RiskAppetitePolicy
from src.core.model_defs.service_appetite_reassessment import ServiceAppetiteReassessment
from src.core.models import BusinessService, Organization, User, ValueStream


_TEST_TABLES = [
    Organization.__table__,
    User.__table__,
    ValueStream.__table__,
    BusinessService.__table__,
    RiskAppetitePolicy.__table__,
    ServiceAppetiteReassessment.__table__,
]


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    # Scoped to just the tables this fixture creates — mutating Base.metadata
    # globally (the common pattern elsewhere in this suite) risks corrupting
    # unrelated tables' column types for whichever real-Postgres test happens
    # to run next (e.g. assets.intent's GIN index needs jsonb, not json).
    for table in _TEST_TABLES:
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(engine, tables=_TEST_TABLES)
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org"),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
            ValueStream(id="process-1", organization_id=1, name="Order to cash"),
            BusinessService(
                id="svc-1",
                organization_id=1,
                name="Checkout",
                tier=SERVICE_TIER_BUSINESS_CRITICAL,
                trading_impact="",
                value_stream_ids=["process-1"],
                l1=[],
                l2=[],
                l3=[],
            ),
        ]
    )
    session.commit()
    yield session
    session.close()


def _context() -> TenantContext:
    return TenantContext(user_id=1, organization_id=1, email="admin@example.com", roles=["org_admin"], permissions=[])


def test_lists_only_review_dated_active_process_policies_and_approved_reassessments(db: Session):
    overdue = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=5)
    db.add_all(
        [
            RiskAppetitePolicy(
                id="policy-with-review",
                organization_id=1,
                scope="business_process",
                process_id="process-1",
                answers={"downtime": 2},
                status=APPETITE_POLICY_ACTIVE,
                version=1,
                approved_by="1",
                review_at=overdue,
            ),
            # No review_at set — must be excluded, never invented.
            RiskAppetitePolicy(
                id="policy-without-review",
                organization_id=1,
                scope="business_process",
                process_id="process-1",
                answers={"downtime": 2},
                status=APPETITE_POLICY_ACTIVE,
                version=1,
                approved_by="1",
            ),
            # Draft (not active) with a review date — must be excluded.
            RiskAppetitePolicy(
                id="policy-draft",
                organization_id=1,
                scope="business_process",
                process_id="process-1",
                answers={"downtime": 2},
                status="draft",
                version=1,
                review_at=overdue,
            ),
            ServiceAppetiteReassessment(
                id="reassessment-approved",
                organization_id=1,
                business_service_id="svc-1",
                process_id="process-1",
                category="downtime",
                requested_level=1,
                reason="reason",
                requested_by="2",
                status=AppetiteReassessmentStatus.APPROVED.value,
                version=1,
                review_at=overdue,
            ),
            # Pending (not approved) with a review date — must be excluded.
            ServiceAppetiteReassessment(
                id="reassessment-pending",
                organization_id=1,
                business_service_id="svc-1",
                process_id="process-1",
                category="dataLoss",
                requested_level=1,
                reason="reason",
                requested_by="2",
                status=AppetiteReassessmentStatus.PENDING.value,
                version=1,
                review_at=overdue,
            ),
        ]
    )
    db.commit()

    reviews = appetite.list_appetite_reviews(ctx=_context(), db=db)

    assert {item.policy_id for item in reviews} == {"policy-with-review", "reassessment-approved"}
    process_review = next(item for item in reviews if item.policy_id == "policy-with-review")
    assert process_review.kind == "business_process"
    assert process_review.process_name == "Order to cash"
    service_review = next(item for item in reviews if item.policy_id == "reassessment-approved")
    assert service_review.kind == "business_service"
    assert service_review.business_service_name == "Checkout"
    assert service_review.process_name == "Order to cash"


def test_returns_an_empty_list_when_nothing_has_a_review_date(db: Session):
    assert appetite.list_appetite_reviews(ctx=_context(), db=db) == []
