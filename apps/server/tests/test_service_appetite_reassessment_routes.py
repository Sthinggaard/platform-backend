"""Service appetite inheritance + reassessment routes: Service Owner requests, Process Owner approves."""

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
from src.api.routes import service_appetite_reassessment_routes as routes
from src.core.constants import SERVICE_TIER_BUSINESS_CRITICAL
from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    MandateAssignmentSubjectType,
    MandateScopeType,
)
from src.core.constants.process_ownership_enums import ProcessOwnershipStatus
from src.core.database import Base
from src.core.exceptions import AuthorizationError
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.model_defs.process_ownership import ProcessOwnerAcceptance
from src.core.model_defs.risk_appetite_policy import RiskAppetitePolicy
from src.core.model_defs.service_appetite_reassessment import ServiceAppetiteReassessment
from src.core.models import AuditEvent, BusinessService, Organization, User, ValueStream


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
            User.__table__,
            ValueStream.__table__,
            BusinessService.__table__,
            OrgMandateRoleAssignment.__table__,
            OrgMandateScopeBinding.__table__,
            ProcessOwnerAcceptance.__table__,
            RiskAppetitePolicy.__table__,
            ServiceAppetiteReassessment.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org"),
            User(id=1, organization_id=1, email="process-owner@example.com", role="member"),
            User(id=2, organization_id=1, email="service-owner@example.com", role="member"),
            ValueStream(id="process-1", organization_id=1, name="Order to cash"),
            BusinessService(
                id="svc-1",
                organization_id=1,
                name="Checkout",
                tier=SERVICE_TIER_BUSINESS_CRITICAL,
                trading_impact="",
                owner_user_id=2,
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


def _context(user_id: int) -> TenantContext:
    return TenantContext(
        user_id=user_id, organization_id=1, email=f"user-{user_id}@example.com", roles=["member"], permissions=[]
    )


def _accept_process_ownership(db: Session) -> None:
    assignment = OrgMandateRoleAssignment(
        id="owner-assignment",
        organization_id=1,
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        subject_type=MandateAssignmentSubjectType.USER.value,
        user_id=1,
    )
    binding = OrgMandateScopeBinding(
        id="owner-binding",
        organization_id=1,
        scope_type=MandateScopeType.BUSINESS_PROCESS.value,
        value_stream_id="process-1",
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        role_assignment_id=assignment.id,
    )
    acceptance = ProcessOwnerAcceptance(
        id="owner-acceptance",
        organization_id=1,
        process_id="process-1",
        scope_binding_id=binding.id,
        role_assignment_id=assignment.id,
        owner_user_id=1,
        status=ProcessOwnershipStatus.ACCEPTED.value,
    )
    db.add_all([assignment, binding, acceptance])
    db.commit()


def test_service_owner_requests_and_process_owner_approves(db: Session):
    _accept_process_ownership(db)

    created = routes.create_reassessment(
        "svc-1",
        routes.ReassessmentRequest(
            process_id="process-1",
            category="downtime",
            requested_level=0,
            reason="Checkout is customer-facing with a shorter MTD than the rest of the process.",
        ),
        ctx=_context(2),
        db=db,
    )
    assert created.status == "pending"

    approved = routes.approve_service_reassessment(
        "svc-1",
        created.id,
        routes.ReassessmentApprovalRequest(review_at=datetime.now(timezone.utc) + timedelta(days=90)),
        ctx=_context(1),
        db=db,
    )
    assert approved.status == "approved"

    effective = routes.get_effective_service_appetite("svc-1", ctx=_context(2), db=db)
    assert effective.answers == {"downtime": 0}
    assert effective.status == "reassessed"
    assert effective.provenance["downtime"] == "reassessed"
    assert effective.provenance["dataLoss"] == "inherited"

    assert [event.event_type for event in db.query(AuditEvent).all()] == [
        "service_appetite_reassessment_requested",
        "service_appetite_reassessment_approved",
    ]


def test_only_the_service_owner_can_request_a_reassessment(db: Session):
    with pytest.raises(AuthorizationError):
        routes.create_reassessment(
            "svc-1",
            routes.ReassessmentRequest(
                process_id="process-1", category="downtime", requested_level=0, reason="reason"
            ),
            ctx=_context(1),
            db=db,
        )


def test_only_the_accepted_process_owner_can_approve(db: Session):
    reassessment = routes.create_reassessment(
        "svc-1",
        routes.ReassessmentRequest(process_id="process-1", category="downtime", requested_level=0, reason="reason"),
        ctx=_context(2),
        db=db,
    )

    with pytest.raises(AuthorizationError):
        routes.approve_service_reassessment(
            "svc-1",
            reassessment.id,
            routes.ReassessmentApprovalRequest(review_at=datetime.now(timezone.utc) + timedelta(days=90)),
            ctx=_context(2),
            db=db,
        )


def test_effective_appetite_shows_pending_reassessment_status_before_approval(db: Session):
    _accept_process_ownership(db)
    routes.create_reassessment(
        "svc-1",
        routes.ReassessmentRequest(process_id="process-1", category="downtime", requested_level=0, reason="reason"),
        ctx=_context(2),
        db=db,
    )

    effective = routes.get_effective_service_appetite("svc-1", ctx=_context(2), db=db)
    assert effective.status == "pending_reassessment"
    assert len(effective.pending) == 1


def test_list_pending_reassessments_is_org_wide_and_excludes_resolved_ones(db: Session):
    _accept_process_ownership(db)
    pending = routes.create_reassessment(
        "svc-1",
        routes.ReassessmentRequest(process_id="process-1", category="downtime", requested_level=0, reason="reason"),
        ctx=_context(2),
        db=db,
    )
    resolved = routes.create_reassessment(
        "svc-1",
        routes.ReassessmentRequest(process_id="process-1", category="dataLoss", requested_level=1, reason="reason"),
        ctx=_context(2),
        db=db,
    )
    routes.approve_service_reassessment(
        "svc-1",
        resolved.id,
        routes.ReassessmentApprovalRequest(review_at=datetime.now(timezone.utc) + timedelta(days=90)),
        ctx=_context(1),
        db=db,
    )

    summaries = routes.list_pending_service_reassessments(ctx=_context(1), db=db)

    assert len(summaries) == 1
    assert summaries[0].reassessment.id == pending.id
    assert summaries[0].business_service_name == "Checkout"
    assert summaries[0].process_name == "Order to cash"


def test_effective_appetite_falls_back_to_the_organisation_policy(db: Session):
    """BPS-38 precedence-chain fix: this endpoint used to query only an active
    business_process-scope policy directly, so a process with nothing but an
    active *organisation* policy incorrectly resolved to nothing at all."""
    db.add(
        RiskAppetitePolicy(
            id="org-policy",
            organization_id=1,
            scope="organisation",
            answers={"downtime": 3, "dataLoss": 3, "regulatory": 3, "financial": 3, "reputational": 3, "security": 3},
            status="active",
            version=1,
        )
    )
    db.commit()

    effective = routes.get_effective_service_appetite("svc-1", ctx=_context(2), db=db)

    assert effective.status == "inherited"
    assert effective.answers == {
        "downtime": 3,
        "dataLoss": 3,
        "regulatory": 3,
        "financial": 3,
        "reputational": 3,
        "security": 3,
    }


def test_effective_appetite_prefers_process_override_over_organisation_policy(db: Session):
    db.add_all(
        [
            RiskAppetitePolicy(
                id="org-policy",
                organization_id=1,
                scope="organisation",
                answers={"downtime": 3, "dataLoss": 3, "regulatory": 3, "financial": 3, "reputational": 3, "security": 3},
                status="active",
                version=1,
            ),
            RiskAppetitePolicy(
                id="process-override",
                organization_id=1,
                scope="business_process",
                process_id="process-1",
                answers={"downtime": 1, "dataLoss": 3, "regulatory": 3, "financial": 3, "reputational": 3, "security": 3},
                status="active",
                version=1,
            ),
        ]
    )
    db.commit()

    effective = routes.get_effective_service_appetite("svc-1", ctx=_context(2), db=db)

    assert effective.answers["downtime"] == 1


def test_rejected_reassessment_leaves_the_service_inherited(db: Session):
    _accept_process_ownership(db)
    reassessment = routes.create_reassessment(
        "svc-1",
        routes.ReassessmentRequest(process_id="process-1", category="downtime", requested_level=0, reason="reason"),
        ctx=_context(2),
        db=db,
    )

    rejected = routes.reject_service_reassessment(
        "svc-1", reassessment.id, routes.ReassessmentRejectionRequest(rejection_reason="Not material."), ctx=_context(1), db=db
    )
    assert rejected.status == "rejected"

    effective = routes.get_effective_service_appetite("svc-1", ctx=_context(2), db=db)
    assert effective.status == "inherited"
    assert effective.pending == []
