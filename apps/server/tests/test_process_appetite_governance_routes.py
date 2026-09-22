"""Process Risk Appetite governance: Process Owner proposes, leadership approves."""

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
from src.core.constants.leadership_authorization_enums import LeadershipAuthorizationStatus
from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    MandateAssignmentSubjectType,
    MandateScopeType,
)
from src.core.constants.process_ownership_enums import ProcessOwnershipStatus
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ValidationError
from src.core.model_defs.leadership_authorization import LeadershipAuthorization
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.model_defs.organization_bia_baseline import OrganizationBiaBaseline
from src.core.model_defs.process_bia_assessment import ProcessBiaAssessment
from src.core.model_defs.process_ownership import ProcessOwnerAcceptance
from src.core.model_defs.risk_appetite_policy import (
    APPETITE_AUDIT_DRAFT_CREATED,
    APPETITE_AUDIT_ORGANISATION_ACCEPTED,
    APPETITE_AUDIT_SUBMITTED,
    APPETITE_POLICY_ACTIVE,
    APPETITE_SCOPE_BUSINESS_PROCESS,
    APPETITE_SCOPE_ORGANISATION,
    APPETITE_POLICY_DRAFT,
    APPETITE_POLICY_LEADERSHIP_REVIEW,
    RiskAppetitePolicy,
)
from src.core.models import AuditEvent, Organization, User, ValueStream


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
            OrgMandateRoleAssignment.__table__,
            OrgMandateScopeBinding.__table__,
            ProcessOwnerAcceptance.__table__,
            OrganizationBiaBaseline.__table__,
            ProcessBiaAssessment.__table__,
            RiskAppetitePolicy.__table__,
            LeadershipAuthorization.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org"),
            User(id=1, organization_id=1, email="owner@example.com", role="member"),
            User(id=2, organization_id=1, email="approver@example.com", role="admin"),
            ValueStream(id="process-1", organization_id=1, name="Order to cash"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _context(user_id: int) -> TenantContext:
    return TenantContext(
        user_id=user_id, organization_id=1, email=f"user-{user_id}@example.com", roles=["member"], permissions=[]
    )


def _accept_process_ownership(db: Session, *, owner_user_id: int) -> None:
    assignment = OrgMandateRoleAssignment(
        id="owner-assignment",
        organization_id=1,
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        subject_type=MandateAssignmentSubjectType.USER.value,
        user_id=owner_user_id,
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
        owner_user_id=owner_user_id,
        status=ProcessOwnershipStatus.ACCEPTED.value,
    )
    db.add_all([assignment, binding, acceptance])
    db.commit()


def _grant_leadership_sponsor(db: Session, *, user_id: int) -> None:
    """Risk appetite approval (organisation and process scope alike) is
    gated on the org's named leadership sponsor — LeadershipAuthorization.sponsor_user_id
    — not the generic Approver/Escalation Contact mandate role."""
    db.add(
        LeadershipAuthorization(
            id="leadership-authorization-1",
            organization_id=1,
            status=LeadershipAuthorizationStatus.ACTIVE.value,
            version=1,
            sponsor_user_id=user_id,
            approving_body="senior_management",
            authorized_scope="Organisation-wide onboarding",
        )
    )
    db.commit()


def test_process_owner_proposes_and_leadership_approves(db: Session):
    _accept_process_ownership(db, owner_user_id=1)
    _grant_leadership_sponsor(db, user_id=2)

    draft = appetite.create_process_appetite_draft(
        "process-1",
        appetite.AppetiteDraftRequest(
            answers={"downtime": 2, "dataLoss": 1},
            review_at=datetime.now(timezone.utc) + timedelta(days=90),
            note="Recommended from BIA + priority.",
        ),
        ctx=_context(1),
        db=db,
    )
    assert draft.status == APPETITE_POLICY_DRAFT
    assert draft.process_id == "process-1"

    submitted = appetite.submit_process_appetite_draft("process-1", draft.policy_id, ctx=_context(1), db=db)
    assert submitted.status == APPETITE_POLICY_LEADERSHIP_REVIEW

    approved = appetite.approve_process_appetite_draft(
        "process-1",
        draft.policy_id,
        appetite.AppetiteApprovalRequest(approval_reference="leadership-review-1"),
        ctx=_context(2),
        db=db,
    )
    assert approved.status == APPETITE_POLICY_ACTIVE
    assert approved.approved_by == "2"

    assert [event.event_type for event in db.query(AuditEvent).all()] == [
        "risk_appetite_draft_created",
        "risk_appetite_submitted_for_leadership_review",
        "risk_appetite_approved",
    ]


def test_proposing_an_appetite_registers_it_on_the_process(db: Session):
    """A process is registered against the appetite it is working under.

    Søren, 2026-09-11: *"creating a new risk appetite creates a new save to db
    and links that new uuid fk to the business process."*

    ⚠️ **The link is the association, not the lifecycle.** Whether the appetite
    yet governs is the policy's own status; this says which appetite the process
    is on, which is what distinguishes a process whose owner has decided from
    one that has never been asked.
    """
    _accept_process_ownership(db, owner_user_id=1)

    draft = appetite.create_process_appetite_draft(
        "process-1",
        appetite.AppetiteDraftRequest(
            answers={"downtime": 2, "dataLoss": 1},
            review_at=datetime.now(timezone.utc) + timedelta(days=90),
            note="Our own guardrails.",
        ),
        ctx=_context(1),
        db=db,
    )

    process = db.query(ValueStream).filter(ValueStream.id == "process-1").one()
    assert process.risk_appetite_policy_id == draft.policy_id

    status = appetite.get_process_appetite_status("process-1", ctx=_context(1), db=db)
    assert status.registered_policy_id == draft.policy_id


def test_accepting_the_inherited_appetite_registers_the_organisation_policy(db: Session):
    """Accepting the organisation's appetite writes no process policy — by design.

    `accept_process_appetite_recommendation`, 2026-08-30: *"no process override
    is written and the process keeps inheriting."*

    ⚠️ **So the decision has to be recorded somewhere else.** Before this it was
    an audit event whose metadata did not carry the process id, so a process
    whose owner had decided to inherit was indistinguishable from one that had
    never been asked — and the workspace asked again on every load (Søren,
    2026-09-11).
    """
    _accept_process_ownership(db, owner_user_id=1)
    recommendation = appetite.get_process_appetite_recommendation(
        "process-1", ctx=_context(1), db=db
    )

    # An organisation policy the recommendation matches exactly, so accepting
    # takes the inheriting branch rather than proposing a deviation.
    organisation_policy = RiskAppetitePolicy(
        organization_id=1,
        scope="organisation",
        process_id=None,
        answers=recommendation.answers,
        status=APPETITE_POLICY_ACTIVE,
        version=1,
        approved_by="2",
    )
    db.add(organisation_policy)
    db.commit()

    accepted = appetite.accept_process_appetite_recommendation(
        "process-1",
        appetite.AppetiteRecommendationAcceptanceRequest(
            answers=recommendation.answers,
            review_at=datetime.now(timezone.utc) + timedelta(days=7),
            note="Inheriting the organisation baseline.",
        ),
        ctx=_context(1),
        db=db,
    )
    assert accepted.policy_id == organisation_policy.id

    # No process-scoped policy was written — the process keeps inheriting.
    assert (
        db.query(RiskAppetitePolicy)
        .filter(RiskAppetitePolicy.scope == "business_process")
        .count()
        == 0
    )

    # ⚠️ And the decision is nonetheless recorded, on the process and in a trail
    # that can say which process it was for.
    process = db.query(ValueStream).filter(ValueStream.id == "process-1").one()
    assert process.risk_appetite_policy_id == organisation_policy.id

    status = appetite.get_process_appetite_status("process-1", ctx=_context(1), db=db)
    assert status.active is None
    assert status.pending is None
    assert status.registered_policy_id == organisation_policy.id

    accepted_event = next(
        event
        for event in db.query(AuditEvent).all()
        if event.event_type == "risk_appetite_organisation_accepted"
    )
    assert accepted_event.metadata_json["process_id"] == "process-1"


def test_accepting_an_unchanged_recommendation_goes_to_leadership_not_live(db: Session):
    """Accepting is a proposal, never an activation.

    Søren, 2026-08-30: changing a Business Process BIA or Risk Appetite needs
    leadership approval before it is accepted. The Process Owner proposes; they
    do not approve their own governing threshold, even unchanged.
    """
    _accept_process_ownership(db, owner_user_id=1)
    recommendation = appetite.get_process_appetite_recommendation(
        "process-1", ctx=_context(1), db=db
    )

    accepted = appetite.accept_process_appetite_recommendation(
        "process-1",
        appetite.AppetiteRecommendationAcceptanceRequest(
            answers=recommendation.answers,
            review_at=datetime.now(timezone.utc) + timedelta(days=7),
            note="Accepted unchanged after Process Owner review.",
        ),
        ctx=_context(1),
        db=db,
    )

    assert accepted.status == APPETITE_POLICY_LEADERSHIP_REVIEW
    assert accepted.answers == recommendation.answers
    # Nothing governs yet: no active process policy exists.
    assert (
        db.query(RiskAppetitePolicy)
        .filter(
            RiskAppetitePolicy.organization_id == 1,
            RiskAppetitePolicy.status == APPETITE_POLICY_ACTIVE,
        )
        .count()
        == 0
    )
    # The trail says proposed and submitted — never approved by the proposer.
    assert [event.event_type for event in db.query(AuditEvent).all()] == [
        APPETITE_AUDIT_DRAFT_CREATED,
        APPETITE_AUDIT_SUBMITTED,
    ]


def test_process_owner_cannot_bypass_leadership_with_changed_answers(db: Session):
    _accept_process_ownership(db, owner_user_id=1)
    recommendation = appetite.get_process_appetite_recommendation(
        "process-1", ctx=_context(1), db=db
    )
    changed_answers = dict(recommendation.answers)
    changed_answers["downtime"] = (changed_answers["downtime"] + 1) % 5

    with pytest.raises(ValidationError, match="leadership review"):
        appetite.accept_process_appetite_recommendation(
            "process-1",
            appetite.AppetiteRecommendationAcceptanceRequest(
                answers=changed_answers,
                review_at=datetime.now(timezone.utc) + timedelta(days=7),
            ),
            ctx=_context(1),
            db=db,
        )


def test_process_owner_cannot_approve_their_own_proposal(db: Session):
    _accept_process_ownership(db, owner_user_id=1)

    draft = appetite.create_process_appetite_draft(
        "process-1",
        appetite.AppetiteDraftRequest(
            answers={"downtime": 2},
            review_at=datetime.now(timezone.utc) + timedelta(days=90),
        ),
        ctx=_context(1),
        db=db,
    )
    appetite.submit_process_appetite_draft("process-1", draft.policy_id, ctx=_context(1), db=db)

    with pytest.raises(AuthorizationError):
        appetite.approve_process_appetite_draft(
            "process-1",
            draft.policy_id,
            appetite.AppetiteApprovalRequest(),
            ctx=_context(1),
            db=db,
        )


def test_non_owner_cannot_propose_a_process_appetite_draft(db: Session):
    _accept_process_ownership(db, owner_user_id=1)

    with pytest.raises(AuthorizationError):
        appetite.create_process_appetite_draft(
            "process-1",
            appetite.AppetiteDraftRequest(
                answers={"downtime": 2},
                review_at=datetime.now(timezone.utc) + timedelta(days=90),
            ),
            ctx=_context(2),
            db=db,
        )


def test_direct_process_appetite_activation_is_blocked(db: Session):
    with pytest.raises(ValidationError):
        appetite.set_process_override(
            "process-1",
            appetite.AppetitePolicyWriteRequest(answers={"downtime": 2}, approved_by="2"),
            ctx=_context(1),
            db=db,
        )


def test_process_appetite_status_reports_active_pending_and_history(db: Session):
    _accept_process_ownership(db, owner_user_id=1)
    _grant_leadership_sponsor(db, user_id=2)

    draft = appetite.create_process_appetite_draft(
        "process-1",
        appetite.AppetiteDraftRequest(
            answers={"downtime": 2},
            review_at=datetime.now(timezone.utc) + timedelta(days=90),
        ),
        ctx=_context(1),
        db=db,
    )
    appetite.submit_process_appetite_draft("process-1", draft.policy_id, ctx=_context(1), db=db)
    appetite.approve_process_appetite_draft(
        "process-1", draft.policy_id, appetite.AppetiteApprovalRequest(), ctx=_context(2), db=db
    )

    status = appetite.get_process_appetite_status("process-1", ctx=_context(1), db=db)
    assert status.active is not None and status.active.policy_id == draft.policy_id
    assert status.pending is None
    assert len(status.history) == 1


def test_process_appetite_recommendation_reads_bia_priority_and_frameworks(db: Session):
    process = db.query(ValueStream).filter(ValueStream.id == "process-1").first()
    process.priority = "critical"
    process.bia_answers = {"mtd": "le_1h", "dataSensitivity": "high"}
    db.query(Organization).filter(Organization.id == 1).update({"required_frameworks": ["NIS2"]})
    db.commit()

    recommendation = appetite.get_process_appetite_recommendation("process-1", ctx=_context(1), db=db)

    assert recommendation.answers["downtime"] == 0
    assert recommendation.confidence == "high"
    assert not recommendation.missing_inputs


def test_process_appetite_recommendation_blends_in_the_peer_benchmark(db: Session):
    process = db.query(ValueStream).filter(ValueStream.id == "process-1").first()
    process.priority = "important"
    process.bia_answers = {"mtd": "le_4h"}
    process.library_item_id = "order_to_cash"
    db.commit()

    for i, level in enumerate([0, 0, 0], start=2):
        db.add(Organization(id=i, name=f"Peer {i}", slug=f"peer-{i}"))
        db.add(ValueStream(id=f"peer-process-{i}", organization_id=i, name="Order to cash", library_item_id="order_to_cash"))
        db.add(
            RiskAppetitePolicy(
                id=f"peer-policy-{i}",
                organization_id=i,
                scope="business_process",
                process_id=f"peer-process-{i}",
                answers={"downtime": level},
                status=APPETITE_POLICY_ACTIVE,
                version=1,
                approved_by=str(i),
            )
        )
    db.commit()

    recommendation = appetite.get_process_appetite_recommendation("process-1", ctx=_context(1), db=db)

    # BIA alone (le_4h) suggests level 2; 3 peers settled at level 0;
    # blended = round((2 + 0) / 2) = 1.
    assert recommendation.answers["downtime"] == 1
    assert "3 similar organisations" in recommendation.reasons["downtime"]


def test_process_appetite_recommendation_starts_from_the_cascaded_org_policy(db: Session):
    """Once an Organisation Risk Appetite is active, the process recommendation
    route's starting answers are what this process currently inherits from it
    — not an independent BIA-driven guess — with the BIA analysis surfaced
    only as a suggested deviation."""
    org_policy = RiskAppetitePolicy(
        id="org-policy-1",
        organization_id=1,
        scope="organisation",
        process_id=None,
        answers={"downtime": 3, "dataLoss": 3, "financial": 3, "reputational": 3, "regulatory": 3, "security": 3},
        status=APPETITE_POLICY_ACTIVE,
        version=1,
        approved_by="2",
    )
    db.add(org_policy)
    process = db.query(ValueStream).filter(ValueStream.id == "process-1").first()
    process.bia_answers = {"mtd": "le_1h", "dataSensitivity": "high"}  # would suggest level 1 alone
    db.commit()

    recommendation = appetite.get_process_appetite_recommendation("process-1", ctx=_context(1), db=db)

    assert recommendation.answers["downtime"] == 3  # the cascaded value, not the BIA-driven 1
    assert "currently inherited from the organisation policy at level 3" in recommendation.reasons["downtime"]
    assert "Risklence would suggest level" in recommendation.reasons["downtime"]


def test_accepting_the_organisation_appetite_inherits_without_leadership_review(db: Session):
    """The owner may accept the organisation-wide appetite for their process.

    Søren, 2026-08-30: accepting the org-wide BIA and Risk Appetite is fine.
    Leadership already approved that policy, so there is nothing new to
    approve — no process override is written and the process keeps inheriting.
    The decision to inherit is still recorded as a human decision.
    """
    _accept_process_ownership(db, owner_user_id=1)
    db.add(
        RiskAppetitePolicy(
            id="org-policy-1",
            organization_id=1,
            scope=APPETITE_SCOPE_ORGANISATION,
            process_id=None,
            answers={"downtime": 3, "dataLoss": 3, "financial": 3, "reputational": 3, "regulatory": 3, "security": 3},
            status=APPETITE_POLICY_ACTIVE,
            version=1,
            approved_by="2",
        )
    )
    db.commit()

    inherited = appetite.get_resolved_process_appetite("process-1", ctx=_context(1), db=db)
    assert inherited.source_scope == APPETITE_SCOPE_ORGANISATION

    accepted = appetite.accept_process_appetite_recommendation(
        "process-1",
        appetite.AppetiteRecommendationAcceptanceRequest(
            answers=inherited.answers,
            review_at=datetime.now(timezone.utc) + timedelta(days=7),
            note="Organisation appetite is right for this process.",
        ),
        ctx=_context(1),
        db=db,
    )

    # It answers with the organisation policy, not a new process-scoped one.
    assert accepted.scope == APPETITE_SCOPE_ORGANISATION
    assert accepted.policy_id == "org-policy-1"
    assert accepted.status == APPETITE_POLICY_ACTIVE
    assert (
        db.query(RiskAppetitePolicy)
        .filter(RiskAppetitePolicy.scope == APPETITE_SCOPE_BUSINESS_PROCESS)
        .count()
        == 0
    )
    assert [event.event_type for event in db.query(AuditEvent).all()] == [
        APPETITE_AUDIT_ORGANISATION_ACCEPTED
    ]
