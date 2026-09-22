"""Business Process Owner invitation and acceptance lifecycle tests."""

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
from src.api.routes import process_ownership
from src.api.schemas.process_ownership import (
    ProcessOwnerProposalResponse,
    ProcessOwnershipInvitationRequest,
    ProcessOwnershipRejectionRequest,
)
from src.core.constants.leadership_authorization_enums import LeadershipAuthorizationStatus
from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    MandateAssignmentSubjectType,
    MandateScopeType,
)
from src.core.constants.process_ownership_enums import (
    ProcessOwnershipAuditEvent,
    ProcessOwnershipRejectionReason,
    ProcessOwnershipStatus,
)
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.leadership_authorization import LeadershipAuthorization
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.models import (
    AuditEvent,
    BusinessService,
    Organization,
    ProcessOwnerAcceptance,
    User,
    ValueStream,
)
from src.core.services.process_ownership_service import (
    ProcessOwnershipValidationError,
    can_process_edit,
    require_accepted_process_owner,
    require_process_editor,
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
            User.__table__,
            ValueStream.__table__,
            BusinessService.__table__,
            OrgMandateRoleAssignment.__table__,
            OrgMandateScopeBinding.__table__,
            ProcessOwnerAcceptance.__table__,
            LeadershipAuthorization.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org"),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
            User(id=2, organization_id=1, email="owner@example.com", role="member"),
            User(id=3, organization_id=1, email="other@example.com", role="member"),
            ValueStream(id="process-1", organization_id=1, name="Order to cash"),
            # Leadership authorisation is a separate onboarding gate (see
            # test_leadership_authorization.py) — seeded active here so these
            # process-ownership tests exercise ownership, not the gate itself.
            LeadershipAuthorization(
                id="leadership-authorization-1",
                organization_id=1,
                status=LeadershipAuthorizationStatus.ACTIVE.value,
                version=1,
                sponsor_user_id=1,
                approving_body="senior_management",
                authorized_scope="Full onboarding programme.",
                approved_by="1",
            ),
        ]
    )
    session.commit()
    yield session
    session.close()


def _context(user_id: int, role: str = "member") -> TenantContext:
    return TenantContext(
        user_id=user_id,
        organization_id=1,
        email=f"user-{user_id}@example.com",
        roles=[role],
        permissions=[],
    )


def _binding(db: Session, *, assignment_id: str = "assignment-1", user_id: int = 2) -> OrgMandateScopeBinding:
    assignment = OrgMandateRoleAssignment(
        id=assignment_id,
        organization_id=1,
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        subject_type=MandateAssignmentSubjectType.USER.value,
        user_id=user_id,
    )
    binding = OrgMandateScopeBinding(
        id="binding-1",
        organization_id=1,
        scope_type=MandateScopeType.BUSINESS_PROCESS.value,
        value_stream_id="process-1",
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        role_assignment_id=assignment.id,
    )
    db.add_all([assignment, binding])
    db.commit()
    return binding


def test_invited_owner_can_accept_and_authorise_process_work(db: Session):
    binding = _binding(db)

    invited = process_ownership.create_process_ownership_invitation(
        ProcessOwnershipInvitationRequest(scope_binding_id=binding.id),
        ctx=_context(1, "org_admin"),
        db=db,
    )
    accepted = process_ownership.accept_process_owner_invitation(
        "process-1",
        ctx=_context(2),
        db=db,
    )

    assert invited.status is ProcessOwnershipStatus.INVITATION_SENT
    assert accepted.status is ProcessOwnershipStatus.ACCEPTED
    assert require_accepted_process_owner(
        db,
        organization_id=1,
        process_id="process-1",
        user_id=2,
    ).id == accepted.id
    assert [event.event_type for event in db.query(AuditEvent).all()] == [
        ProcessOwnershipAuditEvent.INVITATION_SENT.value,
        ProcessOwnershipAuditEvent.ACCEPTED.value,
    ]


def test_only_invited_owner_can_respond_and_rejection_is_structured(db: Session):
    binding = _binding(db)
    process_ownership.create_process_ownership_invitation(
        ProcessOwnershipInvitationRequest(scope_binding_id=binding.id),
        ctx=_context(1, "org_admin"),
        db=db,
    )

    with pytest.raises(ValidationError):
        process_ownership.accept_process_owner_invitation(
            "process-1",
            ctx=_context(3),
            db=db,
        )

    rejected = process_ownership.reject_process_owner_invitation(
        "process-1",
        ProcessOwnershipRejectionRequest(
            reason=ProcessOwnershipRejectionReason.EXECUTIVE_CLARIFICATION
        ),
        ctx=_context(2),
        db=db,
    )

    assert rejected.status is ProcessOwnershipStatus.REJECTED
    assert rejected.rejection_reason is ProcessOwnershipRejectionReason.EXECUTIVE_CLARIFICATION


def test_rebinding_requires_the_new_owner_to_accept_again(db: Session):
    binding = _binding(db)
    process_ownership.create_process_ownership_invitation(
        ProcessOwnershipInvitationRequest(scope_binding_id=binding.id),
        ctx=_context(1, "org_admin"),
        db=db,
    )
    process_ownership.accept_process_owner_invitation("process-1", ctx=_context(2), db=db)

    replacement = OrgMandateRoleAssignment(
        id="assignment-2",
        organization_id=1,
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        subject_type=MandateAssignmentSubjectType.USER.value,
        user_id=3,
    )
    db.add(replacement)
    binding.role_assignment_id = replacement.id
    db.commit()

    with pytest.raises(ProcessOwnershipValidationError, match="Accepted Business Process Owner ownership"):
        require_accepted_process_owner(
            db,
            organization_id=1,
            process_id="process-1",
            user_id=2,
        )


def _accepted_binding(db: Session, *, user_id: int = 2) -> OrgMandateScopeBinding:
    """A binding whose invitation was sent and accepted — the only editing authority."""
    binding = _binding(db, user_id=user_id)
    process_ownership.create_process_ownership_invitation(
        ProcessOwnershipInvitationRequest(scope_binding_id=binding.id),
        ctx=_context(1, "org_admin"),
        db=db,
    )
    process_ownership.accept_process_owner_invitation(
        "process-1",
        ctx=_context(user_id),
        db=db,
    )
    return binding


def test_accepted_process_owner_can_edit_the_process_without_org_admin_role(db: Session):
    _accepted_binding(db)

    require_process_editor(
        db,
        organization_id=1,
        process_id="process-1",
        actor_user_id=2,
    )


def test_binding_without_acceptance_confers_no_edit_rights(db: Session):
    """A scope binding is the offer of the mandate, never the mandate itself."""
    _binding(db)

    with pytest.raises(
        ProcessOwnershipValidationError, match="Accepted Business Process Owner ownership"
    ):
        require_process_editor(
            db,
            organization_id=1,
            process_id="process-1",
            actor_user_id=2,
        )


def test_rejected_owner_cannot_edit_the_process(db: Session):
    """Rejecting with a structured reason must leave ownership unaccepted."""
    binding = _binding(db)
    process_ownership.create_process_ownership_invitation(
        ProcessOwnershipInvitationRequest(scope_binding_id=binding.id),
        ctx=_context(1, "org_admin"),
        db=db,
    )
    process_ownership.reject_process_owner_invitation(
        "process-1",
        ProcessOwnershipRejectionRequest(
            reason=ProcessOwnershipRejectionReason.EXECUTIVE_CLARIFICATION
        ),
        ctx=_context(2),
        db=db,
    )

    assert can_process_edit(
        db,
        organization_id=1,
        process_id="process-1",
        actor_user_id=2,
    ) is False


def test_unassigned_user_cannot_edit_another_process(db: Session):
    _binding(db)

    with pytest.raises(ProcessOwnershipValidationError, match="assigned Business Process Owner"):
        require_process_editor(
            db,
            organization_id=1,
            process_id="process-1",
            actor_user_id=3,
        )


def test_process_edit_capability_is_false_for_unassigned_user(db: Session):
    _binding(db)

    assert can_process_edit(
        db,
        organization_id=1,
        process_id="process-1",
        actor_user_id=3,
    ) is False


def test_process_edit_capability_is_true_for_accepted_owner(db: Session):
    _accepted_binding(db)

    assert can_process_edit(
        db,
        organization_id=1,
        process_id="process-1",
        actor_user_id=2,
    ) is True


def test_owner_proposal_prefers_a_service_owner_with_a_bpo_mandate(db: Session):
    db.add(
        BusinessService(
            id="service-1",
            organization_id=1,
            name="Checkout",
            value_stream_ids=["process-1"],
            owner_user_id=2,
        )
    )
    db.add(
        OrgMandateRoleAssignment(
            id="assignment-service-owner",
            organization_id=1,
            canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
            subject_type=MandateAssignmentSubjectType.USER.value,
            user_id=2,
        )
    )
    db.commit()

    proposal = process_ownership.get_process_owner_proposal(
        "process-1", ctx=_context(1, "org_admin"), db=db
    )

    assert isinstance(proposal, ProcessOwnerProposalResponse)
    assert proposal.status.value == "candidates_available"
    assert proposal.recommended_user_id == 2
    assert proposal.candidates[0].source.value == "service_owner"
    assert db.query(OrgMandateScopeBinding).count() == 0


def test_owner_proposal_reports_admin_assignment_when_no_eligible_user_exists(db: Session):
    proposal = process_ownership.get_process_owner_proposal(
        "process-1", ctx=_context(1, "org_admin"), db=db
    )

    assert proposal.status.value == "needs_admin_assignment"
    assert proposal.recommended_user_id is None
    assert proposal.candidates == []


def test_owner_proposal_can_surface_service_owner_before_role_assignment(db: Session):
    db.add(
        BusinessService(
            id="service-2",
            organization_id=1,
            name="Customer support",
            value_stream_ids=["process-1"],
            owner_user_id=3,
        )
    )
    db.commit()

    proposal = process_ownership.get_process_owner_proposal(
        "process-1", ctx=_context(1, "org_admin"), db=db
    )

    assert proposal.recommended_user_id == 3
    assert proposal.candidates[0].source.value == "service_owner"


def test_owner_proposal_is_scoped_to_an_existing_process(db: Session):
    with pytest.raises(ResourceNotFoundError):
        process_ownership.get_process_owner_proposal(
            "missing-process", ctx=_context(1, "org_admin"), db=db
        )


def test_owner_proposal_is_refused_to_non_administrators(db: Session):
    """The proposal carries the name, email and title of every candidate."""
    db.add(
        BusinessService(
            id="service-1",
            organization_id=1,
            name="Checkout",
            value_stream_ids=["process-1"],
            owner_user_id=2,
        )
    )
    db.commit()

    with pytest.raises(AuthorizationError):
        process_ownership.get_process_owner_proposal(
            "process-1", ctx=_context(3), db=db
        )


def test_service_owner_with_org_wide_role_cannot_edit_without_a_scoped_binding(db: Session):
    """Ownership is granted per process and accepted, never inferred.

    An organisation-wide Business Process Owner role plus ownership of one
    linked service used to confer edit rights on every process that service
    touched. Søren, 2026-08-30: the user is granted ownership of the specific
    business process and accepts it — that is the only route.
    """
    db.add(
        BusinessService(
            id="service-1",
            organization_id=1,
            name="Checkout",
            value_stream_ids=["process-1"],
            owner_user_id=2,
        )
    )
    db.add(
        OrgMandateRoleAssignment(
            id="assignment-org-wide",
            organization_id=1,
            canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
            subject_type=MandateAssignmentSubjectType.USER.value,
            user_id=2,
        )
    )
    db.commit()

    assert can_process_edit(
        db,
        organization_id=1,
        process_id="process-1",
        actor_user_id=2,
    ) is False


def test_service_owner_without_any_mandate_remains_view_only(db: Session):
    db.add(
        BusinessService(
            id="service-1",
            organization_id=1,
            name="Checkout",
            value_stream_ids=["process-1"],
            owner_user_id=2,
        )
    )
    db.commit()

    assert can_process_edit(
        db,
        organization_id=1,
        process_id="process-1",
        actor_user_id=2,
    ) is False


def test_accepted_binding_governs_regardless_of_service_ownership(db: Session):
    binding = _accepted_binding(db, user_id=3)
    db.add(
        BusinessService(
            id="service-1",
            organization_id=1,
            name="Checkout",
            value_stream_ids=["process-1"],
            owner_user_id=2,
        )
    )
    db.commit()

    assert binding.value_stream_id == "process-1"
    assert can_process_edit(
        db,
        organization_id=1,
        process_id="process-1",
        actor_user_id=2,
    ) is False
    assert can_process_edit(
        db,
        organization_id=1,
        process_id="process-1",
        actor_user_id=3,
    ) is True


def test_org_admin_can_edit_a_process_without_process_owner_assignment(db: Session):
    require_process_editor(
        db,
        organization_id=1,
        process_id="process-1",
        actor_user_id=1,
    )


def test_a_candidate_can_find_the_invitation_they_were_sent(db: Session):
    """Without this an invitation cannot be found at all.

    Accept and reject are addressed by process id, so answering one meant
    already knowing the id of a process nobody had told you about — which is
    why every acceptance in the dev organisation was made by calling the API.
    """
    binding = _binding(db)
    db.add(
        BusinessService(
            id="service-1",
            organization_id=1,
            name="Checkout",
            value_stream_ids=["process-1"],
        )
    )
    db.commit()
    process_ownership.create_process_ownership_invitation(
        ProcessOwnershipInvitationRequest(scope_binding_id=binding.id),
        ctx=_context(1, "org_admin"),
        db=db,
    )

    result = process_ownership.list_my_owner_invitations(ctx=_context(2), db=db)

    assert len(result.invitations) == 1
    invitation = result.invitations[0]
    assert invitation.process_id == "process-1"
    assert invitation.process_name == "Order to cash"
    assert invitation.service_count == 1
    assert invitation.invited_by_user_id == 1


def test_an_invitation_belongs_to_the_person_named_on_it(db: Session):
    """Nobody sees another person's invitation — administrator included."""
    binding = _binding(db)
    process_ownership.create_process_ownership_invitation(
        ProcessOwnershipInvitationRequest(scope_binding_id=binding.id),
        ctx=_context(1, "org_admin"),
        db=db,
    )

    # user 2 was invited; the admin who sent it and an unrelated member see nothing
    assert len(process_ownership.list_my_owner_invitations(ctx=_context(2), db=db).invitations) == 1
    assert process_ownership.list_my_owner_invitations(ctx=_context(1, "org_admin"), db=db).invitations == []
    assert process_ownership.list_my_owner_invitations(ctx=_context(3), db=db).invitations == []


def test_an_answered_invitation_stops_being_pending(db: Session):
    binding = _binding(db)
    process_ownership.create_process_ownership_invitation(
        ProcessOwnershipInvitationRequest(scope_binding_id=binding.id),
        ctx=_context(1, "org_admin"),
        db=db,
    )
    assert len(process_ownership.list_my_owner_invitations(ctx=_context(2), db=db).invitations) == 1

    process_ownership.accept_process_owner_invitation("process-1", ctx=_context(2), db=db)

    assert process_ownership.list_my_owner_invitations(ctx=_context(2), db=db).invitations == []


def test_a_rejected_invitation_stops_being_pending(db: Session):
    """A rejection is an answer. It must not linger as something still to do."""
    binding = _binding(db)
    process_ownership.create_process_ownership_invitation(
        ProcessOwnershipInvitationRequest(scope_binding_id=binding.id),
        ctx=_context(1, "org_admin"),
        db=db,
    )
    process_ownership.reject_process_owner_invitation(
        "process-1",
        ProcessOwnershipRejectionRequest(
            reason=ProcessOwnershipRejectionReason.TEMPORARY_VACANCY
        ),
        ctx=_context(2),
        db=db,
    )

    assert process_ownership.list_my_owner_invitations(ctx=_context(2), db=db).invitations == []


def test_nothing_pending_is_an_empty_list_not_an_error(db: Session):
    assert process_ownership.list_my_owner_invitations(ctx=_context(2), db=db).invitations == []
