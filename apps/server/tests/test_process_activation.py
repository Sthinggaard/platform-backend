"""Business Process activation gates and auditable human transitions."""

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
from src.api.routes import process_activation
from src.api.schemas.process_activation import ProcessNonConfirmationRequest
from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    MandateAssignmentSubjectType,
    MandateScopeType,
)
from src.core.constants.process_activation_enums import (
    ProcessActivationState,
    ProcessConfirmationOutcome,
    ProcessConfirmationReasonCode,
)
from src.core.constants.process_ownership_enums import ProcessOwnershipStatus
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ValidationError
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.model_defs.organization_bia_baseline import (
    ORGANIZATION_BIA_BASELINE_ACTIVE,
    OrganizationBiaBaseline,
)
from src.core.model_defs.process_activation import BusinessProcessActivation
from src.core.model_defs.process_bia_assessment import (
    BIA_ASSESSMENT_ATTESTED,
    BIA_ASSESSMENT_PREPARED,
    ProcessBiaAssessment,
)
from src.core.model_defs.process_ownership import ProcessOwnerAcceptance
from src.core.model_defs.risk_appetite_policy import (
    APPETITE_POLICY_ACTIVE,
    APPETITE_SCOPE_ORGANISATION,
    RiskAppetitePolicy,
)
from src.core.models import AuditEvent, Organization, User, ValueStream
from src.core.services.process_activation_service import resolve_process_activation_readiness


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
            ProcessBiaAssessment.__table__,
            OrganizationBiaBaseline.__table__,
            RiskAppetitePolicy.__table__,
            BusinessProcessActivation.__table__,
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
            ValueStream(id="process-2", organization_id=1, name="Billing operations"),
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


def _readiness(db: Session):
    process = db.get(ValueStream, "process-1")
    return resolve_process_activation_readiness(
        db,
        organization_id=1,
        processes=[process],
    )[process.id]


def _accepted_owner(db: Session) -> None:
    assignment = OrgMandateRoleAssignment(
        id="owner-assignment",
        organization_id=1,
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        subject_type=MandateAssignmentSubjectType.USER.value,
        user_id=2,
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
        owner_user_id=2,
        status=ProcessOwnershipStatus.ACCEPTED.value,
    )
    db.add_all([assignment, binding, acceptance])
    db.commit()


def _assessment(db: Session, status: str) -> None:
    db.add(
        ProcessBiaAssessment(
            id="bia-1",
            organization_id=1,
            process_id="process-1",
            status=status,
            answers={
                "impact1h": "high",
                "impact4h": "severe",
                "impact24h": "severe",
                "mtd": "le_4h",
                "workaround": "partial",
                "alternativeChannel": "partial",
                "dataSensitivity": "medium",
            },
            source="manual",
            confidence="high",
            assumption_state="human_entered",
        )
    )
    db.commit()


def _effective_appetite(db: Session) -> None:
    db.add(
        RiskAppetitePolicy(
            id="appetite-1",
            organization_id=1,
            scope=APPETITE_SCOPE_ORGANISATION,
            answers={"downtime": 2},
            status=APPETITE_POLICY_ACTIVE,
            version=1,
            approved_by="1",
        )
    )
    db.commit()


def _organization_baseline(db: Session, baseline_id: str = "organization-bia-1") -> None:
    db.add(
        OrganizationBiaBaseline(
            id=baseline_id,
            organization_id=1,
            status=ORGANIZATION_BIA_BASELINE_ACTIVE,
            answers={
                "impact1h": "high",
                "impact4h": "severe",
                "impact24h": "severe",
                "mtd": "le_4h",
                "workaround": "partial",
                "alternativeChannel": "partial",
                "dataSensitivity": "medium",
            },
        )
    )
    db.commit()


def test_readiness_progresses_through_governed_activation_gates(db: Session):
    # Ownership precedes approval: an unowned process needs an owner before
    # it can be confirmed at all.
    assert _readiness(db).state is ProcessActivationState.OWNERSHIP_REQUIRED

    _accepted_owner(db)
    assert _readiness(db).state is ProcessActivationState.CONFIRMATION_REQUIRED

    process_activation.confirm_process_for_activation(
        "process-1", ctx=_context(2), db=db
    )
    assert _readiness(db).state is ProcessActivationState.BIA_REQUIRED

    _assessment(db, BIA_ASSESSMENT_PREPARED)
    assert _readiness(db).state is ProcessActivationState.BIA_IN_PROGRESS

    db.get(ProcessBiaAssessment, "bia-1").status = BIA_ASSESSMENT_ATTESTED
    db.commit()
    assert _readiness(db).state is ProcessActivationState.LEADERSHIP_APPETITE_REQUIRED

    _effective_appetite(db)
    assert _readiness(db).state is ProcessActivationState.READY_FOR_ACTIVATION


def test_owner_activates_only_after_gates_and_writes_audit_evidence(db: Session):
    _accepted_owner(db)
    process_activation.confirm_process_for_activation(
        "process-1", ctx=_context(2), db=db
    )
    _organization_baseline(db)
    _effective_appetite(db)

    response = process_activation.activate_process_impact_model(
        "process-1", ctx=_context(2), db=db
    )

    assert response.state is ProcessActivationState.IMPACT_UNDERSTOOD
    assert response.impact_model_active is True
    assert [event.event_type for event in db.query(AuditEvent).all()] == [
        "business_process_confirmed",
        "business_process_impact_model_activated",
    ]


def test_active_organisation_baseline_satisfies_process_bia_gate_and_is_snapshotted(db: Session):
    _accepted_owner(db)
    process_activation.confirm_process_for_activation(
        "process-1", ctx=_context(2), db=db
    )
    _organization_baseline(db)

    readiness = _readiness(db)
    assert readiness.bia_attested is True
    assert readiness.state is ProcessActivationState.LEADERSHIP_APPETITE_REQUIRED

    _effective_appetite(db)
    response = process_activation.activate_process_impact_model(
        "process-1", ctx=_context(2), db=db
    )

    assert response.state is ProcessActivationState.IMPACT_UNDERSTOOD
    activation = db.query(BusinessProcessActivation).filter_by(process_id="process-1").one()
    assert activation.activated_bia_assessment_id is None
    assert activation.activated_organization_bia_baseline_id == "organization-bia-1"


def test_new_organisation_baseline_requires_human_reactivation(db: Session):
    _accepted_owner(db)
    process_activation.confirm_process_for_activation(
        "process-1", ctx=_context(2), db=db
    )
    _organization_baseline(db)
    _effective_appetite(db)
    process_activation.activate_process_impact_model(
        "process-1", ctx=_context(2), db=db
    )

    db.get(OrganizationBiaBaseline, "organization-bia-1").status = "superseded"
    _organization_baseline(db, baseline_id="organization-bia-2")

    assert _readiness(db).state is ProcessActivationState.READY_FOR_ACTIVATION


def test_an_activation_recording_no_bia_provenance_is_not_current(db: Session):
    """`None == None` used to pass, so staleness detection was silently dead.

    An activation whose snapshot names no governing BIA — neither a process
    assessment nor an organisation baseline — was compared against an effective
    BIA that also had neither, matched on two nulls, and counted as current
    forever. Later BIA changes could never invalidate it, which is the one thing
    the check exists to do.

    An activation that named no governing BIA cannot be shown to be current, so
    it is not: it reads READY_FOR_ACTIVATION and a human re-activates, which
    captures the provenance.
    """
    _accepted_owner(db)
    process_activation.confirm_process_for_activation("process-1", ctx=_context(2), db=db)
    _organization_baseline(db)
    _effective_appetite(db)
    process_activation.activate_process_impact_model("process-1", ctx=_context(2), db=db)

    assert _readiness(db).state is ProcessActivationState.IMPACT_UNDERSTOOD

    # Strip the provenance the activation recorded, leaving both snapshot
    # columns null — the shape a legacy activation has. The organisation
    # baseline stays active, so every earlier gate still passes and this test
    # is about staleness alone.
    activation = db.query(BusinessProcessActivation).filter_by(process_id="process-1").one()
    activation.activated_bia_assessment_id = None
    activation.activated_organization_bia_baseline_id = None
    db.commit()

    assert _readiness(db).state is ProcessActivationState.READY_FOR_ACTIVATION


def test_non_owner_cannot_activate_a_process(db: Session):
    with pytest.raises(AuthorizationError):
        process_activation.activate_process_impact_model(
            "process-1", ctx=_context(3), db=db
        )


def test_non_owner_cannot_confirm_a_process(db: Session):
    _accepted_owner(db)
    with pytest.raises(AuthorizationError):
        process_activation.confirm_process_for_activation(
            "process-1", ctx=_context(3), db=db
        )


def test_admin_cannot_confirm_a_process_ownership_is_not_curation(db: Session):
    _accepted_owner(db)
    with pytest.raises(AuthorizationError):
        process_activation.confirm_process_for_activation(
            "process-1", ctx=_context(1, "org_admin"), db=db
        )


def test_admin_records_duplicate_process_and_clears_prior_activation(db: Session):
    _accepted_owner(db)
    process_activation.confirm_process_for_activation(
        "process-1", ctx=_context(2), db=db
    )
    _organization_baseline(db)
    _effective_appetite(db)
    process_activation.activate_process_impact_model(
        "process-1", ctx=_context(2), db=db
    )

    response = process_activation.record_process_non_confirmation(
        "process-1",
        body=ProcessNonConfirmationRequest(
            outcome=ProcessConfirmationOutcome.DUPLICATE,
            reason_code=ProcessConfirmationReasonCode.DUPLICATE_PROCESS,
            successor_process_id="process-2",
        ),
        ctx=_context(1, "org_admin"),
        db=db,
    )

    assert response.state is ProcessActivationState.DUPLICATE
    assert response.confirmation_outcome is ProcessConfirmationOutcome.DUPLICATE
    activation = db.query(BusinessProcessActivation).filter_by(process_id="process-1").one()
    assert activation.activated_at is None
    assert activation.activated_organization_bia_baseline_id is None
    assert activation.successor_process_id == "process-2"
    audit = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    assert audit.event_type == "business_process_not_confirmed"
    assert audit.metadata_json["reason_code"] == ProcessConfirmationReasonCode.DUPLICATE_PROCESS.value


def test_duplicate_outcome_requires_a_successor_process(db: Session):
    with pytest.raises(ValidationError):
        process_activation.record_process_non_confirmation(
            "process-1",
            body=ProcessNonConfirmationRequest(
                outcome=ProcessConfirmationOutcome.DUPLICATE,
                reason_code=ProcessConfirmationReasonCode.DUPLICATE_PROCESS,
            ),
            ctx=_context(1, "org_admin"),
            db=db,
        )


def test_admin_can_retire_a_process_and_the_owner_can_reconfirm_it(db: Session):
    # Curation (retiring a bad suggestion) needs no owner and stays with the
    # administrator; only the positive re-confirmation needs the owner.
    process_activation.record_process_non_confirmation(
        "process-1",
        body=ProcessNonConfirmationRequest(
            outcome=ProcessConfirmationOutcome.REDESIGN_REQUIRED,
            reason_code=ProcessConfirmationReasonCode.PROCESS_BOUNDARY_INCORRECT,
        ),
        ctx=_context(1, "org_admin"),
        db=db,
    )
    _accepted_owner(db)

    response = process_activation.confirm_process_for_activation(
        "process-1", ctx=_context(2), db=db
    )

    assert response.state is ProcessActivationState.BIA_REQUIRED
    assert response.confirmation_outcome is ProcessConfirmationOutcome.CONFIRMED
    activation = db.query(BusinessProcessActivation).filter_by(process_id="process-1").one()
    assert activation.confirmation_reason_code is None


def test_first_confirmation_response_reports_the_confirmation_it_just_made(db: Session):
    """The response must describe the state the caller is about to get.

    The session is created with ``autoflush=False``. The very first confirmation
    of a process *creates* the BusinessProcessActivation row, so it was still
    pending when the readiness query ran and the query did not see it: the
    endpoint answered ``process_confirmed: False`` and ``activation_id: None``
    for a confirmation it had just recorded and was about to commit. The owner
    pressed Confirm, the server stored it, and the screen said nothing had
    happened until a manual reload.
    """
    _accepted_owner(db)
    assert db.query(BusinessProcessActivation).filter_by(process_id="process-1").count() == 0
    # The test fixture builds its session with SQLAlchemy's default
    # autoflush=True, while src/core/database.py sets autoflush=False. Without
    # mirroring production here the pending row is flushed for us and this test
    # passes whether or not the route flushes — it would assert the right
    # behaviour and never fail if the defect came back.
    db.autoflush = False

    response = process_activation.confirm_process_for_activation(
        "process-1", ctx=_context(2), db=db
    )

    assert response.process_confirmed is True
    assert response.activation_id is not None
    assert response.next_action is not ProcessActivationState.CONFIRMATION_REQUIRED
