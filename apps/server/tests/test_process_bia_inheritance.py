"""BSP-04: process-level BIA inheritance — route + row-builder wiring."""

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
from src.api.routes import processes
from src.api.routes.services import BiaAnswers
from src.core.constants import SERVICE_TIER_MISSION_CRITICAL
from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    MandateAssignmentSubjectType,
    MandateScopeType,
)
from src.core.constants.process_ownership_enums import (
    ProcessOwnershipErrorMessage,
    ProcessOwnershipStatus,
)
from src.core.database import Base
from src.core.exceptions import AuthorizationError
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.model_defs.risk_appetite_policy import RiskAppetitePolicy
from src.core.model_defs.service_appetite_reassessment import ServiceAppetiteReassessment
from src.core.model_defs.service_bia_exception import ServiceBiaException
from src.core.models import (
    AuditEvent,
    BusinessService,
    Organization,
    ProcessBiaAssessment,
    ProcessOwnerAcceptance,
    User,
    ValueStream,
)
from src.core.services.effective_process_bia_service import EffectiveProcessBia
from src.core.services.service_appetite_reassessment_service import (
    EffectiveServiceAppetiteResolution,
)

_PROCESS_ANSWERS = {
    "impact1h": "severe",
    "impact4h": "high",
    "impact24h": "medium",
    "mtd": "le_4h",
    "dataSensitivity": "high",
    "workaround": "partial",
    "alternativeChannel": "none",
}


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
            ProcessBiaAssessment.__table__,
            OrgMandateRoleAssignment.__table__,
            OrgMandateScopeBinding.__table__,
            ProcessOwnerAcceptance.__table__,
            RiskAppetitePolicy.__table__,
            ServiceAppetiteReassessment.__table__,
            ServiceBiaException.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Org", slug="org"))
    session.add_all(
        [
            User(id=7, organization_id=1, email="sarah.chen@org.com", role="org_admin"),
            User(id=8, organization_id=1, email="other@org.com", role="member"),
        ]
    )
    session.add(ValueStream(id="p-1", organization_id=1, name="Order to Cash"))
    session.add(
        BusinessService(
            id="svc-1",
            organization_id=1,
            name="Payment Processing",
            tier=SERVICE_TIER_MISSION_CRITICAL,
        )
    )
    session.commit()
    yield session
    session.close()


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=7, organization_id=1, email="sarah.chen@org.com", roles=["admin"], permissions=[]
    )


def _other_ctx() -> TenantContext:
    return TenantContext(
        user_id=8, organization_id=1, email="other@org.com", roles=["member"], permissions=[]
    )


def _accept_process_owner(db: Session, *, accepted: bool = True) -> ProcessOwnerAcceptance:
    assignment = OrgMandateRoleAssignment(
        id="owner-assignment",
        organization_id=1,
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        subject_type=MandateAssignmentSubjectType.USER.value,
        user_id=7,
    )
    binding = OrgMandateScopeBinding(
        id="owner-binding",
        organization_id=1,
        scope_type=MandateScopeType.BUSINESS_PROCESS.value,
        value_stream_id="p-1",
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        role_assignment_id=assignment.id,
    )
    acceptance = ProcessOwnerAcceptance(
        id="owner-acceptance",
        organization_id=1,
        process_id="p-1",
        scope_binding_id=binding.id,
        role_assignment_id=assignment.id,
        owner_user_id=7,
        status=(
            ProcessOwnershipStatus.ACCEPTED.value
            if accepted
            else ProcessOwnershipStatus.INVITATION_SENT.value
        ),
    )
    db.add_all([assignment, binding, acceptance])
    db.commit()
    return acceptance


@pytest.fixture(autouse=True)
def _no_bundle_no_appetite(monkeypatch):
    monkeypatch.setattr(processes, "_has_published_bundle", lambda service, db: False)
    monkeypatch.setattr(
        processes,
        "_resolve_service_appetite",
        lambda service, db, process_appetite: EffectiveServiceAppetiteResolution(
            status="not_set", answers=None, provenance={}, pending=[]
        ),
    )


def test_assess_process_bia_stays_non_authoritative_until_attested(db: Session):
    response = processes.assess_process_bia(
        "p-1",
        processes.AssessProcessBiaRequest(biaAnswers=BiaAnswers(**_PROCESS_ANSWERS)),
        ctx=_ctx(),
        db=db,
    )
    assert response.bia_assessment is not None
    assert response.bia_assessment.status == "prepared"
    assert response.bia_assessment.source == "manual"
    assert response.bia_effective_answers is None
    process = db.get(ValueStream, "p-1")
    assessment = db.query(ProcessBiaAssessment).one()
    assert process.bia_answers is None
    assert assessment.answers["mtd"] == "le_4h"
    audit = db.query(AuditEvent).one()
    assert audit.event_type == "PROCESS_BIA_PREPARED"
    assert audit.metadata_json["process_id"] == "p-1"

    with pytest.raises(
        AuthorizationError,
        match=ProcessOwnershipErrorMessage.PROCESS_OWNER_BINDING_NOT_FOUND.value,
    ):
        processes.attest_process_bia("p-1", ctx=_ctx(), db=db)

    acceptance = _accept_process_owner(db, accepted=False)
    with pytest.raises(
        AuthorizationError,
        match=ProcessOwnershipErrorMessage.OWNER_ACCEPTANCE_REQUIRED.value,
    ):
        processes.attest_process_bia("p-1", ctx=_ctx(), db=db)

    acceptance.status = ProcessOwnershipStatus.ACCEPTED.value
    db.commit()
    processes.attest_process_bia("p-1", ctx=_ctx(), db=db)

    process = db.get(ValueStream, "p-1")
    assert process.bia_answers["mtd"] == "le_4h"
    assert db.query(ProcessBiaAssessment).one().status == "attested"


def test_unrelated_member_cannot_update_process_bia(db: Session):
    _accept_process_owner(db)

    with pytest.raises(
        AuthorizationError,
        match="Organisation administrator or assigned Business Process Owner access is required",
    ):
        processes.assess_process_bia(
            "p-1",
            processes.AssessProcessBiaRequest(biaAnswers=BiaAnswers(**_PROCESS_ANSWERS)),
            ctx=_other_ctx(),
            db=db,
        )


def test_unrelated_member_cannot_prepare_process_bia(db: Session):
    _accept_process_owner(db)

    with pytest.raises(
        AuthorizationError,
        match="Organisation administrator or assigned Business Process Owner access is required",
    ):
        processes.prepare_process_bia(
            "p-1",
            processes.PrepareProcessBiaRequest(
                biaAnswers=BiaAnswers(**_PROCESS_ANSWERS),
                source="manual",
                confidence="high",
                assumptionState="human_entered",
            ),
            ctx=_other_ctx(),
            db=db,
        )


def test_prepare_process_bia_preserves_assumption_provenance(db: Session):
    response = processes.prepare_process_bia(
        "p-1",
        processes.PrepareProcessBiaRequest(
            biaAnswers=BiaAnswers(**_PROCESS_ANSWERS),
            source="public_onboarding",
            confidence="medium",
            assumptionState="proposed",
        ),
        ctx=_ctx(),
        db=db,
    )

    assert response.bia_assessment is not None
    assert response.bia_assessment.source == "public_onboarding"
    assert response.bia_assessment.confidence == "medium"
    assert response.bia_assessment.assumption_state == "proposed"
    assessment = db.query(ProcessBiaAssessment).one()
    assert assessment.source == "public_onboarding"
    assert assessment.confidence == "medium"
    assert assessment.assumption_state == "proposed"
    assert db.get(ValueStream, "p-1").bia_answers is None


def test_service_without_own_answers_inherits_process_bia_and_is_complete(db: Session):
    process = db.get(ValueStream, "p-1")
    process.bia_answers = dict(_PROCESS_ANSWERS)
    service = db.get(BusinessService, "svc-1")
    db.commit()

    row = processes._build_service_row(service, db, process)

    assert row.bia_complete is True
    assert row.resilience_score is not None
    assert set(row.bia_provenance.values()) == {"inherited"}


def test_service_inherits_organisation_baseline_when_process_projection_is_empty(db: Session):
    process = db.get(ValueStream, "p-1")
    service = db.get(BusinessService, "svc-1")

    row = processes._build_service_row(
        service,
        db,
        process,
        effective_process_bia=EffectiveProcessBia(
            answers=dict(_PROCESS_ANSWERS),
            process_assessment_id=None,
            organization_baseline_id="org-bia-1",
            process_assessment_started=False,
        ),
    )

    assert row.bia_complete is True
    assert row.resilience_score is not None
    assert set(row.bia_provenance.values()) == {"inherited"}


def test_an_exception_in_this_process_wins_and_is_tagged_as_one(db: Session):
    """#463 — the service's exception in this process replaces that field, and says so."""
    process = db.get(ValueStream, "p-1")
    process.bia_answers = dict(_PROCESS_ANSWERS)
    service = db.get(BusinessService, "svc-1")
    exception = ServiceBiaException(
        organization_id=1,
        service_id="svc-1",
        process_id="p-1",
        field="impact1h",
        value="low",
        previous_value=_PROCESS_ANSWERS["impact1h"],
        reason_code="part_of_process",
        recorded_by_user_id=7,
    )
    db.add(exception)
    db.commit()

    row = processes._build_service_row(service, db, process, bia_exceptions=[exception])

    assert row.bia_complete is True
    assert row.bia_provenance["impact1h"] == "exception"
    assert row.bia_provenance["mtd"] == "inherited"


def test_a_services_copied_answers_are_not_read_as_its_own(db: Session):
    """#463 — `bia_answers` still holds copies of process answers until the write path moves; a
    copy must not count, so without an exception the field is inherited."""
    process = db.get(ValueStream, "p-1")
    process.bia_answers = dict(_PROCESS_ANSWERS)
    service = db.get(BusinessService, "svc-1")
    service.bia_answers = {"impact1h": "low"}
    db.commit()

    row = processes._build_service_row(service, db, process)

    assert row.bia_complete is True
    assert set(row.bia_provenance.values()) == {"inherited"}


def test_service_incomplete_when_neither_process_nor_service_has_full_answers(db: Session):
    service = db.get(BusinessService, "svc-1")
    row = processes._build_service_row(service, db, process=None)

    assert row.bia_complete is False
    assert row.resilience_score is None
    assert set(row.bia_provenance.values()) == {"inherited"}
