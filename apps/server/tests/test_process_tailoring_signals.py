"""ONB-08B (#17) — structured, append-only process-tailoring signals."""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import org_template_config, processes
from src.api.schemas.process_graph import CreateProcessCustomServiceRequest
from src.core.constants.process_tailoring_enums import (
    ProcessTailoringChangeType,
    ProcessTailoringRationaleCode,
    TailoringEvidenceState,
)
from src.core.constants.service_model import (
    SERVICE_TIER_MISSION_CRITICAL,
    SERVICE_TIER_STANDARD_CRITICAL,
)
from src.core.database import Base
from src.core.exceptions import AuthorizationError
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.model_defs.process_activation import BusinessProcessActivation
from src.core.model_defs.process_bia_assessment import ProcessBiaAssessment
from src.core.model_defs.risk_appetite_policy import RiskAppetitePolicy
from src.core.model_defs.service_appetite_reassessment import ServiceAppetiteReassessment
from src.core.model_defs.service_bia_exception import ServiceBiaException
from src.core.models import (
    AuditEvent,
    BusinessService,
    DependencyBundle,
    Organization,
    OrgProcessConfig,
    ProcessTailoringSignal,
    SlotInstance,
    User,
    ValueStream,
)
from src.core.template_models import ProcessTemplate, ServiceTemplate, SlotTemplate

TEMPLATE_KEY = "order_to_cash"
SERVICE_KEYS = ("order_management", "billing_service", "payment_processing")


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
            OrgProcessConfig.__table__,
            BusinessProcessActivation.__table__,
            AuditEvent.__table__,
            ProcessTailoringSignal.__table__,
            RiskAppetitePolicy.__table__,
            ServiceBiaException.__table__,
            ServiceTemplate.__table__,
            SlotTemplate.__table__,
            ProcessTemplate.__table__,
            DependencyBundle.__table__,
            ServiceAppetiteReassessment.__table__,
            SlotInstance.__table__,
            ProcessBiaAssessment.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org"),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
            User(id=2, organization_id=1, email="member@example.com", role="member"),
            # Every test service also belongs here, so excluding it from process-1
            # never trips the #378 orphan-protection guard in update_process_services.
            ValueStream(id="process-2", organization_id=1, name="Elsewhere"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _admin_context() -> TenantContext:
    return TenantContext(
        user_id=1, organization_id=1, email="admin@example.com", roles=["org_admin"], permissions=[]
    )


def _member_context() -> TenantContext:
    return TenantContext(
        user_id=2, organization_id=1, email="member@example.com", roles=["member"], permissions=[]
    )


def _process(db: Session, *, library_item_id: str | None = TEMPLATE_KEY) -> ValueStream:
    process = ValueStream(
        id="process-1", organization_id=1, name="Order to cash", library_item_id=library_item_id
    )
    db.add(process)
    db.commit()
    return process


def _service(db: Session, *, key: str, process_id: str, tier: str) -> BusinessService:
    service = BusinessService(
        id=f"service-{key}",
        organization_id=1,
        name=key,
        library_item_id=key,
        template_key=key,
        # Also a member of process-2, so excluding it from process-1 never
        # orphans it (the #378 guard in update_process_services).
        value_stream_ids=[process_id, "process-2"],
        tier=tier,
        trading_impact="",
    )
    db.add(service)
    db.commit()
    return service


def _confirmed_activation(db: Session, *, process_id: str) -> BusinessProcessActivation:
    activation = BusinessProcessActivation(
        id="activation-1",
        organization_id=1,
        process_id=process_id,
        confirmed_by_user_id=1,
        confirmation_outcome="confirmed",
        activated_by_user_id=1,
    )
    db.add(activation)
    db.commit()
    return activation


def test_excluding_a_service_writes_a_signal_and_audit_event_and_invalidates_activation(
    db: Session,
):
    process = _process(db)
    for key in SERVICE_KEYS:
        _service(db, key=key, process_id=process.id, tier=SERVICE_TIER_STANDARD_CRITICAL)
    _confirmed_activation(db, process_id=process.id)

    body = processes.UpdateProcessServicesRequest(
        included_service_keys=["order_management", "billing_service"]
    )
    processes.update_process_services(process.id, body, _admin_context(), db)

    signals = db.query(ProcessTailoringSignal).all()
    assert len(signals) == 1
    signal = signals[0]
    assert signal.change_type == ProcessTailoringChangeType.SERVICE_EXCLUDED.value
    assert signal.affected_service_keys == ["payment_processing"]
    assert signal.is_process_boundary_change is True
    assert signal.invalidated_activation is True
    assert signal.rationale_code == ProcessTailoringRationaleCode.UNSPECIFIED.value
    assert signal.evidence_state == TailoringEvidenceState.OWNER_APPROVED.value

    audit_events = db.query(AuditEvent).all()
    assert len(audit_events) == 1
    assert audit_events[0].event_type == "business_process_service_excluded"
    assert signal.audit_event_id == audit_events[0].id

    activation = db.get(BusinessProcessActivation, "activation-1")
    assert activation.confirmation_outcome == "pending"
    assert activation.activated_by_user_id is None


def test_excluding_a_mission_critical_service_marks_critical_service_change(db: Session):
    process = _process(db)
    for key in SERVICE_KEYS:
        tier = (
            SERVICE_TIER_MISSION_CRITICAL
            if key == "payment_processing"
            else SERVICE_TIER_STANDARD_CRITICAL
        )
        _service(db, key=key, process_id=process.id, tier=tier)

    body = processes.UpdateProcessServicesRequest(
        included_service_keys=["order_management", "billing_service"]
    )
    processes.update_process_services(process.id, body, _admin_context(), db)

    signal = db.query(ProcessTailoringSignal).one()
    assert signal.is_critical_service_change is True


def test_one_call_can_exclude_and_reinclude_disjoint_keys(db: Session):
    process = _process(db)
    for key in SERVICE_KEYS:
        _service(db, key=key, process_id=process.id, tier=SERVICE_TIER_STANDARD_CRITICAL)

    # First exclude payment_processing.
    processes.update_process_services(
        process.id,
        processes.UpdateProcessServicesRequest(
            included_service_keys=["order_management", "billing_service"]
        ),
        _admin_context(),
        db,
    )
    # Now exclude billing_service and re-include payment_processing in one call.
    processes.update_process_services(
        process.id,
        processes.UpdateProcessServicesRequest(
            included_service_keys=["order_management", "payment_processing"]
        ),
        _admin_context(),
        db,
    )

    signals = db.query(ProcessTailoringSignal).order_by(ProcessTailoringSignal.created_at).all()
    assert len(signals) == 3  # first exclude, then one exclude + one reinclude
    second_batch = signals[1:]
    change_types = {s.change_type for s in second_batch}
    assert change_types == {
        ProcessTailoringChangeType.SERVICE_EXCLUDED.value,
        ProcessTailoringChangeType.SERVICE_REINCLUDED.value,
    }
    for s in second_batch:
        if s.change_type == ProcessTailoringChangeType.SERVICE_EXCLUDED.value:
            assert s.affected_service_keys == ["billing_service"]
        else:
            assert s.affected_service_keys == ["payment_processing"]


def test_resubmitting_the_same_membership_writes_no_new_signal(db: Session):
    process = _process(db)
    for key in SERVICE_KEYS:
        _service(db, key=key, process_id=process.id, tier=SERVICE_TIER_STANDARD_CRITICAL)

    body = processes.UpdateProcessServicesRequest(
        included_service_keys=["order_management", "billing_service", "payment_processing"]
    )
    processes.update_process_services(process.id, body, _admin_context(), db)
    assert db.query(ProcessTailoringSignal).count() == 0

    # Re-submit the exact same membership.
    processes.update_process_services(process.id, body, _admin_context(), db)
    assert db.query(ProcessTailoringSignal).count() == 0


def test_creating_a_custom_service_writes_one_signal_paired_with_the_existing_audit_event(
    db: Session,
):
    process = _process(db)

    body = CreateProcessCustomServiceRequest(
        name="Bespoke Fulfilment",
        tier=SERVICE_TIER_MISSION_CRITICAL,
        archetype="transactional_system",
    )
    processes.create_process_custom_service(process.id, body, _admin_context(), db)

    signal = db.query(ProcessTailoringSignal).one()
    assert signal.change_type == ProcessTailoringChangeType.CUSTOM_SERVICE_ADDED.value
    assert signal.detail == {"archetype": "transactional_system"}
    assert signal.is_critical_service_change is True

    audit_events = db.query(AuditEvent).all()
    assert len(audit_events) == 1
    assert audit_events[0].event_type == "business_process_custom_service_created"
    assert signal.audit_event_id == audit_events[0].id


def test_creating_a_custom_service_with_an_invalid_archetype_is_rejected(db: Session):
    process = _process(db)
    body = CreateProcessCustomServiceRequest(name="Bespoke", archetype="not_a_real_archetype")

    with pytest.raises(HTTPException) as exc_info:
        processes.create_process_custom_service(process.id, body, _admin_context(), db)
    assert exc_info.value.status_code == 422
    assert db.query(ProcessTailoringSignal).count() == 0
    assert db.query(AuditEvent).count() == 0


def test_org_template_config_dismiss_suggestion_path_writes_a_signal_too(db: Session):
    process = _process(db)
    for key in SERVICE_KEYS:
        _service(db, key=key, process_id=process.id, tier=SERVICE_TIER_STANDARD_CRITICAL)

    body = org_template_config.OrgProcessConfigRequest(excluded_service_keys=["billing_service"])
    org_template_config.save_process_config(TEMPLATE_KEY, body, _admin_context(), db)

    signal = db.query(ProcessTailoringSignal).one()
    assert signal.change_type == ProcessTailoringChangeType.SERVICE_EXCLUDED.value
    assert signal.affected_service_keys == ["billing_service"]


def test_org_template_config_save_rejects_a_non_owner_non_admin_actor(db: Session):
    _process(db)
    body = org_template_config.OrgProcessConfigRequest(excluded_service_keys=[])

    with pytest.raises(AuthorizationError):
        org_template_config.save_process_config(TEMPLATE_KEY, body, _member_context(), db)
    assert db.query(ProcessTailoringSignal).count() == 0


def test_every_written_signal_uses_only_controlled_vocabulary_values(db: Session):
    process = _process(db)
    for key in SERVICE_KEYS:
        _service(db, key=key, process_id=process.id, tier=SERVICE_TIER_STANDARD_CRITICAL)

    processes.update_process_services(
        process.id,
        processes.UpdateProcessServicesRequest(
            included_service_keys=["order_management", "billing_service"]
        ),
        _admin_context(),
        db,
    )

    signal = db.query(ProcessTailoringSignal).one()
    assert signal.change_type in {member.value for member in ProcessTailoringChangeType}
    assert signal.rationale_code in {member.value for member in ProcessTailoringRationaleCode}
    assert signal.evidence_state in {member.value for member in TailoringEvidenceState}


def test_multi_step_scenario_writes_the_expected_ordered_audit_events(db: Session):
    process = _process(db)
    for key in SERVICE_KEYS:
        _service(db, key=key, process_id=process.id, tier=SERVICE_TIER_STANDARD_CRITICAL)

    # Exclude payment_processing.
    processes.update_process_services(
        process.id,
        processes.UpdateProcessServicesRequest(
            included_service_keys=["order_management", "billing_service"]
        ),
        _admin_context(),
        db,
    )
    # Re-include it.
    processes.update_process_services(
        process.id,
        processes.UpdateProcessServicesRequest(
            included_service_keys=["order_management", "billing_service", "payment_processing"]
        ),
        _admin_context(),
        db,
    )
    # Add a custom service.
    processes.create_process_custom_service(
        process.id,
        CreateProcessCustomServiceRequest(name="Bespoke"),
        _admin_context(),
        db,
    )

    event_types = [e.event_type for e in db.query(AuditEvent).order_by(AuditEvent.id).all()]
    assert event_types == [
        "business_process_service_excluded",
        "business_process_service_reincluded",
        "business_process_custom_service_created",
    ]
