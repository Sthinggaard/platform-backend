"""Coverage for governed in-place Business Process template rebasing."""

import pytest
from sqlalchemy import JSON, create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes.process_template_variants import (
    apply_process_template_variant as apply_process_template_variant_route,
)
from src.api.routes.process_template_variants import get_process_template_variants
from src.api.schemas.process_template_variants import ApplyProcessTemplateVariantRequest
from src.core.constants import SERVICE_TIER_BUSINESS_CRITICAL
from src.core.database import Base
from src.core.exceptions import ResourceNotFoundError, ValidationError
from src.core.model_defs.process_activation import BusinessProcessActivation
from src.core.models import (
    AuditEvent,
    BusinessService,
    Organization,
    ServiceTemplate,
    SlotTemplate,
    User,
    ValueStream,
    ValueStreamSignal,
)
from src.core.services.process_template_variant_service import (
    ProcessTemplateVariantValidationError,
    apply_template_variant,
    list_comparable_template_variants,
)
from src.core.template_models import ProcessTemplate


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = JSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            User.__table__,
            ValueStream.__table__,
            BusinessService.__table__,
            ProcessTemplate.__table__,
            ServiceTemplate.__table__,
            SlotTemplate.__table__,
            BusinessProcessActivation.__table__,
            ValueStreamSignal.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Match Org", slug="match", nace_code="62.01"),
            Organization(id=2, name="Other Org", slug="other", nace_code="10.10"),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
            ValueStream(
                id="process-1",
                organization_id=1,
                library_item_id="order_to_cash",
                name="Commercial revenue",
                description="Tenant-owned process description",
                priority="critical",
                bia_answers={"mtd": "le_4h"},
                bpmn_definition={"lanes": [], "nodes": [], "flows": []},
            ),
            BusinessService(
                id="order-service",
                organization_id=1,
                name="Order Management",
                library_item_id="order_management",
                value_stream_ids=["process-1"],
                tier=SERVICE_TIER_BUSINESS_CRITICAL,
                trading_impact="",
            ),
            BusinessService(
                id="billing-service",
                organization_id=1,
                name="Billing",
                library_item_id="billing_service",
                value_stream_ids=["process-1"],
                tier=SERVICE_TIER_BUSINESS_CRITICAL,
                trading_impact="",
            ),
            BusinessService(
                id="payment-service",
                organization_id=1,
                name="Payments",
                library_item_id="payment_processing",
                value_stream_ids=["process-1"],
                tier=SERVICE_TIER_BUSINESS_CRITICAL,
                trading_impact="",
            ),
        ]
    )
    session.commit()
    yield session
    session.close()


def _context(organization_id: int) -> TenantContext:
    return TenantContext(
        user_id=1,
        organization_id=organization_id,
        email="admin@example.com",
        roles=["org_admin"],
        permissions=[],
    )


def test_lists_same_outcome_variants_in_industry_fit_order(db: Session):
    process = db.get(ValueStream, "process-1")

    variants = list_comparable_template_variants(process=process, nace_code="62.01")

    assert [variant.template.key for variant in variants] == ["quote_to_cash"]
    assert variants[0].industry_fit == "direct"


def test_rebase_updates_the_existing_process_and_retains_business_context(db: Session):
    process = db.get(ValueStream, "process-1")

    updated = apply_template_variant(
        db,
        organization_id=1,
        process=process,
        target_template_key="quote_to_cash",
    )
    db.commit()

    assert updated.id == "process-1"
    assert updated.library_item_id == "quote_to_cash"
    assert updated.name == "Commercial revenue"
    assert updated.description == "Tenant-owned process description"
    assert updated.priority == "critical"
    assert updated.bia_answers == {"mtd": "le_4h"}
    assert updated.bpmn_definition is None

    services = {service.library_item_id: service for service in db.query(BusinessService).all()}
    assert "process-1" not in services["order_management"].value_stream_ids
    assert "process-1" not in services["payment_processing"].value_stream_ids
    assert "process-1" in services["billing_service"].value_stream_ids
    assert "process-1" in services["crm_service"].value_stream_ids
    assert "process-1" in services["quoting_service"].value_stream_ids
    assert "process-1" in services["contract_management"].value_stream_ids


def test_rebase_rejects_a_template_for_a_different_business_outcome(db: Session):
    process = db.get(ValueStream, "process-1")

    with pytest.raises(ProcessTemplateVariantValidationError):
        apply_template_variant(
            db,
            organization_id=1,
            process=process,
            target_template_key="software_delivery",
        )


def test_variant_read_does_not_expose_a_process_from_another_tenant(db: Session):
    with pytest.raises(ResourceNotFoundError):
        get_process_template_variants("process-1", ctx=_context(2), db=db)


def test_admin_applies_a_variant_with_append_only_provenance(db: Session):
    response = apply_process_template_variant_route(
        "process-1",
        "quote_to_cash",
        body=ApplyProcessTemplateVariantRequest(acknowledgeRebase=True),
        ctx=_context(1),
        db=db,
    )

    assert response.current_template_key == "quote_to_cash"
    assert db.get(ValueStream, "process-1").library_item_id == "quote_to_cash"
    signal = db.query(ValueStreamSignal).one()
    assert signal.payload["previous_template_key"] == "order_to_cash"
    assert signal.payload["applied_template_key"] == "quote_to_cash"
    audit = db.query(AuditEvent).one()
    assert audit.metadata_json["process_id"] == "process-1"


def test_admin_must_acknowledge_a_rebase(db: Session):
    with pytest.raises(ValidationError):
        apply_process_template_variant_route(
            "process-1",
            "quote_to_cash",
            body=ApplyProcessTemplateVariantRequest(acknowledgeRebase=False),
            ctx=_context(1),
            db=db,
        )
