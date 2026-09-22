from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import services
from src.core.constants import (
    SERVICE_TIER_BUSINESS_CRITICAL,
    SERVICE_TIER_MISSION_CRITICAL,
    SERVICE_TIER_STANDARD_CRITICAL,
    normalize_service_tier,
)
from src.core.models import (
    Asset,
    AssetEvidenceSignal,
    BusinessService,
    ServiceBiaException,
    ServiceJourneySignal,
    Threat,
    ValueStream,
)
from src.core.services.bia_inheritance_service import BIA_FIELD_KEYS
from src.core.services.effective_process_bia_service import EffectiveProcessBia


class DummyQuery:
    def __init__(self, rows):
        self._rows = rows
        self._with_entities = False

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def options(self, *_args, **_kwargs):
        return self

    def with_entities(self, *_args, **_kwargs):
        self._with_entities = True
        return self

    def group_by(self, *_args, **_kwargs):
        return self

    def all(self):
        if self._with_entities and self._rows and isinstance(self._rows[0], AssetEvidenceSignal):
            counts: dict[int, int] = {}
            for row in self._rows:
                counts[row.asset_id] = counts.get(row.asset_id, 0) + 1
            return list(counts.items())
        if self._with_entities and self._rows and isinstance(self._rows[0], Threat):
            counts: dict[str, int] = {}
            for row in self._rows:
                if row.status not in {"detected", "in-progress"}:
                    continue
                key = row.asset.strip().casefold()
                counts[key] = counts.get(key, 0) + 1
            return list(counts.items())
        return self._rows

    def first(self):
        return self._rows[0] if self._rows else None


class DummyDB:
    def __init__(self, rows_by_model):
        self._rows_by_model = rows_by_model
        self.added = []

    def query(self, model):
        return DummyQuery(self._rows_by_model.get(model, []))

    def add(self, row):
        if isinstance(row, BusinessService) and row.id is None:
            row.id = str(uuid4())
        self.added.append(row)
        self._rows_by_model.setdefault(type(row), []).append(row)

    def commit(self):
        return None

    def refresh(self, _row):
        return None

    def delete(self, row):
        rows = self._rows_by_model.get(type(row), [])
        if row in rows:
            rows.remove(row)


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=7,
        organization_id=42,
        email="ciso@risklence.test",
        roles=["ciso"],
        permissions=[],
    )


def test_service_requests_allow_standard_critical_tier():
    create_request = services.CreateServiceRequest(
        value_stream_ids=["vs-1"],
        name="Treasury Settlements",
        tier=SERVICE_TIER_STANDARD_CRITICAL,
        toleranceWindow="le_24h",
    )
    update_request = services.UpdateServiceRequest(
        tier=SERVICE_TIER_STANDARD_CRITICAL,
        toleranceWindow="le_24h",
    )

    assert create_request.tier == SERVICE_TIER_STANDARD_CRITICAL
    assert create_request.tolerance_window == "le_24h"
    assert update_request.tier == SERVICE_TIER_STANDARD_CRITICAL
    assert update_request.tolerance_window == "le_24h"


def test_service_requests_reject_unknown_tier():
    with pytest.raises(ValidationError):
        services.CreateServiceRequest(
            value_stream_ids=["vs-1"],
            name="Treasury Settlements",
            tier="Operational",
        )


def test_service_tier_read_compatibility_is_centralized_and_writes_stay_canonical():
    assert normalize_service_tier("mission-critical") == SERVICE_TIER_MISSION_CRITICAL
    assert normalize_service_tier("not-a-tier") is None

    with pytest.raises(ValidationError):
        services.CreateServiceRequest(
            value_stream_ids=["vs-1"],
            name="Treasury Settlements",
            tier="mission-critical",
        )


def test_service_requests_default_to_business_critical():
    create_request = services.CreateServiceRequest(
        name="Customer Payments", value_stream_ids=["vs-1"]
    )

    assert create_request.tier == SERVICE_TIER_BUSINESS_CRITICAL


def test_service_requests_accept_bia_answers_and_service_response_serializes_them():
    create_request = services.CreateServiceRequest(
        value_stream_ids=["vs-1"],
        name="Customer Payments",
        biaAnswers={
            "serviceOwnerTitle": "Head of Platform Engineering",
            "impactPath": ["transactions_stop", "regulatory_failure"],
            "impact1h": "high",
            "impact4h": "severe",
            "impact24h": "severe",
            "mtd": "le_4h",
            "workaround": "partial",
            "alternativeChannel": "partial",
            "dataSensitivity": "high",
        },
    )
    service = BusinessService(
        id="svc-bia",
        organization_id=42,
        name="Customer Payments",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        tolerance_window="le_4h",
        trading_impact="Customer payments stop and regulatory obligations are affected.",
        bia_answers=create_request.bia_answers.model_dump(),
        l1=[],
        l2=[],
        l3=[],
    )

    assert create_request.bia_answers is not None
    # #463 — the BIA in force comes from the process; the service's own record supplies only its
    # setup facts (owner title, impact path).
    process_answers = {
        key: value
        for key, value in create_request.bia_answers.model_dump().items()
        if key in BIA_FIELD_KEYS
    }
    response = services.ServiceResponse.from_orm(service, process_bia_answers=process_answers)
    assert response.biaAnswers is not None
    assert response.toleranceWindow == "le_4h"
    assert response.biaAnswers.serviceOwnerTitle == "Head of Platform Engineering"
    assert response.biaAnswers.mtd == "le_4h"
    assert response.biaAnswers.impactPath == ["transactions_stop", "regulatory_failure"]


@pytest.mark.parametrize(
    ("stored_tolerance", "expected_tolerance"),
    [("2h", "le_4h"), ("48h", "gt_24h"), ("unsupported", None)],
)
def test_service_response_normalizes_legacy_tolerance_windows(
    stored_tolerance: str,
    expected_tolerance: str | None,
):
    service = BusinessService(
        id="svc-legacy-tolerance",
        organization_id=42,
        name="Customer Payments",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        tolerance_window=stored_tolerance,
        trading_impact="Customer payments stop.",
        l1=[],
        l2=[],
        l3=[],
    )

    response = services.ServiceResponse.from_orm(service)

    assert response.toleranceWindow == expected_tolerance


def test_service_response_treats_legacy_bia_metadata_as_unconfigured():
    service = BusinessService(
        id="svc-legacy-bia",
        organization_id=42,
        name="Customer Payments",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="Customer payments stop.",
        bia_answers={
            "suggested_mtd_hours": 2,
            "validated_mtd_hours": 2,
            "validated_by": "Risklence Admin",
        },
        l1=[],
        l2=[],
        l3=[],
    )

    response = services.ServiceResponse.from_orm(service)

    assert response.biaAnswers is None


def test_service_response_ignores_legacy_bia_metadata_when_process_bia_is_available():
    process = ValueStream(
        id="p-legacy-bia",
        organization_id=42,
        name="Order to Cash",
        bia_answers=_PROCESS_ANSWERS,
    )
    service = BusinessService(
        id="svc-legacy-bia-with-process",
        organization_id=42,
        name="Customer Payments",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="Customer payments stop.",
        bia_answers={"validated_by": "Risklence Admin"},
        l1=[],
        l2=[],
        l3=[],
    )

    response = services.ServiceResponse.from_orm(service, process_bia_answers=process.bia_answers)

    assert response.biaAnswers is not None
    assert response.biaAnswers.mtd == _PROCESS_ANSWERS["mtd"]


def test_service_requests_accept_archetype_on_create():
    create_request = services.CreateServiceRequest(
        value_stream_ids=["vs-1"],
        name="Customer Payments",
        archetype="transactional_system",
    )

    assert create_request.archetype == "transactional_system"


def test_service_requests_accept_library_item_id_and_service_response_serializes_it():
    create_request = services.CreateServiceRequest(
        value_stream_ids=["vs-1"],
        name="Customer Payments",
        archetype="transactional_system",
        libraryItemId="bsl-payment-processing",
    )
    service = BusinessService(
        id="svc-library-origin",
        organization_id=42,
        name="Customer Payments",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="Customer payments stop and regulatory obligations are affected.",
        archetype="transactional_system",
        library_item_id="bsl-payment-processing",
        l1=[],
        l2=[],
        l3=[],
    )

    assert create_request.library_item_id == "bsl-payment-processing"
    response = services.ServiceResponse.from_orm(service)
    assert response.libraryItemId == "bsl-payment-processing"


def test_service_requests_accept_value_stream_ids_and_service_response_serializes_them():
    create_request = services.CreateServiceRequest(
        value_stream_ids=["vs-1"],
        name="Customer Payments",
        valueStreamIds=["vs-order-to-cash", "vs-record-to-report"],
    )
    service = BusinessService(
        id="svc-value-stream-origin",
        organization_id=42,
        name="Customer Payments",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="Customer payments stop and regulatory obligations are affected.",
        value_stream_ids=["vs-order-to-cash", "vs-record-to-report"],
        l1=[],
        l2=[],
        l3=[],
    )

    assert create_request.value_stream_ids == ["vs-order-to-cash", "vs-record-to-report"]
    response = services.ServiceResponse.from_orm(service)
    assert response.valueStreamIds == ["vs-order-to-cash", "vs-record-to-report"]


def test_create_service_persists_library_item_id():
    db = DummyDB({BusinessService: []})

    response = services.create_service(
        services.CreateServiceRequest(
            value_stream_ids=["vs-1"],
            name="Customer Payments",
            archetype="transactional_system",
            libraryItemId="bsl-payment-processing",
        ),
        ctx=_ctx(),
        db=db,
    )

    assert len(db.added) == 1
    persisted = db.added[0]
    assert isinstance(persisted, BusinessService)
    assert persisted.library_item_id == "bsl-payment-processing"
    assert response.libraryItemId == "bsl-payment-processing"


def test_create_service_persists_value_stream_ids():
    db = DummyDB({BusinessService: []})

    response = services.create_service(
        services.CreateServiceRequest(
            value_stream_ids=["vs-1"],
            name="Customer Payments",
            archetype="transactional_system",
            valueStreamIds=["vs-order-to-cash"],
        ),
        ctx=_ctx(),
        db=db,
    )

    assert len(db.added) == 1
    persisted = db.added[0]
    assert isinstance(persisted, BusinessService)
    assert persisted.value_stream_ids == ["vs-order-to-cash"]
    assert response.valueStreamIds == ["vs-order-to-cash"]


def test_service_response_migrates_legacy_flat_service_owner():
    service = BusinessService(
        id="svc-bia-legacy",
        organization_id=42,
        name="Customer Payments",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="Customer payments stop and regulatory obligations are affected.",
        bia_answers={
            "serviceOwner": "Head of Platform Engineering",
            "impactPath": ["transactions_stop"],
            "impact1h": "high",
            "impact4h": "severe",
            "impact24h": "severe",
            "mtd": "le_4h",
            "workaround": "partial",
            "alternativeChannel": "partial",
            "dataSensitivity": "high",
        },
        l1=[],
        l2=[],
        l3=[],
    )

    response = services.ServiceResponse.from_orm(
        service,
        process_bia_answers={
            key: value for key, value in service.bia_answers.items() if key in BIA_FIELD_KEYS
        },
    )

    assert response.biaAnswers is not None
    assert response.biaAnswers.serviceOwnerTitle == "Head of Platform Engineering"


def test_record_service_journey_event_accepts_library_signals(monkeypatch):
    logged = []
    db = DummyDB({ServiceJourneySignal: []})

    def capture(event_name, **fields):
        logged.append((event_name, fields))

    monkeypatch.setattr(services.logger, "info", capture)

    response = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="recommendations_shown",
            recommended_service_keys=["payment_processing", "identity_access"],
            organization_context={
                "industry": "Financial Services",
                "companySize": "Enterprise",
                "country": "DK",
            },
        ),
        ctx=_ctx(),
        db=db,
    )

    assert response.accepted is True
    assert logged == [
        (
            "service_journey_event",
            {
                "org_id": 42,
                "user_id": 7,
                "event": "recommendations_shown",
                "service_id": None,
                "library_item_id": None,
                "service_key": None,
                "service_name": None,
                "suggested_tier": None,
                "selected_tier": None,
                "selected_tolerance_window": None,
                "suggested_archetype": None,
                "selected_archetype": None,
                "recommended_service_keys": ["payment_processing", "identity_access"],
                "matched_service_keys": [],
                "search_query": None,
                "dependency_id": None,
                "dependency_label": None,
                "group_key": None,
                "asset_id": None,
                "pattern_key": None,
                "fallback_status": None,
                "business_choice": None,
                "business_impact_level": None,
                "spof_value": None,
                "warning_ids": [],
                "blocker_count": None,
                "warning_count": None,
                "organization_context": {
                    "industry": "Financial Services",
                    "companySize": "Enterprise",
                    "country": "DK",
                },
            },
        ),
    ]


def test_record_service_journey_event_accepts_custom_service_created(monkeypatch):
    logged = []
    db = DummyDB({ServiceJourneySignal: []})

    def capture(event_name, **fields):
        logged.append((event_name, fields))

    monkeypatch.setattr(services.logger, "info", capture)

    response = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="custom_service_created",
            service_name="Treasury Operations Support",
            organization_context={
                "industry": "Financial Services",
            },
        ),
        ctx=_ctx(),
        db=db,
    )

    assert response.accepted is True
    assert logged[0][0] == "service_journey_event"
    assert logged[0][1]["event"] == "custom_service_created"
    assert logged[0][1]["service_name"] == "Treasury Operations Support"
    assert logged[0][1]["suggested_archetype"] is None
    assert logged[0][1]["selected_archetype"] is None


def test_record_service_journey_event_accepts_tier_confirmation_payload(monkeypatch):
    logged = []
    db = DummyDB({ServiceJourneySignal: []})

    def capture(event_name, **fields):
        logged.append((event_name, fields))

    monkeypatch.setattr(services.logger, "info", capture)

    response = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="service_tier_changed",
            serviceId="svc-1",
            libraryItemId="svc-lib-payment-processing",
            serviceKey="payment_processing",
            serviceName="Payment Processing",
            suggestedTier="Mission Critical",
            selectedTier="Business Critical",
            selectedToleranceWindow="le_24h",
            organizationContext={
                "industry": "Financial Services",
                "companySize": "Enterprise",
            },
        ),
        ctx=_ctx(),
        db=db,
    )

    assert response.accepted is True
    assert logged == [
        (
            "service_journey_event",
            {
                "org_id": 42,
                "user_id": 7,
                "event": "service_tier_changed",
                "service_id": "svc-1",
                "library_item_id": "svc-lib-payment-processing",
                "service_key": "payment_processing",
                "service_name": "Payment Processing",
                "suggested_tier": "Mission Critical",
                "selected_tier": "Business Critical",
                "selected_tolerance_window": "le_24h",
                "suggested_archetype": None,
                "selected_archetype": None,
                "recommended_service_keys": [],
                "matched_service_keys": [],
                "search_query": None,
                "dependency_id": None,
                "dependency_label": None,
                "group_key": None,
                "asset_id": None,
                "pattern_key": None,
                "fallback_status": None,
                "business_choice": None,
                "business_impact_level": None,
                "spof_value": None,
                "warning_ids": [],
                "blocker_count": None,
                "warning_count": None,
                "organization_context": {
                    "industry": "Financial Services",
                    "companySize": "Enterprise",
                },
            },
        )
    ]


def test_record_service_journey_event_accepts_archetype_override_payload(monkeypatch):
    logged = []
    db = DummyDB({ServiceJourneySignal: []})

    def capture(event_name, **fields):
        logged.append((event_name, fields))

    monkeypatch.setattr(services.logger, "info", capture)

    response = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="archetype_override",
            serviceId="svc-1",
            libraryItemId="svc-lib-payment-processing",
            serviceKey="payment_processing",
            serviceName="Payment Processing",
            suggestedArchetype="transactional_system",
            selectedArchetype="data_store",
            organizationContext={
                "industry": "Financial Services",
                "companySize": "Enterprise",
            },
        ),
        ctx=_ctx(),
        db=db,
    )

    assert response.accepted is True
    assert logged == [
        (
            "service_journey_event",
            {
                "org_id": 42,
                "user_id": 7,
                "event": "archetype_override",
                "service_id": "svc-1",
                "library_item_id": "svc-lib-payment-processing",
                "service_key": "payment_processing",
                "service_name": "Payment Processing",
                "suggested_tier": None,
                "selected_tier": None,
                "selected_tolerance_window": None,
                "suggested_archetype": "transactional_system",
                "selected_archetype": "data_store",
                "recommended_service_keys": [],
                "matched_service_keys": [],
                "search_query": None,
                "dependency_id": None,
                "dependency_label": None,
                "group_key": None,
                "asset_id": None,
                "pattern_key": None,
                "fallback_status": None,
                "business_choice": None,
                "business_impact_level": None,
                "spof_value": None,
                "warning_ids": [],
                "blocker_count": None,
                "warning_count": None,
                "organization_context": {
                    "industry": "Financial Services",
                    "companySize": "Enterprise",
                },
            },
        )
    ]


def test_get_service_journey_learning_recommendations_returns_ranked_adjustments():
    db = DummyDB(
        {
            ServiceJourneySignal: [
                ServiceJourneySignal(
                    organization_id=42,
                    user_id=7,
                    event="service_selected",
                    service_key="payment_processing",
                    industry="Financial Services",
                    company_size="Enterprise",
                    country="DK",
                    payload={},
                ),
                ServiceJourneySignal(
                    organization_id=42,
                    user_id=7,
                    event="service_added_from_library",
                    service_key="payment_processing",
                    industry="Financial Services",
                    company_size="Enterprise",
                    country="DK",
                    payload={},
                ),
                ServiceJourneySignal(
                    organization_id=42,
                    user_id=7,
                    event="service_searched",
                    matched_service_keys=["identity_access_management"],
                    industry="Financial Services",
                    company_size="Enterprise",
                    country="DK",
                    payload={},
                ),
                ServiceJourneySignal(
                    organization_id=42,
                    user_id=7,
                    event="service_rejected",
                    service_key="customer_support",
                    industry="Financial Services",
                    company_size="Enterprise",
                    country="DK",
                    payload={},
                ),
            ]
        }
    )

    response = services.get_service_journey_learning_recommendations(
        industry="Financial Services",
        company_size="Enterprise",
        country="DK",
        ctx=_ctx(),
        db=db,
    )

    assert [item.serviceKey for item in response.recommendations] == [
        "payment_processing",
        "identity_access_management",
    ]
    assert response.recommendations[0].scoreAdjustment == 7
    assert response.recommendations[0].selectionCount == 1
    assert response.recommendations[0].addFromLibraryCount == 1
    assert response.recommendations[1].scoreAdjustment == 1


def test_record_service_journey_event_accepts_validation_and_publish_signals(monkeypatch):
    logged = []
    db = DummyDB({ServiceJourneySignal: []})

    def capture(event_name, **fields):
        logged.append((event_name, fields))

    monkeypatch.setattr(services.logger, "info", capture)

    accepted = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="validation_warning_accepted",
            serviceId="svc-1",
            serviceName="Payment Processing",
            organizationContext={"industry": "Financial Services"},
        ),
        ctx=_ctx(),
        db=db,
    )
    published = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="bundle_published",
            serviceId="svc-1",
            serviceName="Payment Processing",
            organizationContext={"industry": "Financial Services"},
        ),
        ctx=_ctx(),
        db=db,
    )

    assert accepted.accepted is True
    assert published.accepted is True
    assert logged[0][1]["event"] == "validation_warning_accepted"
    assert logged[1][1]["event"] == "bundle_published"


def test_record_service_journey_event_accepts_search_and_audit_payloads(monkeypatch):
    logged = []
    db = DummyDB({ServiceJourneySignal: []})

    def capture(event_name, **fields):
        logged.append((event_name, fields))

    monkeypatch.setattr(services.logger, "info", capture)

    searched = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="service_searched",
            searchQuery="payment",
            matchedServiceKeys=["payment_processing", "order_management"],
            organizationContext={"industry": "Financial Services"},
        ),
        ctx=_ctx(),
        db=db,
    )
    accepted = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="recommendation_accepted",
            serviceKey="payment_processing",
            organizationContext={"industry": "Financial Services"},
        ),
        ctx=_ctx(),
        db=db,
    )
    completed = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="publish_completed",
            serviceId="svc-1",
            warningIds=["validation-warning-1"],
            warningCount=1,
            organizationContext={"industry": "Financial Services"},
        ),
        ctx=_ctx(),
        db=db,
    )

    assert searched.accepted is True
    assert accepted.accepted is True
    assert completed.accepted is True
    assert logged[0][1]["event"] == "service_searched"
    assert logged[0][1]["search_query"] == "payment"
    assert logged[0][1]["matched_service_keys"] == ["payment_processing", "order_management"]
    assert logged[1][1]["event"] == "recommendation_accepted"
    assert logged[2][1]["event"] == "publish_completed"
    assert logged[2][1]["warning_ids"] == ["validation-warning-1"]
    assert logged[2][1]["warning_count"] == 1


def test_record_service_journey_event_accepts_dependency_action_payloads(monkeypatch):
    logged = []
    db = DummyDB({ServiceJourneySignal: []})

    def capture(event_name, **fields):
        logged.append((event_name, fields))

    monkeypatch.setattr(services.logger, "info", capture)

    response = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="asset_replaced",
            serviceId="svc-1",
            serviceName="Payment Processing",
            dependencyId="node-1",
            dependencyLabel="Payment gateway",
            groupKey="systems",
            assetId="asset-7",
            organizationContext={"industry": "Financial Services"},
        ),
        ctx=_ctx(),
        db=db,
    )

    assert response.accepted is True
    assert logged == [
        (
            "service_journey_event",
            {
                "org_id": 42,
                "user_id": 7,
                "event": "asset_replaced",
                "service_id": "svc-1",
                "library_item_id": None,
                "service_key": None,
                "service_name": "Payment Processing",
                "suggested_tier": None,
                "selected_tier": None,
                "selected_tolerance_window": None,
                "suggested_archetype": None,
                "selected_archetype": None,
                "recommended_service_keys": [],
                "matched_service_keys": [],
                "search_query": None,
                "dependency_id": "node-1",
                "dependency_label": "Payment gateway",
                "group_key": "systems",
                "asset_id": "asset-7",
                "pattern_key": None,
                "fallback_status": None,
                "business_choice": None,
                "business_impact_level": None,
                "spof_value": None,
                "warning_ids": [],
                "blocker_count": None,
                "warning_count": None,
                "organization_context": {"industry": "Financial Services"},
            },
        )
    ]


def test_record_service_journey_event_accepts_asset_confirmed_payload(monkeypatch):
    logged = []
    db = DummyDB({ServiceJourneySignal: []})

    def capture(event_name, **fields):
        logged.append((event_name, fields))

    monkeypatch.setattr(services.logger, "info", capture)

    response = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="asset_confirmed",
            serviceId="svc-1",
            serviceName="Payment Processing",
            dependencyId="node-1",
            dependencyLabel="Transaction database",
            groupKey="data",
            assetId="asset-db-1",
            organizationContext={"industry": "Financial Services"},
        ),
        ctx=_ctx(),
        db=db,
    )

    assert response.accepted is True
    assert logged == [
        (
            "service_journey_event",
            {
                "org_id": 42,
                "user_id": 7,
                "event": "asset_confirmed",
                "service_id": "svc-1",
                "library_item_id": None,
                "service_key": None,
                "service_name": "Payment Processing",
                "suggested_tier": None,
                "selected_tier": None,
                "selected_tolerance_window": None,
                "suggested_archetype": None,
                "selected_archetype": None,
                "recommended_service_keys": [],
                "matched_service_keys": [],
                "search_query": None,
                "dependency_id": "node-1",
                "dependency_label": "Transaction database",
                "group_key": "data",
                "asset_id": "asset-db-1",
                "pattern_key": None,
                "fallback_status": None,
                "business_choice": None,
                "business_impact_level": None,
                "spof_value": None,
                "warning_ids": [],
                "blocker_count": None,
                "warning_count": None,
                "organization_context": {"industry": "Financial Services"},
            },
        )
    ]


def test_record_service_journey_event_accepts_recovery_dependency_marked_payload(monkeypatch):
    logged = []
    db = DummyDB({ServiceJourneySignal: []})

    def capture(event_name, **fields):
        logged.append((event_name, fields))

    monkeypatch.setattr(services.logger, "info", capture)

    response = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="recovery_dependency_marked",
            serviceId="svc-1",
            serviceName="Payment Processing",
            dependencyId="node-2",
            dependencyLabel="Operational database",
            groupKey="data",
            organizationContext={"industry": "Financial Services"},
        ),
        ctx=_ctx(),
        db=db,
    )

    assert response.accepted is True
    assert logged == [
        (
            "service_journey_event",
            {
                "org_id": 42,
                "user_id": 7,
                "event": "recovery_dependency_marked",
                "service_id": "svc-1",
                "library_item_id": None,
                "service_key": None,
                "service_name": "Payment Processing",
                "suggested_tier": None,
                "selected_tier": None,
                "selected_tolerance_window": None,
                "suggested_archetype": None,
                "selected_archetype": None,
                "recommended_service_keys": [],
                "matched_service_keys": [],
                "search_query": None,
                "dependency_id": "node-2",
                "dependency_label": "Operational database",
                "group_key": "data",
                "asset_id": None,
                "pattern_key": None,
                "fallback_status": None,
                "business_choice": None,
                "business_impact_level": None,
                "spof_value": None,
                "warning_ids": [],
                "blocker_count": None,
                "warning_count": None,
                "organization_context": {"industry": "Financial Services"},
            },
        )
    ]


def test_record_service_journey_event_accepts_publish_blocked_and_service_removed(monkeypatch):
    logged = []
    db = DummyDB({ServiceJourneySignal: []})

    def capture(event_name, **fields):
        logged.append((event_name, fields))

    monkeypatch.setattr(services.logger, "info", capture)

    blocked = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="publish_blocked",
            serviceId="svc-1",
            blockerCount=2,
            warningCount=1,
            organizationContext={"industry": "Financial Services"},
        ),
        ctx=_ctx(),
        db=db,
    )
    removed = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="service_removed_after_selection",
            serviceId="svc-2",
            serviceKey="payment_processing",
            organizationContext={"industry": "Financial Services"},
        ),
        ctx=_ctx(),
        db=db,
    )

    assert blocked.accepted is True
    assert removed.accepted is True
    assert logged[0][1]["event"] == "publish_blocked"
    assert logged[0][1]["blocker_count"] == 2
    assert logged[0][1]["warning_count"] == 1
    assert logged[1][1]["event"] == "service_removed_after_selection"
    assert logged[1][1]["service_id"] == "svc-2"


def test_record_service_journey_event_persists_learning_signal(monkeypatch):
    logged = []
    db = DummyDB({ServiceJourneySignal: []})

    def capture(event_name, **fields):
        logged.append((event_name, fields))

    monkeypatch.setattr(services.logger, "info", capture)

    response = services.record_service_journey_event(
        services.ServiceJourneyEventRequest(
            event="service_added_from_library",
            serviceId="svc-3",
            serviceKey="order_management",
            serviceName="Order Management",
            organizationContext={
                "organizationType": "Bank",
                "industry": "Financial Services",
                "companySize": "Enterprise",
                "country": "DK",
            },
        ),
        ctx=_ctx(),
        db=db,
    )

    assert response.accepted is True
    assert len(db.added) == 1
    persisted = db.added[0]
    assert isinstance(persisted, ServiceJourneySignal)
    assert persisted.event == "service_added_from_library"
    assert persisted.service_key == "order_management"
    assert persisted.organization_type == "Bank"
    assert persisted.company_size == "Enterprise"
    assert persisted.payload["service_name"] == "Order Management"
    assert logged[0][0] == "service_journey_event"


def test_get_service_journey_learning_aggregates_groups_counts_by_segment():
    db = DummyDB(
        {
            ServiceJourneySignal: [
                ServiceJourneySignal(
                    organization_id=42,
                    user_id=7,
                    event="recommendation_accepted",
                    service_key="payment_processing",
                    industry="Financial Services",
                    company_size="Enterprise",
                    country="DK",
                    payload={},
                ),
                ServiceJourneySignal(
                    organization_id=42,
                    user_id=7,
                    event="service_added_from_library",
                    service_key="payment_processing",
                    industry="Financial Services",
                    company_size="Enterprise",
                    country="DK",
                    payload={},
                ),
                ServiceJourneySignal(
                    organization_id=42,
                    user_id=7,
                    event="service_searched",
                    matched_service_keys=["payment_processing", "order_management"],
                    industry="Financial Services",
                    company_size="Enterprise",
                    country="DK",
                    payload={},
                ),
                ServiceJourneySignal(
                    organization_id=42,
                    user_id=7,
                    event="recommendation_rejected",
                    service_key="identity_access",
                    industry="Financial Services",
                    company_size="Enterprise",
                    country="DK",
                    payload={},
                ),
                ServiceJourneySignal(
                    organization_id=42,
                    user_id=7,
                    event="service_removed_after_selection",
                    service_key="order_management",
                    industry="Financial Services",
                    company_size="Enterprise",
                    country="DK",
                    payload={},
                ),
                ServiceJourneySignal(
                    organization_id=42,
                    user_id=7,
                    event="recommendation_accepted",
                    service_key="customer_support",
                    industry="Healthcare",
                    company_size="Enterprise",
                    country="DK",
                    payload={},
                ),
                ServiceJourneySignal(
                    organization_id=999,
                    user_id=7,
                    event="recommendation_accepted",
                    service_key="should_not_leak",
                    industry="Financial Services",
                    company_size="Enterprise",
                    country="DK",
                    payload={},
                ),
            ]
        }
    )

    response = services.get_service_journey_learning_aggregates(ctx=_ctx(), db=db)

    assert len(response.segments) == 2
    financial_segment = next(
        segment
        for segment in response.segments
        if segment.industry == "Financial Services" and segment.companySize == "Enterprise"
    )
    payment_processing = next(
        service
        for service in financial_segment.services
        if service.serviceKey == "payment_processing"
    )
    order_management = next(
        service
        for service in financial_segment.services
        if service.serviceKey == "order_management"
    )
    identity_access = next(
        service for service in financial_segment.services if service.serviceKey == "identity_access"
    )

    assert financial_segment.signalCount == 5
    assert payment_processing.selectionCount == 1
    assert payment_processing.addFromLibraryCount == 1
    assert payment_processing.searchCount == 1
    assert order_management.searchCount == 1
    assert order_management.removedAfterSelectionCount == 1
    assert identity_access.rejectionCount == 1


def test_get_service_dependencies_returns_service_led_dependency_layers():
    service = BusinessService(
        id="svc-1",
        organization_id=42,
        name="Payment Processing",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="Card payments stop within one hour.",
        l1=["asset-7"],
        l2=["11"],
        l3=["asset-13"],
    )
    l1_asset = Asset(
        id=7,
        organization_id=42,
        display_name="Payment Processing App",
        type="Application",
        layer="Application",
        status="AT_RISK",
        is_spof=True,
        business_owner_ref="Platform Engineering",
    )
    l2_asset = Asset(
        id=11,
        organization_id=42,
        display_name="Primary Database Cluster",
        type="Database",
        layer="Data",
        status="PARTIALLY_OBSERVED",
        technical_owner_ref="Data Engineering",
    )
    l3_asset = Asset(
        id=13,
        organization_id=42,
        display_name="Payment Provider Infrastructure",
        type="Cloud Infrastructure",
        layer="Network",
        status="OBSERVED",
        setup_assignee_ref="External Provider",
    )
    signal_rows = [
        AssetEvidenceSignal(
            id=1,
            organization_id=42,
            asset_id=7,
            kind="packet_loss",
            payload_json={"message": "packet loss"},
            observed_at=datetime(2026, 3, 29, 8, 0, tzinfo=timezone.utc),
        ),
        AssetEvidenceSignal(
            id=2,
            organization_id=42,
            asset_id=11,
            kind="backup_failure",
            payload_json={"message": "backup failure"},
            observed_at=datetime(2026, 3, 29, 8, 5, tzinfo=timezone.utc),
        ),
        AssetEvidenceSignal(
            id=3,
            organization_id=42,
            asset_id=11,
            kind="latency_rise",
            payload_json={"message": "latency rise"},
            observed_at=datetime(2026, 3, 29, 8, 10, tzinfo=timezone.utc),
        ),
    ]

    open_threat = Threat(
        id="thr-1",
        organization_id=42,
        status="detected",
        severity="high",
        source="cmdb",
        asset="Payment Processing App",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        signal="Latency rising",
        what_it_means="Payments will slow down.",
        recommendation="Investigate.",
        intelligence={},
        daily_cost=1000,
        frameworks=[],
        requires_escalation=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    ignored_threat = Threat(
        id="thr-2",
        organization_id=42,
        status="kept-safe",
        severity="medium",
        source="glic",
        asset="Payment Processing App",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        signal="Recovered",
        what_it_means="Recovered.",
        recommendation="None",
        intelligence={},
        daily_cost=0,
        frameworks=[],
        requires_escalation=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    db = DummyDB(
        {
            BusinessService: [service],
            Asset: [l1_asset, l2_asset, l3_asset],
            AssetEvidenceSignal: signal_rows,
            Threat: [open_threat, ignored_threat],
        }
    )

    response = services.get_service_dependencies("svc-1", ctx=_ctx(), db=db)

    assert response.serviceId == "svc-1"
    assert response.serviceName == "Payment Processing"
    assert [item.id for item in response.l1] == ["asset-7"]
    assert [item.id for item in response.l2] == ["asset-11"]
    assert [item.id for item in response.l3] == ["asset-13"]
    assert response.l1[0].health == "at-risk"
    assert response.l1[0].owner == "Platform Engineering"
    assert response.l1[0].is_spof is True
    assert response.l1[0].signal_count == 1
    assert response.l1[0].threat_count == 1
    assert response.l2[0].health == "watching"
    assert response.l2[0].owner == "Data Engineering"
    assert response.l2[0].signal_count == 2
    assert response.l3[0].health == "healthy"
    assert response.l3[0].owner == "External Provider"


def test_list_service_dependencies_returns_all_services_without_n_plus_one_contract():
    payment_service = BusinessService(
        id="svc-1",
        organization_id=42,
        name="Payment Processing",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="Card payments stop within one hour.",
        l1=["asset-7"],
        l2=["11"],
        l3=[],
    )
    lending_service = BusinessService(
        id="svc-2",
        organization_id=42,
        name="Lending Platform",
        tier=SERVICE_TIER_STANDARD_CRITICAL,
        trading_impact="Loan intake stalls within four hours.",
        l1=["asset-17"],
        l2=[],
        l3=[],
    )
    payment_asset = Asset(
        id=7,
        organization_id=42,
        display_name="Payment Processing App",
        type="Application",
        layer="Application",
        status="AT_RISK",
        business_owner_ref="Platform Engineering",
    )
    payment_dependency = Asset(
        id=11,
        organization_id=42,
        display_name="Primary Database Cluster",
        type="Database",
        layer="Data",
        status="PARTIALLY_OBSERVED",
        technical_owner_ref="Data Engineering",
    )
    lending_asset = Asset(
        id=17,
        organization_id=42,
        display_name="Lending Application",
        type="Application",
        layer="Application",
        status="OBSERVED",
        business_owner_ref="Lending Engineering",
    )
    open_threat = Threat(
        id="thr-1",
        organization_id=42,
        status="in-progress",
        severity="critical",
        source="cmdb",
        asset="Primary Database Cluster",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        signal="Backups failing",
        what_it_means="Recovery risk is increasing.",
        recommendation="Repair backup validation.",
        intelligence={},
        daily_cost=2500,
        frameworks=[],
        requires_escalation=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    db = DummyDB(
        {
            BusinessService: [payment_service, lending_service],
            Asset: [payment_asset, payment_dependency, lending_asset],
            AssetEvidenceSignal: [],
            Threat: [open_threat],
        }
    )

    response = services.list_service_dependencies(ctx=_ctx(), db=db)

    assert [service.serviceId for service in response] == ["svc-1", "svc-2"]
    assert response[0].l1[0].id == "asset-7"
    assert response[0].l2[0].id == "asset-11"
    assert response[0].l2[0].threat_count == 1
    assert response[1].l1[0].id == "asset-17"
    assert response[1].l1[0].owner == "Lending Engineering"


def test_get_service_dependencies_raises_not_found_for_missing_service():
    db = DummyDB({BusinessService: []})

    with pytest.raises(Exception) as exc_info:
        services.get_service_dependencies("missing", ctx=_ctx(), db=db)

    assert exc_info.value.status_code == 404


# ─── BSP-04: process-level BIA inheritance ──────────────────────────────────

_PROCESS_ANSWERS = {
    "impact1h": "severe",
    "impact4h": "high",
    "impact24h": "medium",
    "mtd": "le_4h",
    "dataSensitivity": "high",
    "workaround": "partial",
    "alternativeChannel": "none",
}


def test_service_response_inherits_process_bia_when_service_has_none():
    process = ValueStream(
        id="p-1", organization_id=42, name="Order to Cash", bia_answers=_PROCESS_ANSWERS
    )
    service = BusinessService(
        id="svc-inherit",
        organization_id=42,
        name="Payment Processing",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="",
        value_stream_ids=["p-1"],
        l1=[],
        l2=[],
        l3=[],
    )

    response = services.ServiceResponse.from_orm(service, process_bia_answers=process.bia_answers)

    assert response.biaAnswers is not None
    assert response.biaAnswers.mtd == "le_4h"
    assert set(response.biaProvenance.values()) == {"inherited"}


def test_service_response_layers_an_exception_on_the_process_answers():
    """#463 — the service's exception in its primary process replaces that field, and says so."""
    service = BusinessService(
        id="svc-override",
        organization_id=42,
        name="Payment Processing",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="",
        value_stream_ids=["p-1"],
        l1=[],
        l2=[],
        l3=[],
    )
    exception = ServiceBiaException(
        organization_id=42,
        service_id="svc-override",
        process_id="p-1",
        field="impact1h",
        value="low",
        recorded_before_reasons=False,
    )

    response = services.ServiceResponse.from_orm(
        service, process_bia_answers=_PROCESS_ANSWERS, bia_exceptions=[exception]
    )

    assert response.biaAnswers.impact1h == "low"
    assert response.biaAnswers.mtd == "le_4h"
    assert response.biaProvenance["impact1h"] == "exception"
    assert response.biaProvenance["mtd"] == "inherited"


def test_service_response_does_not_read_a_services_copied_answers_as_its_own():
    """#463 — `bia_answers` still holds copies of process answers until the write path moves."""
    service = BusinessService(
        id="svc-copy",
        organization_id=42,
        name="Payment Processing",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="",
        value_stream_ids=["p-1"],
        bia_answers={"impact1h": "low"},
        l1=[],
        l2=[],
        l3=[],
    )

    response = services.ServiceResponse.from_orm(service, process_bia_answers=_PROCESS_ANSWERS)

    assert response.biaAnswers.impact1h == _PROCESS_ANSWERS["impact1h"]
    assert set(response.biaProvenance.values()) == {"inherited"}


def test_list_services_resolves_each_services_primary_process_in_one_query(monkeypatch):
    process = ValueStream(id="p-1", organization_id=42, name="Order to Cash", bia_answers=None)
    service = BusinessService(
        id="svc-inherit",
        organization_id=42,
        name="Payment Processing",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="",
        value_stream_ids=["p-1"],
        l1=[],
        l2=[],
        l3=[],
    )
    db = DummyDB({BusinessService: [service], ValueStream: [process]})
    resolved: list[list[str]] = []

    def _resolve(_db, *, organization_id, processes):
        resolved.append([p.id for p in processes])
        return {
            p.id: EffectiveProcessBia(
                answers=_PROCESS_ANSWERS,
                process_assessment_id=None,
                organization_baseline_id="org-bia-1",
                process_assessment_started=False,
            )
            for p in processes
        }

    monkeypatch.setattr(services, "resolve_effective_process_bia_by_process", _resolve)
    monkeypatch.setattr(services, "active_bia_exceptions", lambda _db, **_kwargs: {})

    [response] = services.list_services(ctx=_ctx(), db=db)

    # #463 — the process's BIA in force (here the organisation baseline, where the legacy
    # projection is empty), resolved once for the whole list.
    assert response.biaAnswers.mtd == "le_4h"
    assert resolved == [["p-1"]]


# ─── #378 — a service in no process should not exist ────────────────────────
#
# Søren, 2026-08-31. Accountability resolves dependency → service → process →
# owner, so a service in no process terminates that chain at nobody and every
# dependency beneath it becomes unowned and undecidable. 57 such services exist,
# and they exist because these two request models allowed it.


def test_a_service_cannot_be_created_without_a_process():
    with pytest.raises(ValidationError):
        services.CreateServiceRequest(name="Card Processing", value_stream_ids=[])

    with pytest.raises(ValidationError):
        # It used to default to `[]`, which is how they were made by omission.
        services.CreateServiceRequest(name="Card Processing")


def test_a_service_cannot_have_its_last_process_taken_away():
    # `PATCH /{id}/value-streams` has always refused an empty set. The general
    # update route could go around it and silently orphan the service.
    with pytest.raises(ValidationError):
        services.UpdateServiceRequest(value_stream_ids=[])


def test_leaving_the_processes_alone_is_still_allowed():
    # Omission means "do not touch"; it is emptiness that is refused. An update
    # of a service's tier must not have to restate where it belongs.
    request = services.UpdateServiceRequest(tier=SERVICE_TIER_MISSION_CRITICAL)

    assert request.value_stream_ids is None


def test_the_dedicated_assignment_route_still_refuses_an_empty_set():
    with pytest.raises(ValidationError):
        services.AssignValueStreamsRequest(value_stream_ids=[])

    assert services.AssignValueStreamsRequest(value_stream_ids=["vs-1"]).value_stream_ids == [
        "vs-1"
    ]
