"""Tests for value stream library, inference engine, and API routes."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import value_streams
from src.api.routes.activation import _build_handoff_process_candidates
from src.core.constants import SERVICE_TIER_BUSINESS_CRITICAL
from src.api.routes.value_streams import (
    CreateValueStreamRequest,
    OrgValueStreamProfileRequest,
    UpdateValueStreamRequest,
    ValueStreamEventRequest,
)
from src.core.constants.value_stream_library import (
    UNIVERSAL_STREAM_KEYS,
    VALUE_STREAM_BY_KEY,
    VALUE_STREAM_LIBRARY,
    infer_value_streams_from_nace,
)
from src.core.models import BusinessService, OrgProcessConfig, ValueStream


class DummyQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *args, **_kwargs):
        filtered = list(self._rows)
        for arg in args:
            left = getattr(arg, "left", None)
            right = getattr(arg, "right", None)
            field_name = getattr(left, "key", None)
            value = getattr(right, "value", None)
            if field_name is None:
                continue
            filtered = [row for row in filtered if getattr(row, field_name, None) == value]
        self._rows = filtered
        return self

    def all(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None


class DummyDB:
    def __init__(self, rows_by_model):
        self._rows_by_model = rows_by_model
        self.added: list[object] = []
        self.committed = False

    def query(self, model):
        return DummyQuery(self._rows_by_model.get(model, []))

    def add(self, row):
        self.added.append(row)
        self._rows_by_model.setdefault(type(row), []).append(row)

    def flush(self):
        return None

    def commit(self):
        self.committed = True

    def refresh(self, _row):
        return None


def test_service_count_filters_value_stream_memberships_in_python():
    process = ValueStream(
        id="vs-order-to-cash",
        organization_id=7,
        library_item_id="order_to_cash",
        name="Order to Cash",
        priority="critical",
        source="in_platform",
    )
    assigned = BusinessService(
        id="svc-order",
        organization_id=7,
        name="Order Management",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="",
        library_item_id="order_management",
        archetype="transactional_system",
        value_stream_ids=["vs-order-to-cash"],
        l1=[],
        l2=[],
        l3=[],
    )
    unassigned = BusinessService(
        id="svc-payment",
        organization_id=7,
        name="Payment Processing",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="",
        library_item_id="payment_processing",
        archetype="transactional_system",
        value_stream_ids=["vs-other"],
        l1=[],
        l2=[],
        l3=[],
    )
    db = DummyDB({ValueStream: [process], BusinessService: [assigned, unassigned]})

    total, configured = value_streams._service_count(process.organization_id, process.id, db)

    assert total == 1
    assert configured == 0


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=1,
        organization_id=7,
        email="architect@risklence.test",
        roles=["admin"],
        permissions=[],
    )


# ─── Library tests ───────────────────────────────────────────────────────────


def test_library_has_items():
    # 3 universal + 6 customer_revenue + 3 supply_chain + 4 finance_compliance + 10 industry_specific
    assert len(VALUE_STREAM_LIBRARY) >= 26


def test_all_library_keys_unique():
    keys = [vs.key for vs in VALUE_STREAM_LIBRARY]
    assert len(keys) == len(set(keys))


def test_universal_streams_in_library():
    for key in UNIVERSAL_STREAM_KEYS:
        assert key in VALUE_STREAM_BY_KEY, f"Universal stream '{key}' missing from library"


def test_library_by_key_lookup():
    item = VALUE_STREAM_BY_KEY["order_to_cash"]
    assert item.name == "Order to Cash"
    assert "order_management" in item.core_service_keys


def test_all_library_items_have_required_fields():
    for item in VALUE_STREAM_LIBRARY:
        assert item.key, f"Missing key: {item}"
        assert item.name, f"Missing name: {item.key}"
        assert item.description, f"Missing description: {item.key}"
        assert item.process_family in {
            "universal", "customer_revenue", "supply_chain",
            "finance_compliance", "industry_specific"
        }, f"Invalid process_family: {item.key}"


# ─── Inference engine tests ───────────────────────────────────────────────────


def test_inference_always_includes_universal_streams():
    result = infer_value_streams_from_nace("47.11")
    keys = {r.key for r in result}
    for key in UNIVERSAL_STREAM_KEYS:
        assert key in keys, f"Universal stream '{key}' missing from inference result"


def test_inference_returns_list_of_inferred_streams():
    result = infer_value_streams_from_nace("47.11")
    assert isinstance(result, list)
    assert len(result) > 0


def test_inference_retail_nace():
    result = infer_value_streams_from_nace("47.11")
    keys = {r.key for r in result}
    assert "order_to_cash" in keys
    assert "customer_acquisition" in keys
    assert "procure_to_pay" in keys


def test_inference_software_nace():
    result = infer_value_streams_from_nace("62.01")
    keys = {r.key for r in result}
    assert "software_delivery" in keys
    assert "platform_operations" in keys
    assert "quote_to_cash" in keys


def test_inference_financial_services_nace():
    result = infer_value_streams_from_nace("64.19")
    keys = {r.key for r in result}
    assert "record_to_report" in keys
    assert "close_to_disclose" in keys
    assert "risk_to_mitigate" in keys
    assert "regulatory_reporting" in keys


def test_inference_healthcare_nace():
    result = infer_value_streams_from_nace("86.10")
    keys = {r.key for r in result}
    assert "patient_to_discharge" in keys
    assert "risk_to_mitigate" in keys


def test_inference_public_sector_nace():
    result = infer_value_streams_from_nace("84.11")
    keys = {r.key for r in result}
    assert "citizen_service_delivery" in keys
    assert "grant_to_report" in keys
    assert "record_to_report" in keys


def test_inference_listed_company_gets_close_to_disclose():
    result = infer_value_streams_from_nace("47.11", company_form="A/S")
    keys = {r.key for r in result}
    assert "close_to_disclose" in keys


def test_inference_ngo_gets_grant_to_report():
    result = infer_value_streams_from_nace("88.10", company_form="Forening")
    keys = {r.key for r in result}
    assert "grant_to_report" in keys


def test_inference_micro_company_excludes_platform_operations():
    result = infer_value_streams_from_nace("62.01", company_size="micro")
    keys = {r.key for r in result}
    assert "platform_operations" not in keys
    assert "software_delivery" not in keys


def test_inference_unknown_nace_returns_universal_only():
    result = infer_value_streams_from_nace("INVALID")
    keys = {r.key for r in result}
    assert keys == UNIVERSAL_STREAM_KEYS


def test_inference_all_results_have_valid_confidence():
    result = infer_value_streams_from_nace("64.19")
    for r in result:
        assert r.confidence in {"high", "medium", "low"}, f"Invalid confidence: {r.key}"


def test_inference_all_results_have_valid_priority():
    result = infer_value_streams_from_nace("47.11")
    for r in result:
        assert r.suggested_priority in {"critical", "important", "standard"}, f"Invalid priority: {r.key}"


def test_inference_no_duplicate_keys():
    result = infer_value_streams_from_nace("64.19", company_form="A/S", company_size="large")
    keys = [r.key for r in result]
    assert len(keys) == len(set(keys)), "Duplicate keys in inference result"


def test_inference_sorted_high_confidence_first():
    result = infer_value_streams_from_nace("64.19")
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    orders = [confidence_order[r.confidence] for r in result]
    assert orders == sorted(orders), "Results not sorted by confidence"


# ─── Request schema validation ────────────────────────────────────────────────


def test_create_request_valid_priority():
    req = CreateValueStreamRequest(name="Test Process", priority="critical")
    assert req.priority == "critical"


def test_create_request_rejects_invalid_priority():
    with pytest.raises(ValidationError):
        CreateValueStreamRequest(name="Test", priority="urgent")


def test_create_request_defaults():
    req = CreateValueStreamRequest(name="Test Process")
    assert req.priority == "standard"
    assert req.source == "in_platform"
    assert req.library_item_id is None
    assert req.excluded_service_keys == []


def test_create_request_accepts_excluded_service_keys():
    req = CreateValueStreamRequest(
        name="Order to Cash",
        library_item_id="order_to_cash",
        excluded_service_keys=["billing_service"],
    )

    assert req.excluded_service_keys == ["billing_service"]


def test_update_request_all_optional():
    req = UpdateValueStreamRequest()
    assert req.name is None
    assert req.priority is None


def test_update_request_valid_priority():
    req = UpdateValueStreamRequest(priority="important")
    assert req.priority == "important"


def test_update_request_rejects_invalid_priority():
    with pytest.raises(ValidationError):
        UpdateValueStreamRequest(priority="high")


def test_profile_request_defaults():
    req = OrgValueStreamProfileRequest()
    assert req.streams == []
    assert req.nace_code is None


def test_build_handoff_process_candidates_from_workspace_snapshot():
    candidates = _build_handoff_process_candidates(
        workspace_snapshot={
            "valueStreamProfile": {
                "naceCode": "62.01",
                "confirmedAt": "2026-04-09T10:30:00Z",
                "streams": [
                    {
                        "key": "order_to_cash",
                        "name": "Order to Cash",
                        "description": "Revenue collection flow.",
                        "priority": "critical",
                        "source": "inferred",
                        "confidence": "high",
                        "inferenceReason": "Primary software revenue cycle.",
                    },
                    {
                        "key": "order_to_cash",
                        "name": "Order to Cash",
                        "priority": "critical",
                        "source": "inferred",
                    },
                ],
            }
        },
    )

    assert candidates == [
        {
            "key": "order_to_cash",
            "name": "Order to Cash",
            "priority": "critical",
            "confidence": "high",
            "inference_reason": "Primary software revenue cycle.",
            # #281 — normalised through `to_utc_iso` rather than passed through as
            # whatever the snapshot held. Same instant, one format, and an offset
            # that is always present.
            "public_confirmation_at": "2026-04-09T10:30:00+00:00",
        }
    ]


def test_build_handoff_process_candidates_preserves_unconfirmed_suggestions():
    candidates = _build_handoff_process_candidates(
        workspace_snapshot={
            "valueStreamProfile": {
                "streams": [
                    {
                        "key": "procure_to_pay",
                        "name": "Procure to Pay",
                        "priority": "important",
                        "source": "user_added",
                    }
                ]
            }
        },
    )

    assert candidates[0]["key"] == "procure_to_pay"
    assert candidates[0]["public_confirmation_at"] is None


def test_build_handoff_process_candidates_returns_empty_without_streams():
    candidates = _build_handoff_process_candidates(
        workspace_snapshot={"valueStreamProfile": {"streams": []}},
    )
    assert candidates == []


def test_value_stream_event_request_valid():
    req = ValueStreamEventRequest(
        event="value_stream_added",
        streamId="stream-1",
        libraryItemId="order_to_cash",
        streamKey="order_to_cash",
        name="Order to Cash",
        priority="critical",
        source="in_platform",
    )
    assert req.event == "value_stream_added"
    assert req.priority == "critical"


def test_value_stream_event_request_accepts_journey_started():
    req = ValueStreamEventRequest(
        event="value_stream_journey_started",
        streamId="vs-order-to-cash",
        libraryItemId="order_to_cash",
        streamKey="order_to_cash",
        name="Order to Cash",
    )

    assert req.event == "value_stream_journey_started"
    assert req.stream_id == "vs-order-to-cash"


def test_value_stream_event_request_rejects_invalid_priority():
    with pytest.raises(ValidationError):
        ValueStreamEventRequest(event="value_stream_added", priority="urgent")


def test_create_value_stream_skips_excluded_template_services_and_saves_process_config():
    db = DummyDB({
        ValueStream: [],
        BusinessService: [],
        OrgProcessConfig: [],
    })
    body = CreateValueStreamRequest(
        library_item_id="order_to_cash",
        name="Order to Cash",
        priority="critical",
        source="in_platform",
        excluded_service_keys=["billing_service"],
    )

    with patch.object(value_streams, "_to_response", side_effect=lambda vs, _db: vs), patch.object(
        value_streams,
        "get_active_service_template",
        return_value=SimpleNamespace(version=3),
    ):
        created = value_streams.create_value_stream(body, _ctx(), db)

    assert isinstance(created, ValueStream)
    created_services = [row for row in db.added if isinstance(row, BusinessService)]
    assert {service.library_item_id for service in created_services} == {
        "order_management",
        "payment_processing",
    }
    configs = [row for row in db.added if isinstance(row, OrgProcessConfig)]
    assert len(configs) == 1
    assert configs[0].template_key == "order_to_cash"
    assert configs[0].excluded_service_keys == ["billing_service"]
    assert db.committed is True


def test_create_value_stream_rejects_unknown_excluded_service_keys():
    db = DummyDB({
        ValueStream: [],
        BusinessService: [],
        OrgProcessConfig: [],
    })
    body = CreateValueStreamRequest(
        library_item_id="order_to_cash",
        name="Order to Cash",
        excluded_service_keys=["not_real_service"],
    )

    with pytest.raises(Exception) as exc_info:
        value_streams.create_value_stream(body, _ctx(), db)

    assert getattr(exc_info.value, "status_code", None) == 422
    assert "Unknown excluded service keys" in str(exc_info.value.detail)
