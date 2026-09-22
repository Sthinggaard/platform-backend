from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import graph
from src.core.constants import SERVICE_TIER_BUSINESS_CRITICAL
from src.core.models import Asset, BusinessService, DependencyBundle, SlotInstance, ValueStream


class DummyQuery:
    def __init__(self, rows):
        self._rows = list(rows)

    def filter(self, *args, **_kwargs):
        filtered = list(self._rows)
        for arg in args:
            left = getattr(arg, "left", None)
            right = getattr(arg, "right", None)
            field_name = getattr(left, "key", None)
            value = getattr(right, "value", None)
            if field_name is None:
                continue
            if isinstance(value, (list, tuple, set)):
                filtered = [row for row in filtered if getattr(row, field_name, None) in value]
                continue
            filtered = [row for row in filtered if getattr(row, field_name, None) == value]
        self._rows = filtered
        return self

    def all(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None

    def order_by(self, *_args, **_kwargs):
        return self


class DummyDB:
    def __init__(self, rows_by_model):
        self._rows_by_model = {
            model: list(rows)
            for model, rows in rows_by_model.items()
        }

    def query(self, model):
        return DummyQuery(self._rows_by_model.get(model, []))

    def add(self, row):
        self._rows_by_model.setdefault(type(row), []).append(row)

    def flush(self):
        return None

    def commit(self):
        return None


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=1,
        organization_id=7,
        email="architect@risklence.test",
        roles=["admin"],
        permissions=[],
    )


def test_get_process_graph_returns_process_and_service_nodes():
    process = ValueStream(
        id="vs-order-to-cash",
        organization_id=7,
        library_item_id="order_to_cash",
        name="Order to Cash",
        priority="critical",
        source="in_platform",
    )
    service = BusinessService(
        id="svc-orders",
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
        bia_answers={
            "impact1h": "low",
            "impact4h": "low",
            "impact24h": "low",
            "mtd": "gt_24h",
            "dataSensitivity": "low",
            "workaround": "yes",
            "alternativeChannel": "full",
        },
    )
    bundle = DependencyBundle(
        id="bundle-orders",
        organization_id=7,
        service_id="svc-orders",
        status="draft",
        mode="manual_training",
        lifecycle_state="bundle_published",
        groups=[],
    )
    db = DummyDB({
        ValueStream: [process],
        BusinessService: [service],
        DependencyBundle: [bundle],
    })

    response = graph.get_scoped_graph(level="process", id="vs-order-to-cash", ctx=_ctx(), db=db)

    assert response.level == "process"
    assert response.nodes[0].id == "vs-order-to-cash"
    assert response.nodes[1].id == "svc-orders"
    assert response.nodes[1].type == "service"
    assert response.edges[0].from_id == "vs-order-to-cash"
    assert response.edges[0].to_id == "svc-orders"


def test_get_service_graph_returns_dependency_nodes_with_encoded_scope_ids():
    service = BusinessService(
        id="svc-orders",
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
    bundle = DependencyBundle(
        id="bundle-orders",
        organization_id=7,
        service_id="svc-orders",
        status="draft",
        mode="manual_training",
        lifecycle_state="bundle_published",
        groups=[
            {
                "key": "network_connectivity",
                "label": "Network connectivity",
                "description": "Core network paths.",
                "required": True,
            }
        ],
    )
    slot = SlotInstance(
        id="slot-network",
        organization_id=7,
        service_id="svc-orders",
        slot_id="network_connectivity",
        group_key="network_connectivity",
        status="mapped",
        asset_id="asset-11",
        asset_label="Core WAN",
    )
    db = DummyDB({
        BusinessService: [service],
        DependencyBundle: [bundle],
        SlotInstance: [slot],
    })

    response = graph.get_scoped_graph(level="service", id="svc-orders", ctx=_ctx(), db=db)

    assert response.level == "service"
    assert response.nodes[0].id == "svc-orders"
    assert response.nodes[1].id == graph.encode_dependency_scope_id("svc-orders", "network_connectivity")
    assert response.nodes[1].type == "dependency"


def test_get_dependency_graph_returns_asset_nodes_and_spof_edge():
    service = BusinessService(
        id="svc-orders",
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
    bundle = DependencyBundle(
        id="bundle-orders",
        organization_id=7,
        service_id="svc-orders",
        status="draft",
        mode="manual_training",
        lifecycle_state="bundle_published",
        groups=[
            {
                "key": "network_connectivity",
                "label": "Network connectivity",
                "description": "Core network paths.",
                "required": True,
            }
        ],
    )
    slot = SlotInstance(
        id="slot-network",
        organization_id=7,
        service_id="svc-orders",
        slot_id="network_connectivity",
        group_key="network_connectivity",
        status="mapped",
        asset_id="asset-11",
        asset_label="Core WAN",
    )
    asset = Asset(
        id=11,
        organization_id=7,
        display_name="Core WAN",
        type="network",
        level=2,
        is_spof=True,
        risk_score=7.4,
        findings_count=3,
    )
    db = DummyDB({
        BusinessService: [service],
        DependencyBundle: [bundle],
        SlotInstance: [slot],
        Asset: [asset],
    })

    response = graph.get_scoped_graph(
        level="dependency",
        id=graph.encode_dependency_scope_id("svc-orders", "network_connectivity"),
        ctx=_ctx(),
        db=db,
    )

    assert response.level == "dependency"
    assert response.nodes[0].type == "dependency"
    assert response.nodes[1].id == "asset-11"
    assert response.nodes[1].is_spof is True
    assert response.edges[0].edge_type == "single_point_of_failure"


def test_parse_dependency_scope_id_rejects_invalid_value():
    with pytest.raises(HTTPException):
        graph.parse_dependency_scope_id("svc-orders-only")
