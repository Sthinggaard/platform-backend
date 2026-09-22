from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import processes
from src.core.constants import SERVICE_TIER_BUSINESS_CRITICAL
from src.core.model_defs.risk_appetite_policy import (
    APPETITE_POLICY_DRAFT,
    APPETITE_SCOPE_BUSINESS_PROCESS,
)
from src.core.models import (
    BusinessService,
    DependencyBundle,
    OrgProcessConfig,
    RiskAppetitePolicy,
    ValueStream,
)
from src.core.services.process_activation_readiness_service import ProcessActivationReadiness


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
            next_rows = []
            for row in filtered:
                row_value = getattr(row, field_name, None)
                if isinstance(value, list):
                    if isinstance(row_value, list):
                        if all(item in row_value for item in value):
                            next_rows.append(row)
                        continue
                    if row_value in value:
                        next_rows.append(row)
                        continue
                if row_value == value:
                    next_rows.append(row)
            filtered = next_rows
        self._rows = filtered
        return self

    def order_by(self, *_args, **_kwargs):
        # No test using this double seeds RiskAppetitePolicy/ServiceAppetiteReassessment
        # rows directly, so ordering is a no-op here — see test_processes_appetite_resolution.py
        # for real cascade-resolution coverage against a real SQLite session.
        return self

    def all(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None


class DummyScalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)


class DummyResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return DummyScalars(self._rows)


class DummyDB:
    def __init__(self, rows_by_model):
        self._rows_by_model = rows_by_model
        self.added = []
        self.committed = False

    def query(self, model):
        return DummyQuery(self._rows_by_model.get(model, []))

    def execute(self, stmt):
        # Enough to serve TenantRepository.filter_by: ONB-08B's tailoring-signal
        # recording looks up any existing BusinessProcessActivation this way.
        # Ignores the filter clauses — every fixture using this exercises the
        # "no such row" case, so returning the model's full (empty) row list is
        # exactly the answer a real session would give.
        model = stmt.column_descriptions[0]["entity"]
        return DummyResult(self._rows_by_model.get(model, []))

    def add(self, row):
        self.added.append(row)
        if row not in self._rows_by_model.setdefault(type(row), []):
            self._rows_by_model[type(row)].append(row)

    def flush(self):
        pass

    def commit(self):
        self.committed = True


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=11,
        organization_id=7,
        email="architect@risklence.test",
        roles=["admin"],
        permissions=[],
    )


def test_update_process_services_syncs_template_membership(monkeypatch):
    monkeypatch.setattr(processes, "require_process_editor", lambda *args, **kwargs: None)
    process = ValueStream(
        id="vs-order-to-cash",
        organization_id=7,
        library_item_id="order_to_cash",
        name="Order to Cash",
        priority="critical",
        source="in_platform",
    )
    config = OrgProcessConfig(
        id="cfg-process",
        organization_id=7,
        template_key="order_to_cash",
        excluded_service_keys=["billing_service"],
        custom_service_slots=[],
        note=None,
    )
    existing_order = BusinessService(
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
    existing_payment = BusinessService(
        id="svc-payment",
        organization_id=7,
        name="Payment Processing",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="",
        library_item_id="payment_processing",
        archetype="transactional_system",
        value_stream_ids=["vs-order-to-cash", "vs-other"],
        l1=[],
        l2=[],
        l3=[],
    )
    db = DummyDB(
        {
            ValueStream: [process],
            OrgProcessConfig: [config],
            BusinessService: [existing_order, existing_payment],
            DependencyBundle: [],
        }
    )
    monkeypatch.setattr(
        processes,
        "get_active_service_template",
        lambda _db, _service_key: SimpleNamespace(version=5),
    )
    monkeypatch.setattr(
        processes,
        "_build_capability_groups_for_service",
        lambda _service, _db: [],
    )

    response = processes.update_process_services(
        "vs-order-to-cash",
        processes.UpdateProcessServicesRequest(
            included_service_keys=["order_management", "billing_service"],
        ),
        ctx=_ctx(),
        db=db,
    )

    created_billing = next(
        service
        for service in db._rows_by_model[BusinessService]
        if service.library_item_id == "billing_service"
    )

    assert db.committed is True
    assert config.excluded_service_keys == ["payment_processing"]
    assert created_billing.value_stream_ids == ["vs-order-to-cash"]
    assert created_billing.template_key == "billing_service"
    assert created_billing.template_version == 5
    assert existing_payment.value_stream_ids == ["vs-other"]
    assert response.core_service_keys == ["order_management", "billing_service"]
    assert {service.library_item_id for service in response.services} == {
        "order_management",
        "billing_service",
    }


def test_update_process_services_rejects_non_template_process(monkeypatch):
    monkeypatch.setattr(processes, "require_process_editor", lambda *args, **kwargs: None)
    process = ValueStream(
        id="vs-custom",
        organization_id=7,
        library_item_id=None,
        name="Custom Process",
        priority="important",
        source="in_platform",
    )
    db = DummyDB(
        {ValueStream: [process], BusinessService: [], OrgProcessConfig: [], DependencyBundle: []}
    )

    with pytest.raises(HTTPException) as exc_info:
        processes.update_process_services(
            "vs-custom",
            processes.UpdateProcessServicesRequest(included_service_keys=["order_management"]),
            ctx=_ctx(),
            db=db,
        )

    assert exc_info.value.status_code == 422


def test_update_process_services_rejects_unknown_service_keys(monkeypatch):
    monkeypatch.setattr(processes, "require_process_editor", lambda *args, **kwargs: None)
    process = ValueStream(
        id="vs-order-to-cash",
        organization_id=7,
        library_item_id="order_to_cash",
        name="Order to Cash",
        priority="critical",
        source="in_platform",
    )
    db = DummyDB(
        {ValueStream: [process], BusinessService: [], OrgProcessConfig: [], DependencyBundle: []}
    )

    with pytest.raises(HTTPException) as exc_info:
        processes.update_process_services(
            "vs-order-to-cash",
            processes.UpdateProcessServicesRequest(included_service_keys=["not_real_service"]),
            ctx=_ctx(),
            db=db,
        )

    assert exc_info.value.status_code == 422


def test_build_process_detail_response_includes_capability_groups(monkeypatch):
    process = ValueStream(
        id="vs-order-to-cash",
        organization_id=7,
        library_item_id="order_to_cash",
        name="Order to Cash",
        priority="critical",
        source="in_platform",
    )
    service = BusinessService(
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
    db = DummyDB(
        {
            ValueStream: [process],
            BusinessService: [service],
            OrgProcessConfig: [],
            DependencyBundle: [],
        }
    )
    monkeypatch.setattr(
        processes,
        "_build_capability_groups_for_service",
        lambda _service, _db: [
            {
                "group_key": "core",
                "group_name": "Core",
                "slots": [],
            }
        ],
    )

    response = processes._build_process_detail_response(process, db)

    assert response.process_id == "vs-order-to-cash"
    assert response.service_count == 1
    assert response.services[0].capability_groups[0].group_key == "core"
    assert response.services[0].linked_asset_ids == []


def test_build_process_health_surfaces_owner_bia_and_appetite_status():
    process = ValueStream(
        id="vs-order-to-cash",
        organization_id=7,
        name="Order to Cash",
        priority="critical",
        source="in_platform",
    )
    db = DummyDB({OrgProcessConfig: []})
    readiness = ProcessActivationReadiness(
        process_id="vs-order-to-cash",
        activation_id=None,
        state="bia_required",
        next_action="bia_required",
        confirmation_outcome="confirmed",
        process_confirmed=True,
        owner_assigned=True,
        owner_user_id=2,
        ownership_accepted=True,
        bia_attested=False,
        organisation_appetite_effective=False,
        impact_model_active=False,
    )

    response = processes._build_process_health(
        process,
        [],
        db,
        readiness=readiness,
        owner_name="Søren Thinggaard",
        appetite_status="pending_review",
    )

    assert response.owner_user_id == 2
    assert response.owner_name == "Søren Thinggaard"
    assert response.ownership_accepted is True
    assert response.bia_attested is False
    assert response.appetite_status == "pending_review"


def test_build_process_health_defaults_when_no_owner_assigned():
    process = ValueStream(
        id="vs-order-to-cash",
        organization_id=7,
        name="Order to Cash",
        priority="critical",
        source="in_platform",
    )
    db = DummyDB({OrgProcessConfig: []})

    response = processes._build_process_health(process, [], db)

    assert response.owner_user_id is None
    assert response.owner_name is None
    assert response.ownership_accepted is False
    assert response.bia_attested is False
    assert response.appetite_status == "not_set"


def test_build_process_detail_response_includes_linked_asset_ids(monkeypatch):
    process = ValueStream(
        id="vs-billing",
        organization_id=7,
        library_item_id="order_to_cash",
        name="Billing",
        priority="critical",
        source="in_platform",
    )
    service = BusinessService(
        id="svc-billing",
        organization_id=7,
        name="Billing Platform",
        tier=SERVICE_TIER_BUSINESS_CRITICAL,
        trading_impact="",
        library_item_id="billing_service",
        archetype="transactional_system",
        value_stream_ids=["vs-billing"],
        l1=["asset-10", "asset-11"],
        l2=[],
        l3=[],
    )
    db = DummyDB(
        {
            ValueStream: [process],
            BusinessService: [service],
            OrgProcessConfig: [],
            DependencyBundle: [],
        }
    )
    monkeypatch.setattr(
        processes,
        "_build_capability_groups_for_service",
        lambda _service, _db: [],
    )

    response = processes._build_process_detail_response(process, db)

    assert response.services[0].linked_asset_ids == ["asset-10", "asset-11"]


def _process_for_appetite() -> ValueStream:
    return ValueStream(
        id="vs-billing",
        organization_id=7,
        name="Billing",
        priority="critical",
        source="in_platform",
    )


def test_the_detail_route_reports_the_appetite_the_process_resolved(monkeypatch):
    """The process page reads its own route, and that route was silent.

    `list_processes` has derived `appetite_status` since #379; the detail route
    never did, so `ProcessDetailResponse` had no such field and the tenant read
    `undefined` — which the process map header prints as "appetite not
    configured", for a process carrying its own active policy.
    """
    process = _process_for_appetite()
    db = DummyDB({ValueStream: [process], BusinessService: [], OrgProcessConfig: []})
    monkeypatch.setattr(
        processes,
        "resolve_process_appetite",
        lambda *_args, **_kwargs: SimpleNamespace(policy_id="rap-1"),
    )

    response = processes._build_process_detail_response(process, db)

    assert response.appetite_status == "active"


def test_a_process_whose_only_policy_is_unapproved_is_pending_review(monkeypatch):
    process = _process_for_appetite()
    draft = RiskAppetitePolicy(
        id="rap-draft",
        organization_id=7,
        scope=APPETITE_SCOPE_BUSINESS_PROCESS,
        process_id="vs-billing",
        status=APPETITE_POLICY_DRAFT,
    )
    db = DummyDB(
        {
            ValueStream: [process],
            BusinessService: [],
            OrgProcessConfig: [],
            RiskAppetitePolicy: [draft],
        }
    )
    monkeypatch.setattr(processes, "resolve_process_appetite", lambda *_args, **_kwargs: None)

    response = processes._build_process_detail_response(process, db)

    assert response.appetite_status == "pending_review"


def test_a_process_that_has_decided_nothing_is_not_set(monkeypatch):
    process = _process_for_appetite()
    db = DummyDB(
        {
            ValueStream: [process],
            BusinessService: [],
            OrgProcessConfig: [],
            RiskAppetitePolicy: [],
        }
    )
    monkeypatch.setattr(processes, "resolve_process_appetite", lambda *_args, **_kwargs: None)

    response = processes._build_process_detail_response(process, db)

    assert response.appetite_status == "not_set"


### `_has_configured_appetite`/`BusinessServiceAppetiteConfig` were retired in
### BPS-38 — appetite completeness now resolves through the RiskAppetitePolicy
### cascade (`_resolve_service_appetite`), covered against a real SQLite
### session in test_processes_appetite_resolution.py (the DummyDB double here
### can't exercise `.order_by()`-using queries).
