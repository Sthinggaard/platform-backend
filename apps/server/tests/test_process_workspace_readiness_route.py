"""Workspace readiness: what the Process Map, its chips and its notice deck read.

#460 (Søren, 2026-09-15): a service's live dependency state is composed from its slot records, the
one live record of a dependency decision. A stored bundle supplies identity, lifecycle and group
metadata; its nodes are the published snapshot and are never read here. That is what fixes #452:
an answer given in the step slide-out used to leave the map on `NO DEPS`, because this route counted
only bundle nodes.
"""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import process_workspace_readiness as route
from src.core.services.dependency_decision_service import ServiceSlotContext

COMPLETE_BIA = {
    "impact1h": "high",
    "impact4h": "high",
    "impact24h": "medium",
    "mtd": "short",
    "dataSensitivity": "high",
    "workaround": "manual",
    "alternativeChannel": "none",
}

CANONICAL_SLOT = "order_processing.data.order_store"


def _ctx() -> TenantContext:
    return TenantContext(
        user_id=7,
        organization_id=11,
        email="admin@example.test",
        roles=["admin"],
        permissions=[],
    )


def _process(description: str | None = "Keep customer orders moving.") -> SimpleNamespace:
    return SimpleNamespace(
        id="process-1",
        library_item_id="saas_operations",
        name="Customer operations",
        description=description,
        source="inferred",
    )


def _service() -> SimpleNamespace:
    return SimpleNamespace(
        id="service-1",
        value_stream_ids=["process-1"],
        archived_at=None,
        name="Order processing",
        tier="business_critical",
        library_item_id="order_processing",
        owner_user_id=None,
        bia_answers=None,
        l1=[],
    )


def _bundle(nodes: list[dict] | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        id="bundle-1",
        service_id="service-1",
        lifecycle_state="bundle_manual_training",
        groups=[{"key": "data", "label": "Data", "required": True, "nodes": nodes or []}],
        validation_snapshot=None,
    )


def _record(slot_id: str = CANONICAL_SLOT, group_key: str = "data", **fields) -> SimpleNamespace:
    """A slot record a person decided in the slide-out: mapped to asset 92."""
    values = {
        "id": f"row-{slot_id}",
        "slot_id": slot_id,
        "group_key": group_key,
        "status": "mapped",
        "asset_id": "asset-92",
        "asset_label": "Orders database",
        "mapping_status": "approved",
        "mapping_confidence": 1.0,
        "evidence_source": "manual",
        "decided_by": "7",
    }
    values.update(fields)
    return SimpleNamespace(**values)


def _serve(
    monkeypatch: pytest.MonkeyPatch,
    *,
    bundles: list,
    records: list,
    bia: dict | None = COMPLETE_BIA,
    observed_asset_ids: tuple[int, ...] = (),
    description: str | None = "Keep customer orders moving.",
):
    process = _process(description)
    service = _service()
    observed = [
        SimpleNamespace(id=asset_id, last_observed_at=datetime.now(timezone.utc), is_spof=False)
        for asset_id in observed_asset_ids
    ]
    # A human has confirmed this is how the organisation works. Without it the
    # workspace is `uncertain` — Risklence's suggestion, not their answer.
    activations = [SimpleNamespace(process_id="process-1", confirmation_outcome="confirmed")]

    class FakeRepository:
        def __init__(self, _db, model, _organization_id):
            self.model = model

        def get_by_id(self, _row_id):
            return process if self.model is route.ValueStream else None

        def get_all(self):
            return {
                route.BusinessService: [service],
                route.DependencyBundle: bundles,
                route.Asset: observed,
                route.BusinessProcessActivation: activations,
            }.get(self.model, [])

    monkeypatch.setattr(route, "TenantRepository", FakeRepository)
    monkeypatch.setattr(
        route,
        "load_service_slot_context",
        lambda _db, _service: ServiceSlotContext(
            records=records,
            canonical_slot_ids=frozenset({CANONICAL_SLOT}),
            slot_labels={CANONICAL_SLOT: "Order store"},
            template_version=1,
        ),
    )
    monkeypatch.setattr(
        route,
        "resolve_effective_process_bia_by_process",
        lambda *_args, **_kwargs: {"process-1": SimpleNamespace(answers=bia)},
    )
    monkeypatch.setattr(route, "resolve_process_appetite", lambda *_args, **_kwargs: object())
    # #463 — no service holds an exception here, so each inherits the process's BIA.
    monkeypatch.setattr(route, "active_bia_exceptions", lambda *_args, **_kwargs: {})
    return route.get_process_workspace_readiness("process-1", _ctx(), object())


def test_readiness_route_projects_initial_facts_and_a_service_nobody_has_mapped(monkeypatch):
    """Nobody has answered a slot: one mapping gap, no evidence gap, and nothing started."""
    response = _serve(monkeypatch, bundles=[_bundle()], records=[])

    assert response.state.value == "prepared"
    assert response.release_allowed is True
    assert response.service_count == 1
    assert response.dependency_mapping_gap_count == 1
    assert response.evidence_gap_count == 0
    assert response.process_name == "Customer operations"
    assert response.outcome_statement == "Keep customer orders moving."
    dependency = response.services[0].dependency
    assert dependency.bundle_id == "bundle-1"
    assert dependency.dependency_mapping_started is False
    assert dependency.slots == []


def test_a_stored_bundle_node_is_never_read_as_live_state(monkeypatch):
    """#460: the stored node is the published snapshot. Only slot records count."""
    stale = {"id": "slot-1", "label": "Stale snapshot", "linked_asset_ids": ["asset-5"]}

    response = _serve(monkeypatch, bundles=[_bundle([stale])], records=[])

    assert response.services[0].dependency.slots == []


def test_an_answer_given_in_the_slide_out_counts_on_the_map(monkeypatch):
    """⚠️ #452, pinned. The bundle holds no node; the slot record holds the decision. The map
    used to keep `NO DEPS` until publish."""
    response = _serve(
        monkeypatch, bundles=[_bundle()], records=[_record()], observed_asset_ids=(92,)
    )

    dependency = response.services[0].dependency
    assert dependency.dependency_mapping_started is True
    assert [slot.slot_id for slot in dependency.slots] == [CANONICAL_SLOT]
    assert dependency.slots[0].status.value == "mapped"
    assert dependency.slots[0].linked_asset_ids == ["asset-92"]
    assert dependency.slots[0].label == "Order store"
    assert response.dependency_mapping_gap_count == 0
    assert response.evidence_gap_count == 0


def test_a_named_dependency_nothing_observed_backs_is_an_evidence_gap(monkeypatch):
    response = _serve(monkeypatch, bundles=[_bundle()], records=[_record()])

    assert response.dependency_mapping_gap_count == 0
    assert response.evidence_gap_count == 1


def test_a_service_with_no_bundle_row_counts_once_a_slot_is_answered(monkeypatch):
    """The slide-out can answer a slot before any bundle exists."""
    response = _serve(monkeypatch, bundles=[], records=[_record()], observed_asset_ids=(92,))

    dependency = response.services[0].dependency
    assert dependency.bundle_id is None
    assert dependency.dependency_mapping_started is True
    assert len(dependency.slots) == 1


def test_an_orphaned_decision_reaches_the_map_flagged_for_review(monkeypatch):
    """Søren, 2026-09-15: a decision whose slot left the template stays live, flagged (#472)."""
    orphan = _record("order_processing_legacy.data.order_store")

    response = _serve(monkeypatch, bundles=[_bundle()], records=[orphan], observed_asset_ids=(92,))

    [slot] = response.services[0].dependency.slots
    assert slot.template_orphaned is True


def test_teams_are_not_dependencies_on_the_map(monkeypatch):
    """#434: the accountable team is not a dependency question; its rows are not counted."""
    response = _serve(monkeypatch, bundles=[_bundle()], records=[_record("teams", "teams")])

    dependency = response.services[0].dependency
    assert dependency.slots == []
    assert dependency.dependency_mapping_started is False


def test_readiness_route_does_not_release_without_initial_bia(monkeypatch):
    response = _serve(monkeypatch, bundles=[], records=[], bia=None, description=None)

    assert response.state.value == "incomplete"
    assert response.release_allowed is False
    assert response.reasons[0].value == "bia_missing"
