"""Workspace projection: per-slot gap attribution, and totals that are the sum of parts."""

from __future__ import annotations

from types import SimpleNamespace

from src.core.constants.process_workspace_enums import ProcessWorkspaceDependencySlotStatus
from src.core.services.process_workspace_projection_service import (
    build_workspace_service_contexts,
    workspace_gap_totals,
)

COMPLETE_BIA = {
    "mtd": "le_4h",
    "dataSensitivity": "high",
    "regulatoryExposure": "high",
    "customerImpact": "high",
    "revenueImpact": "high",
    "operationalDependency": "high",
}


def _service(
    service_id: str = "svc-1",
    name: str = "Checkout",
    *,
    processes: list[str] | None = None,
    assets: list[str] | None = None,
):
    return SimpleNamespace(
        id=service_id,
        name=name,
        tier="Mission Critical",
        library_item_id="lib-1",
        owner_user_id=2,
        bia_answers=None,
        archived_at=None,
        value_stream_ids=processes if processes is not None else ["process-1"],
        l1=assets if assets is not None else ["asset-1"],
        l2=None,
        l3=None,
    )


def _bundle(*, service_id: str = "svc-1", nodes: list[dict], findings: list[dict] | None = None):
    return SimpleNamespace(
        id="bundle-1",
        service_id=service_id,
        lifecycle_state="bundle_validated",
        groups=[{"key": "payments", "nodes": nodes}],
        validation_snapshot={"findings": findings or []},
    )


def _node(
    slot_id: str,
    *,
    linked: list[str] | None = None,
    deferred: bool = False,
    spof=None,
):
    return {
        "id": slot_id,
        "label": slot_id.replace("-", " ").title(),
        "linked_asset_ids": linked or [],
        "deferred_asset_mapping": deferred,
        "spof": spof,
    }


def _contexts(
    services,
    bundles_by_service_id,
    *,
    observed: set[str] | None = None,
    spof_assets: set[str] | None = None,
    organisation_services=None,
    process_id: str = "process-1",
):
    return build_workspace_service_contexts(
        services,
        bundles_by_service_id,
        process_id=process_id,
        process_bia_answers=COMPLETE_BIA,
        bia_exceptions_by_service_id={},
        appetite_complete=True,
        observed_asset_refs=frozenset(observed or set()),
        spof_asset_refs=frozenset(spof_assets or set()),
        organisation_services=organisation_services
        if organisation_services is not None
        else services,
    )


def test_an_asserted_dependency_with_nothing_observed_is_an_evidence_gap():
    """Søren, 2026-08-30: evidence comes from the scanner and the collected artefacts.

    A dependency somebody typed in, pointing at an asset the Collector has never
    seen, is named but not evidenced — analysis has no artefact to work on, so
    the dependency setup cannot be assessed however confidently it was entered.
    """
    service = _service()
    bundle = _bundle(
        nodes=[
            _node("observed", linked=["asset-1"]),
            _node("asserted", linked=["asset-99"]),
        ]
    )

    [context] = _contexts([service], {"svc-1": bundle}, observed={"asset-1"})
    flagged = {slot.slot_id: slot.evidence_gap for slot in context.slots}

    assert flagged == {"observed": False, "asserted": True}
    assert context.evidence_gap_count == 1


def test_one_observed_asset_is_enough_to_evidence_a_slot():
    service = _service()
    bundle = _bundle(nodes=[_node("mixed", linked=["asset-99", "asset-1"])])

    [context] = _contexts([service], {"svc-1": bundle}, observed={"asset-1"})

    assert context.slots[0].evidence_gap is False
    assert context.evidence_gap_count == 0


def test_an_unmapped_slot_is_a_mapping_gap_and_not_also_an_evidence_gap():
    """The two gaps are different questions; counting one slot twice overstates.

    Nothing has been identified yet, so the user is asked to find the
    dependency. That is not the same as having named one nothing backs.
    """
    service = _service()
    bundle = _bundle(nodes=[_node("nothing-yet")])

    [context] = _contexts([service], {"svc-1": bundle}, observed={"asset-1"})

    assert context.slots[0].status is ProcessWorkspaceDependencySlotStatus.UNMAPPED
    assert context.slots[0].evidence_gap is False
    assert context.mapping_gap_count == 1
    assert context.evidence_gap_count == 0


def test_slot_status_distinguishes_deferred_from_unmapped():
    """Deferred is a human decision; unmapped is nobody having done it yet."""
    service = _service()
    bundle = _bundle(
        nodes=[
            _node("mapped", linked=["asset-9"]),
            _node("deferred", deferred=True),
            _node("unmapped"),
        ]
    )

    [context] = _contexts([service], {"svc-1": bundle})
    statuses = {slot.slot_id: slot.status for slot in context.slots}

    assert statuses == {
        "mapped": ProcessWorkspaceDependencySlotStatus.MAPPED,
        "deferred": ProcessWorkspaceDependencySlotStatus.DEFERRED,
        "unmapped": ProcessWorkspaceDependencySlotStatus.UNMAPPED,
    }
    # Only the unmapped slot is a gap — a deferred one was decided.
    assert context.mapping_gap_count == 1


def test_totals_are_the_sum_of_the_per_service_counts():
    service_a = _service("svc-1", "Checkout")
    service_b = _service("svc-2", "Fulfilment")
    bundles = {
        "svc-1": _bundle(
            service_id="svc-1",
            nodes=[_node("a1"), _node("a2", linked=["asset-99"])],
        ),
        # svc-2 has no bundle at all — itself one mapping gap.
    }

    contexts = _contexts([service_a, service_b], bundles, observed={"asset-1"})
    mapping_gaps, evidence_gaps = workspace_gap_totals(contexts)

    assert [c.mapping_gap_count for c in contexts] == [1, 1]
    assert mapping_gaps == sum(c.mapping_gap_count for c in contexts) == 2
    assert evidence_gaps == sum(c.evidence_gap_count for c in contexts) == 1


def test_a_malformed_bundle_row_is_skipped_rather_than_raising():
    """The aggregate and the detail used to guard this differently.

    `_service_context` skipped non-dict groups and nodes; the separate gap
    counter did not, and would raise on the same row. Two derivations of one
    number, one of which crashed.
    """
    service = _service()
    bundle = SimpleNamespace(
        id="bundle-1",
        service_id="svc-1",
        lifecycle_state="template_loaded",
        groups=["not-a-group", {"key": "ok", "nodes": ["not-a-node", _node("real")]}],
        validation_snapshot=None,
    )

    contexts = _contexts([service], {"svc-1": bundle})
    mapping_gaps, evidence_gaps = workspace_gap_totals(contexts)

    assert [slot.slot_id for slot in contexts[0].slots] == ["real"]
    assert mapping_gaps == 1  # the one real slot is unmapped
    assert evidence_gaps == 0


def test_an_unanswered_spof_question_is_not_a_no():
    """60 of 75 live slots have never been asked. `null` must stay `null`.

    Rendering an unanswered question as "not a single point of failure" is the
    platform claiming something nobody checked.
    """
    service = _service()
    bundle = _bundle(
        nodes=[
            _node("asked-yes", linked=["asset-1"], spof=True),
            _node("asked-no", linked=["asset-1"], spof=False),
            _node("never-asked", linked=["asset-1"]),
        ]
    )

    [context] = _contexts([service], {"svc-1": bundle}, observed={"asset-1"})
    answers = {slot.slot_id: slot.single_point_of_failure for slot in context.slots}

    assert answers == {"asked-yes": True, "asked-no": False, "never-asked": None}
    # Only an actual yes counts.
    assert context.spof_slot_count == 1


def test_a_spof_claim_carries_the_assets_it_rests_on():
    """Stated with its grounds, never as a bare score."""
    service = _service()
    bundle = _bundle(nodes=[_node("db", linked=["asset-1", "asset-2"], spof=True)])

    [context] = _contexts(
        [service],
        {"svc-1": bundle},
        observed={"asset-1", "asset-2"},
        spof_assets={"asset-2"},
    )

    assert context.slots[0].spof_asset_ids == ["asset-2"]


def test_a_shared_dependency_names_the_other_processes_that_go_down_with_it():
    """A single process's view is exactly where shared exposure gets missed."""
    this_process_service = _service("svc-1", processes=["process-1"], assets=["asset-1"])
    other_process_service = _service(
        "svc-2", "Fulfilment", processes=["process-2", "process-3"], assets=["asset-1"]
    )
    bundle = _bundle(nodes=[_node("shared-db", linked=["asset-1"], spof=True)])

    [context] = _contexts(
        [this_process_service],
        {"svc-1": bundle},
        observed={"asset-1"},
        spof_assets={"asset-1"},
        organisation_services=[this_process_service, other_process_service],
    )

    # This process is not listed as sharing with itself.
    assert context.slots[0].shared_with_process_ids == ["process-2", "process-3"]


def test_an_archived_service_does_not_widen_the_blast_radius():
    this_process_service = _service("svc-1", processes=["process-1"], assets=["asset-1"])
    archived = _service("svc-2", "Retired", processes=["process-9"], assets=["asset-1"])
    archived.archived_at = "2026-01-01"
    bundle = _bundle(nodes=[_node("db", linked=["asset-1"])])

    [context] = _contexts(
        [this_process_service],
        {"svc-1": bundle},
        observed={"asset-1"},
        organisation_services=[this_process_service, archived],
    )

    assert context.slots[0].shared_with_process_ids == []


def test_both_stored_asset_reference_shapes_are_understood():
    """Two flows write this field in two shapes, and both mean the same thing.

    The slot-mapping wizard stores `"asset-92"`; the manual dependency review
    stores the bare integer `92`. Reading only strings dropped every manually
    reviewed dependency — the slot reported as Unmapped while a human was
    looking at the asset they had linked to it, which also inflated the mapping
    gap count and hid the SPOF and evidence signals on exactly those slots.
    """
    service = _service()
    bundle = _bundle(
        nodes=[
            _node("from-wizard", linked=["asset-92"], spof=True),
            _node("from-manual-review", linked=[92], spof=True),
        ]
    )

    [context] = _contexts(
        [service],
        {"svc-1": bundle},
        observed={"asset-92"},
        spof_assets={"asset-92"},
    )

    by_id = {slot.slot_id: slot for slot in context.slots}
    assert by_id["from-manual-review"].linked_asset_ids == ["asset-92"]
    assert by_id["from-manual-review"].status is ProcessWorkspaceDependencySlotStatus.MAPPED
    assert by_id["from-manual-review"].spof_asset_ids == ["asset-92"]
    # Both shapes resolve to the same asset, so neither is a gap.
    assert context.mapping_gap_count == 0
    assert context.evidence_gap_count == 0


def test_a_reference_that_is_not_an_asset_id_is_skipped_not_invented():
    service = _service()
    bundle = _bundle(nodes=[_node("odd", linked=["", "   ", True, None])])

    [context] = _contexts([service], {"svc-1": bundle})

    assert context.slots[0].linked_asset_ids == []
    assert context.slots[0].status is ProcessWorkspaceDependencySlotStatus.UNMAPPED


def test_a_bundle_with_nothing_in_it_is_still_a_service_nobody_has_started():
    """#433. The gap used to be `bundle is None`, and that stopped being the question.

    Deciding one slot now creates the bundle row its audit trail is written
    against, so a service that has answered nothing can hold a bundle loaded
    from its template — five groups, no nodes. Under the old rule its one
    mapping gap disappeared the moment the row appeared, and *Contract
    Management* went from "no dependency mapping at all" to no gap at all
    without anybody answering anything.
    """
    service = _service(service_id="svc-contract", name="Contract Management")
    template_loaded = SimpleNamespace(
        id="bundle-new",
        service_id="svc-contract",
        lifecycle_state="template_loaded",
        groups=[{"key": "data", "nodes": []}, {"key": "systems", "nodes": []}],
        validation_snapshot={"findings": []},
    )

    [context] = _contexts([service], {"svc-contract": template_loaded})

    assert context.slots == []
    assert context.dependency_mapping_started is False
    assert context.mapping_gap_count == 1


def test_a_service_with_no_bundle_reads_exactly_as_it_did_before():
    service = _service(service_id="svc-contract", name="Contract Management")

    [context] = _contexts([service], {})

    assert context.dependency_mapping_started is False
    assert context.mapping_gap_count == 1


def test_a_service_with_slots_has_started_however_few_are_answered():
    service = _service()
    bundle = _bundle(nodes=[_node("unanswered")])

    [context] = _contexts([service], {"svc-1": bundle})

    assert context.dependency_mapping_started is True
    # One slot, unmapped — one gap, and not a second one for the service.
    assert context.mapping_gap_count == 1
