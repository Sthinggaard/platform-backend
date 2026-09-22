"""Projection of a prepared Business Process workspace's services and dependencies.

Sits beside the evaluator it feeds. The route used to hold this, and computed the
aggregate gap counts a second time from a second query — the two copies guarded
malformed rows differently, so the total and the per-service detail shown on the
same screen could disagree with no way to tell which was right. Here the
per-service contexts are built once and the totals are their sum, so they cannot.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from src.core.constants.process_workspace_enums import ProcessWorkspaceDependencySlotStatus
from src.core.model_defs.value_streams import BusinessService, DependencyBundle
from src.core.services.asset_context_service import normalise_asset_reference
from src.core.services.bia_inheritance_service import (
    BiaExceptionRecord,
    bia_is_complete,
    effective_service_bia,
)

# What an evidence gap is. Søren, 2026-08-30:
#
#   "evidence should come from the scanner and the collected artefacts. These are
#   the dependencies for e.g. a payment or subscription. So the collector finds
#   this dependency when it scans... If there is no artefact or dependency found
#   then there is a dependency gap. This is where the user is asked to find the
#   dependency for the system to be able to at some point, via the analysis,
#   capture potential vulnerabilities in the dependency setup."
#
# So the two gaps are different questions about the same slot, and neither
# substitutes for the other:
#
#   mapping gap   — no dependency has been identified at all. The user is asked
#                   to supply it.
#   evidence gap  — a dependency *is* named, but nothing the Collector observed
#                   backs it. Somebody asserted it. Vulnerability analysis has
#                   no artefact to work on, so the dependency cannot be assessed
#                   however confidently it was typed in.
#
# A slot with no dependency at all is a mapping gap and not also an evidence gap:
# counting it twice would overstate how much is unevidenced.
#
# This replaces a substring search for the word "evidence" in a validation
# finding's id or message. Nothing ever produced such a finding, so every
# evidence gap read as a clean zero — indistinguishable from having none.


@dataclass(frozen=True)
class WorkspaceDependencySlot:
    """One dependency slot, with the gap flags that belong to *this* slot."""

    slot_id: str
    label: str | None
    group_key: str | None
    status: ProcessWorkspaceDependencySlotStatus
    linked_asset_ids: list[str]
    deferred_asset_mapping: bool
    evidence_gap: bool
    # Tri-state on purpose. `None` means nobody has answered whether this
    # dependency is a single point of failure — 60 of 75 live slots are in that
    # state — and an unanswered question must not read as "no".
    single_point_of_failure: bool | None
    # The observable basis for the claim: linked assets independently flagged as
    # single points of failure. A SPOF is stated with its grounds, never as a
    # score and never as a verdict the platform reached on its own.
    spof_asset_ids: list[str]
    # Other Business Processes whose services depend on the same assets. If this
    # dependency goes down, they go with it — and a single process's view is
    # exactly where that gets missed.
    shared_with_process_ids: list[str]
    # #460 (Søren, 2026-09-15) — the decision's slot has left the service's active
    # template: kept live, flagged for review (#472).
    template_orphaned: bool = False


@dataclass(frozen=True)
class WorkspaceServiceContext:
    service_id: str
    service_name: str
    tier: str | None
    library_item_id: str | None
    owner_user_id: int | None
    bia_complete: bool
    appetite_complete: bool
    linked_asset_ids: list[str]
    bundle_id: str | None
    lifecycle_state: str | None
    # Whether anyone has begun mapping this service's dependencies at all.
    #
    # Stated, rather than inferred from `bundle_id is None` by each of the five
    # readers that used to. That proxy stopped being the same question on
    # 2026-09-11, when deciding a single slot started creating the bundle row it
    # writes its audit trail against (#433) — so an untouched service acquired a
    # bundle, its one mapping gap vanished, and it read as clean having answered
    # nothing. The honest test is whether any dependency slot exists to answer.
    dependency_mapping_started: bool
    slots: list[WorkspaceDependencySlot]
    mapping_gap_count: int
    evidence_gap_count: int
    # Slots a human has classified as a single point of failure for this service.
    spof_slot_count: int


def build_workspace_service_contexts(
    services: list[BusinessService],
    bundles_by_service_id: dict[str, DependencyBundle],
    *,
    process_id: str,
    process_bia_answers: dict | None,
    bia_exceptions_by_service_id: Mapping[str, Sequence[BiaExceptionRecord]],
    appetite_complete: bool,
    observed_asset_refs: frozenset[str],
    spof_asset_refs: frozenset[str],
    organisation_services: list[BusinessService],
) -> list[WorkspaceServiceContext]:
    """Project one process's services, with the gaps and exposure on each slot.

    `observed_asset_refs` are the assets the Collector has actually seen and
    `spof_asset_refs` those independently flagged as single points of failure.
    Both are passed in rather than queried here so this stays a pure projection
    and the caller does each tenant-scoped read once for the whole workspace.

    `bia_exceptions_by_service_id` holds each service's active BIA exceptions **in this process**
    (#463): a service's BIA is this process's, with only those exceptions over it.

    `organisation_services` is every service in the organisation, not only this
    process's, because "what else goes down with it" cannot be answered from
    inside one process.
    """
    processes_by_asset_ref = _processes_by_asset_ref(organisation_services)
    return [
        _service_context(
            service,
            bundles_by_service_id.get(service.id),
            process_id=process_id,
            process_bia_answers=process_bia_answers,
            bia_exceptions=bia_exceptions_by_service_id.get(service.id, ()),
            appetite_complete=appetite_complete,
            observed_asset_refs=observed_asset_refs,
            spof_asset_refs=spof_asset_refs,
            processes_by_asset_ref=processes_by_asset_ref,
        )
        for service in services
    ]


def _processes_by_asset_ref(
    organisation_services: list[BusinessService],
) -> dict[str, set[str]]:
    """Which Business Processes reach each asset, across the whole organisation."""
    reach: dict[str, set[str]] = {}
    for service in organisation_services:
        if service.archived_at is not None:
            continue
        process_ids = {
            process_id
            for process_id in (service.value_stream_ids or [])
            if isinstance(process_id, str) and process_id.strip()
        }
        if not process_ids:
            continue
        for asset_ids in (
            getattr(service, "l1", None),
            getattr(service, "l2", None),
            getattr(service, "l3", None),
        ):
            for value in asset_ids or []:
                asset_ref = normalise_asset_reference(value)
                if asset_ref is not None:
                    reach.setdefault(asset_ref, set()).update(process_ids)
    return reach


def workspace_gap_totals(contexts: list[WorkspaceServiceContext]) -> tuple[int, int]:
    """Workspace totals are the sum of the parts, never a second derivation."""
    return (
        sum(context.mapping_gap_count for context in contexts),
        sum(context.evidence_gap_count for context in contexts),
    )


def _service_context(
    service: BusinessService,
    bundle: DependencyBundle | None,
    *,
    process_id: str,
    process_bia_answers: dict | None,
    bia_exceptions: Sequence[BiaExceptionRecord],
    appetite_complete: bool,
    observed_asset_refs: frozenset[str],
    spof_asset_refs: frozenset[str],
    processes_by_asset_ref: dict[str, set[str]],
) -> WorkspaceServiceContext:
    slots: list[WorkspaceDependencySlot] = []
    mapping_gap_count = 0
    evidence_gap_count = 0
    spof_slot_count = 0

    if bundle is not None:
        for group in bundle.groups or []:
            if not isinstance(group, dict):
                continue
            group_key = group.get("key")
            for node in group.get("nodes", []) or []:
                if not isinstance(node, dict):
                    continue
                # #460 — a node composed from a slot record carries that record's
                # `slot_id`, the id `/slots`, `decide` and the slide-out all use; its
                # `id` is the record's own row id. Snapshot nodes from before #460
                # have no `slot_id` and keep their old id.
                slot_id = node.get("slot_id") or node.get("id") or node.get("template_key")
                if not isinstance(slot_id, str) or not slot_id.strip():
                    continue
                # Two flows write this field in two shapes — the wizard stores
                # "asset-92", the manual dependency review stores 92 — so it is
                # normalised on read. Accepting only strings dropped every
                # manually reviewed dependency, reporting it unmapped while a
                # human was looking at the asset they had linked to it.
                linked_asset_ids = [
                    reference
                    for reference in (
                        normalise_asset_reference(value)
                        for value in node.get("linked_asset_ids", []) or []
                    )
                    if reference is not None
                ]
                deferred = bool(node.get("deferred_asset_mapping"))
                if deferred:
                    status = ProcessWorkspaceDependencySlotStatus.DEFERRED
                elif linked_asset_ids:
                    status = ProcessWorkspaceDependencySlotStatus.MAPPED
                else:
                    status = ProcessWorkspaceDependencySlotStatus.UNMAPPED
                    mapping_gap_count += 1

                # Named, but nothing observed backs it: somebody asserted this
                # dependency and the Collector has never seen any of the assets
                # it points at, so analysis has no artefact to work on. An
                # unmapped slot is a mapping gap instead — never both.
                slot_evidence_gap = bool(linked_asset_ids) and not any(
                    asset_ref in observed_asset_refs for asset_ref in linked_asset_ids
                )
                if slot_evidence_gap:
                    evidence_gap_count += 1

                # The human's answer, kept tri-state: unanswered is not "no".
                spof = node.get("spof")
                single_point_of_failure = spof if isinstance(spof, bool) else None
                if single_point_of_failure:
                    spof_slot_count += 1

                slots.append(
                    WorkspaceDependencySlot(
                        slot_id=slot_id,
                        label=node.get("label"),
                        group_key=group_key,
                        status=status,
                        linked_asset_ids=linked_asset_ids,
                        deferred_asset_mapping=deferred,
                        evidence_gap=slot_evidence_gap,
                        single_point_of_failure=single_point_of_failure,
                        spof_asset_ids=[
                            asset_ref
                            for asset_ref in linked_asset_ids
                            if asset_ref in spof_asset_refs
                        ],
                        shared_with_process_ids=sorted(
                            {
                                other_process_id
                                for asset_ref in linked_asset_ids
                                for other_process_id in processes_by_asset_ref.get(asset_ref, ())
                                if other_process_id != process_id
                            }
                        ),
                        template_orphaned=bool(node.get("template_orphaned", False)),
                    )
                )

    # A service with no dependency slot at all — no bundle, or a bundle loaded
    # from its template and never answered — is itself one mapping gap. Nobody
    # has started, and that is a gap whatever rows happen to exist behind it.
    if not slots:
        mapping_gap_count = 1

    return WorkspaceServiceContext(
        service_id=service.id,
        service_name=service.name,
        tier=service.tier,
        library_item_id=service.library_item_id,
        owner_user_id=service.owner_user_id,
        bia_complete=bia_is_complete(effective_service_bia(process_bia_answers, bia_exceptions)),
        appetite_complete=appetite_complete,
        linked_asset_ids=[
            reference
            for asset_ids in (
                getattr(service, "l1", None),
                getattr(service, "l2", None),
                getattr(service, "l3", None),
            )
            for reference in (normalise_asset_reference(value) for value in (asset_ids or []))
            if reference is not None
        ],
        bundle_id=bundle.id if bundle else None,
        lifecycle_state=bundle.lifecycle_state if bundle else None,
        dependency_mapping_started=bool(slots),
        slots=slots,
        mapping_gap_count=mapping_gap_count,
        evidence_gap_count=evidence_gap_count,
        spof_slot_count=spof_slot_count,
    )
