"""Tenant-scoped prepared Business Process workspace readiness endpoint."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.schemas.process_workspace_readiness import (
    ProcessWorkspaceDependencyResponse,
    ProcessWorkspaceDependencySlotResponse,
    ProcessWorkspaceReadinessResponse,
    ProcessWorkspaceServiceResponse,
)
from src.core.constants.process_activation_enums import (
    TERMINAL_PROCESS_CONFIRMATION_OUTCOMES,
    ProcessConfirmationOutcome,
)
from src.core.database import get_db
from src.core.exceptions import ResourceNotFoundError
from src.core.models import (
    Asset,
    BusinessProcessActivation,
    BusinessService,
    DependencyBundle,
    ValueStream,
)
from src.core.repository import TenantRepository
from src.core.services.asset_context_service import asset_reference
from src.core.services.bia_inheritance_service import bia_is_complete
from src.core.services.dependency_decision_service import live_groups, load_service_slot_context
from src.core.services.dependency_live_state_service import LiveDependencyBundle
from src.core.services.effective_process_bia_service import (
    resolve_effective_process_bia_by_process,
)
from src.core.services.process_workspace_projection_service import (
    WorkspaceServiceContext,
    build_workspace_service_contexts,
    workspace_gap_totals,
)
from src.core.services.process_workspace_readiness_service import (
    ProcessWorkspaceReadinessInput,
    evaluate_process_workspace_readiness,
)
from src.core.services.risk_appetite_resolution_service import resolve_process_appetite
from src.core.services.service_bia_exception_service import active_bia_exceptions

router = APIRouter(prefix="/api/v1/processes", tags=["Process workspace readiness"])


@router.get("/{process_id}/workspace-readiness", response_model=ProcessWorkspaceReadinessResponse)
def get_process_workspace_readiness(
    process_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessWorkspaceReadinessResponse:
    process = TenantRepository(db, ValueStream, ctx.organization_id).get_by_id(process_id)
    if process is None:
        raise ResourceNotFoundError("Business Process not found in this organisation")

    organisation_services = TenantRepository(db, BusinessService, ctx.organization_id).get_all()
    services = [
        service
        for service in organisation_services
        if process.id in (service.value_stream_ids or []) and service.archived_at is None
    ]
    service_ids = {service.id for service in services}
    stored_bundles = {
        bundle.service_id: bundle
        for bundle in TenantRepository(db, DependencyBundle, ctx.organization_id).get_all()
        if bundle.service_id in service_ids
    }
    # #460 — each service's live dependency state is composed from its slot records, the one live
    # record of a dependency decision. A stored bundle supplies identity, lifecycle and group
    # metadata only; its nodes are the published snapshot and are never read here. A service
    # with no bundle row still counts once a person has answered one of its slots (#452).
    bundles_by_service_id: dict[str, LiveDependencyBundle] = {}
    for service in services:
        stored = stored_bundles.get(service.id)
        groups = live_groups(
            stored.groups if stored else [], load_service_slot_context(db, service)
        )
        if stored is None and not any(group["nodes"] for group in groups):
            continue
        bundles_by_service_id[service.id] = LiveDependencyBundle(
            id=stored.id if stored else None,
            service_id=service.id,
            lifecycle_state=stored.lifecycle_state if stored else None,
            groups=groups,
        )

    effective_bia = resolve_effective_process_bia_by_process(
        db,
        organization_id=ctx.organization_id,
        processes=[process],
    )[process.id]
    appetite_effective = (
        resolve_process_appetite(
            db,
            organization_id=ctx.organization_id,
            process_id=process.id,
        )
        is not None
    )

    activation = next(
        (
            row
            for row in TenantRepository(
                db, BusinessProcessActivation, ctx.organization_id
            ).get_all()
            if row.process_id == process.id
        ),
        None,
    )
    terminal_process_outcome = bool(
        activation
        and activation.confirmation_outcome
        in {outcome.value for outcome in TERMINAL_PROCESS_CONFIRMATION_OUTCOMES}
    )
    # No activation row, or an outcome still pending, both mean nobody has
    # confirmed the process. Absence of a confirmation is not a confirmation.
    process_confirmed = bool(
        activation and activation.confirmation_outcome == ProcessConfirmationOutcome.CONFIRMED.value
    )

    # The assets the Collector has actually observed. A dependency pointing only
    # at assets absent from this set is asserted, not evidenced — read once for
    # the whole workspace, tenant-scoped like every other read here.
    organisation_assets = TenantRepository(db, Asset, ctx.organization_id).get_all()
    observed_asset_refs = frozenset(
        asset_reference(asset.id)
        for asset in organisation_assets
        if asset.last_observed_at is not None
    )
    spof_asset_refs = frozenset(
        asset_reference(asset.id) for asset in organisation_assets if asset.is_spof
    )

    # Built once. The workspace totals below are the sum of these, not a second
    # derivation from a second query — that is how the aggregate and the detail
    # used to be able to disagree on the same screen.
    # #463 — each service's BIA exceptions in this process.
    bia_exceptions = active_bia_exceptions(
        db, organization_id=ctx.organization_id, process_ids=[process.id]
    )
    service_contexts = build_workspace_service_contexts(
        services,
        bundles_by_service_id,
        process_id=process.id,
        process_bia_answers=effective_bia.answers,
        bia_exceptions_by_service_id={
            service_id: exceptions for (service_id, _), exceptions in bia_exceptions.items()
        },
        appetite_complete=appetite_effective,
        observed_asset_refs=observed_asset_refs,
        spof_asset_refs=spof_asset_refs,
        organisation_services=organisation_services,
    )
    mapping_gaps, evidence_gaps = workspace_gap_totals(service_contexts)

    result = evaluate_process_workspace_readiness(
        ProcessWorkspaceReadinessInput(
            process_exists=True,
            service_count=len(services),
            bia_prepared=bia_is_complete(effective_bia.answers),
            appetite_effective=appetite_effective,
            process_confirmed=process_confirmed,
            terminal_process_outcome=terminal_process_outcome,
            dependency_mapping_gap_count=mapping_gaps,
            evidence_gap_count=evidence_gaps,
        )
    )

    return ProcessWorkspaceReadinessResponse(
        process_id=process.id,
        state=result.state,
        release_allowed=result.release_allowed,
        reasons=result.reasons,
        next_actions=result.next_actions,
        service_count=result.service_count,
        dependency_mapping_gap_count=result.dependency_mapping_gap_count,
        evidence_gap_count=result.evidence_gap_count,
        process_name=process.name,
        outcome_statement=process.description,
        process_source=process.source,
        services=[_service_response(context) for context in service_contexts],
    )


def _service_response(context: WorkspaceServiceContext) -> ProcessWorkspaceServiceResponse:
    """Map the domain projection onto the API schema. No logic beyond the mapping."""
    return ProcessWorkspaceServiceResponse(
        service_id=context.service_id,
        service_name=context.service_name,
        tier=context.tier,
        library_item_id=context.library_item_id,
        owner_user_id=context.owner_user_id,
        bia_complete=context.bia_complete,
        appetite_complete=context.appetite_complete,
        linked_asset_ids=context.linked_asset_ids,
        dependency=ProcessWorkspaceDependencyResponse(
            bundle_id=context.bundle_id,
            lifecycle_state=context.lifecycle_state,
            dependency_mapping_started=context.dependency_mapping_started,
            slots=[
                ProcessWorkspaceDependencySlotResponse(
                    slot_id=slot.slot_id,
                    label=slot.label,
                    group_key=slot.group_key,
                    status=slot.status,
                    linked_asset_ids=slot.linked_asset_ids,
                    deferred_asset_mapping=slot.deferred_asset_mapping,
                    evidence_gap=slot.evidence_gap,
                    single_point_of_failure=slot.single_point_of_failure,
                    spof_asset_ids=slot.spof_asset_ids,
                    shared_with_process_ids=slot.shared_with_process_ids,
                    template_orphaned=slot.template_orphaned,
                )
                for slot in context.slots
            ],
            mapping_gap_count=context.mapping_gap_count,
            evidence_gap_count=context.evidence_gap_count,
            spof_slot_count=context.spof_slot_count,
        ),
    )
