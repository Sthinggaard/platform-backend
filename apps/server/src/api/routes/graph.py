from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.database import get_db

from .bundle_slot_mapping_routes import get_dependency_group_drill, get_service_bundle_runtime
from .graph_contracts import GraphEdgeResponse, GraphNodeResponse, GraphSliceResponse, GraphLevel
from .processes import ProcessServiceRow, _build_process_detail_response, _get_process

router = APIRouter(prefix="/api/v1/graph", tags=["Processes"])

DEPENDENCY_SCOPE_SEPARATOR = "::"


def encode_dependency_scope_id(service_id: str, group_key: str) -> str:
    return f"{service_id}{DEPENDENCY_SCOPE_SEPARATOR}{group_key}"


def parse_dependency_scope_id(scope_id: str) -> tuple[str, str]:
    service_id, separator, group_key = scope_id.partition(DEPENDENCY_SCOPE_SEPARATOR)
    if not separator or not service_id or not group_key:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Dependency graph scope id must be in '<serviceId>::<groupKey>' format.",
        )
    return service_id, group_key


def _service_graph_status(service: ProcessServiceRow) -> str:
    if not service.bia_complete or not service.bundle_complete:
        return "incomplete"
    if service.resilience_score is None:
        return "incomplete"
    if service.resilience_score >= 80:
        return "healthy"
    if service.resilience_score >= 60:
        return "attention"
    return "critical"


def _setup_progress_detail(service: ProcessServiceRow) -> str:
    completed_steps = sum(
        1 for done in (service.bia_complete, service.bundle_complete, service.appetite_complete) if done
    )
    return f"{completed_steps}/3 setup steps complete"


def _build_process_graph(
    process_id: str,
    ctx: TenantContext,
    db: Session,
) -> GraphSliceResponse:
    process = _get_process(process_id, ctx.organization_id, db)
    detail = _build_process_detail_response(process, db)

    nodes = [
        GraphNodeResponse(
            id=detail.process_id,
            label=detail.name,
            type="process",
            status=detail.status,
            detail=f"{detail.service_count} service{'s' if detail.service_count != 1 else ''}",
        )
    ]
    edges: list[GraphEdgeResponse] = []

    for service in detail.services:
        nodes.append(
            GraphNodeResponse(
                id=service.service_id,
                label=service.service_name,
                type="service",
                status=_service_graph_status(service),
                tier=service.tier,
                detail=_setup_progress_detail(service),
                unmapped=not service.bundle_complete,
            )
        )
        edges.append(
            GraphEdgeResponse(
                from_id=detail.process_id,
                to_id=service.service_id,
                edge_type="depends_on",
            )
        )

    return GraphSliceResponse(
        level="process",
        scope_id=detail.process_id,
        nodes=nodes,
        edges=edges,
    )


def _build_service_graph(
    service_id: str,
    ctx: TenantContext,
    db: Session,
) -> GraphSliceResponse:
    bundle = get_service_bundle_runtime(service_id, ctx, db)
    if bundle.lifecycle_state != "bundle_published" or not bundle.groups:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Diagram unavailable for this service. Showing list view.",
        )

    coverage_score = bundle.coverage_score or 0
    root_status = "healthy" if coverage_score >= 100 else "attention_needed" if coverage_score > 0 else "at_risk"
    nodes = [
        GraphNodeResponse(
            id=bundle.service_id,
            label=bundle.service_name,
            type="service",
            status=root_status,
            tier=bundle.tier,
            detail=f"{coverage_score}% dependency coverage",
        )
    ]
    edges: list[GraphEdgeResponse] = []

    for group in bundle.groups:
        scope_id = encode_dependency_scope_id(bundle.service_id, group.key)
        nodes.append(
            GraphNodeResponse(
                id=scope_id,
                label=group.label,
                type="dependency",
                status=group.status,
                detail=f"{group.mapped_count}/{group.total_slots} mapped",
                unmapped=group.total_slots == 0,
            )
        )
        edges.append(
            GraphEdgeResponse(
                from_id=bundle.service_id,
                to_id=scope_id,
                edge_type="depends_on",
            )
        )

    return GraphSliceResponse(
        level="service",
        scope_id=bundle.service_id,
        nodes=nodes,
        edges=edges,
    )


def _build_dependency_graph(
    scope_id: str,
    ctx: TenantContext,
    db: Session,
) -> GraphSliceResponse:
    service_id, group_key = parse_dependency_scope_id(scope_id)
    drill = get_dependency_group_drill(service_id, group_key, ctx, db)
    if not drill.assets:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Diagram unavailable for this dependency. Showing list view.",
        )

    nodes = [
        GraphNodeResponse(
            id=scope_id,
            label=drill.label,
            type="dependency",
            status=drill.status,
            detail=f"{drill.mapped_count}/{drill.total_slots} mapped",
            unmapped=drill.mapped_count == 0,
        )
    ]
    edges: list[GraphEdgeResponse] = []

    for index, asset in enumerate(drill.assets):
        asset_node_id = asset.asset_id or f"{scope_id}{DEPENDENCY_SCOPE_SEPARATOR}{index}"
        detail_parts = [part for part in [asset.asset_type, f"{asset.shared_service_count} shared" if asset.shared_service_count > 0 else None] if part]
        nodes.append(
            GraphNodeResponse(
                id=asset_node_id,
                label=asset.display_name or asset.asset_label or f"Dependency asset {index + 1}",
                type="asset",
                status=asset.status,
                detail=" • ".join(detail_parts) if detail_parts else None,
                is_spof=asset.is_spof,
                unmapped=asset.status != "mapped",
            )
        )
        edges.append(
            GraphEdgeResponse(
                from_id=scope_id,
                to_id=asset_node_id,
                edge_type="single_point_of_failure" if asset.is_spof else "depends_on",
            )
        )

    return GraphSliceResponse(
        level="dependency",
        scope_id=scope_id,
        nodes=nodes,
        edges=edges,
    )


@router.get("", response_model=GraphSliceResponse, status_code=status.HTTP_200_OK)
def get_scoped_graph(
    level: GraphLevel = Query(...),
    id: str = Query(...),
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> GraphSliceResponse:
    if level == "process":
        return _build_process_graph(id, ctx, db)
    if level == "service":
        return _build_service_graph(id, ctx, db)
    return _build_dependency_graph(id, ctx, db)
