"""Validation and activation invalidation for tenant-owned BPMN process graphs."""

from __future__ import annotations

import uuid
from collections import deque

from sqlalchemy.orm import Session

from src.api.schemas.process_graph import BpmnDefinitionWrite, BpmnNodeWrite
from src.core.constants.process_activation_enums import ProcessConfirmationOutcome
from src.core.constants.process_graph_enums import (
    BpmnEventType,
    BpmnNodeType,
    ProcessGraphAuditEvent,
    ProcessGraphErrorMessage,
)
from src.core.constants.process_tailoring_enums import (
    ProcessTailoringAuditEvent,
    ProcessTailoringChangeType,
    ProcessTailoringRationaleCode,
    TailoringEvidenceState,
)
from src.core.model_defs.process_activation import BusinessProcessActivation
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.model_defs.value_streams import BusinessService, ProcessTailoringSignal, ValueStream
from src.core.repository import TenantRepository


class ProcessGraphValidationError(ValueError):
    """Raised when a tenant BPMN graph does not model a valid Business Process."""


def validate_process_graph(
    definition: BpmnDefinitionWrite,
    *,
    process: ValueStream,
    services: list[BusinessService],
) -> None:
    """Validate topology and service-task bindings before a graph is persisted."""
    lane_ids = {lane.id for lane in definition.lanes}
    node_by_id = {node.id: node for node in definition.nodes}
    if len(node_by_id) != len(definition.nodes):
        raise ProcessGraphValidationError(
            ProcessGraphErrorMessage.PROCESS_GRAPH_DUPLICATE_NODE.value
        )

    service_ids = {
        service.id for service in services if process.id in (service.value_stream_ids or [])
    }
    start_nodes: list[BpmnNodeWrite] = []
    task_ids: set[str] = set()
    for node in definition.nodes:
        if node.type is BpmnNodeType.BOUNDARY_EVENT:
            host = node_by_id.get(node.host_task_id)
            if host is None or host.type is not BpmnNodeType.TASK:
                raise ProcessGraphValidationError(
                    ProcessGraphErrorMessage.PROCESS_GRAPH_BOUNDARY_HOST.value
                )
            continue
        if node.lane not in lane_ids:
            raise ProcessGraphValidationError(
                ProcessGraphErrorMessage.PROCESS_GRAPH_UNKNOWN_LANE.value
            )
        if node.type is BpmnNodeType.TASK:
            task_ids.add(node.id)
            if not node.service_id:
                raise ProcessGraphValidationError(
                    ProcessGraphErrorMessage.PROCESS_GRAPH_SERVICE_REQUIRED.value
                )
            if node.service_id not in service_ids:
                raise ProcessGraphValidationError(
                    ProcessGraphErrorMessage.PROCESS_GRAPH_SERVICE_NOT_MEMBER.value
                )
        if node.type is BpmnNodeType.EVENT and node.event_type is BpmnEventType.START:
            start_nodes.append(node)

    if len(start_nodes) != 1:
        raise ProcessGraphValidationError(ProcessGraphErrorMessage.PROCESS_GRAPH_START_EVENT.value)
    if not any(
        node.type is BpmnNodeType.EVENT and node.event_type is BpmnEventType.END
        for node in definition.nodes
    ):
        raise ProcessGraphValidationError(ProcessGraphErrorMessage.PROCESS_GRAPH_END_EVENT.value)

    adjacency: dict[str, set[str]] = {node_id: set() for node_id in node_by_id}
    for flow in definition.flows:
        if flow.from_node_id not in node_by_id or flow.to_node_id not in node_by_id:
            raise ProcessGraphValidationError(
                ProcessGraphErrorMessage.PROCESS_GRAPH_INVALID_FLOW.value
            )
        adjacency[flow.from_node_id].add(flow.to_node_id)

    reachable = _reachable_nodes(start_nodes[0].id, adjacency)
    if not task_ids.issubset(reachable):
        raise ProcessGraphValidationError(
            ProcessGraphErrorMessage.PROCESS_GRAPH_UNREACHABLE_TASK.value
        )


def invalidate_process_graph_activation(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
) -> None:
    """Require renewed human confirmation after a process topology change."""
    activation = next(
        iter(
            TenantRepository(db, BusinessProcessActivation, organization_id).filter_by(
                process_id=process_id
            )
        ),
        None,
    )
    if activation is None:
        return
    TenantRepository(db, BusinessProcessActivation, organization_id).update(
        activation,
        confirmed_by_user_id=None,
        confirmed_at=None,
        confirmation_outcome=ProcessConfirmationOutcome.PENDING.value,
        confirmation_reason_code=None,
        confirmation_reason_detail=None,
        successor_process_id=None,
        activated_by_user_id=None,
        activated_at=None,
        activated_bia_assessment_id=None,
        activated_organization_bia_baseline_id=None,
        activated_owner_acceptance_id=None,
        activated_appetite_policy_id=None,
        activated_confirmation_at=None,
    )


def _reachable_nodes(start_node_id: str, adjacency: dict[str, set[str]]) -> set[str]:
    reachable: set[str] = set()
    queue = deque([start_node_id])
    while queue:
        node_id = queue.popleft()
        if node_id in reachable:
            continue
        reachable.add(node_id)
        queue.extend(adjacency[node_id] - reachable)
    return reachable


_TAILORING_AUDIT_EVENT_BY_CHANGE_TYPE = {
    ProcessTailoringChangeType.SERVICE_EXCLUDED: ProcessTailoringAuditEvent.SERVICE_EXCLUDED,
    ProcessTailoringChangeType.SERVICE_REINCLUDED: ProcessTailoringAuditEvent.SERVICE_REINCLUDED,
    ProcessTailoringChangeType.CUSTOM_SERVICE_ADDED: ProcessGraphAuditEvent.CUSTOM_SERVICE_CREATED,
}


def record_process_tailoring_signal(
    db: Session,
    *,
    organization_id: int,
    process_id: str | None,
    template_key: str | None,
    template_version: int | None,
    change_type: ProcessTailoringChangeType,
    affected_service_keys: list[str],
    is_critical_service_change: bool,
    actor_user_id: int | None,
    rationale_code: ProcessTailoringRationaleCode | None = None,
    evidence_state: TailoringEvidenceState | None = None,
    detail: dict | None = None,
    note: str | None = None,
    audit_event: AuditEvent | None = None,
) -> ProcessTailoringSignal:
    """Record one approved process-tailoring decision.

    Pairs a structured, append-only `ProcessTailoringSignal` row with a generic
    `AuditEvent`, then invalidates the process's impact-model snapshot — every
    tailoring change is process-boundary-material by definition (excluding,
    re-including, or adding a service always changes what the process is made
    of), so this always invalidates any existing activation.

    Pass an already-created `audit_event` when the caller has its own reason to
    write one (e.g. custom-service creation, which already logs
    `ProcessGraphAuditEvent.CUSTOM_SERVICE_CREATED`) so the two stay paired
    instead of duplicating. Otherwise one is created here.
    """
    resolved_rationale = rationale_code or ProcessTailoringRationaleCode.UNSPECIFIED
    resolved_evidence = evidence_state or TailoringEvidenceState.OWNER_APPROVED

    activation_existed = process_id is not None and (
        next(
            iter(
                TenantRepository(db, BusinessProcessActivation, organization_id).filter_by(
                    process_id=process_id
                )
            ),
            None,
        )
        is not None
    )

    if audit_event is None:
        audit_event = AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            event_type=_TAILORING_AUDIT_EVENT_BY_CHANGE_TYPE[change_type].value,
            metadata_json={
                "process_id": process_id,
                "template_key": template_key,
                "change_type": change_type.value,
                "affected_service_keys": list(affected_service_keys),
            },
        )
        db.add(audit_event)
    db.flush()

    signal = ProcessTailoringSignal(
        id=str(uuid.uuid4()),
        organization_id=organization_id,
        process_id=process_id,
        template_key=template_key,
        template_version=template_version,
        change_type=change_type.value,
        affected_service_keys=list(affected_service_keys),
        detail=detail or {},
        rationale_code=resolved_rationale.value,
        evidence_state=resolved_evidence.value,
        actor_user_id=actor_user_id,
        is_process_boundary_change=True,
        is_critical_service_change=is_critical_service_change,
        invalidated_activation=activation_existed,
        audit_event_id=audit_event.id,
        note=note,
    )
    db.add(signal)

    if process_id is not None:
        invalidate_process_graph_activation(
            db, organization_id=organization_id, process_id=process_id
        )

    return signal
