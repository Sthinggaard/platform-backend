"""Transport contract for a tenant-owned Business Process BPMN graph."""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field

from src.core.constants.process_graph_enums import (
    BpmnEventMarker,
    BpmnEventType,
    BpmnFlowKind,
    BpmnGatewayType,
    BpmnNodeType,
    BpmnTaskType,
)
from src.core.constants.process_tailoring_enums import (
    ProcessTailoringRationaleCode,
    TailoringEvidenceState,
)


class BpmnLaneWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    label: str = Field(min_length=1, max_length=200)
    color: str | None = Field(default=None, max_length=32)
    external: bool = False


class BpmnNodeBaseWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)


class BpmnTaskNodeWrite(BpmnNodeBaseWrite):
    type: Literal[BpmnNodeType.TASK]
    lane: str = Field(min_length=1, max_length=100)
    col: int = Field(ge=1, le=500)
    name: str = Field(min_length=1, max_length=200)
    task_type: BpmnTaskType = BpmnTaskType.NONE
    service_id: str = Field(min_length=1, max_length=36)


class BpmnGatewayNodeWrite(BpmnNodeBaseWrite):
    type: Literal[BpmnNodeType.GATEWAY]
    lane: str = Field(min_length=1, max_length=100)
    col: int = Field(ge=1, le=500)
    gateway_type: BpmnGatewayType
    question: str | None = Field(default=None, max_length=300)


class BpmnEventNodeWrite(BpmnNodeBaseWrite):
    type: Literal[BpmnNodeType.EVENT]
    lane: str = Field(min_length=1, max_length=100)
    col: int = Field(ge=1, le=500)
    event_type: BpmnEventType
    marker: BpmnEventMarker = BpmnEventMarker.NONE
    throw_catch: Literal["throw", "catch"] | None = None
    label: str = Field(min_length=1, max_length=200)


class BpmnBoundaryEventNodeWrite(BpmnNodeBaseWrite):
    type: Literal[BpmnNodeType.BOUNDARY_EVENT]
    host_task_id: str = Field(min_length=1, max_length=100)
    marker: BpmnEventMarker
    interrupting: bool
    label: str = Field(min_length=1, max_length=200)


BpmnNodeWrite = Annotated[
    Union[
        BpmnTaskNodeWrite,
        BpmnGatewayNodeWrite,
        BpmnEventNodeWrite,
        BpmnBoundaryEventNodeWrite,
    ],
    Field(discriminator="type"),
]


class BpmnFlowWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    from_node_id: str = Field(alias="from", min_length=1, max_length=100)
    to_node_id: str = Field(alias="to", min_length=1, max_length=100)
    label: str | None = Field(default=None, max_length=200)
    kind: BpmnFlowKind = BpmnFlowKind.SEQUENCE
    is_default: bool = False
    loopback: bool = False


class BpmnDefinitionWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lanes: list[BpmnLaneWrite] = Field(min_length=1, max_length=50)
    nodes: list[BpmnNodeWrite] = Field(min_length=2, max_length=500)
    flows: list[BpmnFlowWrite] = Field(min_length=1, max_length=1000)


class CreateProcessCustomServiceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    tier: str = Field(default="Business Critical", max_length=50)
    archetype: str | None = Field(default=None, max_length=50)
    rationale_code: ProcessTailoringRationaleCode | None = None
    evidence_state: TailoringEvidenceState | None = None
