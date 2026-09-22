from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

GraphLevel = Literal["process", "service", "dependency"]
GraphNodeType = Literal["process", "service", "dependency", "asset"]
GraphStatus = Literal[
    "healthy",
    "attention",
    "critical",
    "incomplete",
    "attention_needed",
    "at_risk",
    "unverified",
    "mapped",
    "not_applicable",
    "unknown",
]
GraphEdgeType = Literal["depends_on", "external_dependency", "single_point_of_failure"]


class GraphNodeResponse(BaseModel):
    id: str
    label: str
    type: GraphNodeType
    status: GraphStatus
    tier: str | None = None
    detail: str | None = None
    is_spof: bool = False
    unmapped: bool = False


class GraphEdgeResponse(BaseModel):
    from_id: str
    to_id: str
    edge_type: GraphEdgeType


class GraphSliceResponse(BaseModel):
    level: GraphLevel
    scope_id: str
    nodes: list[GraphNodeResponse]
    edges: list[GraphEdgeResponse]
