"""Stable BPMN graph identifiers for tenant Business Process topology."""

from enum import StrEnum


class BpmnNodeType(StrEnum):
    TASK = "task"
    GATEWAY = "gateway"
    EVENT = "event"
    BOUNDARY_EVENT = "boundary_event"


class BpmnTaskType(StrEnum):
    NONE = "none"
    USER = "user"
    MANUAL = "manual"
    SERVICE = "service"
    SCRIPT = "script"
    BUSINESS_RULE = "business_rule"
    SEND = "send"
    RECEIVE = "receive"


class BpmnEventType(StrEnum):
    START = "start"
    INTERMEDIATE = "intermediate"
    END = "end"


class BpmnEventMarker(StrEnum):
    NONE = "none"
    MESSAGE = "message"
    TIMER = "timer"
    ERROR = "error"
    ESCALATION = "escalation"
    CONDITIONAL = "conditional"
    SIGNAL = "signal"
    TERMINATE = "terminate"


class BpmnGatewayType(StrEnum):
    EXCLUSIVE = "exclusive"
    INCLUSIVE = "inclusive"
    PARALLEL = "parallel"
    EVENT_BASED = "eventBased"


class BpmnFlowKind(StrEnum):
    SEQUENCE = "sequence"
    MESSAGE = "message"


class ProcessGraphAuditEvent(StrEnum):
    GRAPH_SAVED = "business_process_graph_saved"
    CUSTOM_SERVICE_CREATED = "business_process_custom_service_created"


class ProcessGraphErrorMessage(StrEnum):
    PROCESS_GRAPH_REQUIRED = "A Business Process graph requires at least one lane, node, and flow"
    PROCESS_GRAPH_DUPLICATE_NODE = "A Business Process graph cannot contain duplicate node identifiers"
    PROCESS_GRAPH_UNKNOWN_LANE = "Every BPMN node must reference a process lane"
    PROCESS_GRAPH_INVALID_FLOW = "Every BPMN flow must connect existing graph nodes"
    PROCESS_GRAPH_START_EVENT = "A Business Process graph requires exactly one start event"
    PROCESS_GRAPH_END_EVENT = "A Business Process graph requires at least one end event"
    PROCESS_GRAPH_UNREACHABLE_TASK = "Every Business Service task must be reachable from the start event"
    PROCESS_GRAPH_SERVICE_REQUIRED = "Every BPMN task must reference a Business Service"
    PROCESS_GRAPH_SERVICE_NOT_MEMBER = "A BPMN task can reference only a Business Service in this process"
    PROCESS_GRAPH_BOUNDARY_HOST = "A BPMN boundary event must reference an existing Business Service task"

