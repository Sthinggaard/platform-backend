"""OSI layer metadata used for provider-agnostic asset onboarding."""

from enum import Enum
from typing import TypedDict


class LayerMeta(TypedDict):
    id: str
    label: str
    #: The layer's name on its own, for places that show a layer beside other
    #: values and cannot carry the full parenthesised label — a discovered
    #: artefact's row, for instance. Declared rather than derived by splitting
    #: ``label`` on " (", which would couple every caller to that formatting.
    short_label: str
    description: str


class OSILayer(str, Enum):
    L1_PHYSICAL = "L1"
    L2_NETWORK = "L2"
    L3_TRANSPORT = "L3"
    L4_SESSION = "L4"
    L5_APPLICATION = "L5"
    L6_DATA = "L6"
    L7_GOVERNANCE = "L7"


LAYER_METADATA: list[LayerMeta] = [
    {
        "id": OSILayer.L1_PHYSICAL.value,
        "short_label": "Infrastructure",
        "label": "Infrastructure (Hosts / Hardware / Facilities)",
        "description": "Physical infrastructure: compute hosts, hardware appliances, data center facilities.",
    },
    {
        "id": OSILayer.L2_NETWORK.value,
        "short_label": "Network",
        "label": "Network (Segmentation / Routing / Firewalls)",
        "description": "Network infrastructure: network segmentation, routing, perimeter firewalls, and connectivity controls.",
    },
    {
        "id": OSILayer.L3_TRANSPORT.value,
        "short_label": "Transport",
        "label": "Transport (Ports / TLS / Load Balancing)",
        "description": "Transport layer: port management, TLS termination, load balancers, and traffic distribution.",
    },
    {
        "id": OSILayer.L4_SESSION.value,
        "short_label": "Session",
        "label": "Session (Authentication Sessions / Tokens)",
        "description": "Session layer: authentication sessions, token management, identity federation, and session control.",
    },
    {
        "id": OSILayer.L5_APPLICATION.value,
        "short_label": "Application",
        "label": "Application (Services / APIs / Runtime)",
        "description": "Application layer: business services, APIs, container platforms, and application runtimes.",
    },
    {
        "id": OSILayer.L6_DATA.value,
        "short_label": "Data",
        "label": "Data (Storage / Databases / Encryption)",
        "description": "Data layer: storage systems, databases, data lakes, and encryption at rest.",
    },
    {
        "id": OSILayer.L7_GOVERNANCE.value,
        "short_label": "Governance",
        "label": "Governance (Identity / Policies / Control Plane)",
        "description": "Governance layer: cloud accounts, identity providers, policy engines, and control plane administration.",
    },
]


#: Shown when the evidence does not support a layer. Not an OSILayer member on
#: purpose — "we could not tell" is the absence of a classification, not an
#: eighth kind of layer.
UNKNOWN_LAYER = "Unknown"


def layer_short_label(layer_id: str) -> str:
    """The layer's short name, or the id itself if it is not a known layer.

    Falling back to the id rather than raising keeps a legacy free-text value
    (this column held words before the canonical ids) renderable instead of
    breaking the screen it appears on.
    """
    if layer_id == UNKNOWN_LAYER:
        return UNKNOWN_LAYER
    meta = next((entry for entry in LAYER_METADATA if entry["id"] == layer_id), None)
    return meta["short_label"] if meta else layer_id
