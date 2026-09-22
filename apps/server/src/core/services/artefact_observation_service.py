"""CA-06.2 — what was structurally observed on an artefact.

Ports, protocols and service names used to survive only inside
``AssetEvidenceSignal.payload_json`` and as service-name strings in
``Asset.intent``, so "what is this thing exposing, and since when" could only be
answered by re-parsing raw scanner output. This module owns turning a scanner's
host record into those structured facts and recording them against the artefact.

Two rules shape everything here:

* **Only what was seen.** A protocol the scanner did not state is recorded as
  unknown, not assumed to be tcp. A service name is a claim the scanner made,
  not an inference from the port number — port 22 answering something that is
  not SSH is exactly the kind of thing an inventory exists to surface.
* **Nothing is erased.** A port that stops answering keeps its row and its
  ``last_seen_at``; that is what makes "closed since when" answerable at all.
  Deleting it would destroy the only evidence it was ever open.

Deliberately not here: severity, risk, or any judgement about whether an open
port is *bad*. These are technical facts. Interpretation belongs to
``AssetFinding`` and the intelligence layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from src.core.model_defs.assets_runtime import Asset, AssetObservedPort
from src.core.model_defs.common import utcnow

#: What a protocol column says when the evidence did not state one. An explicit
#: value, because a NULL protocol would make the uniqueness constraint
#: (asset, port, protocol) stop working — in SQL, NULL is never equal to NULL,
#: so every rescan of the same port would insert another row.
UNKNOWN_PROTOCOL = "unknown"

_MAX_PROTOCOL_LENGTH = 10
_MAX_SERVICE_NAME_LENGTH = 100
_MAX_PRODUCT_LENGTH = 255
_MAX_PRODUCT_VERSION_LENGTH = 100


@dataclass(frozen=True)
class ObservedPort:
    """One port/protocol seen answering on an artefact."""

    port: int
    protocol: str
    service_name: str | None = None
    product: str | None = None
    product_version: str | None = None


def _clean(value: Any, *, max_length: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    return cleaned[:max_length]


def extract_observed_ports(host_record: dict[str, Any]) -> tuple[ObservedPort, ...]:
    """Read the structured port facts out of a scanner host record.

    Accepts both key spellings this codebase's parsers emit (``service`` from
    the Nmap parser, ``name`` from the generic collector payload) rather than
    forcing one of them to change — the point of this story is to record what
    the existing pipeline already produces, not to alter what is scanned.

    A record without a usable port number contributes nothing. It is not
    recorded as port 0, and it does not stop the rest of the record being read.
    """
    services = host_record.get("services")
    if not isinstance(services, list):
        return ()

    observed: dict[tuple[int, str], ObservedPort] = {}
    for service in services:
        if not isinstance(service, dict):
            continue

        raw_port = service.get("port")
        if isinstance(raw_port, bool) or not isinstance(raw_port, int):
            # bool is an int subclass in Python, and `True` is not a port.
            continue
        if not 0 < raw_port <= 65535:
            continue

        protocol = _clean(service.get("protocol"), max_length=_MAX_PROTOCOL_LENGTH)
        protocol = protocol.lower() if protocol else UNKNOWN_PROTOCOL

        name = _clean(service.get("service"), max_length=_MAX_SERVICE_NAME_LENGTH) or _clean(
            service.get("name"), max_length=_MAX_SERVICE_NAME_LENGTH
        )

        # One record can legitimately list the same port twice (two script
        # results on one port). Last write wins for detail; the port is one fact.
        observed[(raw_port, protocol)] = ObservedPort(
            port=raw_port,
            protocol=protocol,
            service_name=name.lower() if name else None,
            product=_clean(service.get("product"), max_length=_MAX_PRODUCT_LENGTH),
            product_version=_clean(service.get("version"), max_length=_MAX_PRODUCT_VERSION_LENGTH),
        )

    return tuple(observed.values())


def record_observed_ports(
    db: Session,
    *,
    asset: Asset,
    ports: tuple[ObservedPort, ...],
    observed_at: datetime | None = None,
) -> tuple[ObservedPort, ...]:
    """Record this observation's ports against the artefact.

    Returns the ports that were *newly* observed on it, so the caller can say
    what changed rather than re-deriving it.

    Ports absent from this observation are left exactly as they are. Their
    ``last_seen_at`` stops advancing, which is the record that they were not
    seen this time — the platform states what it observed, and does not
    conclude "closed" on the artefact's behalf.
    """
    if not ports:
        return ()
    if asset.id is None:
        db.flush()

    now = observed_at or utcnow()
    existing = {
        (row.port, row.protocol): row
        for row in db.query(AssetObservedPort).filter(
            AssetObservedPort.organization_id == asset.organization_id,
            AssetObservedPort.asset_id == asset.id,
        )
    }

    newly_observed: list[ObservedPort] = []
    for port in ports:
        row = existing.get((port.port, port.protocol))
        if row is None:
            db.add(
                AssetObservedPort(
                    organization_id=asset.organization_id,
                    asset_id=asset.id,
                    port=port.port,
                    protocol=port.protocol,
                    service_name=port.service_name,
                    product=port.product,
                    product_version=port.product_version,
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            newly_observed.append(port)
            continue

        row.last_seen_at = now
        # Later evidence supersedes earlier evidence about the same port, but
        # only where there *is* later evidence: a scan that reported no service
        # name does not erase the name an earlier scan established.
        if port.service_name:
            row.service_name = port.service_name
        if port.product:
            row.product = port.product
        if port.product_version:
            row.product_version = port.product_version
        db.add(row)

    return tuple(newly_observed)
