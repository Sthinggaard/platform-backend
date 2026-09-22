from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from sqlalchemy import func
from sqlalchemy.orm import Session

from src.core.constants import SERVICE_TIER_MISSION_CRITICAL
from src.core.models import Asset, BusinessService, SlotInstance, ValueStream

ASSET_REFERENCE_PREFIX = "asset-"
MAPPED_SLOT_STATUS = "mapped"
SERVICE_ASSET_ROLES = ("l1", "l2", "l3")
SLOT_MAPPED_SERVICE_ROLE = "slot_mapped"
CROWN_JEWEL_EXPOSURE_THRESHOLD = Decimal("1000000")
EXPOSURE_NUMBER_PATTERN = re.compile(r"(?P<amount>\d+(?:[.,]\d+)?)\s*(?P<scale>[kKmMbB])?")
EXPOSURE_SCALE_MULTIPLIERS: dict[str, Decimal] = {
    "k": Decimal("1000"),
    "m": Decimal("1000000"),
    "b": Decimal("1000000000"),
}


@dataclass(frozen=True)
class LinkedDependencyContext:
    dependency_id: str
    pattern_key: str | None
    label: str | None
    service_id: str
    service_name: str


@dataclass(frozen=True)
class LinkedServiceContext:
    service_id: str
    service_name: str
    service_tier: str
    financial_exposure: str | None
    role: str


@dataclass(frozen=True)
class LinkedProcessContext:
    process_id: str
    process_name: str


@dataclass(frozen=True)
class AssetBlastRadiusContext:
    service_count: int
    total_exposure: float
    mission_critical_count: int
    has_financial_exposure: bool


@dataclass(frozen=True)
class AssetBusinessContext:
    asset_id: int
    display_name: str
    asset_type: str | None
    is_spof: bool
    risk_score: float
    findings_count: int
    crown_jewel_candidate: bool
    linked_dependencies: list[LinkedDependencyContext]
    linked_services: list[LinkedServiceContext]
    linked_processes: list[LinkedProcessContext]
    blast_radius: AssetBlastRadiusContext


def _asset_reference(asset: Asset) -> str:
    return f"{ASSET_REFERENCE_PREFIX}{asset.id}"


def asset_reference(asset_id: int) -> str:
    """The `asset-{id}` reference other records use to point at an Asset.

    The format has one definition, here, because a reader that builds it and a
    reader that parses it drifting apart is silent — the link simply stops
    matching and everything reports zero.
    """
    return f"{ASSET_REFERENCE_PREFIX}{asset_id}"


def normalise_asset_reference(value: object) -> str | None:
    """Accept either stored form of an asset link and return the canonical one.

    Asset links have reached storage in three spellings: ``"asset-92"`` (the tenant
    and supersede), the bare integer ``92`` (the internal tenant seed, fixed
    2026-08-30), and the digit string ``"92"`` — the scanner's slot-mapping
    suggestions wrote ``str(asset.id)``, and accepting one carried it into slot rows
    and bundle links (#363, found and fixed 2026-09-13). A reader
    that understands only the first drops the others silently — the slot then
    reports as unmapped while a human is looking at the asset they linked to it.

    Writers normalise through this too, so storage converges on one spelling.

    Returns ``None`` for anything that is not a usable reference, so callers can
    skip it rather than fabricate a link.
    """
    if isinstance(value, bool):  # bool is an int; never an asset id
        return None
    if isinstance(value, int):
        return asset_reference(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.startswith(ASSET_REFERENCE_PREFIX):
            return text if text != ASSET_REFERENCE_PREFIX else None
        return asset_reference(int(text)) if text.isdigit() else text
    return None


def _canonical_links(links: list[object] | None) -> list[str]:
    """Every usable link in its stored spelling, in order, each asset once."""
    canonical: list[str] = []
    for value in links or []:
        reference = normalise_asset_reference(value)
        if reference is not None and reference not in canonical:
            canonical.append(reference)
    return canonical


def link_asset_reference(links: list[object] | None, reference: str) -> list[str]:
    """A node's links with one asset added, all in the one stored spelling.

    ⚠️ **#363.** ``assign_asset`` appended the request's value as sent, so the
    same asset could be stored twice — once as ``"92"``, once as ``"asset-92"``.
    The existing links are normalised on the way through, so any node a write
    touches leaves in one spelling.

    ``reference`` must already be normalised; callers refuse the request when
    ``normalise_asset_reference`` returns ``None``.
    """
    canonical = _canonical_links(links)
    if reference not in canonical:
        canonical.append(reference)
    return canonical


def unlink_asset_reference(links: list[object] | None, reference: str) -> list[str]:
    """A node's links with one asset removed, however either side spelled it.

    ⚠️ **#363.** ``unassign_asset`` compared raw values, so a link stored as
    ``"asset-92"`` survived a request carrying ``"92"``, and the reverse — the
    response showed it gone while the bundle kept it.
    """
    return [link for link in _canonical_links(links) if link != reference]


def resolve_asset_by_label(asset_label: str | None, org_id: int, db: Session) -> Asset | None:
    normalized = (asset_label or "").strip()
    if not normalized:
        return None

    exact = (
        db.query(Asset)
        .filter(
            Asset.organization_id == org_id,
            func.lower(Asset.display_name) == normalized.lower(),
        )
        .order_by(Asset.id.asc())
        .first()
    )
    if exact is not None:
        return exact

    return (
        db.query(Asset)
        .filter(
            Asset.organization_id == org_id,
            func.lower(Asset.display_name).contains(normalized.lower()),
        )
        .order_by(Asset.id.asc())
        .first()
    )


def _service_role_for_asset(service: BusinessService, asset_reference: str) -> str | None:
    for role in SERVICE_ASSET_ROLES:
        if asset_reference in (getattr(service, role) or []):
            return role
    return None


def _append_linked_service(
    linked_services: list[LinkedServiceContext],
    linked_service_ids: set[str],
    service: BusinessService,
    role: str,
) -> None:
    if service.id in linked_service_ids:
        return

    linked_service_ids.add(service.id)
    linked_services.append(
        LinkedServiceContext(
            service_id=service.id,
            service_name=service.name,
            service_tier=service.tier,
            financial_exposure=service.trading_impact or None,
            role=role,
        )
    )


def _find_asset_dependencies(
    asset_reference: str,
    org_id: int,
    services_by_id: dict[str, BusinessService],
    db: Session,
) -> list[LinkedDependencyContext]:
    slot_rows = (
        db.query(SlotInstance)
        .filter(
            SlotInstance.organization_id == org_id,
            SlotInstance.asset_id == asset_reference,
            SlotInstance.status == MAPPED_SLOT_STATUS,
        )
        .all()
    )

    return [
        LinkedDependencyContext(
            dependency_id=str(row.id),
            pattern_key=getattr(row, "pattern_key", None),
            label=getattr(row, "label", None),
            service_id=row.service_id,
            service_name=services_by_id[row.service_id].name,
        )
        for row in slot_rows
        if row.service_id in services_by_id
    ]


def _resolve_linked_processes(
    linked_service_ids: set[str],
    services: list[BusinessService],
    org_id: int,
    db: Session,
) -> list[LinkedProcessContext]:
    process_ids: set[str] = set()
    for service in services:
        if service.id not in linked_service_ids:
            continue
        for value_stream_id in service.value_stream_ids or []:
            process_ids.add(value_stream_id)

    if not process_ids:
        return []

    streams = (
        db.query(ValueStream)
        .filter(
            ValueStream.organization_id == org_id,
            ValueStream.id.in_(process_ids),
        )
        .all()
    )
    return [
        LinkedProcessContext(process_id=stream.id, process_name=stream.name) for stream in streams
    ]


def _financial_exposure_amount(financial_exposure: str | None) -> Decimal:
    if not financial_exposure:
        return Decimal("0")

    match = EXPOSURE_NUMBER_PATTERN.search(financial_exposure)
    if match is None:
        return Decimal("0")

    raw_amount = match.group("amount").replace(",", ".")
    try:
        amount = Decimal(raw_amount)
    except InvalidOperation:
        return Decimal("0")

    scale = match.group("scale")
    if scale is None:
        return amount
    return amount * EXPOSURE_SCALE_MULTIPLIERS[scale.lower()]


def _total_financial_exposure(linked_services: list[LinkedServiceContext]) -> float:
    total = sum(
        (_financial_exposure_amount(service.financial_exposure) for service in linked_services),
        Decimal("0"),
    )
    return float(total)


def _is_crown_jewel_candidate(
    *,
    asset_is_spof: bool,
    linked_services: list[LinkedServiceContext],
    total_exposure: float,
) -> bool:
    """Whether this asset's failure would create the largest business harm.

    The prototype's own definition: *"a service-supporting asset whose failure
    would create the largest business harm"*. **Consequence, not ownership** —
    there is deliberately no condition on which level the asset is registered
    at (#211, where a test asserted an L1 rule that had never existed).

    That distinction matters rather than being pedantry. The assets that carry
    the most harm are routinely **not** the organisation's own: a payment
    provider, a cloud region, the shared thing every service quietly runs
    through. Requiring L1 would hide precisely the concentration risks this
    platform exists to surface — the product's own language table names
    "Payment Provider Concentration" as a first-class finding.
    """
    mission_critical_count = sum(
        1 for service in linked_services if service.service_tier == SERVICE_TIER_MISSION_CRITICAL
    )
    total_exposure_amount = Decimal(str(total_exposure))

    return (
        mission_critical_count >= 2
        or (asset_is_spof and mission_critical_count >= 1)
        or total_exposure_amount > CROWN_JEWEL_EXPOSURE_THRESHOLD
    )


def build_asset_business_context(asset: Asset, org_id: int, db: Session) -> AssetBusinessContext:
    asset_reference = _asset_reference(asset)
    all_services = db.query(BusinessService).filter(BusinessService.organization_id == org_id).all()
    services_by_id = {service.id: service for service in all_services}

    linked_services: list[LinkedServiceContext] = []
    linked_service_ids: set[str] = set()

    for service in all_services:
        role = _service_role_for_asset(service, asset_reference)
        if role is None:
            continue
        _append_linked_service(linked_services, linked_service_ids, service, role)

    linked_dependencies = _find_asset_dependencies(
        asset_reference,
        org_id,
        services_by_id,
        db,
    )

    for dependency in linked_dependencies:
        service = services_by_id.get(dependency.service_id)
        if service is None:
            continue
        _append_linked_service(
            linked_services,
            linked_service_ids,
            service,
            SLOT_MAPPED_SERVICE_ROLE,
        )

    linked_processes = _resolve_linked_processes(linked_service_ids, all_services, org_id, db)
    total_exposure = _total_financial_exposure(linked_services)

    mission_critical_count = sum(
        1 for service in linked_services if service.service_tier == SERVICE_TIER_MISSION_CRITICAL
    )
    crown_jewel_candidate = _is_crown_jewel_candidate(
        asset_is_spof=asset.is_spof,
        linked_services=linked_services,
        total_exposure=total_exposure,
    )

    return AssetBusinessContext(
        asset_id=asset.id,
        display_name=asset.display_name,
        asset_type=asset.type,
        is_spof=asset.is_spof,
        risk_score=asset.risk_score,
        findings_count=asset.findings_count,
        crown_jewel_candidate=crown_jewel_candidate,
        linked_dependencies=linked_dependencies,
        linked_services=linked_services,
        linked_processes=linked_processes,
        blast_radius=AssetBlastRadiusContext(
            service_count=len(linked_service_ids),
            total_exposure=total_exposure,
            mission_critical_count=mission_critical_count,
            has_financial_exposure=any(service.financial_exposure for service in linked_services),
        ),
    )
