"""May this person record a binding decision about this threat?

Søren's ruling, 2026-08-31 — **authority follows ownership of the thing decided**:

    "The owner needs to have the final mandate on what is done or decided in a
    business service or process. This is not for leadership to decide... In this
    case the owner of this service makes the decisions and the ones affected by
    this decision is informed."

🚨 **What this replaces.** ``POST /api/v1/recommendations/decisions`` was guarded
by ``_require_non_consultant`` alone, so **any active non-consultant could accept
risk, escalate, or dispatch to Jira on any threat in the organisation** — a
view-only member included. Søren found it on 2026-08-31 testing as
``viewer@risklence.com``, a member holding no mandate at all, and was offered
*Change decision* and a *Capture Resolution* panel for a process he does not own.

The decision is attributed to a human either way. Attribution without authority
records who clicked, not who was accountable (#374).

⚠️ **It fails closed.** Where the threat reaches no service, or the service it
reaches has nobody accountable, nobody may decide. The repair is to state an
owner (#376), not to widen who may act — and a decision recorded by nobody in
particular is the outcome this exists to prevent.

⚠️ **A process owner who merely depends on the service is refused.** That is the
case Søren named and the one that makes this rule different from "may they act
on the affected process". They are *informed* instead (#375).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy.orm import Session

from src.core.models import Asset, BusinessService
from src.core.services.service_accountability_service import (
    ServiceAccountability,
    resolve_service_accountability,
)
from src.core.services.asset_context_service import normalise_asset_reference


class ThreatDecisionRefusal(StrEnum):
    """Why the decision was refused. Each needs a different repair."""

    #: The threat's asset matches no artefact this organisation holds.
    ASSET_NOT_FOUND = "asset_not_found"
    #: The artefact is not carried by any Business Service.
    NO_SERVICE_REACHED = "no_service_reached"
    #: A service is reached, but nobody is accountable for it yet (#376).
    ACCOUNTABILITY_UNRESOLVED = "accountability_unresolved"
    #: Somebody is accountable, and it is not this person.
    NOT_THE_HOLDER = "not_the_holder"


@dataclass(frozen=True)
class ThreatDecisionAuthority:
    may_decide: bool
    #: Services carrying the threat's artefact.
    affected_service_ids: tuple[str, ...]
    #: Who may decide. Empty whenever ``may_decide`` is false.
    holder_user_ids: tuple[int, ...]
    refusal: ThreatDecisionRefusal | None


def _asset_refs_for(db: Session, *, organization_id: int, asset_name: str) -> set[str]:
    """The artefact references a threat's asset name resolves to.

    ⚠️ **By name, because that is the only link there is.** ``threats.asset`` is
    free text with no foreign key, and the tenant's own projection matches the
    same way. A rename therefore breaks the chain — which fails closed here, and
    is worth a real reference on the threat.
    """
    wanted = (asset_name or "").strip().lower()
    if not wanted:
        return set()

    refs: set[str] = set()
    for asset in db.query(Asset).filter(Asset.organization_id == organization_id).all():
        if (asset.display_name or "").strip().lower() != wanted:
            continue
        reference = normalise_asset_reference(asset.id)
        if reference is not None:
            refs.add(reference)
    return refs


def _services_carrying(services: list[BusinessService], refs: set[str]) -> list[BusinessService]:
    carrying: list[BusinessService] = []
    for service in services:
        if service.archived_at is not None:
            continue
        linked = {
            reference
            for tier in (service.l1, service.l2, service.l3)
            for reference in (normalise_asset_reference(value) for value in tier or [])
            if reference is not None
        }
        if linked & refs:
            carrying.append(service)
    return carrying


def resolve_threat_decision_authority(
    db: Session,
    *,
    organization_id: int,
    threat_asset_name: str,
    actor_user_id: int | None,
) -> ThreatDecisionAuthority:
    """Whether ``actor_user_id`` may record a decision about this threat.

    Authorised by the accountability of the service carrying the artefact — the
    stated holder where there is one, otherwise the owner of its single process
    (``service_accountability_service``). One resolver, so "who may act" and
    "who is told" cannot disagree.
    """
    refs = _asset_refs_for(db, organization_id=organization_id, asset_name=threat_asset_name)
    if not refs:
        return ThreatDecisionAuthority(False, (), (), ThreatDecisionRefusal.ASSET_NOT_FOUND)

    services = (
        db.query(BusinessService)
        .filter(BusinessService.organization_id == organization_id)
        .all()
    )
    carrying = _services_carrying(services, refs)
    if not carrying:
        return ThreatDecisionAuthority(False, (), (), ThreatDecisionRefusal.NO_SERVICE_REACHED)

    accountability: dict[str, ServiceAccountability] = resolve_service_accountability(
        db, organization_id=organization_id, services=carrying
    )
    holders = {
        answer.holder_user_id
        for answer in accountability.values()
        if answer.holder_user_id is not None
    }
    service_ids = tuple(sorted(answer.service_id for answer in accountability.values()))

    if not holders:
        return ThreatDecisionAuthority(
            False, service_ids, (), ThreatDecisionRefusal.ACCOUNTABILITY_UNRESOLVED
        )
    if actor_user_id is None or actor_user_id not in holders:
        return ThreatDecisionAuthority(
            False, service_ids, tuple(sorted(holders)), ThreatDecisionRefusal.NOT_THE_HOLDER
        )

    return ThreatDecisionAuthority(True, service_ids, tuple(sorted(holders)), None)
