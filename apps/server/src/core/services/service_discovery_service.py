"""Evidence-driven service discovery (BSP-11).

The BSP-05 matcher run in reverse: instead of asking "which artefact fills
this slot?", ask "which Business Services does the organisation evidently
run that it has not modelled yet?" — by scoring the org's Asset registry
against every active service template's profile knowledge.

Invariants (risklence-domain-decision-model / business-service-profiles):

- Discovery writes *hypothesis assumptions*, never Business Services — a
  human confirms before anything exists (BSP-13 review flow).
- A whole-service claim needs real evidence: only hint-based matches
  (provider or display name) qualify. A bare asset-type agreement is too
  generic to claim the organisation runs a service.
- Items a human already decided (confirmed/dismissed) are never modified.
- Services the organisation already models are skipped — discovery proposes
  what is missing, it does not re-litigate what exists.
- Every proposal carries evidence, confidence, and an explainable reason.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.value_stream_library import VALUE_STREAM_BY_KEY
from src.core.model_defs.assets_runtime import Asset
from src.core.model_defs.baseline_risk_hypothesis import (
    ASSUMPTION_PROPOSED,
    BaselineRiskHypothesis,
)
from src.core.models import BusinessService
from src.core.services.artefact_matching import confidence_scale, score_asset_against_slot
from src.core.services.template_library_service import (
    list_active_service_templates,
    list_slot_templates_for_service,
)

PROVENANCE_SCANNER = "scanner"


@dataclass(frozen=True)
class DiscoveredService:
    service_key: str
    service_name: str
    confidence: float
    reason: str
    evidence: list[dict]  # [{asset_id, asset_label, slot_label, matched_hint}]


@dataclass(frozen=True)
class ServiceDiscoveryResult:
    newly_proposed: list[str]
    strengthened: list[str]
    skipped_modelled: list[str]
    discovered: list[DiscoveredService]


def _modelled_service_keys(db: Session, organization_id: int) -> set[str]:
    rows = (
        db.query(BusinessService.template_key, BusinessService.library_item_id)
        .filter(BusinessService.organization_id == organization_id)
        .all()
    )
    keys: set[str] = set()
    for template_key, library_item_id in rows:
        if template_key:
            keys.add(template_key)
        if library_item_id:
            keys.add(library_item_id)
    return keys


def _discover_for_template(template, slots, assets: list[Asset]) -> DiscoveredService | None:
    """Best hint-based evidence that the org runs this service, or None."""
    evidence: list[dict] = []
    best_confidence = 0.0
    best: tuple | None = None  # (confidence, -asset_id, asset, slot, hint)

    for slot in slots:
        for asset in assets:
            match = score_asset_against_slot(slot, asset)
            if match is None or match.matched_hint is None:
                continue  # whole-service claims need hint evidence, not bare type matches
            evidence.append(
                {
                    "asset_id": str(asset.id),
                    "asset_label": asset.display_name,
                    "slot_label": slot.label,
                    "matched_hint": match.matched_hint,
                }
            )
            candidate = (match.confidence, -(asset.id or 0), asset, slot, match.matched_hint)
            if best is None or candidate[:2] > best[:2]:
                best = candidate
                best_confidence = match.confidence

    if best is None:
        return None
    _, _, asset, slot, hint = best
    service_name = template.service_name or template.service_key
    reason = (
        f"Scanner evidence suggests your organisation runs a {service_name} capability: "
        f"'{asset.display_name}' matches the '{hint}' pattern for its {slot.label} "
        "dependency. Proposed for your review — not yet part of your business model."
    )
    return DiscoveredService(
        service_key=template.service_key,
        service_name=service_name,
        confidence=best_confidence,
        reason=reason,
        evidence=evidence,
    )


def _parent_process_key(service_key: str, assumptions: list[dict]) -> str | None:
    """Attach a discovered service to a non-dismissed process already in the hypothesis."""
    process_keys = {
        item.get("key")
        for item in assumptions
        if item.get("kind") == "business_process" and item.get("validation") != "dismissed"
    }
    for stream_key, library_item in VALUE_STREAM_BY_KEY.items():
        if service_key in library_item.core_service_keys and stream_key in process_keys:
            return stream_key
    return None


def run_service_discovery_pass(
    db: Session, *, organization_id: int, hypothesis: BaselineRiskHypothesis
) -> ServiceDiscoveryResult:
    """Discover unmodelled services from scanner evidence into the hypothesis.

    The caller owns the transaction (commit).
    """
    assets = db.query(Asset).filter(Asset.organization_id == organization_id).all()
    modelled_keys = _modelled_service_keys(db, organization_id)

    discovered: list[DiscoveredService] = []
    skipped_modelled: list[str] = []
    for template in list_active_service_templates(db):
        slots = list_slot_templates_for_service(db, template.id)
        candidate = _discover_for_template(template, slots, assets)
        if candidate is None:
            continue
        if candidate.service_key in modelled_keys:
            skipped_modelled.append(candidate.service_key)
            continue
        discovered.append(candidate)

    assumptions = [dict(item) for item in (hypothesis.assumptions or [])]
    items_by_service_key = {
        item.get("key"): item for item in assumptions if item.get("kind") == "business_service"
    }

    newly_proposed: list[str] = []
    strengthened: list[str] = []
    for candidate in discovered:
        existing = items_by_service_key.get(candidate.service_key)
        if existing is not None:
            # Human-decided items are never modified by the engine.
            if existing.get("validation") != ASSUMPTION_PROPOSED:
                continue
            existing["provenance"] = PROVENANCE_SCANNER
            existing["confidence"] = confidence_scale(candidate.confidence)
            existing["reason"] = candidate.reason
            existing["evidence"] = candidate.evidence
            existing["evidence_confidence"] = candidate.confidence
            strengthened.append(candidate.service_key)
        else:
            assumptions.append(
                {
                    "kind": "business_service",
                    "key": candidate.service_key,
                    "name": candidate.service_name,
                    "parent_key": _parent_process_key(candidate.service_key, assumptions),
                    "provenance": PROVENANCE_SCANNER,
                    "confidence": confidence_scale(candidate.confidence),
                    "reason": candidate.reason,
                    "evidence": candidate.evidence,
                    "evidence_confidence": candidate.confidence,
                    "suggested_priority": None,
                    "validation": ASSUMPTION_PROPOSED,
                    "decided_by": None,
                    "decided_at": None,
                }
            )
            newly_proposed.append(candidate.service_key)

    if newly_proposed or strengthened:
        hypothesis.assumptions = assumptions  # reassign — JSONB columns don't track mutation
        db.add(hypothesis)

    return ServiceDiscoveryResult(
        newly_proposed=newly_proposed,
        strengthened=strengthened,
        skipped_modelled=skipped_modelled,
        discovered=discovered,
    )
