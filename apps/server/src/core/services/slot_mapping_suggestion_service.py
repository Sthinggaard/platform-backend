"""Intelligence Engine — first-pass slot-mapping suggestions (BSP-05).

Maps ingested physical artefacts (Asset registry rows) onto a Business
Service's logical dependency slots, using the profile-enriched
``SlotTemplate.matching_hints`` and ``expected_asset_types`` as matching
input. This module is the single source of truth for the matching and
confidence rules.

Invariants (skill: risklence-business-service-profiles):

- The engine recommends; humans decide. Suggestions are written with
  ``mapping_status="suggested"`` and the operational ``status`` stays
  ``"unknown"`` — nothing counts as mapped until the owner approves it
  in the wizard.
- Confidence is about verification, never fabricated: engine suggestions
  are capped at ``ENGINE_CONFIDENCE_CAP``; only an accountable human
  decision reaches 1.0 (``owner_approved``).
- Rows carrying a human decision (approved/rejected mapping status, or
  owner_approved/overridden provenance) are never modified.
- Every suggestion carries an explainable, evidence-based reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from src.core.model_defs.assets_runtime import NON_DEPENDABLE_LIFECYCLE_STATES, Asset
from src.core.model_defs.value_streams import BusinessService, SlotInstance
from src.core.services.artefact_matching import (
    ASSET_TYPE_CONFIDENCE,
    ENGINE_CONFIDENCE_CAP,
    NAME_HINT_CONFIDENCE,
    PROVIDER_HINT_CONFIDENCE,
    TYPE_AGREEMENT_BOOST,
    VERIFIED_CONNECTION_BOOST,
    score_asset_against_slot,
)
from src.core.services.asset_context_service import asset_reference
from src.core.services.slot_mapping_refutation_service import Refutation, load_refutations
from src.core.services.template_library_service import (
    list_slot_templates_for_service,
    resolve_active_service_template,
)
from src.core.template_models import SlotTemplate

# Matching + confidence rules live in artefact_matching (shared with BSP-11
# service discovery); the constants are re-exported here for compatibility.
__all__ = [
    "ASSET_TYPE_CONFIDENCE",
    "ENGINE_CONFIDENCE_CAP",
    "NAME_HINT_CONFIDENCE",
    "PROVIDER_HINT_CONFIDENCE",
    "TYPE_AGREEMENT_BOOST",
    "VERIFIED_CONNECTION_BOOST",
    "SlotMappingSuggestion",
    "SlotSuggestionPassResult",
    "is_human_decided",
    "run_slot_mapping_suggestion_pass",
]

MAPPING_STATUS_SUGGESTED = "suggested"
PROVENANCE_SCANNER = "scanner"
EVIDENCE_SOURCE_SCANNER = "scanner"

_HUMAN_DECIDED_MAPPING_STATUSES = frozenset({"approved", "rejected"})
_HUMAN_PROVENANCE = frozenset({"owner_approved", "overridden"})


@dataclass(frozen=True)
class SlotMappingSuggestion:
    slot_id: str
    group_key: str
    slot_label: str
    asset_id: str
    asset_label: str
    confidence: float
    reason: str


@dataclass(frozen=True)
class ParkedSlot:
    """A slot the engine parked, and the group a reader will find it under.

    Carries both because they answer different questions. ``slot_id`` is what
    was actually refused, and what an auditor needs; ``group_key`` is where the
    reviewer's surface shows it, since the wizard is grouped by capability and a
    group can list several slots. A parked slot has **no row of its own** — that
    is the point, since a row would place it in the set a reader takes as
    decided — so neither can be looked up afterwards.
    """

    slot_id: str
    group_key: str


@dataclass(frozen=True)
class SlotSuggestionPassResult:
    template_version: int | None
    suggestions: list[SlotMappingSuggestion]
    skipped_human_decided: list[str]
    unmatched_slot_ids: list[str]
    #: CA-09A.6 — slots this pass **parked** rather than suggest for, because a
    #: person already ruled that artefact out for that slot.
    #:
    #: "Parked", not "withheld" (Søren, 2026-08-27: *"withheld is a bit too
    #: arbitrary"*). Parked says what actually happened and what a reader can do
    #: about it: the question is set aside, not answered, and it can be picked
    #: up again. Withheld sounds like the platform is keeping something back.
    #:
    #: ⚠️ **A parked slot is never part of the active, approved set.** It is not
    #: mapped, not approved, and not counted as matched — it carries no asset at
    #: all. Reported rather than silently omitted, because an engine that
    #: quietly offers less is indistinguishable from one that has stopped
    #: working, and the epic's contract word is "explainable".
    parked_by_refutation: list[ParkedSlot] = field(default_factory=list)


def is_human_decided(row: SlotInstance) -> bool:
    """A row the engine must never touch: a human already decided it."""
    return (row.mapping_status or "") in _HUMAN_DECIDED_MAPPING_STATUSES or (
        row.provenance or ""
    ) in _HUMAN_PROVENANCE


def _score_asset(slot: SlotTemplate, asset: Asset) -> tuple[float, str] | None:
    """Score one artefact against one slot; returns (confidence, reason) or None."""
    match = score_asset_against_slot(slot, asset)
    if match is None:
        return None
    return match.confidence, match.reason


def _best_match(
    slot: SlotTemplate,
    assets: list[Asset],
    refuted: dict[tuple[str, str], Refutation] | None = None,
) -> SlotMappingSuggestion | None:
    refuted = refuted or {}
    best: tuple[float, int, Asset, str] | None = None
    for asset in assets:
        # CA-09A.6 — a person already said this artefact is not what fills this
        # slot. Skipped rather than scored-and-discarded so the next-best
        # candidate is still offered: refuting one answer must not silence the
        # question.
        if (slot.slot_id, asset_reference(asset.id)) in refuted:
            continue
        scored = _score_asset(slot, asset)
        if scored is None:
            continue
        confidence, reason = scored
        # Deterministic ranking: highest confidence wins; ties break on the
        # oldest (lowest-id) artefact so reruns are stable.
        candidate = (confidence, -(asset.id or 0), asset, reason)
        if best is None or candidate[:2] > best[:2]:
            best = candidate
    if best is None:
        return None
    confidence, _, asset, reason = best
    return SlotMappingSuggestion(
        slot_id=slot.slot_id,
        group_key=slot.capability_group_key,
        slot_label=slot.label,
        # ⚠️ #363 — the canonical reference, never ``str(asset.id)``. This line wrote
        # ``"92"`` into every scanner suggestion, and accepting one carried the
        # digit string into slot rows and bundle links beside ``"asset-92"``.
        asset_id=asset_reference(asset.id),
        asset_label=asset.display_name,
        confidence=confidence,
        reason=reason,
    )


def _upsert_suggested_row(
    db: Session,
    *,
    service: BusinessService,
    suggestion: SlotMappingSuggestion,
    existing: SlotInstance | None,
    template_version: int | None,
) -> None:
    lifecycle = {
        "asset_id": suggestion.asset_id,
        "asset_label": suggestion.asset_label,
        "group_key": suggestion.group_key,
        "template_version": template_version,
        "mapping_status": MAPPING_STATUS_SUGGESTED,
        "mapping_confidence": suggestion.confidence,
        "evidence_source": EVIDENCE_SOURCE_SCANNER,
        "mapping_reason": suggestion.reason,
        "provenance": PROVENANCE_SCANNER,
        # No human decision has been made on this suggestion.
        "decided_by": None,
        "decided_at": None,
    }
    if existing is not None:
        for attr, value in lifecycle.items():
            setattr(existing, attr, value)
        db.add(existing)
    else:
        db.add(
            SlotInstance(
                organization_id=service.organization_id,
                service_id=service.id,
                slot_id=suggestion.slot_id,
                status="unknown",
                **lifecycle,
            )
        )


def run_slot_mapping_suggestion_pass(
    db: Session, *, service: BusinessService
) -> SlotSuggestionPassResult:
    """Compute and persist first-pass suggestions for one service.

    The caller owns the transaction (commit) and any signal emission.
    """
    template = resolve_active_service_template(
        db, template_key=service.template_key, archetype=service.archetype
    )
    if template is None:
        return SlotSuggestionPassResult(None, [], [], [])

    slots = list_slot_templates_for_service(db, template.id)
    # A reviewer's disposition on an artefact has to reach the dependency
    # picture, or it means nothing: suggesting something the user has already
    # said is not theirs — or is theirs but will never be depended on — asks
    # them the same question again in a place where saying no is harder.
    #
    # The REMOVED case predates "Will not use" (#150 added rejection without
    # teaching this path about it); NOT_USED would have shipped with the same
    # hole. Both are excluded here by the one shared definition.
    assets = (
        db.query(Asset)
        .filter(Asset.organization_id == service.organization_id)
        .filter(Asset.lifecycle_state.notin_(NON_DEPENDABLE_LIFECYCLE_STATES))
        .all()
    )
    existing_by_slot: dict[str, SlotInstance] = {
        row.slot_id: row
        for row in db.query(SlotInstance)
        .filter(
            SlotInstance.organization_id == service.organization_id,
            SlotInstance.service_id == service.id,
        )
        .all()
    }

    # Every (slot, artefact) pair this organisation has ruled out as a wrong
    # match. Loaded once for the pass, not per slot: it is a property of the
    # organisation's decisions, not of the service being suggested for — which
    # is the point. A refusal recorded against one service now reaches every
    # other service whose template names the same slot, where before it stopped
    # at the row it was made on.
    refuted = load_refutations(db, organization_id=service.organization_id)

    suggestions: list[SlotMappingSuggestion] = []
    skipped_human_decided: list[str] = []
    unmatched_slot_ids: list[str] = []
    parked_by_refutation: list[ParkedSlot] = []
    for slot in slots:
        existing = existing_by_slot.get(slot.slot_id)
        if existing is not None and is_human_decided(existing):
            skipped_human_decided.append(slot.slot_id)
            continue
        suggestion = _best_match(slot, assets, refuted)
        if suggestion is None:
            if _best_match(slot, assets) is not None:
                # There *was* a candidate and a person ruled it out. Reported
                # apart from "nothing matched", and never as well as it: one
                # says the estate holds nothing for this slot, the other says
                # the engine had an answer and was told it was wrong. A slot
                # counted as both would tell a reviewer the estate is emptier
                # than it is *and* hide the learning they taught.
                parked_by_refutation.append(
                    ParkedSlot(slot_id=slot.slot_id, group_key=slot.capability_group_key)
                )
                continue
            # No fabricated mapping and no fabricated confidence — the gap
            # itself is the finding ("Risklence cannot confidently assess…").
            unmatched_slot_ids.append(slot.slot_id)
            continue
        _upsert_suggested_row(
            db,
            service=service,
            suggestion=suggestion,
            existing=existing,
            template_version=template.version,
        )
        suggestions.append(suggestion)

    return SlotSuggestionPassResult(
        template_version=template.version,
        suggestions=suggestions,
        skipped_human_decided=skipped_human_decided,
        unmatched_slot_ids=unmatched_slot_ids,
        parked_by_refutation=parked_by_refutation,
    )
