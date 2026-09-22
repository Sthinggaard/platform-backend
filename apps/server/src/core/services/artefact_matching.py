"""Artefact-to-slot matching rules — shared Intelligence Engine core.

Single source of truth for how an ingested physical artefact (Asset registry
row) is scored against a logical dependency slot's profile knowledge
(``SlotTemplate.matching_hints`` / ``expected_asset_types``). Used by:

- the slot-mapping suggestion pass (BSP-05) — which asset fills this slot;
- evidence-driven service discovery (BSP-11) — which services the
  organisation evidently runs.

Confidence model (skill: confidence = verification, never fabricated):
provider evidence is the strongest signal an artefact offers; a display-name
match is weaker; an asset-type match with no hint is the weakest acceptable
basis. Engine results are capped below 1.0 — only an accountable human
decision reaches full confidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from src.core.constants.artefact_identity_evidence_enums import (
    IDENTITY_BASIS_PHRASE,
    IDENTITY_BASIS_PRECEDENCE,
)
from src.core.model_defs.assets_runtime import Asset, ConnectivityStatus
from src.core.template_models import SlotTemplate

PROVIDER_HINT_CONFIDENCE = 0.7
NAME_HINT_CONFIDENCE = 0.6
ASSET_TYPE_CONFIDENCE = 0.45
VERIFIED_CONNECTION_BOOST = 0.1
TYPE_AGREEMENT_BOOST = 0.05
ENGINE_CONFIDENCE_CAP = 0.85

# ── CA-09A.4 (#316) — what deep verification learned is matching evidence ────
#
# The scorer read `matching_hints`, `expected_asset_types` and
# `connectivity_status` and nothing else, so an artefact the platform can now
# name *"Uvicorn, read off the service banner it returned"* was still matched by
# a substring of its display name and a type guess.
#
# A determined identity is a better surface to match on than a display name,
# because a display name is deliberately **not** the identity: `_display_name`
# prefers a hostname the organisation already gave the host, so on a named
# estate the determined identity never reaches the scorer at all.
#
# How much it is worth depends on what it was read from, and that ordering
# already exists exactly once, in `IDENTITY_BASIS_PRECEDENCE`. These two bounds
# are interpolated across it rather than restating it as a second table — the
# ticket's own instruction, and the only way the two cannot drift apart.
IDENTITY_HINT_CONFIDENCE_CEILING = 0.72
IDENTITY_HINT_CONFIDENCE_FLOOR = 0.50

#: Added when a second, independent basis produced a name matching the same
#: hint. Søren, 2026-08-27: *"the title and the TLS certificate might make the
#: mapping stronger."* Two readings that agree are a better claim than either
#: alone — a certificate issued to `payments.internal` and a page that titles
#: itself `payments` are different questions asked of the same host, and both
#: answering the same way is evidence in a way neither is on its own.
#:
#: Deliberately modest, and still capped by ``ENGINE_CONFIDENCE_CAP``:
#: corroboration strengthens a claim, it does not make one certain, and no
#: amount of agreeing evidence may carry an engine suggestion to where only an
#: accountable person can take it.
CORROBORATING_BASIS_BOOST = 0.06


def identity_hint_confidence(basis: str | None) -> float:
    """What a hint matching a determined identity is worth, given its basis.

    Strongest at the top of ``IDENTITY_BASIS_PRECEDENCE`` — evidence read inside
    the host under an approval — and weakest at the bottom, where a hardware
    vendor names the manufacturer rather than the job. An unknown or missing
    basis gets the floor: it cannot be placed, so it is not credited.
    """
    order = [b.value for b in IDENTITY_BASIS_PRECEDENCE]
    if basis not in order:
        return IDENTITY_HINT_CONFIDENCE_FLOOR
    if len(order) == 1:
        return IDENTITY_HINT_CONFIDENCE_CEILING
    position = order.index(basis) / (len(order) - 1)
    span = IDENTITY_HINT_CONFIDENCE_CEILING - IDENTITY_HINT_CONFIDENCE_FLOOR
    return round(IDENTITY_HINT_CONFIDENCE_CEILING - span * position, 3)


@dataclass(frozen=True)
class ArtefactSlotMatch:
    confidence: float
    reason: str
    #: The profile hint the artefact matched, or None for a bare type match.
    matched_hint: str | None
    evidence: Literal["provider", "identity", "name", "type"]
    verified: bool


def confidence_scale(confidence: float) -> Literal["high", "medium", "low"]:
    """Map a numeric engine confidence onto the hypothesis high/medium/low scale."""
    if confidence >= PROVIDER_HINT_CONFIDENCE:
        return "high"
    if confidence >= 0.55:
        return "medium"
    return "low"


def score_asset_against_slot(slot: SlotTemplate, asset: Asset) -> ArtefactSlotMatch | None:
    """Score one artefact against one slot; None when no acceptable evidence exists."""
    hints = [str(hint).lower() for hint in (slot.matching_hints or []) if hint]
    provider_text = " ".join(
        part for part in (asset.provider, asset.provider_display_name) if part
    ).lower()
    name_text = (asset.display_name or "").lower()
    type_agrees = (asset.type or "").lower() in {
        str(expected).lower() for expected in (slot.expected_asset_types or [])
    }

    identity_name, identity_basis = _determined_identity(asset)
    identity_text = (identity_name or "").lower()

    matched_hint: str | None = None
    base: float | None = None
    evidence: Literal["provider", "identity", "name", "type"] = "type"
    for hint in hints:
        if provider_text and hint in provider_text:
            matched_hint, base, evidence = hint, PROVIDER_HINT_CONFIDENCE, "provider"
            break
    if base is None:
        # Before the display name, because it is the better claim: a display
        # name is whatever the row happens to be titled, and may be an address
        # or a hostname somebody chose, while a determined identity is a
        # statement about what the thing *is*, with recorded evidence behind it.
        for hint in hints:
            if identity_text and hint in identity_text:
                matched_hint = hint
                base = identity_hint_confidence(identity_basis)
                evidence = "identity"
                break
    if base is None:
        for hint in hints:
            if name_text and hint in name_text:
                matched_hint, base, evidence = hint, NAME_HINT_CONFIDENCE, "name"
                break
    if base is None:
        if not type_agrees:
            return None
        # A type-only match is the weakest thing this scorer will act on, and
        # `Asset.type` is itself derived from the observed services. When none
        # of those was probed, the type is nmap restating a port number — so a
        # slot expecting a database would be filled on the evidence that
        # something answered on 5432, which is exactly the noise CA-09A exists
        # to stop feeding the matcher.
        #
        # Refusing is the safe direction: a person can still map this by hand,
        # and a suggestion nobody can defend costs more than a suggestion never
        # made. A hint match above is independent of this and is unaffected.
        if _type_came_from_a_scan(asset) and not _any_service_probed(asset):
            return None
        base = ASSET_TYPE_CONFIDENCE

    verified = asset.connectivity_status == ConnectivityStatus.CONNECTED
    corroborated = evidence == "identity" and _corroborated(asset)
    confidence = base
    if verified:
        confidence += VERIFIED_CONNECTION_BOOST
    if matched_hint and type_agrees:
        confidence += TYPE_AGREEMENT_BOOST
    if corroborated:
        confidence += CORROBORATING_BASIS_BOOST
    confidence = round(min(confidence, ENGINE_CONFIDENCE_CAP), 2)

    if matched_hint and evidence == "identity":
        # Names the evidence, not just the score. A reviewer who disagrees needs
        # to be able to disagree with the *claim* — "we read that off its TLS
        # certificate" is arguable; "confidence 0.68" is not.
        basis = (
            f"it was identified as '{identity_name}' ({_basis_phrase(identity_basis)}), "
            f"which matches the '{matched_hint}' pattern known for this capability"
        )
        if corroborated:
            basis += ", and a second, independent reading of the host agrees"
    elif matched_hint:
        basis = (
            f"its {evidence} matches the '{matched_hint}' pattern known for this capability"
        )
    else:
        basis = (
            f"it is registered as a {asset.type}, the kind of asset expected here, "
            "and a scan probed the service behind that"
        )
    verification = (
        "the integration connection is verified"
        if verified
        else "the connection is not yet verified"
    )
    reason = (
        f"Scanner evidence suggests '{asset.display_name}' fulfils the "
        f"{slot.label} dependency: {basis}; {verification}. "
        "Awaiting owner review — not yet confirmed."
    )
    return ArtefactSlotMatch(
        confidence=confidence,
        reason=reason,
        matched_hint=matched_hint,
        evidence=evidence,
        verified=verified,
    )


def _determined_identity(asset: Asset) -> tuple[str | None, str | None]:
    """The name the scan concluded, and what it was read from.

    Defensive twice over. ``intent`` is a JSON column that predates the key, so
    an artefact ingested before CA-07.1 simply has none — that must read as "no
    identity" rather than raise. And the annotation above is optimistic: BSP-11's
    service discovery scores duck-typed rows that carry only the attributes it
    needs, so ``intent`` may not be present as an attribute at all. Both are the
    same answer: nothing was determined.
    """
    intent = getattr(asset, "intent", None)
    intent = intent if isinstance(intent, dict) else {}
    identity = intent.get("identity")
    if not isinstance(identity, dict):
        return None, None
    name = identity.get("name")
    basis = identity.get("basis")
    return (name if isinstance(name, str) and name.strip() else None), (
        basis if isinstance(basis, str) else None
    )


def _any_service_probed(asset: Asset) -> bool:
    """Whether anything behind this artefact's type was actually asked.

    ``observedServiceEvidence`` is per port and carries #249's ``probed`` flag.
    An artefact recorded before that key existed has only the de-duplicated
    names, which cannot say — and is treated as **not** probed rather than
    assumed to have been, because the whole point of the guard is that an
    unearned certainty must not reach a suggestion.

    ``getattr`` for the same reason as ``_determined_identity``: this scorer is
    also called with duck-typed rows, and an absent attribute is not a claim
    that anything was probed.
    """
    intent = getattr(asset, "intent", None)
    intent = intent if isinstance(intent, dict) else {}
    recorded = intent.get("observedServiceEvidence")
    if not isinstance(recorded, list):
        return False
    return any(
        isinstance(item, dict) and bool(item.get("probed")) for item in recorded
    )


def _basis_phrase(basis: str | None) -> str:
    """How the identity was arrived at, in words a non-technical reader can weigh."""
    return IDENTITY_BASIS_PHRASE.get(basis or "", "from what the scan observed")


def _type_came_from_a_scan(asset: Asset) -> bool:
    """Whether this artefact's type was derived from services a scan observed.

    The probed guard exists to stop nmap's port-number table filling a slot. It
    has no business touching an asset that did not come from a scan at all —
    today those are the rows that let business services be assembled before any
    Collector existed, and in general they are **the organisation's own
    register**: a CMDB extract from ServiceNow, or a spreadsheet (Søren,
    2026-08-27, correcting "hand maintained": *"it might be that the assets or
    artefacts come from the cmdb"*).

    That provenance is a *stronger* claim than a scan, not a weaker one. A scan
    says something answered on an address; a CMDB entry says the organisation
    owns this and knows what it is for. Suppressing those would have removed the
    best-attested assets in the estate from matching.

    ⚠️ This is a **proxy**. The model records no provenance at all — `provider`
    carries both "collector" and "Okta", so *who told us* and *what it is* are
    the same column — so "did a scan decide this type?" has to be inferred from
    whether observed services exist. #325 is filed to give provenance a field of
    its own; when it lands, this should read it instead of inferring it.

    Asked as "did a scan decide this type?" rather than by reading `provider` or
    `observation_level`, because that is the actual precondition for the guard:
    a type with no observed services behind it was not derived from a port
    number, whatever produced the row.
    """
    intent = getattr(asset, "intent", None)
    intent = intent if isinstance(intent, dict) else {}
    observed = intent.get("observedServices")
    return isinstance(observed, list) and bool(observed)


def _corroborated(asset: Asset) -> bool:
    """Whether more than one independent basis produced a name for this host.

    Read from ``corroboratingBases``, which records every basis that yielded a
    candidate rather than only the one precedence chose. Absent on artefacts
    recorded before it existed, which reads as "not corroborated" — the same
    direction every other unknown is resolved in here.
    """
    intent = getattr(asset, "intent", None)
    intent = intent if isinstance(intent, dict) else {}
    identity = intent.get("identity")
    if not isinstance(identity, dict):
        return False
    bases = identity.get("corroboratingBases")
    return isinstance(bases, list) and len(bases) > 1
