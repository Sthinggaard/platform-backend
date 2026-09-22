"""Recommend a Process Risk Appetite from BIA + regulatory context + process criticality.

Contract (risklence-domain-decision-model): Risklence recommends, a human
decides. This module never activates anything — it produces a suggested
six-dimension appetite (the same vocabulary `RiskAppetitePolicy.answers`
already uses). The Process Owner may accept it unchanged, or adjust it
through structured choices and submit that deviation for leadership approval
(`risk_appetite_resolution_service` owns that lifecycle).

Every recommended level carries a short, business-worded reason ("on what
grounds"), mirroring `org_context_profile_tuning.py`'s explicit rule-table
style rather than a black-box score.

An optional cross-organisation peer benchmark (`peer_appetite_benchmark_service`)
can nudge the recommendation toward what comparable organisations settled on
for the same process template — never a per-organisation lookup, only an
aggregate, and only once enough peers exist (see that module's docstring).

Cascade redesign (risk-appetite-governance-cascade): once an active
Organisation Risk Appetite exists, this process's recommended *starting*
answers are the currently-cascaded org values (`cascaded_org_answers`) —
not the independent BIA-driven computation — since that is genuinely what
the process already inherits today; the Process Owner is reviewing and
adjusting an inherited value, not starting from nothing. The BIA/regulatory/
priority/peer analysis this module has always done still runs in full, and
its own suggested level is now surfaced as part of each dimension's reason
("your process's own BIA would suggest level X instead") whenever it
diverges from the cascaded starting point, so the Process Owner can see
both the inherited baseline and Risklence's own process-specific read
before deciding whether to submit a deviation. When no org policy is
active yet (a genuine bootstrapping case, not a data gap), this falls back
to the independent BIA-driven computation exactly as before.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.core.services.peer_appetite_benchmark_service import PeerAppetiteBenchmark

_SEVERITY_TO_LEVEL: dict[str, int] = {"severe": 1, "high": 2, "medium": 3, "low": 4}
_MTD_TO_LEVEL: dict[str, int] = {"le_1h": 1, "le_4h": 2, "le_24h": 3, "gt_24h": 4}
_DATA_SENSITIVITY_TO_LEVEL: dict[str, int] = {"high": 1, "medium": 2, "low": 3}

_REGULATED_FRAMEWORKS = frozenset({"NIS2", "DORA", "PCIDSS", "GDPR"})

_PRIORITY_SHIFT: dict[str, int] = {"critical": -1, "important": 0, "standard": 1}


def _normalize_framework(value: str) -> str:
    return "".join(ch for ch in value.upper() if ch.isalnum())


@dataclass(frozen=True)
class AppetiteDimensionRecommendation:
    level: int
    reason: str


@dataclass(frozen=True)
class DimensionGrounds:
    """Why one dimension is recommended at the level it is, as facts.

    ⚠️ **Four facts, not one sentence.** These were composed into a single
    semicolon-joined string, six of which were then joined again into one text
    node and rendered above the answers they explained — Søren, 2026-09-11: *"it
    has no styling nor structure to it. Nothing guides the reader."* There was
    nothing to style, because there was nothing but a string.

    Composing them here was also a copy decision taken in the wrong place: how
    this reads is the interface's to choose, and it cannot choose while the
    clauses are already glued together.

    `reason` is still produced alongside, unchanged, because it is the note
    submitted to leadership and read back from the audit trail.
    """

    #: What the organisation policy already gives this process, if anything.
    inherited_level: int | None
    #: What is being proposed — the inherited level, or Risklence's read when
    #: nothing is inherited.
    recommended_level: int
    #: Risklence's own read of this process, present only when it **differs**
    #: from what is inherited. This is the live part: the platform disagreeing.
    suggested_level: int | None
    #: The separate reasons, each a finished clause. Never joined here.
    grounds: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProcessAppetiteRecommendation:
    answers: dict[str, int]
    reasons: dict[str, str] = field(default_factory=dict)
    #: The same explanation as `reasons`, as facts rather than prose.
    grounds: dict[str, DimensionGrounds] = field(default_factory=dict)
    confidence: str = "medium"
    missing_inputs: list[str] = field(default_factory=list)


def _clamp(level: int) -> int:
    return max(0, min(4, level))


def _worst_impact_level(bia: dict) -> tuple[int, str]:
    severities = [
        bia.get("impact1h"),
        bia.get("impact4h"),
        bia.get("impact24h"),
    ]
    known = [s for s in severities if s in _SEVERITY_TO_LEVEL]
    if not known:
        return 3, "no BIA impact severity recorded — defaulting to a moderate, unverified level"
    worst = min(_SEVERITY_TO_LEVEL[s] for s in known)
    label = next(s for s in known if _SEVERITY_TO_LEVEL[s] == worst)
    return worst, f"the process's worst recorded impact severity is '{label}'"


def _priority_reason(priority: str, shift: int) -> str:
    if shift < 0:
        return f"tightened one level because this process is marked '{priority}'"
    if shift > 0:
        return f"relaxed one level because this process is marked '{priority}'"
    return f"no adjustment for a '{priority}' priority process"


def _blend_with_peers(base_level: int, peer: "PeerAppetiteBenchmark | None") -> tuple[int, str | None]:
    """Nudge toward the peer median; never a per-organisation lookup, only an aggregate."""
    if peer is None:
        return base_level, None
    blended = round((base_level + peer.median_level) / 2)
    if peer.median_level == base_level:
        note = (
            f"{peer.peer_count} similar organisations (same process template) also settled "
            f"around level {peer.median_level}"
        )
    else:
        direction = "tighter" if peer.median_level < base_level else "more relaxed"
        note = (
            f"{peer.peer_count} similar organisations (same process template) set this to "
            f"level {peer.median_level} or {direction} — your BIA alone would suggest level {base_level}"
        )
    return blended, note


def recommend_process_appetite(
    *,
    bia_answers: dict | None,
    required_frameworks: list[str] | None,
    process_priority: str,
    peer_benchmark: dict[str, PeerAppetiteBenchmark] | None = None,
    cascaded_org_answers: dict[str, int] | None = None,
) -> ProcessAppetiteRecommendation:
    """Build a suggested six-dimension appetite. Never activates anything.

    When ``cascaded_org_answers`` is provided (an active Organisation Risk
    Appetite exists), the returned ``answers`` are that cascaded baseline —
    the genuine current starting point for this process — while the BIA/
    regulatory/priority/peer analysis below still runs in full and surfaces
    its own suggested level in ``reasons`` whenever it would diverge from
    that baseline. Without a cascaded baseline (no org policy active yet),
    the BIA-driven computation itself is the starting point, unchanged from
    this module's original behaviour."""
    bia = bia_answers or {}
    missing_inputs: list[str] = []
    if not bia:
        missing_inputs.append("business_impact_assessment")

    priority = process_priority if process_priority in _PRIORITY_SHIFT else "important"
    shift = _PRIORITY_SHIFT[priority]

    active_frameworks = {_normalize_framework(f) for f in (required_frameworks or []) if f}
    regulated = bool(active_frameworks & _REGULATED_FRAMEWORKS)
    if not required_frameworks:
        missing_inputs.append("regulatory_context")

    downtime_level, downtime_reason = (
        (_MTD_TO_LEVEL[bia["mtd"]], f"the process's attested maximum tolerable disruption is '{bia['mtd']}'")
        if bia.get("mtd") in _MTD_TO_LEVEL
        else (3, "no BIA maximum-tolerable-disruption recorded — defaulting to a moderate, unverified level")
    )
    data_loss_level, data_loss_reason = (
        (
            _DATA_SENSITIVITY_TO_LEVEL[bia["dataSensitivity"]],
            f"the process's attested data sensitivity is '{bia['dataSensitivity']}'",
        )
        if bia.get("dataSensitivity") in _DATA_SENSITIVITY_TO_LEVEL
        else (3, "no BIA data-sensitivity recorded — defaulting to a moderate, unverified level")
    )
    impact_level, impact_reason = _worst_impact_level(bia)

    regulatory_level = 1 if regulated else 3
    regulatory_reason = (
        f"active regulatory frameworks ({', '.join(sorted(active_frameworks))}) require tight compliance escalation"
        if regulated
        else "no regulatory framework recorded as requiring tight compliance escalation for this process"
    )
    security_level = 1 if regulated else 3
    security_reason = (
        "active regulatory frameworks expect provable, fast-closing security response"
        if regulated
        else "no regulatory framework recorded as demanding a fast security response floor"
    )

    dimensions: dict[str, AppetiteDimensionRecommendation] = {
        "downtime": AppetiteDimensionRecommendation(downtime_level, downtime_reason),
        "dataLoss": AppetiteDimensionRecommendation(data_loss_level, data_loss_reason),
        "financial": AppetiteDimensionRecommendation(impact_level, impact_reason),
        "reputational": AppetiteDimensionRecommendation(impact_level, impact_reason),
        "regulatory": AppetiteDimensionRecommendation(regulatory_level, regulatory_reason),
        "security": AppetiteDimensionRecommendation(security_level, security_reason),
    }

    # Peer data is a bonus signal, not a required input — its absence is the
    # common case (few or no comparable peers yet) and must never lower
    # confidence the way a missing BIA or regulatory context does.
    peers = peer_benchmark or {}

    org_baseline = cascaded_org_answers or {}

    answers: dict[str, int] = {}
    reasons: dict[str, str] = {}
    grounds: dict[str, DimensionGrounds] = {}
    for dim, rec in dimensions.items():
        base_level, peer_note = _blend_with_peers(rec.level, peers.get(dim))
        floor = rec.level if dim in ("regulatory", "security") and regulated else None
        suggested = _clamp(base_level + shift)
        if floor is not None:
            suggested = min(suggested, floor)

        reason = rec.reason
        # The same clauses the sentence below is built from, kept apart so the
        # interface can decide how they read.
        clauses = [rec.reason]
        if peer_note:
            reason = f"{reason}; {peer_note}"
            clauses.append(peer_note)
        if shift != 0:
            priority_reason = _priority_reason(priority, shift)
            reason = f"{reason}; {priority_reason}"
            clauses.append(priority_reason)

        cascaded_level = org_baseline.get(dim)
        if cascaded_level is not None:
            # The genuine current starting point is what this process
            # already inherits from the org policy — the BIA/peer/priority
            # analysis above is Risklence's own process-specific read,
            # surfaced as a suggestion only when it actually diverges.
            answers[dim] = cascaded_level
            if suggested != cascaded_level:
                reason = (
                    f"currently inherited from the organisation policy at level {cascaded_level}; "
                    f"{reason}; based on this process's own profile Risklence would suggest level {suggested} instead"
                )
            else:
                reason = f"inherited from the organisation policy at level {cascaded_level}; {reason}"
        else:
            answers[dim] = suggested
        reasons[dim] = reason
        grounds[dim] = DimensionGrounds(
            inherited_level=cascaded_level,
            recommended_level=answers[dim],
            # Only when it diverges: "Risklence would suggest 0 instead" said on
            # every row, including the ones it agrees with, is not a signal.
            suggested_level=suggested if cascaded_level is not None and suggested != cascaded_level else None,
            grounds=clauses,
        )

    confidence = "low" if len(missing_inputs) >= 2 else "medium" if missing_inputs else "high"
    return ProcessAppetiteRecommendation(
        answers=answers,
        reasons=reasons,
        grounds=grounds,
        confidence=confidence,
        missing_inputs=missing_inputs,
    )
