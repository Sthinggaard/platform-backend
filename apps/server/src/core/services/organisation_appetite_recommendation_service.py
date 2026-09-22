"""Recommend an Organisation Risk Appetite from regulatory context + peer benchmarking.

Mirrors process_appetite_recommendation_service.py's exact style — a
rule-based recommendation, never a black-box score, with a plain-language
"on what grounds" reason per dimension. Contract (risklence-domain-decision-model):
Risklence recommends, leadership decides — this module never activates
anything, it only feeds the draft leadership reviews and corrects
(risk_appetite_resolution_service's create_appetite_draft at
APPETITE_SCOPE_ORGANISATION).

No process-level input feeds this — there is nothing above organisation
scope to inherit from, unlike the process-level engine's BIA. Every
dimension without a stronger signal honestly defaults to a moderate,
unverified level 3 (identical fallback the process engine already uses when
its own BIA is missing) rather than inventing organisation-specific rules
this repo has no real basis for. Regulatory frameworks tighten the
regulatory/security floor exactly as they do at process scope. An optional
cross-organisation peer benchmark (peer_appetite_benchmark_service.org_peer_appetite_benchmark,
comparable only by industry/NACE code — there is no process-template
equivalent at this scope) can nudge the recommendation toward what
comparable organisations settled on.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.core.services.peer_appetite_benchmark_service import PeerAppetiteBenchmark

_REGULATED_FRAMEWORKS = frozenset({"NIS2", "DORA", "PCIDSS", "GDPR"})

_BASELINE_LEVEL = 3
_BASELINE_REASON = "no organisation-wide impact baseline exists yet — defaulting to a moderate, unverified level"


def _normalize_framework(value: str) -> str:
    return "".join(ch for ch in value.upper() if ch.isalnum())


@dataclass(frozen=True)
class OrganisationAppetiteRecommendation:
    answers: dict[str, int]
    reasons: dict[str, str] = field(default_factory=dict)
    confidence: str = "medium"
    missing_inputs: list[str] = field(default_factory=list)


def _clamp(level: int) -> int:
    return max(0, min(4, level))


def _blend_with_peers(base_level: int, peer: PeerAppetiteBenchmark | None) -> tuple[int, str | None]:
    """Nudge toward the peer median; never a per-organisation lookup, only an aggregate."""
    if peer is None:
        return base_level, None
    blended = round((base_level + peer.median_level) / 2)
    if peer.median_level == base_level:
        note = f"{peer.peer_count} similar organisations (same industry) also settled around level {peer.median_level}"
    else:
        direction = "tighter" if peer.median_level < base_level else "more relaxed"
        note = (
            f"{peer.peer_count} similar organisations (same industry) set this to level "
            f"{peer.median_level}, {direction} than the baseline level {base_level}"
        )
    return blended, note


def recommend_organisation_appetite(
    *,
    required_frameworks: list[str] | None,
    peer_benchmark: dict[str, PeerAppetiteBenchmark] | None = None,
) -> OrganisationAppetiteRecommendation:
    """Build a suggested six-dimension organisation appetite for leadership to
    review and correct. Never activates anything."""
    missing_inputs: list[str] = []
    active_frameworks = {_normalize_framework(f) for f in (required_frameworks or []) if f}
    regulated = bool(active_frameworks & _REGULATED_FRAMEWORKS)
    if not required_frameworks:
        missing_inputs.append("regulatory_context")

    regulatory_level = 1 if regulated else _BASELINE_LEVEL
    regulatory_reason = (
        f"active regulatory frameworks ({', '.join(sorted(active_frameworks))}) require tight compliance escalation"
        if regulated
        else "no regulatory framework recorded as requiring tight compliance escalation"
    )
    security_level = 1 if regulated else _BASELINE_LEVEL
    security_reason = (
        "active regulatory frameworks expect provable, fast-closing security response"
        if regulated
        else "no regulatory framework recorded as demanding a fast security response floor"
    )

    base_levels: dict[str, tuple[int, str]] = {
        "downtime": (_BASELINE_LEVEL, _BASELINE_REASON),
        "dataLoss": (_BASELINE_LEVEL, _BASELINE_REASON),
        "financial": (_BASELINE_LEVEL, _BASELINE_REASON),
        "reputational": (_BASELINE_LEVEL, _BASELINE_REASON),
        "regulatory": (regulatory_level, regulatory_reason),
        "security": (security_level, security_reason),
    }

    # Peer data is a bonus signal, not a required input — its absence (the
    # common case: few or no comparable peers yet) must never lower
    # confidence the way missing regulatory context does.
    peers = peer_benchmark or {}

    answers: dict[str, int] = {}
    reasons: dict[str, str] = {}
    for dim, (level, reason) in base_levels.items():
        blended, peer_note = _blend_with_peers(level, peers.get(dim))
        floor = level if dim in ("regulatory", "security") and regulated else None
        adjusted = _clamp(blended)
        if floor is not None:
            adjusted = min(adjusted, floor)
        answers[dim] = adjusted
        reasons[dim] = f"{reason}; {peer_note}" if peer_note else reason

    # Only one real input exists at this scope (regulatory context) — unlike
    # the process-level engine's BIA + frameworks two-input spread, there is
    # no honest middle "medium" state to report here.
    confidence = "low" if missing_inputs else "high"
    return OrganisationAppetiteRecommendation(
        answers=answers, reasons=reasons, confidence=confidence, missing_inputs=missing_inputs
    )
