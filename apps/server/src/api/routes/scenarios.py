"""Decision Layer — Scenario & Disruption Analysis endpoint.

GET /api/v1/scenarios — derives disruption scenarios from live threat data.

Each unique asset with active threats becomes one scenario. Scenarios are
sorted by probability (high first). Every endpoint is tenant-scoped via
TenantContext.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.database import get_db
from src.core.logging_config import get_logger
from src.core.models import Asset, BusinessService, Threat, ValueStream
from src.core.repository import TenantRepository
from src.core.services.process_activation_service import resolve_process_activation_readiness
from src.core.services.process_dashboard_projection_service import (
    mapped_asset_names,
    normalize_asset_id,
    normalize_asset_name,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/scenarios", tags=["Decision Layer"])

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_TOLERANCE_HOURS: dict[str, int] = {
    "critical": 1,
    "high": 4,
    "medium": 24,
    "low": 72,
}
_PROBABILITY_FROM_SEVERITY: dict[str, str] = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
}
_PROBABILITY_ORDER = {"high": 0, "medium": 1, "low": 2}


# ─── SCHEMAS ──────────────────────────────────────────────────────────────────

class ServiceImpactResponse(BaseModel):
    serviceName: str
    impact: str
    toleranceBreachHours: int


class ScenarioTimeWindowResponse(BaseModel):
    label: str  # "1 hour" | "4 hours" | "24 hours"
    consequence: str


class ScenarioRecoveryRealityResponse(BaseModel):
    workaroundExists: bool
    workaroundDescription: Optional[str] = None
    alternativeChannelExists: bool
    alternativeChannelDescription: Optional[str] = None
    recoveryProven: bool
    recoveryNote: Optional[str] = None


class ScenarioResponse(BaseModel):
    id: str
    name: str
    probability: str
    totalExposure: int
    businessConsequence: Optional[str] = None
    timeEscalation: Optional[list[ScenarioTimeWindowResponse]] = None
    recoveryReality: Optional[ScenarioRecoveryRealityResponse] = None
    decisionOptions: Optional[list[str]] = None
    serviceImpacts: list[ServiceImpactResponse]
    mitigations: list[str]
    frameworks: list[str]


# ─── HELPERS ──────────────────────────────────────────────────────────────────


def _build_business_consequence(asset_name: str, what_it_means: str, severity: str) -> str:
    """Build a single plain-English sentence describing the business consequence."""
    if severity == "critical":
        prefix = f"If {asset_name} fails, the impact is immediate and severe"
    elif severity == "high":
        prefix = f"If {asset_name} fails, business operations are significantly disrupted"
    elif severity == "medium":
        prefix = f"If {asset_name} fails, business capability is reduced"
    else:
        prefix = f"If {asset_name} fails, some business functions are affected"

    # Trim what_it_means to first sentence if it is long
    first_sentence = what_it_means.split(".")[0].strip() if what_it_means else ""
    if first_sentence and len(first_sentence) < 200:
        return f"{prefix} — {first_sentence.lower().rstrip('.')}."
    return f"{prefix}."


def _build_time_escalation(
    asset_name: str,
    severity: str,
    what_it_means: str,
) -> list[ScenarioTimeWindowResponse]:
    """Build time-based business consequence windows from severity tier."""
    if severity == "critical":
        return [
            ScenarioTimeWindowResponse(
                label="1 hour",
                consequence=f"Customer-facing disruption becomes visible. Fallback pressure begins immediately. {what_it_means[:120] if what_it_means else ''}",
            ),
            ScenarioTimeWindowResponse(
                label="4 hours",
                consequence="Operational workarounds start to saturate. Revenue impact becomes material. Leadership awareness required.",
            ),
            ScenarioTimeWindowResponse(
                label="24 hours",
                consequence="Regulatory, revenue, and executive escalation become unavoidable. Recovery SLAs are breached.",
            ),
        ]
    if severity == "high":
        return [
            ScenarioTimeWindowResponse(
                label="1 hour",
                consequence="Service throughput drops. Assisted channels begin absorbing demand. Internal teams notified.",
            ),
            ScenarioTimeWindowResponse(
                label="4 hours",
            consequence="Customer response times and operating windows come under pressure. Backlogs grow.",
            ),
            ScenarioTimeWindowResponse(
                label="24 hours",
                consequence="Business leadership intervention becomes necessary to protect service continuity.",
            ),
        ]
    if severity == "medium":
        return [
            ScenarioTimeWindowResponse(
                label="4 hours",
                consequence="Internal teams begin to queue. Productivity drops become noticeable.",
            ),
            ScenarioTimeWindowResponse(
                label="24 hours",
                consequence="Operational workarounds carry most of the load. Service debt accumulates.",
            ),
        ]
    return [
        ScenarioTimeWindowResponse(
            label="24 hours",
            consequence="Low-severity disruption. Internal operations may be slowed. No immediate customer impact expected.",
        ),
    ]


def _build_recovery_reality(threats: "list[Any]") -> ScenarioRecoveryRealityResponse:
    """Derive recovery reality from threat intelligence fields."""
    worst = min(threats, key=lambda t: _SEVERITY_ORDER.get(t.severity, 99))
    intel = worst.intelligence or {}

    # Workaround: look for intel basis or peer evidence mentioning fallback
    peer_data = intel.get("peer_data", {}) if isinstance(intel, dict) else {}
    reasoning = intel.get("reasoning", "") if isinstance(intel, dict) else ""

    has_workaround = bool(peer_data.get("alternative_channel") or "fallback" in str(reasoning).lower())
    workaround_desc = peer_data.get("alternative_channel") if has_workaround else None

    has_channel = bool(peer_data.get("alternative_channel"))
    channel_desc = peer_data.get("alternative_channel") if has_channel else None

    # Recovery proven only if a saved_per_hour value exists and a decision was made
    recovery_proven = bool(worst.saved_per_hour and worst.decision)
    recovery_note = (
        f"A decision has been made and recovery is being tracked. Savings rate: €{worst.saved_per_hour}/hr."
        if recovery_proven
        else "Recovery capability has not been validated for this dependency path."
    )
    return ScenarioRecoveryRealityResponse(
        workaroundExists=has_workaround,
        workaroundDescription=workaround_desc,
        alternativeChannelExists=has_channel,
        alternativeChannelDescription=channel_desc,
        recoveryProven=recovery_proven,
        recoveryNote=recovery_note,
    )


def _active_process_asset_names(db: Session, organization_id: int) -> set[str]:
    """Return asset names with an active Business Process decision context."""
    processes = TenantRepository(db, ValueStream, organization_id).get_all()
    readiness_by_process = resolve_process_activation_readiness(
        db,
        organization_id=organization_id,
        processes=processes,
    )
    active_process_ids = {
        process_id
        for process_id, readiness in readiness_by_process.items()
        if readiness.impact_model_active
    }
    if not active_process_ids:
        return set()
    services = TenantRepository(db, BusinessService, organization_id).get_all()
    active_services = [
        service
        for service in services
        if active_process_ids.intersection(service.value_stream_ids or [])
        and getattr(service, "archived_at", None) is None
    ]
    assets = TenantRepository(db, Asset, organization_id).get_all()
    asset_names = {
        normalize_asset_id(asset.id): normalize_asset_name(asset.display_name) for asset in assets
    }
    return mapped_asset_names(active_services, asset_names)


# ─── ROUTES ───────────────────────────────────────────────────────────────────

@router.get("", response_model=list[ScenarioResponse])
def list_scenarios(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[ScenarioResponse]:
    """Return disruption scenarios derived from active threats for the org."""
    threats = (
        db.query(Threat)
        .filter(Threat.organization_id == ctx.organization_id)
        .all()
    )
    active_asset_names = _active_process_asset_names(db, ctx.organization_id)
    threats = [
        threat for threat in threats if normalize_asset_name(threat.asset) in active_asset_names
    ]

    # Group threats by asset
    by_asset: dict[str, list[Threat]] = defaultdict(list)
    for t in threats:
        by_asset[t.asset].append(t)

    scenarios: list[ScenarioResponse] = []
    for asset_name, asset_threats in by_asset.items():
        # Use worst severity in the group to determine probability
        worst_severity = min(
            asset_threats, key=lambda t: _SEVERITY_ORDER.get(t.severity, 99)
        ).severity

        probability = _PROBABILITY_FROM_SEVERITY.get(worst_severity, "medium")
        total_exposure = sum(t.daily_cost or 0 for t in asset_threats)

        # Build service impact rows — one per threat
        service_impacts: list[ServiceImpactResponse] = []
        seen_impacts: set[str] = set()
        for t in sorted(asset_threats, key=lambda t: _SEVERITY_ORDER.get(t.severity, 99)):
            impact_key = t.what_it_means[:80]
            if impact_key in seen_impacts:
                continue
            seen_impacts.add(impact_key)
            service_impacts.append(
                ServiceImpactResponse(
                    serviceName=t.tier.replace("-", " ").title(),
                    impact=t.what_it_means,
                    toleranceBreachHours=_TOLERANCE_HOURS.get(t.severity, 24),
                )
            )

        # Collect unique mitigations and frameworks
        mitigations: list[str] = []
        seen_recs: set[str] = set()
        all_frameworks: list[str] = []
        for t in asset_threats:
            if t.recommendation and t.recommendation not in seen_recs:
                seen_recs.add(t.recommendation)
                mitigations.append(t.recommendation)
            for fw in (t.frameworks or []):
                if fw not in all_frameworks:
                    all_frameworks.append(fw)

        # ── Business consequence (plain language, from worst threat) ─────────
        top_threat = min(asset_threats, key=lambda t: _SEVERITY_ORDER.get(t.severity, 99))
        business_consequence = _build_business_consequence(asset_name, top_threat.what_it_means, worst_severity)

        # ── Time-based escalation ─────────────────────────────────────────────
        time_escalation = _build_time_escalation(asset_name, worst_severity, top_threat.what_it_means)

        # ── Recovery reality (derived from threat intelligence) ───────────────
        recovery_reality = _build_recovery_reality(asset_threats)

        # ── Decision options (always provide full set) ────────────────────────
        decision_options: list[str]
        if worst_severity in ("critical", "high"):
            decision_options = ["improve_resilience", "review_dependencies", "escalate", "accept_exposure"]
        else:
            decision_options = ["improve_resilience", "review_dependencies", "accept_exposure"]

        safe_id = asset_name.lower().replace(" ", "-").replace("/", "-")
        scenarios.append(
            ScenarioResponse(
                id=f"scenario-{safe_id}",
                name=f"If {asset_name} fails",
                probability=probability,
                totalExposure=total_exposure,
                businessConsequence=business_consequence,
                timeEscalation=time_escalation,
                recoveryReality=recovery_reality,
                decisionOptions=decision_options,
                serviceImpacts=service_impacts,
                mitigations=mitigations,
                frameworks=all_frameworks,
            )
        )

    # Sort: high probability first, then by exposure descending
    scenarios.sort(
        key=lambda s: (_PROBABILITY_ORDER.get(s.probability, 99), -s.totalExposure)
    )

    logger.info(
        "scenarios_listed",
        org_id=ctx.organization_id,
        count=len(scenarios),
    )
    return scenarios
