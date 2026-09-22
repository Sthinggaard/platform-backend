"""Forecast Impact snapshots (dashboard slice 3).

A Forecast Impact is an explainable estimate of potential business effect,
with its inputs, assumptions, confidence, and source retained. Rules:

- Never a confirmed loss, never derived from tier defaults, never a monetary
  figure the organisation has not itself declared. Today the only financially
  honest input is the approved Business Impact Assessment, so the forecast is
  a *consequence profile*: how bad the disruption becomes at 1h/4h/24h, the
  maximum tolerable disruption, and what workarounds exist.
- No complete BIA → no forecast. The absence is the finding.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.core.services.bia_inheritance_service import bia_is_complete, effective_service_bia

# Severity ordering for worst-of aggregation across a process's services.
_SEVERITY_ORDER = ["none", "low", "medium", "high", "severe"]

FORECAST_SOURCE_BIA = "bia_consequence_profile"


@dataclass(frozen=True)
class ForecastSnapshot:
    estimate: dict
    inputs: dict
    assumptions: list[str]
    confidence: str  # medium | low
    source: str


def _worst(values: list[str | None]) -> str | None:
    ranked = [v for v in values if v in _SEVERITY_ORDER]
    if not ranked:
        return None
    return max(ranked, key=_SEVERITY_ORDER.index)


def build_forecast_snapshot(
    process,
    services: list[object],
    *,
    process_bia_answers: dict | None,
    bia_exceptions: dict[tuple[str, str], list[object]],
) -> ForecastSnapshot | None:
    """Consequence-profile forecast from the effective BIA, or None.

    Aggregates worst-of across the process's services (a process is disrupted
    when its most affected service is). #463 — a service's answers are the
    process's resolved BIA with that service's exceptions in this process.
    """
    per_service: list[dict] = []
    for service in services:
        answers = effective_service_bia(
            process_bia_answers, bia_exceptions.get((service.id, process.id), ())
        )
        if answers and bia_is_complete(answers):
            per_service.append(
                {
                    "service_id": service.id,
                    "service_name": getattr(service, "name", service.id),
                    "answers": answers,
                }
            )

    if not per_service:
        return None

    estimate = {
        "impact_1h": _worst([entry["answers"].get("impact1h") for entry in per_service]),
        "impact_4h": _worst([entry["answers"].get("impact4h") for entry in per_service]),
        "impact_24h": _worst([entry["answers"].get("impact24h") for entry in per_service]),
        # The tightest tolerance across services binds the process.
        "maximum_tolerable_disruption": min(
            (entry["answers"].get("mtd") for entry in per_service if entry["answers"].get("mtd")),
            default=None,
        ),
        "workaround": _weakest_capability(
            [entry["answers"].get("workaround") for entry in per_service]
        ),
        "alternative_channel": _weakest_capability(
            [entry["answers"].get("alternativeChannel") for entry in per_service]
        ),
    }

    full_coverage = len(per_service) == len(services) and len(services) > 0
    return ForecastSnapshot(
        estimate=estimate,
        inputs={"services": per_service},
        assumptions=[
            "Derived from the approved Business Impact Assessment; the process profile is the worst case across its services.",
            "This is an estimate of potential business effect, not a confirmed loss.",
            "No monetary figure is forecast because no financially validated inputs exist.",
        ],
        confidence="medium" if full_coverage else "low",
        source=FORECAST_SOURCE_BIA,
    )


def _weakest_capability(values: list[str | None]) -> str | None:
    """Worst-of for capability answers: none < partial < full."""
    order = ["full", "partial", "none"]
    ranked = [v for v in values if v in order]
    if not ranked:
        return None
    return max(ranked, key=order.index)
