"""Process-linked Risk Evaluation (dashboard slice 3).

Creates the contract's central analytical object per Business Process:
observed-risk evidence, resolved BIA and appetite with provenance, dependency
and recovery gaps, residual state, a Forecast Impact snapshot, confidence,
and the eight-part explanation. Evaluations are append-only — a re-run
creates a new record and the old one stays as audit history.

Rules (risklence-domain-decision-model):
- An evaluation is only created after resolving BIA, appetite, evidence,
  dependency bundles, and recovery context. When inputs are missing the
  status is ``not_proven`` and the explanation says exactly why.
- A strong result in one dimension never cancels a zero-tolerance breach in
  another: any appetite category at 0 with active observed risk is
  ``outside_appetite`` regardless of everything else.
- The engine evaluates and explains; it never decides.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.decision_runtime import VERIFICATION_STATUS_SUCCESSFUL
from src.core.constants.process_dashboard_enums import ACTIVE_THREAT_STATUSES
from src.core.model_defs.risk_evaluation import (
    PREPAREDNESS_CANNOT_PROVE,
    PREPAREDNESS_NOT_PREPARED,
    PREPAREDNESS_PARTIALLY_PREPARED,
    PREPAREDNESS_PREPARED,
    RISK_STATUS_APPROACHING_APPETITE,
    RISK_STATUS_NOT_PROVEN,
    RISK_STATUS_OUTSIDE_APPETITE,
    RISK_STATUS_WITHIN_APPETITE,
    ForecastImpact,
    RiskEvaluation,
)
from src.core.services.bia_inheritance_service import bia_is_complete, effective_service_bia
from src.core.services.forecast_impact_service import build_forecast_snapshot
from src.core.services.process_dashboard_projection_service import (
    PUBLISHED_BUNDLE_LIFECYCLE_STATE,
    mapped_asset_names,
    normalize_asset_id,
    normalize_asset_name,
)
from src.core.services.risk_appetite_resolution_service import (
    ResolvedProcessAppetite,
    resolve_appetite_for_processes,
)


@dataclass(frozen=True)
class EvaluationPassResult:
    evaluated_process_ids: list[str]
    evaluations_by_process_id: dict[str, RiskEvaluation]


def _bia_snapshot(
    process,
    services: list[object],
    *,
    process_bia_answers: dict | None,
    bia_exceptions: dict[tuple[str, str], list[object]],
) -> dict | None:
    """#463 — each service's answers are the process's resolved BIA with that service's exceptions
    in this process. It used to read the legacy `process.bia_answers` projection, which exists only
    once a process assessment is attested, and relied on every service holding its own copy."""
    per_service = []
    complete = bool(services)
    for service in services:
        answers = effective_service_bia(
            process_bia_answers, bia_exceptions.get((service.id, process.id), ())
        )
        service_complete = bool(answers) and bia_is_complete(answers)
        complete = complete and service_complete
        per_service.append(
            {
                "service_id": service.id,
                "complete": service_complete,
                "answers": answers,
            }
        )
    if not per_service:
        return None
    return {"complete": complete, "services": per_service}


def _appetite_snapshot(resolved: ResolvedProcessAppetite | None) -> dict | None:
    if resolved is None:
        return None
    return {
        "answers": resolved.answers,
        "source_scope": resolved.source_scope,
        "policy_id": resolved.policy_id,
        "version": resolved.version,
        "approved_by": resolved.approved_by,
        "effective_to": resolved.effective_to.isoformat() if resolved.effective_to else None,
        "decision_reference": resolved.decision_reference,
        "expired_exception_reference": resolved.expired_exception_reference,
    }


def _zero_tolerance_categories(resolved: ResolvedProcessAppetite | None) -> list[str]:
    if resolved is None:
        return []
    return sorted(category for category, level in (resolved.answers or {}).items() if level == 0)


def evaluate_process(
    *,
    process,
    services: list[object],
    asset_name_by_id: dict[str, str],
    threats: list[object],
    decisions_by_threat_id: dict[str, list[object]],
    latest_verification_by_threat_id: dict[str, object],
    published_bundle_service_ids: set[str],
    resolved_appetite: ResolvedProcessAppetite | None,
    process_bia_answers: dict | None,
    bia_exceptions: dict[tuple[str, str], list[object]],
    overdue_reviews: list[dict] | None = None,
) -> tuple[RiskEvaluation, ForecastImpact | None]:
    """Assemble one evaluation (unpersisted rows; caller adds and commits)."""
    process_asset_names = mapped_asset_names(services, asset_name_by_id)
    observed = [t for t in threats if normalize_asset_name(t.asset) in process_asset_names]
    active = [t for t in observed if t.status in ACTIVE_THREAT_STATUSES]
    undecided_active = [t for t in active if not decisions_by_threat_id.get(t.id)]
    verified_ids = {
        threat_id
        for threat_id, verification in latest_verification_by_threat_id.items()
        if verification.verification_status == VERIFICATION_STATUS_SUCCESSFUL
    }
    verified_observed = [t for t in observed if t.id in verified_ids]

    bia = _bia_snapshot(
        process, services, process_bia_answers=process_bia_answers, bia_exceptions=bia_exceptions
    )
    bia_complete = bool(bia and bia["complete"])
    appetite = _appetite_snapshot(resolved_appetite)
    zero_tolerance = _zero_tolerance_categories(resolved_appetite)
    unpublished_services = [s.id for s in services if s.id not in published_bundle_service_ids]

    overdue_reviews = overdue_reviews or []
    evidence_snapshot = {
        "observed_risk_count": len(observed),
        "active_risk_count": len(active),
        "undecided_active_count": len(undecided_active),
        "verified_outcome_count": len(verified_observed),
        "critical_active_count": sum(t.severity == "critical" for t in active),
        "overdue_review_count": len(overdue_reviews),
    }
    dependency_snapshot = {
        "service_count": len(services),
        "services_without_published_bundle": unpublished_services,
    }
    recovery_snapshot = {
        # Recovery capability is evidenced today only through verified outcomes;
        # a dedicated recovery-capability model is future scope.
        "verified_outcome_count": len(verified_observed),
        "basis": "verification_records",
    }

    status, preparedness, missing = _resolve_status(
        bia_complete=bia_complete,
        appetite=resolved_appetite,
        zero_tolerance=zero_tolerance,
        observed=observed,
        active=active,
        verified_observed=verified_observed,
        services=services,
        unpublished_services=unpublished_services,
    )

    # A lapsed review removes any protected/within claim: the decision's
    # justification has expired, so the exposure is live again until a human
    # renews or resolves it (contract: reopening at Business Process level).
    if overdue_reviews:
        if status == RISK_STATUS_WITHIN_APPETITE:
            status = RISK_STATUS_APPROACHING_APPETITE
        if preparedness == PREPAREDNESS_PREPARED:
            preparedness = PREPAREDNESS_PARTIALLY_PREPARED

    forecast_snapshot = (
        build_forecast_snapshot(
            process,
            services,
            process_bia_answers=process_bia_answers,
            bia_exceptions=bia_exceptions,
        )
        if bia_complete
        else None
    )
    forecast_row = (
        ForecastImpact(
            organization_id=process.organization_id,
            process_id=process.id,
            estimate=forecast_snapshot.estimate,
            inputs=forecast_snapshot.inputs,
            assumptions=forecast_snapshot.assumptions,
            confidence=forecast_snapshot.confidence,
            source=forecast_snapshot.source,
        )
        if forecast_snapshot
        else None
    )

    residual = _residual(status, active, undecided_active, zero_tolerance)
    if overdue_reviews:
        residual = {
            "state": residual["state"],
            "explanation": residual["explanation"]
            + f" {len(overdue_reviews)} review{'s have' if len(overdue_reviews) != 1 else ' has'} lapsed without verified evidence.",
        }
    explanation = _explanation(
        process=process,
        bia=bia,
        bia_complete=bia_complete,
        appetite=resolved_appetite,
        zero_tolerance=zero_tolerance,
        evidence=evidence_snapshot,
        dependency=dependency_snapshot,
        forecast=forecast_snapshot,
        residual=residual,
        status=status,
        missing=missing,
        undecided_active=undecided_active,
        overdue_reviews=overdue_reviews,
    )

    evaluation = RiskEvaluation(
        organization_id=process.organization_id,
        process_id=process.id,
        status=status,
        preparedness=preparedness,
        # Confidence reflects input completeness, not optimism: an evaluation
        # built on missing inputs cannot claim more than low confidence.
        confidence="medium" if not missing else "low",
        bia_snapshot=bia,
        appetite_snapshot=appetite,
        evidence_snapshot=evidence_snapshot,
        dependency_snapshot=dependency_snapshot,
        recovery_snapshot=recovery_snapshot,
        residual=residual,
        explanation=explanation,
    )
    return evaluation, forecast_row


def _resolve_status(
    *,
    bia_complete: bool,
    appetite: ResolvedProcessAppetite | None,
    zero_tolerance: list[str],
    observed: list[object],
    active: list[object],
    verified_observed: list[object],
    services: list[object],
    unpublished_services: list[str],
) -> tuple[str, str, list[str]]:
    missing: list[str] = []
    if not services:
        missing.append("no services are mapped to this process")
    if not bia_complete:
        missing.append("the Business Impact Assessment is incomplete")
    if appetite is None:
        missing.append("risk appetite is not resolved at the process level")
    if unpublished_services:
        missing.append("dependency mapping is unpublished for some services")

    # Zero-tolerance breach outranks everything, including missing inputs
    # elsewhere: leadership said none of this is acceptable, and it is happening.
    if zero_tolerance and active:
        preparedness = _preparedness(observed, active, verified_observed)
        return RISK_STATUS_OUTSIDE_APPETITE, preparedness, missing

    if missing:
        return RISK_STATUS_NOT_PROVEN, PREPAREDNESS_CANNOT_PROVE, missing

    if not observed:
        # Inputs are resolved but no evidence has been observed either way.
        return (
            RISK_STATUS_NOT_PROVEN,
            PREPAREDNESS_CANNOT_PROVE,
            ["no observed evidence exists for this process yet"],
        )

    preparedness = _preparedness(observed, active, verified_observed)
    if any(t.severity == "critical" for t in active):
        return RISK_STATUS_OUTSIDE_APPETITE, preparedness, missing
    if active:
        return RISK_STATUS_APPROACHING_APPETITE, preparedness, missing
    if len(verified_observed) == len(observed):
        return RISK_STATUS_WITHIN_APPETITE, preparedness, missing
    return (
        RISK_STATUS_NOT_PROVEN,
        preparedness,
        ["observed risks are resolved but lack verified outcomes"],
    )


def _preparedness(observed: list[object], active: list[object], verified: list[object]) -> str:
    if not observed:
        return PREPAREDNESS_CANNOT_PROVE
    if len(verified) == len(observed):
        return PREPAREDNESS_PREPARED
    if verified:
        return PREPAREDNESS_PARTIALLY_PREPARED
    if active:
        return PREPAREDNESS_NOT_PREPARED
    return PREPAREDNESS_CANNOT_PROVE


def _residual(
    status: str, active: list[object], undecided: list[object], zero_tolerance: list[str]
) -> dict:
    if status == RISK_STATUS_OUTSIDE_APPETITE:
        return {
            "state": "outside_appetite",
            "explanation": (
                f"{len(active)} active observed risk{'s' if len(active) != 1 else ''} against "
                + (
                    f"zero-tolerance categories ({', '.join(zero_tolerance)})"
                    if zero_tolerance
                    else "critical severity"
                )
                + "."
            ),
        }
    if status == RISK_STATUS_APPROACHING_APPETITE:
        return {
            "state": "approaching_appetite",
            "explanation": f"{len(active)} active observed risk{'s' if len(active) != 1 else ''}, {len(undecided)} awaiting a decision.",
        }
    if status == RISK_STATUS_WITHIN_APPETITE:
        return {
            "state": "within_appetite",
            "explanation": "All observed risks carry verified outcomes.",
        }
    return {
        "state": "not_proven",
        "explanation": "Residual risk cannot be stated until the missing inputs are resolved.",
    }


def _explanation(
    *,
    process,
    bia,
    bia_complete: bool,
    appetite: ResolvedProcessAppetite | None,
    zero_tolerance: list[str],
    evidence: dict,
    dependency: dict,
    forecast,
    residual: dict,
    status: str,
    missing: list[str],
    undecided_active: list[object],
    overdue_reviews: list[dict],
) -> list[dict]:
    """The contract's eight-part explanation, in plain business language."""
    return [
        {"aspect": "affected", "text": f"Business process: {process.name}."},
        {
            "aspect": "bia",
            "text": (
                "The Business Impact Assessment is approved and inherited across services."
                if bia_complete
                else "The Business Impact Assessment is incomplete — business consequence is not yet established."
            ),
        },
        {
            "aspect": "evidence",
            "text": (
                f"{evidence['observed_risk_count']} observed risk(s); {evidence['active_risk_count']} active, "
                f"{evidence['undecided_active_count']} awaiting a decision, "
                f"{evidence['verified_outcome_count']} with verified outcomes."
            ),
        },
        {
            "aspect": "appetite",
            "text": (
                f"Appetite resolved from {appetite.source_scope} (v{appetite.version}, approved by {appetite.approved_by})"
                + (
                    f"; zero tolerance declared for: {', '.join(zero_tolerance)}."
                    if zero_tolerance
                    else "."
                )
                if appetite
                else "Risk appetite is not resolved at the process level."
            ),
        },
        {
            "aspect": "capability_gap",
            "text": (
                f"{len(dependency['services_without_published_bundle'])} of {dependency['service_count']} services lack a published dependency mapping."
                if dependency["services_without_published_bundle"]
                else "All services have published dependency mappings."
            ),
        },
        {
            "aspect": "forecast",
            "text": (
                f"Consequence estimate ({forecast.confidence} confidence, from the BIA): impact reaches "
                f"{forecast.estimate.get('impact_24h') or 'unknown'} within 24 hours; maximum tolerable disruption {forecast.estimate.get('maximum_tolerable_disruption') or 'unknown'}."
                if forecast
                else "No forecast is possible until the Business Impact Assessment is complete."
            ),
        },
        {"aspect": "residual", "text": residual["explanation"]},
        {
            "aspect": "decision",
            "text": _decision_text(undecided_active, overdue_reviews, missing),
        },
    ]


def _decision_text(
    undecided_active: list[object], overdue_reviews: list[dict], missing: list[str]
) -> str:
    parts: list[str] = []
    if overdue_reviews:
        references = ", ".join(item.get("decision_reference", "?") for item in overdue_reviews)
        parts.append(
            f"{len(overdue_reviews)} review{'s' if len(overdue_reviews) != 1 else ''} lapsed without verified evidence ({references}) — the decision must be renewed or resolved."
        )
    if undecided_active:
        parts.append(f"{len(undecided_active)} active risk(s) have no recorded decision.")
    if parts:
        return "A decision is needed: " + " ".join(parts)
    if missing:
        return "No decision is needed right now: " + "; ".join(missing) + "."
    return "No decision is needed right now."


def run_risk_evaluation_pass(
    db: Session,
    *,
    organization_id: int,
    process_ids: list[str] | None = None,
    overdue_reviews_by_process: dict[str, list[dict]] | None = None,
) -> EvaluationPassResult:
    """Evaluate processes (all, or the given subset). Caller owns the commit."""
    from src.core.models import (  # local import to avoid module cycle at import time
        Asset,
        BusinessService,
        DecisionRecord,
        DependencyBundle,
        Threat,
        ValueStream,
        VerificationRecord,
    )

    processes = db.query(ValueStream).filter(ValueStream.organization_id == organization_id).all()
    if process_ids is not None:
        wanted = set(process_ids)
        processes = [p for p in processes if p.id in wanted]
    from src.core.services.process_activation_service import resolve_process_activation_readiness

    readiness_by_process = resolve_process_activation_readiness(
        db,
        organization_id=organization_id,
        processes=processes,
    )
    processes = [
        process for process in processes if readiness_by_process[process.id].impact_model_active
    ]
    overdue_reviews_by_process = overdue_reviews_by_process or {}
    services = (
        db.query(BusinessService).filter(BusinessService.organization_id == organization_id).all()
    )
    bundles = (
        db.query(DependencyBundle).filter(DependencyBundle.organization_id == organization_id).all()
    )
    assets = db.query(Asset).filter(Asset.organization_id == organization_id).all()
    threats = db.query(Threat).filter(Threat.organization_id == organization_id).all()
    decisions = (
        db.query(DecisionRecord).filter(DecisionRecord.organization_id == organization_id).all()
    )
    verifications = (
        db.query(VerificationRecord)
        .filter(VerificationRecord.organization_id == organization_id)
        .all()
    )

    asset_name_by_id = {
        normalize_asset_id(asset.id): normalize_asset_name(asset.display_name) for asset in assets
    }
    services_by_process: dict[str, list[object]] = {}
    for service in services:
        if getattr(service, "archived_at", None) is not None:
            continue
        for process_id in service.value_stream_ids or []:
            services_by_process.setdefault(process_id, []).append(service)
    published_bundle_service_ids = {
        bundle.service_id
        for bundle in bundles
        if bundle.lifecycle_state == PUBLISHED_BUNDLE_LIFECYCLE_STATE
    }
    decisions_by_threat_id: dict[str, list[object]] = {}
    for decision in decisions:
        if decision.threat_id:
            decisions_by_threat_id.setdefault(decision.threat_id, []).append(decision)
    latest_verification_by_threat_id: dict[str, object] = {}
    for verification in verifications:
        if not verification.threat_id:
            continue
        current = latest_verification_by_threat_id.get(verification.threat_id)
        if current is None or (getattr(verification, "created_at", None) or 0) > (
            getattr(current, "created_at", None) or 0
        ):
            latest_verification_by_threat_id[verification.threat_id] = verification

    resolved_appetites = resolve_appetite_for_processes(
        db, organization_id=organization_id, process_ids=[p.id for p in processes]
    )
    # #463 — the process BIA in force (attested assessment, organisation baseline, then the legacy
    # projection) and each service's exceptions in each process, read once for the pass.
    from src.core.services.effective_process_bia_service import (
        resolve_effective_process_bia_by_process,
    )
    from src.core.services.service_bia_exception_service import active_bia_exceptions

    effective_bia_by_process = (
        resolve_effective_process_bia_by_process(
            db, organization_id=organization_id, processes=processes
        )
        if processes
        else {}
    )
    bia_exceptions = active_bia_exceptions(
        db, organization_id=organization_id, process_ids=[p.id for p in processes]
    )

    evaluated: list[str] = []
    evaluations_by_process_id: dict[str, RiskEvaluation] = {}
    for process in processes:
        evaluation, forecast = evaluate_process(
            process=process,
            services=services_by_process.get(process.id, []),
            asset_name_by_id=asset_name_by_id,
            threats=threats,
            decisions_by_threat_id=decisions_by_threat_id,
            latest_verification_by_threat_id=latest_verification_by_threat_id,
            published_bundle_service_ids=published_bundle_service_ids,
            resolved_appetite=resolved_appetites.get(process.id),
            process_bia_answers=(
                effective_bia_by_process[process.id].answers
                if process.id in effective_bia_by_process
                else None
            ),
            bia_exceptions=bia_exceptions,
            overdue_reviews=overdue_reviews_by_process.get(process.id),
        )
        if forecast is not None:
            db.add(forecast)
            db.flush()
            evaluation.forecast_id = forecast.id
        db.add(evaluation)
        db.flush()
        evaluated.append(process.id)
        evaluations_by_process_id[process.id] = evaluation

    return EvaluationPassResult(
        evaluated_process_ids=evaluated,
        evaluations_by_process_id=evaluations_by_process_id,
    )
