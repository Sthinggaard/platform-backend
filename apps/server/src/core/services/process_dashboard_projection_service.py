"""Business Process dashboard read-model projection.

This module intentionally projects persisted setup, risk, decision, and
verification records. It does not calculate a resilience score, forecast, or
financial exposure. Missing canonical inputs remain explicit until their
dedicated domain workstreams supply them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from src.core.constants.decision_runtime import VERIFICATION_STATUS_SUCCESSFUL
from src.core.constants.process_activation_enums import (
    TERMINAL_PROCESS_ACTIVATION_STATES,
    ProcessActivationState,
)
from src.core.constants.process_dashboard_enums import (
    ACTIVE_THREAT_STATUSES,
    PUBLISHED_BUNDLE_LIFECYCLE_STATE,
    ProcessDashboardActionEligibility,
    ProcessDashboardReasonCode,
    ProcessDashboardState,
)
from src.core.services.bia_inheritance_service import bia_is_complete, effective_service_bia
from src.core.services.process_activation_service import ProcessActivationReadiness
from src.core.services.risk_appetite_resolution_service import ResolvedProcessAppetite


@dataclass(frozen=True)
class ProcessDashboardProjectionInput:
    processes: list[object]
    services: list[object]
    dependency_bundles: list[object]
    legacy_service_appetite_configs: list[object]
    assets: list[object]
    threats: list[object]
    decisions: list[object]
    verifications: list[object]
    # process_id -> effective appetite with provenance; absent = unresolved.
    resolved_process_appetites: dict[str, ResolvedProcessAppetite]
    # process_id -> latest persisted RiskEvaluation row; absent = never evaluated.
    latest_evaluations: dict[str, object]
    # forecast_id -> ForecastImpact row for the evaluations above.
    forecasts_by_id: dict[str, object]
    # Captured resolutions (awaiting verification until proven).
    resolutions: list[object]
    # process_id -> lapsed reviews awaiting renewal/resolution.
    overdue_reviews_by_process: dict[str, list[object]]
    # process_id -> resolved access for the viewer (visibility already applied
    # by the loader; this carries eligibility, detail, and mandate holder).
    access_by_process_id: dict[str, object]
    access_model_configured: bool
    activation_by_process_id: dict[str, ProcessActivationReadiness] = field(default_factory=dict)
    # process_id -> effective BIA answers (organisation baseline or attested
    # process exception), resolved once by the tenant loader.
    effective_process_bia_answers: dict[str, dict | None] = field(default_factory=dict)
    # #463 — (service_id, process_id) -> that service's active BIA exceptions in that process.
    bia_exceptions: dict[tuple[str, str], list[object]] = field(default_factory=dict)
    # The viewer resolving this projection — lets a pending activation step
    # (accept ownership, approve the process) be shown as personally
    # actionable only to the person it actually belongs to.
    viewer_user_id: int | None = None


@dataclass(frozen=True)
class ProcessDashboardTemporaryException:
    expires_at: str
    review_at: str | None
    decision_reference: str | None


@dataclass(frozen=True)
class ProcessDashboardAppetite:
    resolved: bool
    source_scope: str | None = None
    version: int | None = None
    approved_by: str | None = None
    # The approved tolerance levels themselves (category -> 0..4), so the UI
    # can show what leadership actually signed off, not just that it exists.
    answers: dict | None = None
    temporary_exception: ProcessDashboardTemporaryException | None = None
    # An exception that lapsed without renewal — surfaced, never silently dropped.
    expired_exception_reference: str | None = None


@dataclass(frozen=True)
class ProcessDashboardMandate:
    assigned: bool
    holder_user_id: int | None = None
    holder_name: str | None = None
    canonical_role: str | None = None


@dataclass(frozen=True)
class ProcessDashboardForecast:
    estimate: dict
    confidence: str
    source: str
    created_at: str


@dataclass(frozen=True)
class ProcessDashboardEvaluation:
    evaluation_id: str
    status: str
    preparedness: str
    confidence: str
    evaluated_at: str
    residual: dict
    explanation: list
    forecast: ProcessDashboardForecast | None


@dataclass(frozen=True)
class ProcessDashboardDecisionItem:
    """An undecided observed risk on this process — a pending human decision.

    ``service_id`` anchors the BPMN deep link (node id = service id); it is
    None only when the threat maps onto the process without a resolvable
    member service — the UI must show that as a mapping gap, never invent
    process context around it.
    """

    threat_id: str
    asset: str
    severity: str
    service_id: str | None
    service_name: str | None


@dataclass(frozen=True)
class ProcessDashboardUnmappedRisk:
    """An active observed risk no process claims — a mapping task, not context."""

    threat_id: str
    asset: str
    severity: str


@dataclass(frozen=True)
class ProcessDashboardCoverage:
    service_count: int
    bia_complete: bool
    process_confirmed: bool
    owner_assigned: bool
    ownership_accepted: bool
    bia_attested: bool
    organisation_appetite_effective: bool
    impact_model_active: bool
    dependency_bundles_complete: bool
    process_appetite_resolved: bool
    legacy_service_appetite_configured_count: int


@dataclass(frozen=True)
class ProcessDashboardProcess:
    process_id: str
    name: str
    priority: str
    state: ProcessDashboardState
    reasons: list[ProcessDashboardReasonCode]
    coverage: ProcessDashboardCoverage
    activation_state: ProcessActivationState | None
    next_activation_action: ProcessActivationState | None
    # "accept_ownership" | "confirm" | None — set only when the CURRENT
    # viewer is the one who must take the next activation step. Distinct
    # from `state`/`reasons` (which stay honest for every viewer): this is
    # the personal call to action the dashboard row surfaces.
    activation_action_for_viewer: str | None
    appetite: ProcessDashboardAppetite
    evaluation: ProcessDashboardEvaluation | None
    observed_risk_count: int
    active_threat_count: int
    active_decision_count: int
    verified_outcome_count: int
    awaiting_verification_count: int
    overdue_review_count: int
    visible_to_user: bool
    action_eligibility: ProcessDashboardActionEligibility
    access_detail: str
    mandate: ProcessDashboardMandate
    # Undecided observed risks with their BPMN service anchors.
    decision_items: list[ProcessDashboardDecisionItem]


@dataclass(frozen=True)
class ProcessDashboardProjection:
    processes: list[ProcessDashboardProcess]
    unmapped_observed_risk_count: int
    access_model_configured: bool
    unmapped_observed_risks: list[ProcessDashboardUnmappedRisk]


# Canonical worklist order: setup blockers first, then pending human
# decisions, then decided-but-active risk, then unproven, then protected.
_STATE_SORT_RANK: dict[ProcessDashboardState, int] = {
    ProcessDashboardState.BLOCKED: 0,
    ProcessDashboardState.DECISION_NEEDED: 1,
    ProcessDashboardState.AT_RISK: 2,
    ProcessDashboardState.NOT_PROVEN: 3,
    ProcessDashboardState.PROTECTED: 4,
}

_PRIORITY_SORT_RANK: dict[str, int] = {"critical": 0, "important": 1, "standard": 2}

_ACTIVATION_REASON_BY_STATE: dict[ProcessActivationState, ProcessDashboardReasonCode] = {
    ProcessActivationState.CONFIRMATION_REQUIRED: ProcessDashboardReasonCode.PROCESS_CONFIRMATION_REQUIRED,
    ProcessActivationState.OWNERSHIP_REQUIRED: ProcessDashboardReasonCode.PROCESS_OWNER_REQUIRED,
    ProcessActivationState.OWNER_ACCEPTANCE_REQUIRED: ProcessDashboardReasonCode.OWNER_ACCEPTANCE_REQUIRED,
    ProcessActivationState.BIA_REQUIRED: ProcessDashboardReasonCode.BIA_ATTESTATION_REQUIRED,
    ProcessActivationState.BIA_IN_PROGRESS: ProcessDashboardReasonCode.BIA_ATTESTATION_REQUIRED,
    ProcessActivationState.LEADERSHIP_APPETITE_REQUIRED: ProcessDashboardReasonCode.LEADERSHIP_APPETITE_REQUIRED,
    ProcessActivationState.READY_FOR_ACTIVATION: ProcessDashboardReasonCode.PROCESS_ACTIVATION_REQUIRED,
}


def _row_sort_key(row: ProcessDashboardProcess) -> tuple:
    return (
        _STATE_SORT_RANK.get(row.state, len(_STATE_SORT_RANK)),
        -row.overdue_review_count,
        _PRIORITY_SORT_RANK.get(row.priority, len(_PRIORITY_SORT_RANK)),
        row.name,
    )


def build_process_dashboard_projection(
    projection_input: ProcessDashboardProjectionInput,
) -> ProcessDashboardProjection:
    """Project existing tenant data without manufacturing risk assurance."""
    asset_name_by_id = {
        _normalize_asset_id(asset.id): _normalize_asset_name(asset.display_name)
        for asset in projection_input.assets
    }
    visible_processes = [
        process
        for process in projection_input.processes
        if not _is_terminal_confirmation_outcome(
            projection_input.activation_by_process_id.get(process.id)
        )
    ]
    visible_process_ids = {process.id for process in visible_processes}
    visible_services = [
        service
        for service in projection_input.services
        if _service_maps_to_processes(service, visible_process_ids)
    ]
    services_by_process_id = _services_by_process_id(visible_services)
    published_bundle_service_ids = {
        bundle.service_id
        for bundle in projection_input.dependency_bundles
        if bundle.lifecycle_state == PUBLISHED_BUNDLE_LIFECYCLE_STATE
    }
    legacy_appetite_service_ids = {
        config.business_service_id for config in projection_input.legacy_service_appetite_configs
    }
    decisions_by_threat_id = _group_by_threat_id(projection_input.decisions)
    latest_verification_by_threat_id = _latest_by_threat_id(projection_input.verifications)
    resolutions_by_threat_id = _group_by_threat_id(projection_input.resolutions)
    all_mapped_asset_names = _mapped_asset_names(visible_services, asset_name_by_id)

    rows = [
        _project_process(
            process=process,
            services=services_by_process_id.get(process.id, []),
            asset_name_by_id=asset_name_by_id,
            published_bundle_service_ids=published_bundle_service_ids,
            legacy_appetite_service_ids=legacy_appetite_service_ids,
            threats=projection_input.threats,
            decisions_by_threat_id=decisions_by_threat_id,
            latest_verification_by_threat_id=latest_verification_by_threat_id,
            resolved_appetite=projection_input.resolved_process_appetites.get(process.id),
            latest_evaluation=projection_input.latest_evaluations.get(process.id),
            forecasts_by_id=projection_input.forecasts_by_id,
            resolutions_by_threat_id=resolutions_by_threat_id,
            overdue_reviews=projection_input.overdue_reviews_by_process.get(process.id, []),
            access=projection_input.access_by_process_id.get(process.id),
            activation=projection_input.activation_by_process_id.get(process.id),
            effective_process_bia_answers=projection_input.effective_process_bia_answers.get(
                process.id, _UNSET_PROCESS_BIA
            ),
            bia_exceptions=projection_input.bia_exceptions,
            viewer_user_id=projection_input.viewer_user_id,
        )
        for process in visible_processes
    ]
    unmapped_observed_risks = [
        ProcessDashboardUnmappedRisk(
            threat_id=threat.id,
            asset=threat.asset,
            severity=getattr(threat, "severity", None) or "",
        )
        for threat in projection_input.threats
        if threat.status in ACTIVE_THREAT_STATUSES
        and _normalize_asset_name(threat.asset) not in all_mapped_asset_names
    ]
    return ProcessDashboardProjection(
        processes=sorted(rows, key=_row_sort_key),
        unmapped_observed_risk_count=len(unmapped_observed_risks),
        access_model_configured=projection_input.access_model_configured,
        unmapped_observed_risks=unmapped_observed_risks,
    )


def _is_terminal_confirmation_outcome(
    activation: ProcessActivationReadiness | None,
) -> bool:
    return activation is not None and activation.state in TERMINAL_PROCESS_ACTIVATION_STATES


def _service_maps_to_processes(service: object, process_ids: set[str]) -> bool:
    return bool(set(getattr(service, "value_stream_ids", []) or []) & process_ids)


def _project_process(
    *,
    process: object,
    services: list[object],
    asset_name_by_id: dict[str, str],
    published_bundle_service_ids: set[str],
    legacy_appetite_service_ids: set[str],
    threats: list[object],
    decisions_by_threat_id: dict[str, list[object]],
    latest_verification_by_threat_id: dict[str, object],
    resolved_appetite: ResolvedProcessAppetite | None,
    latest_evaluation: object | None,
    forecasts_by_id: dict[str, object],
    resolutions_by_threat_id: dict[str, list[object]],
    overdue_reviews: list[object],
    access: object | None,
    activation: ProcessActivationReadiness | None,
    effective_process_bia_answers: dict | None | object,
    bia_exceptions: dict[tuple[str, str], list[object]],
    viewer_user_id: int | None,
) -> ProcessDashboardProcess:
    mapped_asset_names = _mapped_asset_names(services, asset_name_by_id)
    mapped_threats = [
        threat for threat in threats if _normalize_asset_name(threat.asset) in mapped_asset_names
    ]
    active_threats = [
        threat for threat in mapped_threats if threat.status in ACTIVE_THREAT_STATUSES
    ]
    verified_threat_ids = {
        threat_id
        for threat_id, verification in latest_verification_by_threat_id.items()
        if verification.verification_status == VERIFICATION_STATUS_SUCCESSFUL
    }
    coverage = ProcessDashboardCoverage(
        service_count=len(services),
        bia_complete=_bia_is_complete(
            process,
            services,
            process_bia_answers=effective_process_bia_answers,
            bia_exceptions=bia_exceptions,
        ),
        process_confirmed=activation.process_confirmed if activation else False,
        owner_assigned=activation.owner_assigned if activation else False,
        ownership_accepted=activation.ownership_accepted if activation else False,
        bia_attested=activation.bia_attested if activation else False,
        organisation_appetite_effective=(
            activation.organisation_appetite_effective if activation else False
        ),
        impact_model_active=activation.impact_model_active if activation else False,
        dependency_bundles_complete=_dependency_bundles_are_complete(
            services,
            published_bundle_service_ids,
        ),
        process_appetite_resolved=resolved_appetite is not None,
        legacy_service_appetite_configured_count=sum(
            service.id in legacy_appetite_service_ids for service in services
        ),
    )
    appetite = _project_appetite(resolved_appetite)
    evaluation = _project_evaluation(latest_evaluation, forecasts_by_id)
    state, reasons = _resolve_state(
        coverage=coverage,
        observed_threats=mapped_threats,
        active_threats=active_threats,
        decisions_by_threat_id=decisions_by_threat_id,
        verified_threat_ids=verified_threat_ids,
    )
    activation_action_for_viewer: str | None = None
    if activation is not None and not activation.impact_model_active:
        state = ProcessDashboardState.BLOCKED
        reasons = [_ACTIVATION_REASON_BY_STATE[activation.state]]
        # The next activation step is a personal decision, not a generic
        # setup blocker, when it belongs to the person looking at the
        # dashboard: only the viewer who IS the assigned owner can accept
        # ownership or approve the process. Everyone else still sees an
        # honest, informational "blocked" — they cannot act on it either way.
        is_viewer_the_owner = (
            viewer_user_id is not None and activation.owner_user_id == viewer_user_id
        )
        if (
            is_viewer_the_owner
            and activation.state is ProcessActivationState.OWNER_ACCEPTANCE_REQUIRED
        ):
            state = ProcessDashboardState.DECISION_NEEDED
            activation_action_for_viewer = "accept_ownership"
        elif (
            is_viewer_the_owner and activation.state is ProcessActivationState.CONFIRMATION_REQUIRED
        ):
            state = ProcessDashboardState.DECISION_NEEDED
            activation_action_for_viewer = "confirm"
    # A lapsed review is a decision need at Business Process level — it removes
    # any protected claim and cannot be out-shone by other dimensions.
    if overdue_reviews:
        reasons = [*reasons, ProcessDashboardReasonCode.REVIEW_OVERDUE]
        if state != ProcessDashboardState.BLOCKED:
            state = ProcessDashboardState.DECISION_NEEDED
    return ProcessDashboardProcess(
        process_id=process.id,
        name=process.name,
        priority=process.priority,
        state=state,
        reasons=reasons,
        coverage=coverage,
        activation_state=activation.state if activation else None,
        next_activation_action=activation.next_action if activation else None,
        activation_action_for_viewer=activation_action_for_viewer,
        appetite=appetite,
        evaluation=evaluation,
        observed_risk_count=len(mapped_threats),
        active_threat_count=len(active_threats),
        active_decision_count=sum(
            len(decisions_by_threat_id.get(threat.id, [])) for threat in active_threats
        ),
        verified_outcome_count=sum(threat.id in verified_threat_ids for threat in mapped_threats),
        # Captured resolutions are "awaiting verification", never protected.
        awaiting_verification_count=sum(
            bool(resolutions_by_threat_id.get(threat.id)) and threat.id not in verified_threat_ids
            for threat in mapped_threats
        ),
        overdue_review_count=len(overdue_reviews),
        visible_to_user=access.visible if access is not None else True,
        action_eligibility=(
            ProcessDashboardActionEligibility(access.eligibility)
            if access is not None
            else ProcessDashboardActionEligibility.NOT_EVALUATED
        ),
        access_detail=access.detail if access is not None else "overview",
        mandate=(
            ProcessDashboardMandate(
                assigned=True,
                holder_user_id=access.mandate_holder.user_id,
                holder_name=access.mandate_holder.name,
                canonical_role=access.mandate_holder.canonical_role,
            )
            if access is not None and access.mandate_holder is not None
            else ProcessDashboardMandate(assigned=False)
        ),
        decision_items=_decision_items(
            active_threats=active_threats,
            decisions_by_threat_id=decisions_by_threat_id,
            services=services,
            asset_name_by_id=asset_name_by_id,
        ),
    )


def _decision_items(
    *,
    active_threats: list[object],
    decisions_by_threat_id: dict[str, list[object]],
    services: list[object],
    asset_name_by_id: dict[str, str],
) -> list[ProcessDashboardDecisionItem]:
    """Undecided observed risks anchored to the member service that maps them."""
    service_by_asset_name: dict[str, object] = {}
    for service in services:
        for asset_name in _mapped_asset_names([service], asset_name_by_id):
            service_by_asset_name.setdefault(asset_name, service)
    items: list[ProcessDashboardDecisionItem] = []
    for threat in active_threats:
        if decisions_by_threat_id.get(threat.id):
            continue
        service = service_by_asset_name.get(_normalize_asset_name(threat.asset))
        items.append(
            ProcessDashboardDecisionItem(
                threat_id=threat.id,
                asset=threat.asset,
                severity=getattr(threat, "severity", None) or "",
                service_id=service.id if service is not None else None,
                service_name=getattr(service, "name", None) if service is not None else None,
            )
        )
    return items


def _project_evaluation(
    evaluation: object | None, forecasts_by_id: dict[str, object]
) -> ProcessDashboardEvaluation | None:
    if evaluation is None:
        return None
    forecast_row = forecasts_by_id.get(evaluation.forecast_id) if evaluation.forecast_id else None
    forecast = (
        ProcessDashboardForecast(
            estimate=dict(forecast_row.estimate or {}),
            confidence=forecast_row.confidence,
            source=forecast_row.source,
            created_at=forecast_row.created_at.isoformat(),
        )
        if forecast_row is not None
        else None
    )
    return ProcessDashboardEvaluation(
        evaluation_id=evaluation.id,
        status=evaluation.status,
        preparedness=evaluation.preparedness,
        confidence=evaluation.confidence,
        evaluated_at=evaluation.evaluated_at.isoformat(),
        residual=dict(evaluation.residual or {}),
        explanation=list(evaluation.explanation or []),
        forecast=forecast,
    )


def _project_appetite(resolved: ResolvedProcessAppetite | None) -> ProcessDashboardAppetite:
    if resolved is None:
        return ProcessDashboardAppetite(resolved=False)
    temporary_exception = (
        ProcessDashboardTemporaryException(
            expires_at=resolved.effective_to.isoformat(),
            review_at=resolved.review_at.isoformat() if resolved.review_at else None,
            decision_reference=resolved.decision_reference,
        )
        if resolved.source_scope == "decision_exception" and resolved.effective_to
        else None
    )
    return ProcessDashboardAppetite(
        resolved=True,
        source_scope=resolved.source_scope,
        version=resolved.version,
        approved_by=resolved.approved_by,
        answers=dict(resolved.answers or {}),
        temporary_exception=temporary_exception,
        expired_exception_reference=resolved.expired_exception_reference,
    )


def _resolve_state(
    *,
    coverage: ProcessDashboardCoverage,
    observed_threats: list[object],
    active_threats: list[object],
    decisions_by_threat_id: dict[str, list[object]],
    verified_threat_ids: set[str],
) -> tuple[ProcessDashboardState, list[ProcessDashboardReasonCode]]:
    setup_reasons = _setup_reasons(coverage)
    if setup_reasons:
        return ProcessDashboardState.BLOCKED, setup_reasons

    undecided_active_threats = [
        threat for threat in active_threats if not decisions_by_threat_id.get(threat.id)
    ]
    if undecided_active_threats:
        return ProcessDashboardState.DECISION_NEEDED, [ProcessDashboardReasonCode.DECISION_REQUIRED]
    if active_threats:
        return ProcessDashboardState.AT_RISK, [
            ProcessDashboardReasonCode.DECISION_RECORDED_RISK_REMAINS,
        ]
    if observed_threats and all(threat.id in verified_threat_ids for threat in observed_threats):
        return ProcessDashboardState.PROTECTED, []
    return ProcessDashboardState.NOT_PROVEN, [ProcessDashboardReasonCode.NO_VERIFIED_OUTCOME]


def _setup_reasons(coverage: ProcessDashboardCoverage) -> list[ProcessDashboardReasonCode]:
    reasons: list[ProcessDashboardReasonCode] = []
    if coverage.service_count == 0:
        reasons.append(ProcessDashboardReasonCode.NO_MAPPED_SERVICES)
    if not coverage.bia_complete:
        reasons.append(ProcessDashboardReasonCode.MISSING_BIA)
    if not coverage.dependency_bundles_complete:
        reasons.append(ProcessDashboardReasonCode.MISSING_DEPENDENCY_BUNDLE)
    if not coverage.process_appetite_resolved:
        reasons.append(ProcessDashboardReasonCode.PROCESS_APPETITE_NOT_RESOLVED)
    return reasons


def _services_by_process_id(services: Iterable[object]) -> dict[str, list[object]]:
    result: dict[str, list[object]] = {}
    for service in services:
        if getattr(service, "archived_at", None) is not None:
            continue
        for process_id in service.value_stream_ids or []:
            result.setdefault(process_id, []).append(service)
    return result


_UNSET_PROCESS_BIA = object()


def _bia_is_complete(
    process: object,
    services: list[object],
    *,
    process_bia_answers: dict | None | object = _UNSET_PROCESS_BIA,
    bia_exceptions: dict[tuple[str, str], list[object]],
) -> bool:
    resolved_process_answers = (
        getattr(process, "bia_answers", None)
        if process_bia_answers is _UNSET_PROCESS_BIA
        else process_bia_answers
    )
    # #463 — each service's BIA is this process's, with only its exceptions in this process.
    return bool(services) and all(
        bia_is_complete(
            effective_service_bia(
                resolved_process_answers, bia_exceptions.get((service.id, process.id), ())
            )
        )
        for service in services
    )


def _dependency_bundles_are_complete(
    services: list[object],
    published_bundle_service_ids: set[str],
) -> bool:
    return bool(services) and all(
        service.id in published_bundle_service_ids for service in services
    )


# Public aliases — the risk evaluation service maps threats onto processes
# through exactly the same asset-name normalisation as the projection.
def mapped_asset_names(services: Iterable[object], asset_name_by_id: dict[str, str]) -> set[str]:
    return _mapped_asset_names(services, asset_name_by_id)


def normalize_asset_id(asset_id: object) -> str:
    return _normalize_asset_id(asset_id)


def normalize_asset_name(asset_name: str) -> str:
    return _normalize_asset_name(asset_name)


def _mapped_asset_names(services: Iterable[object], asset_name_by_id: dict[str, str]) -> set[str]:
    asset_names: set[str] = set()
    for service in services:
        for asset_id in [*(service.l1 or []), *(service.l2 or []), *(service.l3 or [])]:
            asset_name = asset_name_by_id.get(_normalize_asset_id(asset_id))
            if asset_name:
                asset_names.add(asset_name)
    return asset_names


def _group_by_threat_id(records: Iterable[object]) -> dict[str, list[object]]:
    grouped: dict[str, list[object]] = {}
    for record in records:
        if record.threat_id:
            grouped.setdefault(record.threat_id, []).append(record)
    return grouped


def _latest_by_threat_id(records: Iterable[object]) -> dict[str, object]:
    latest: dict[str, object] = {}
    for record in records:
        if not record.threat_id:
            continue
        current = latest.get(record.threat_id)
        if current is None or _record_created_at(record) > _record_created_at(current):
            latest[record.threat_id] = record
    return latest


def _record_created_at(record: object) -> str:
    created_at = getattr(record, "created_at", None)
    if isinstance(created_at, datetime):
        return created_at.isoformat()
    return ""


def _normalize_asset_id(asset_id: object) -> str:
    return str(asset_id).strip().lower().removeprefix("asset-")


def _normalize_asset_name(asset_name: str) -> str:
    return asset_name.strip().lower()
