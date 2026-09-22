"""Response contracts for the Business Process dashboard projection."""

from pydantic import BaseModel

from src.core.constants.process_activation_enums import ProcessActivationState
from src.core.constants.process_dashboard_enums import (
    ProcessDashboardActionEligibility,
    ProcessDashboardReasonCode,
    ProcessDashboardState,
)
from src.api.schemas.timestamps import UtcTimestamp


class ProcessDashboardCoverageResponse(BaseModel):
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


class ProcessDashboardTemporaryExceptionResponse(BaseModel):
    expires_at: UtcTimestamp
    review_at: UtcTimestamp | None = None
    decision_reference: str | None = None


class ProcessDashboardAppetiteResponse(BaseModel):
    resolved: bool
    source_scope: str | None = None
    version: int | None = None
    approved_by: str | None = None
    answers: dict | None = None
    temporary_exception: ProcessDashboardTemporaryExceptionResponse | None = None
    expired_exception_reference: str | None = None


class ProcessDashboardMandateResponse(BaseModel):
    assigned: bool
    holder_user_id: int | None = None
    holder_name: str | None = None
    canonical_role: str | None = None


class ProcessDashboardDecisionItemResponse(BaseModel):
    threat_id: str
    asset: str
    severity: str
    service_id: str | None = None
    service_name: str | None = None


class ProcessDashboardUnmappedRiskResponse(BaseModel):
    threat_id: str
    asset: str
    severity: str


class ProcessDashboardForecastResponse(BaseModel):
    estimate: dict
    confidence: str
    source: str
    created_at: UtcTimestamp


class ProcessDashboardEvaluationResponse(BaseModel):
    evaluation_id: str
    status: str
    preparedness: str
    confidence: str
    evaluated_at: UtcTimestamp
    residual: dict
    explanation: list
    forecast: ProcessDashboardForecastResponse | None = None


class ProcessDashboardProcessResponse(BaseModel):
    process_id: str
    name: str
    priority: str
    state: ProcessDashboardState
    reasons: list[ProcessDashboardReasonCode]
    coverage: ProcessDashboardCoverageResponse
    activation_state: ProcessActivationState | None = None
    next_activation_action: ProcessActivationState | None = None
    # "accept_ownership" | "confirm" | None — set only when the viewer
    # resolving this response is the one who must take the next step.
    activation_action_for_viewer: str | None = None
    appetite: ProcessDashboardAppetiteResponse
    evaluation: ProcessDashboardEvaluationResponse | None = None
    observed_risk_count: int
    active_threat_count: int
    active_decision_count: int
    verified_outcome_count: int
    awaiting_verification_count: int
    overdue_review_count: int
    visible_to_user: bool
    action_eligibility: ProcessDashboardActionEligibility
    access_detail: str
    mandate: ProcessDashboardMandateResponse
    decision_items: list[ProcessDashboardDecisionItemResponse]


class ProcessDashboardResponse(BaseModel):
    processes: list[ProcessDashboardProcessResponse]
    unmapped_observed_risk_count: int
    access_model_configured: bool
    unmapped_observed_risks: list[ProcessDashboardUnmappedRiskResponse]
