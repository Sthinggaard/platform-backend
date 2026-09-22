"""Canonical values for the Business Process dashboard projection."""

from enum import StrEnum

from src.core.constants.decision_runtime import (
    THREAT_STATUS_ACCEPTED,
    THREAT_STATUS_IN_PROGRESS,
)


class ProcessDashboardState(StrEnum):
    NOT_PROVEN = "not_proven"
    BLOCKED = "blocked"
    DECISION_NEEDED = "decision_needed"
    AT_RISK = "at_risk"
    PROTECTED = "protected"


class ProcessDashboardReasonCode(StrEnum):
    PROCESS_CONFIRMATION_REQUIRED = "process_confirmation_required"
    PROCESS_OWNER_REQUIRED = "process_owner_required"
    OWNER_ACCEPTANCE_REQUIRED = "owner_acceptance_required"
    BIA_ATTESTATION_REQUIRED = "bia_attestation_required"
    LEADERSHIP_APPETITE_REQUIRED = "leadership_appetite_required"
    PROCESS_ACTIVATION_REQUIRED = "process_activation_required"
    NO_MAPPED_SERVICES = "no_mapped_services"
    MISSING_BIA = "missing_bia"
    MISSING_DEPENDENCY_BUNDLE = "missing_dependency_bundle"
    PROCESS_APPETITE_NOT_RESOLVED = "process_appetite_not_resolved"
    DECISION_REQUIRED = "decision_required"
    DECISION_RECORDED_RISK_REMAINS = "decision_recorded_risk_remains"
    NO_VERIFIED_OUTCOME = "no_verified_outcome"
    REVIEW_OVERDUE = "review_overdue"


class ProcessDashboardActionEligibility(StrEnum):
    NOT_EVALUATED = "not_evaluated"
    CAN_ACT = "can_act"
    VIEW_ONLY = "view_only"


THREAT_STATUS_DETECTED = "detected"
PUBLISHED_BUNDLE_LIFECYCLE_STATE = "bundle_published"

ACTIVE_THREAT_STATUSES: frozenset[str] = frozenset(
    {
        THREAT_STATUS_DETECTED,
        THREAT_STATUS_IN_PROGRESS,
        THREAT_STATUS_ACCEPTED,
    }
)
