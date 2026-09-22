"""Lifecycle values for a Business Service's Risk Appetite reassessment (ONB-GOV-11)."""

from enum import StrEnum


class AppetiteReassessmentStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


APPETITE_REASSESSMENT_AUDIT_REQUESTED = "service_appetite_reassessment_requested"
APPETITE_REASSESSMENT_AUDIT_APPROVED = "service_appetite_reassessment_approved"
APPETITE_REASSESSMENT_AUDIT_REJECTED = "service_appetite_reassessment_rejected"

APPETITE_REASSESSMENT_ERROR_OWNER_REQUIRED = (
    "The accepted Service Owner must request the reassessment"
)
APPETITE_REASSESSMENT_ERROR_PROCESS_OWNER_REQUIRED = (
    "The accepted Process Owner must approve or reject the reassessment"
)
APPETITE_REASSESSMENT_ERROR_NOT_FOUND = "Service appetite reassessment not found"
APPETITE_REASSESSMENT_ERROR_INVALID_CATEGORY = "Unknown appetite category"
APPETITE_REASSESSMENT_ERROR_INVALID_LEVEL = "Appetite level must be between 0 and 4"
