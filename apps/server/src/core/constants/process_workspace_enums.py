"""Lifecycle values for initial Business Process workspace preparation."""

from enum import StrEnum


class ProcessWorkspaceReadinessState(StrEnum):
    PREPARED = "prepared"
    INCOMPLETE = "incomplete"
    UNCERTAIN = "uncertain"
    BLOCKED = "blocked"


class ProcessWorkspaceReadinessReason(StrEnum):
    PROCESS_MISSING = "process_missing"
    SERVICES_MISSING = "services_missing"
    BIA_MISSING = "bia_missing"
    APPETITE_MISSING = "appetite_missing"
    DEPENDENCY_MAPPING_GAPS = "dependency_mapping_gaps"
    EVIDENCE_GAPS = "evidence_gaps"
    TERMINAL_PROCESS_OUTCOME = "terminal_process_outcome"
    # The facts exist, but the structure they describe is still Risklence's
    # suggestion — nobody has confirmed it is how the organisation works.
    PROCESS_NOT_CONFIRMED = "process_not_confirmed"


class ProcessWorkspaceReadinessAction(StrEnum):
    PREPARE_PROCESS_STRUCTURE = "prepare_process_structure"
    PREPARE_BUSINESS_SERVICES = "prepare_business_services"
    PREPARE_PROCESS_BIA = "prepare_process_bia"
    PREPARE_ORGANISATION_APPETITE = "prepare_organisation_appetite"
    REVIEW_DEPENDENCY_MAPPINGS = "review_dependency_mappings"
    REVIEW_EVIDENCE_GAPS = "review_evidence_gaps"
    REVIEW_TERMINAL_PROCESS_OUTCOME = "review_terminal_process_outcome"
    CONFIRM_PROCESS = "confirm_process"


class ProcessWorkspaceDependencySlotStatus(StrEnum):
    """Read-only mapping state for a prepared dependency slot."""

    MAPPED = "mapped"
    DEFERRED = "deferred"
    UNMAPPED = "unmapped"
