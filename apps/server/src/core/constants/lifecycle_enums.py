"""Shared lifecycle vocabulary.

These enums describe conventions shared by bounded domains. They do not
replace domain-owned state enums such as ``DiscoveryRunStatus``.
"""

from enum import StrEnum


class LifecycleFamily(StrEnum):
    APPROVAL = "approval"
    EXECUTION = "execution"
    EVIDENCE = "evidence"
    PUBLICATION = "publication"
    RESPONSIBILITY = "responsibility"


class LifecycleTransitionSource(StrEnum):
    HUMAN_INITIATED = "human_initiated"
    HUMAN_APPROVED = "human_approved"
    SYSTEM_OBSERVED = "system_observed"
    SYSTEM_EXECUTED = "system_executed"
    TIME_DRIVEN = "time_driven"
    EXTERNAL_PROVIDER_REPORTED = "external_provider_reported"
    DERIVED = "derived"


class LifecycleDenialReason(StrEnum):
    INVALID_SOURCE_STATE = "invalid_source_state"
    INVALID_TARGET_STATE = "invalid_target_state"
    INSUFFICIENT_PERMISSION = "insufficient_permission"
    TENANT_MISMATCH = "tenant_mismatch"
    APPROVAL_REQUIRED = "approval_required"
    REASON_REQUIRED = "reason_required"
    MISSING_REQUIRED_EVIDENCE = "missing_required_evidence"
    OBJECT_EXPIRED = "object_expired"
    OBJECT_SUPERSEDED = "object_superseded"
    OBJECT_CANCELLED = "object_cancelled"
    TERMINAL_STATE = "terminal_state"
    VERSION_CONFLICT = "version_conflict"
    RETRY_NOT_ALLOWED = "retry_not_allowed"


class LifecycleFailureCategory(StrEnum):
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    AUTHORISATION = "authorisation"
    CONNECTIVITY = "connectivity"
    PROVIDER = "provider"
    TIMEOUT = "timeout"
    CONFIGURATION = "configuration"
    INTERNAL = "internal"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"
