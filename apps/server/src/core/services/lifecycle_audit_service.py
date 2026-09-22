"""Additive lifecycle metadata for the existing ``AuditEvent`` write path."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.core.constants.lifecycle_enums import LifecycleFamily, LifecycleTransitionSource


@dataclass(frozen=True)
class LifecycleAuditDetails:
    object_type: str
    object_id: str
    family: LifecycleFamily
    source: LifecycleTransitionSource
    previous_state: str | None = None
    current_state: str | None = None
    reason_code: str | None = None
    approval_reference_id: str | None = None
    correlation_id: str | None = None
    object_version: int | None = None


def with_lifecycle_audit_metadata(metadata: dict[str, Any], details: LifecycleAuditDetails) -> dict[str, Any]:
    """Return additive metadata without changing existing event consumers.

    The lifecycle block intentionally contains no raw technical failure
    details or tenant identifiers. The trusted tenant and actor stay on the
    ``AuditEvent`` row itself.
    """
    lifecycle = {
        "objectType": details.object_type,
        "objectId": details.object_id,
        "family": details.family.value,
        "transitionSource": details.source.value,
        "previousState": details.previous_state,
        "currentState": details.current_state,
        "reasonCode": details.reason_code,
        "approvalReferenceId": details.approval_reference_id,
        "correlationId": details.correlation_id,
        "objectVersion": details.object_version,
    }
    return {**metadata, "lifecycle": {key: value for key, value in lifecycle.items() if value is not None}}
