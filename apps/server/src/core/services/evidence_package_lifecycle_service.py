"""Guarded transitions for EvidencePackage normalization processing."""

from src.core.constants.discovery_execution_enums import ALLOWED_EVIDENCE_NORMALIZATION_TRANSITIONS
from src.core.constants.lifecycle_enums import LifecycleDenialReason
from src.core.model_defs.discovery_execution import EvidencePackage


class EvidencePackageTransitionError(ValueError):
    def __init__(self, reason: LifecycleDenialReason, current_state: str, target_state: str):
        self.reason = reason
        self.current_state = current_state
        self.target_state = target_state
        super().__init__(
            f"Evidence package cannot transition from '{current_state}' to '{target_state}'."
        )


def transition_evidence_package_normalization(package: EvidencePackage, target_state: str) -> None:
    if target_state not in ALLOWED_EVIDENCE_NORMALIZATION_TRANSITIONS:
        raise EvidencePackageTransitionError(
            LifecycleDenialReason.INVALID_TARGET_STATE, package.normalization_status, target_state
        )
    if target_state not in ALLOWED_EVIDENCE_NORMALIZATION_TRANSITIONS.get(
        package.normalization_status, frozenset()
    ):
        reason = (
            LifecycleDenialReason.TERMINAL_STATE
            if not ALLOWED_EVIDENCE_NORMALIZATION_TRANSITIONS.get(package.normalization_status)
            else LifecycleDenialReason.INVALID_SOURCE_STATE
        )
        raise EvidencePackageTransitionError(reason, package.normalization_status, target_state)
    package.normalization_status = target_state
