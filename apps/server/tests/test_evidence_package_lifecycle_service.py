import pytest

from src.core.constants.discovery_execution_enums import EvidenceNormalizationStatus
from src.core.constants.lifecycle_enums import LifecycleDenialReason
from src.core.model_defs.discovery_execution import EvidencePackage
from src.core.services.evidence_package_lifecycle_service import (
    EvidencePackageTransitionError,
    transition_evidence_package_normalization,
)


def _package(status: str) -> EvidencePackage:
    return EvidencePackage(
        discovery_run_id="run-1",
        execution_plan_id="plan-1",
        execution_stage_id="stage-1",
        provider_execution_id="execution-1",
        organization_id=1,
        provider_id="nmap",
        raw_evidence_reference="evidence://package-1",
        evidence_format="nmap_xml",
        processing_status="stored",
        normalization_status=status,
    )


def test_evidence_normalization_allows_queued_to_normalized():
    package = _package(EvidenceNormalizationStatus.QUEUED.value)

    transition_evidence_package_normalization(package, EvidenceNormalizationStatus.NORMALIZED.value)

    assert package.normalization_status == EvidenceNormalizationStatus.NORMALIZED.value


def test_evidence_normalization_rejects_reopening_a_terminal_state():
    with pytest.raises(EvidencePackageTransitionError) as error:
        transition_evidence_package_normalization(
            _package(EvidenceNormalizationStatus.NORMALIZED.value),
            EvidenceNormalizationStatus.QUEUED.value,
        )

    assert error.value.reason == LifecycleDenialReason.TERMINAL_STATE
