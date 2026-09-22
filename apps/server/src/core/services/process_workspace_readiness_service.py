"""Pure evaluator for the initial prepared Business Process workspace.

This is deliberately separate from process activation readiness. Initial
workspace preparation happens before Process Owner delegation and before the
owner's BIA attestation or dependency review. The evaluator receives facts
from the tenant read model and never persists a workspace lifecycle state.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.core.constants.process_workspace_enums import (
    ProcessWorkspaceReadinessAction,
    ProcessWorkspaceReadinessReason,
    ProcessWorkspaceReadinessState,
)


@dataclass(frozen=True)
class ProcessWorkspaceReadinessInput:
    process_exists: bool
    service_count: int
    bia_prepared: bool
    appetite_effective: bool
    # Has a human confirmed this is how the organisation actually works? A
    # Risklence-suggested process nobody has confirmed is inference, however
    # complete its facts are.
    process_confirmed: bool = False
    terminal_process_outcome: bool = False
    dependency_mapping_gap_count: int = 0
    evidence_gap_count: int = 0


@dataclass(frozen=True)
class ProcessWorkspaceReadiness:
    state: ProcessWorkspaceReadinessState
    release_allowed: bool
    reasons: list[ProcessWorkspaceReadinessReason] = field(default_factory=list)
    next_actions: list[ProcessWorkspaceReadinessAction] = field(default_factory=list)
    service_count: int = 0
    dependency_mapping_gap_count: int = 0
    evidence_gap_count: int = 0


def evaluate_process_workspace_readiness(
    readiness_input: ProcessWorkspaceReadinessInput,
) -> ProcessWorkspaceReadiness:
    """Derive initial workspace readiness from existing domain facts.

    Process Owner assignment is intentionally absent. Mapping and evidence
    gaps are surfaced for the later owner/consultant phase and do not block the
    initial handoff once the core process package is prepared.

    **How the process was arrived at is not a readiness input.** Søren,
    2026-08-30: the acceptance flow has three paths — accept the suggested
    Risklence process, pick a different template, or edit a template until it
    matches how the organisation actually works — and *"all these should be
    releasable and are right. Risklence has no ruling on what is right or wrong
    here."* So a process without a template is not less ready than one with a
    template; it is a process that was tailored, which is a supported path.

    Which path an organisation took still matters — it is the raw material for
    spotting a tendency across organisations and improving the suggestions — but
    that is a signal to record, not a gate to fail. See the learning log.

    What *is* a readiness input is whether a human has **confirmed** the
    structure. An unconfirmed process is Risklence's suggestion, not the
    organisation's answer, and saying it is prepared would present inference as
    fact.
    """
    if readiness_input.terminal_process_outcome:
        return _result(
            ProcessWorkspaceReadinessState.BLOCKED,
            readiness_input,
            reasons=[ProcessWorkspaceReadinessReason.TERMINAL_PROCESS_OUTCOME],
            actions=[ProcessWorkspaceReadinessAction.REVIEW_TERMINAL_PROCESS_OUTCOME],
        )

    missing_reasons: list[ProcessWorkspaceReadinessReason] = []
    missing_actions: list[ProcessWorkspaceReadinessAction] = []
    if not readiness_input.process_exists:
        missing_reasons.append(ProcessWorkspaceReadinessReason.PROCESS_MISSING)
        missing_actions.append(ProcessWorkspaceReadinessAction.PREPARE_PROCESS_STRUCTURE)
    if readiness_input.service_count < 1:
        missing_reasons.append(ProcessWorkspaceReadinessReason.SERVICES_MISSING)
        missing_actions.append(ProcessWorkspaceReadinessAction.PREPARE_BUSINESS_SERVICES)
    if not readiness_input.bia_prepared:
        missing_reasons.append(ProcessWorkspaceReadinessReason.BIA_MISSING)
        missing_actions.append(ProcessWorkspaceReadinessAction.PREPARE_PROCESS_BIA)
    if not readiness_input.appetite_effective:
        missing_reasons.append(ProcessWorkspaceReadinessReason.APPETITE_MISSING)
        missing_actions.append(ProcessWorkspaceReadinessAction.PREPARE_ORGANISATION_APPETITE)

    if missing_reasons:
        return _result(
            ProcessWorkspaceReadinessState.INCOMPLETE,
            readiness_input,
            reasons=missing_reasons,
            actions=missing_actions,
        )

    # The required facts exist. If nobody has confirmed the structure they
    # describe, it is still Risklence's suggestion — `uncertain` in the CA-09B.1
    # vocabulary: "the required preparation facts exist, but inferred/template
    # or dependency evidence still needs human review. This is not a failure and
    # must not be shown as proven resilience."
    if not readiness_input.process_confirmed:
        return _result(
            ProcessWorkspaceReadinessState.UNCERTAIN,
            readiness_input,
            reasons=[ProcessWorkspaceReadinessReason.PROCESS_NOT_CONFIRMED],
            actions=[ProcessWorkspaceReadinessAction.CONFIRM_PROCESS],
        )

    uncertainty_reasons: list[ProcessWorkspaceReadinessReason] = []
    uncertainty_actions: list[ProcessWorkspaceReadinessAction] = []
    if readiness_input.dependency_mapping_gap_count:
        uncertainty_reasons.append(ProcessWorkspaceReadinessReason.DEPENDENCY_MAPPING_GAPS)
        uncertainty_actions.append(ProcessWorkspaceReadinessAction.REVIEW_DEPENDENCY_MAPPINGS)
    if readiness_input.evidence_gap_count:
        uncertainty_reasons.append(ProcessWorkspaceReadinessReason.EVIDENCE_GAPS)
        uncertainty_actions.append(ProcessWorkspaceReadinessAction.REVIEW_EVIDENCE_GAPS)

    return _result(
        ProcessWorkspaceReadinessState.PREPARED,
        readiness_input,
        reasons=uncertainty_reasons,
        actions=uncertainty_actions,
    )


def _result(
    state: ProcessWorkspaceReadinessState,
    readiness_input: ProcessWorkspaceReadinessInput,
    *,
    reasons: list[ProcessWorkspaceReadinessReason],
    actions: list[ProcessWorkspaceReadinessAction],
) -> ProcessWorkspaceReadiness:
    return ProcessWorkspaceReadiness(
        state=state,
        release_allowed=state is ProcessWorkspaceReadinessState.PREPARED,
        reasons=reasons,
        next_actions=actions,
        service_count=readiness_input.service_count,
        dependency_mapping_gap_count=readiness_input.dependency_mapping_gap_count,
        evidence_gap_count=readiness_input.evidence_gap_count,
    )
