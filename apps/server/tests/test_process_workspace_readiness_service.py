from src.core.constants.process_workspace_enums import (
    ProcessWorkspaceReadinessAction,
    ProcessWorkspaceReadinessReason,
    ProcessWorkspaceReadinessState,
)
from src.core.services.process_workspace_readiness_service import (
    ProcessWorkspaceReadinessInput,
    evaluate_process_workspace_readiness,
)


def test_prepared_workspace_can_be_released_with_explicit_later_phase_gaps():
    result = evaluate_process_workspace_readiness(
        ProcessWorkspaceReadinessInput(
            process_exists=True,
            service_count=4,
            bia_prepared=True,
            appetite_effective=True,
            process_confirmed=True,
            dependency_mapping_gap_count=2,
            evidence_gap_count=1,
        )
    )

    assert result.state is ProcessWorkspaceReadinessState.PREPARED
    assert result.release_allowed is True
    assert result.reasons == [
        ProcessWorkspaceReadinessReason.DEPENDENCY_MAPPING_GAPS,
        ProcessWorkspaceReadinessReason.EVIDENCE_GAPS,
    ]
    assert result.next_actions == [
        ProcessWorkspaceReadinessAction.REVIEW_DEPENDENCY_MAPPINGS,
        ProcessWorkspaceReadinessAction.REVIEW_EVIDENCE_GAPS,
    ]


def test_missing_initial_facts_is_incomplete_and_not_released():
    result = evaluate_process_workspace_readiness(
        ProcessWorkspaceReadinessInput(
            process_exists=True,
            service_count=0,
            bia_prepared=False,
            appetite_effective=False,
        )
    )

    assert result.state is ProcessWorkspaceReadinessState.INCOMPLETE
    assert result.release_allowed is False
    assert result.reasons == [
        ProcessWorkspaceReadinessReason.SERVICES_MISSING,
        ProcessWorkspaceReadinessReason.BIA_MISSING,
        ProcessWorkspaceReadinessReason.APPETITE_MISSING,
    ]


def test_terminal_process_outcome_is_blocked_before_other_facts():
    result = evaluate_process_workspace_readiness(
        ProcessWorkspaceReadinessInput(
            process_exists=True,
            service_count=3,
            bia_prepared=True,
            appetite_effective=True,
            terminal_process_outcome=True,
        )
    )

    assert result.state is ProcessWorkspaceReadinessState.BLOCKED
    assert result.release_allowed is False
    assert result.reasons == [ProcessWorkspaceReadinessReason.TERMINAL_PROCESS_OUTCOME]


def test_a_tailored_process_names_every_missing_input():
    """The required facts are evaluated before the template question.

    The template question used to be asked first and returned immediately, so
    a tailored process with no services, no BIA and no appetite reported none of
    them. The reader could not see what was actually absent.
    """
    result = evaluate_process_workspace_readiness(
        ProcessWorkspaceReadinessInput(
            process_exists=True,
            service_count=0,
            bia_prepared=False,
            appetite_effective=False,
        )
    )

    assert result.state is ProcessWorkspaceReadinessState.INCOMPLETE
    assert result.release_allowed is False
    assert result.reasons == [
        ProcessWorkspaceReadinessReason.SERVICES_MISSING,
        ProcessWorkspaceReadinessReason.BIA_MISSING,
        ProcessWorkspaceReadinessReason.APPETITE_MISSING,
    ]


def test_tailored_process_reports_its_remaining_gap_as_it_is_prepared():
    """Partially prepared: the BIA has landed, the appetite has not."""
    result = evaluate_process_workspace_readiness(
        ProcessWorkspaceReadinessInput(
            process_exists=True,
            service_count=2,
            bia_prepared=True,
            appetite_effective=False,
        )
    )

    assert result.state is ProcessWorkspaceReadinessState.INCOMPLETE
    assert result.reasons == [ProcessWorkspaceReadinessReason.APPETITE_MISSING]


def test_a_tailored_process_is_releasable_like_any_other():
    """How the process was arrived at is not a readiness input.

    Søren, 2026-08-30: the acceptance flow has three paths — accept the
    suggested Risklence process, pick a different template, or edit a template
    until it matches how the organisation actually works — and "all these should
    be releasable and are right. Risklence has no ruling on what is right or
    wrong here."

    This previously returned UNCERTAIN with release_allowed False purely because
    the process had no template behind it, which made a tailored process
    permanently unreleasable however completely it was prepared.
    """
    result = evaluate_process_workspace_readiness(
        ProcessWorkspaceReadinessInput(
            process_exists=True,
            service_count=2,
            bia_prepared=True,
            appetite_effective=True,
            process_confirmed=True,
        )
    )

    assert result.state is ProcessWorkspaceReadinessState.PREPARED
    assert result.release_allowed is True
    assert result.reasons == []


def test_an_unconfirmed_process_is_uncertain_not_prepared():
    """The facts exist, but the structure is still Risklence's suggestion.

    CA-09B.1: uncertain is "the required preparation facts exist, but
    inferred/template or dependency evidence still needs human review. This is
    not a failure and must not be shown as proven resilience." Calling an
    unconfirmed process prepared would present inference as fact.
    """
    result = evaluate_process_workspace_readiness(
        ProcessWorkspaceReadinessInput(
            process_exists=True,
            service_count=2,
            bia_prepared=True,
            appetite_effective=True,
            process_confirmed=False,
        )
    )

    assert result.state is ProcessWorkspaceReadinessState.UNCERTAIN
    assert result.release_allowed is False
    assert result.reasons == [ProcessWorkspaceReadinessReason.PROCESS_NOT_CONFIRMED]
    assert result.next_actions == [ProcessWorkspaceReadinessAction.CONFIRM_PROCESS]


def test_a_missing_required_fact_outranks_the_confirmation_question():
    """Incomplete first: naming what is absent beats asking to confirm it."""
    result = evaluate_process_workspace_readiness(
        ProcessWorkspaceReadinessInput(
            process_exists=True,
            service_count=0,
            bia_prepared=False,
            appetite_effective=True,
            process_confirmed=False,
        )
    )

    assert result.state is ProcessWorkspaceReadinessState.INCOMPLETE
    assert ProcessWorkspaceReadinessReason.PROCESS_NOT_CONFIRMED not in result.reasons


def test_a_confirmed_process_with_gaps_is_still_prepared():
    """Gaps stay visible without blocking the handoff — unchanged by this."""
    result = evaluate_process_workspace_readiness(
        ProcessWorkspaceReadinessInput(
            process_exists=True,
            service_count=2,
            bia_prepared=True,
            appetite_effective=True,
            process_confirmed=True,
            dependency_mapping_gap_count=3,
        )
    )

    assert result.state is ProcessWorkspaceReadinessState.PREPARED
    assert result.release_allowed is True
    assert result.reasons == [ProcessWorkspaceReadinessReason.DEPENDENCY_MAPPING_GAPS]
