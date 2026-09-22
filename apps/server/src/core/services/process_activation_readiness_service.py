"""Read-only resolution of Business Process activation readiness."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    MandateAssignmentSubjectType,
    MandateScopeType,
)
from src.core.constants.process_activation_enums import (
    PROCESS_CONFIRMATION_OUTCOME_TO_ACTIVATION_STATE,
    ProcessActivationState,
    ProcessConfirmationOutcome,
)
from src.core.constants.process_ownership_enums import ProcessOwnershipStatus
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.model_defs.process_activation import BusinessProcessActivation
from src.core.model_defs.process_ownership import ProcessOwnerAcceptance
from src.core.model_defs.tenant_identity import User
from src.core.model_defs.value_streams import ValueStream
from src.core.repository import TenantRepository
from src.core.services.bia_inheritance_service import bia_is_complete
from src.core.services.effective_process_bia_service import (
    EffectiveProcessBia,
    resolve_effective_process_bia_by_process,
)
from src.core.services.risk_appetite_resolution_service import (
    ResolvedProcessAppetite,
    resolve_organisation_appetite,
)


@dataclass(frozen=True)
class ProcessActivationReadiness:
    process_id: str
    activation_id: str | None
    state: ProcessActivationState
    next_action: ProcessActivationState
    confirmation_outcome: ProcessConfirmationOutcome
    process_confirmed: bool
    owner_assigned: bool
    # The assigned owner's user id, so a viewer-scoped surface (the dashboard)
    # can tell whether the pending step belongs to the person looking at it.
    # None until an active, resolvable user holds the assignment.
    owner_user_id: int | None
    ownership_accepted: bool
    bia_attested: bool
    organisation_appetite_effective: bool
    impact_model_active: bool
    # The invitation behind the assignment, so the process itself can say how
    # long it has been waiting and — when the candidate refused — why. A
    # rejection reason that is only stored leaves a process quietly stopped
    # with nobody told (#365). Default None: a process nobody was ever invited
    # to has no invitation, which is not the same as an empty one.
    owner_acceptance_status: str | None = None
    owner_invited_at: datetime | None = None
    owner_rejection_reason: str | None = None


def resolve_process_activation_readiness(
    db: Session,
    *,
    organization_id: int,
    processes: list[ValueStream],
) -> dict[str, ProcessActivationReadiness]:
    """Resolve current activation truth without copying mandate or assessment state."""
    if not processes:
        return {}
    activations = TenantRepository(db, BusinessProcessActivation, organization_id).get_all()
    bindings = TenantRepository(db, OrgMandateScopeBinding, organization_id).get_all()
    assignments = TenantRepository(db, OrgMandateRoleAssignment, organization_id).get_all()
    acceptances = TenantRepository(db, ProcessOwnerAcceptance, organization_id).get_all()
    users = TenantRepository(db, User, organization_id).get_all()
    appetite = resolve_organisation_appetite(db, organization_id=organization_id)
    effective_bia_by_process = resolve_effective_process_bia_by_process(
        db,
        organization_id=organization_id,
        processes=processes,
    )
    return _resolve_all(
        processes=processes,
        activations=activations,
        bindings=bindings,
        assignments=assignments,
        acceptances=acceptances,
        effective_bia_by_process=effective_bia_by_process,
        users=users,
        appetite=appetite,
    )


def _resolve_all(
    *,
    processes: list[ValueStream],
    activations: list[BusinessProcessActivation],
    bindings: list[OrgMandateScopeBinding],
    assignments: list[OrgMandateRoleAssignment],
    acceptances: list[ProcessOwnerAcceptance],
    effective_bia_by_process: dict[str, EffectiveProcessBia],
    users: list[User],
    appetite: ResolvedProcessAppetite | None,
) -> dict[str, ProcessActivationReadiness]:
    activation_by_process = {row.process_id: row for row in activations}
    assignment_by_id = {row.id: row for row in assignments}
    user_by_id = {row.id: row for row in users}
    acceptance_by_binding = {row.scope_binding_id: row for row in acceptances}
    binding_by_process = {
        row.value_stream_id: row
        for row in bindings
        if row.scope_type == MandateScopeType.BUSINESS_PROCESS.value
        and row.canonical_role == CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value
        and row.value_stream_id is not None
    }
    return {
        process.id: _resolve_process(
            process=process,
            activation=activation_by_process.get(process.id),
            binding=binding_by_process.get(process.id),
            assignment_by_id=assignment_by_id,
            acceptance_by_binding=acceptance_by_binding,
            user_by_id=user_by_id,
            effective_bia=effective_bia_by_process[process.id],
            appetite=appetite,
        )
        for process in processes
    }


def _resolve_process(
    *,
    process: ValueStream,
    activation: BusinessProcessActivation | None,
    binding: OrgMandateScopeBinding | None,
    assignment_by_id: dict[str, OrgMandateRoleAssignment],
    acceptance_by_binding: dict[str, ProcessOwnerAcceptance],
    user_by_id: dict[int, User],
    effective_bia: EffectiveProcessBia,
    appetite: ResolvedProcessAppetite | None,
) -> ProcessActivationReadiness:
    confirmation_outcome = _confirmation_outcome(activation)
    confirmed = (
        confirmation_outcome is ProcessConfirmationOutcome.CONFIRMED
        and activation is not None
        and activation.confirmed_at is not None
    )
    assignment = assignment_by_id.get(binding.role_assignment_id) if binding else None
    owner_assigned = bool(
        assignment
        and assignment.subject_type == MandateAssignmentSubjectType.USER.value
        and assignment.user_id is not None
        and (owner := user_by_id.get(assignment.user_id))
        and owner.is_active
    )
    owner_user_id = assignment.user_id if owner_assigned and assignment else None
    acceptance = acceptance_by_binding.get(binding.id) if binding else None
    accepted = bool(
        owner_assigned
        and acceptance
        and acceptance.status == ProcessOwnershipStatus.ACCEPTED.value
        and acceptance.role_assignment_id == assignment.id
        and acceptance.owner_user_id == assignment.user_id
    )
    bia_started = effective_bia.process_assessment_started
    bia_attested = bia_is_complete(effective_bia.answers)
    state = _state(
        confirmation_outcome=confirmation_outcome,
        confirmed=confirmed,
        owner_assigned=owner_assigned,
        accepted=accepted,
        bia_started=bia_started,
        bia_attested=bia_attested,
        appetite_effective=appetite is not None,
        activation_current=_activation_is_current(activation, effective_bia, acceptance, appetite),
    )
    return ProcessActivationReadiness(
        process_id=process.id,
        activation_id=activation.id if activation else None,
        state=state,
        next_action=state,
        confirmation_outcome=confirmation_outcome,
        process_confirmed=confirmed,
        owner_assigned=owner_assigned,
        owner_user_id=owner_user_id,
        ownership_accepted=accepted,
        owner_acceptance_status=acceptance.status if acceptance else None,
        owner_invited_at=acceptance.invited_at if acceptance else None,
        owner_rejection_reason=acceptance.rejection_reason if acceptance else None,
        bia_attested=bia_attested,
        organisation_appetite_effective=appetite is not None,
        impact_model_active=state == ProcessActivationState.IMPACT_UNDERSTOOD,
    )


def _state(
    *,
    confirmation_outcome: ProcessConfirmationOutcome,
    confirmed: bool,
    owner_assigned: bool,
    accepted: bool,
    bia_started: bool,
    bia_attested: bool,
    appetite_effective: bool,
    activation_current: bool,
) -> ProcessActivationState:
    terminal_state = PROCESS_CONFIRMATION_OUTCOME_TO_ACTIVATION_STATE.get(
        confirmation_outcome
    )
    if terminal_state is not None:
        return terminal_state
    # Ownership precedes approval: the accepted owner is the only one who may
    # confirm a process, so ownership and acceptance are resolved first.
    # Terminal curation outcomes above are the one exception — retiring a bad
    # suggestion is administrator curation, not approval, and needs no owner.
    if not owner_assigned:
        return ProcessActivationState.OWNERSHIP_REQUIRED
    if not accepted:
        return ProcessActivationState.OWNER_ACCEPTANCE_REQUIRED
    if not confirmed:
        return ProcessActivationState.CONFIRMATION_REQUIRED
    if not bia_attested:
        return ProcessActivationState.BIA_IN_PROGRESS if bia_started else ProcessActivationState.BIA_REQUIRED
    if not appetite_effective:
        return ProcessActivationState.LEADERSHIP_APPETITE_REQUIRED
    if not activation_current:
        return ProcessActivationState.READY_FOR_ACTIVATION
    return ProcessActivationState.IMPACT_UNDERSTOOD


def _confirmation_outcome(
    activation: BusinessProcessActivation | None,
) -> ProcessConfirmationOutcome:
    if activation is None:
        return ProcessConfirmationOutcome.PENDING
    try:
        return ProcessConfirmationOutcome(activation.confirmation_outcome)
    except ValueError:
        return ProcessConfirmationOutcome.PENDING


def _bia_snapshot_matches(
    activation: BusinessProcessActivation,
    effective_bia: EffectiveProcessBia,
) -> bool:
    """Whether the BIA recorded at activation is still the one that governs.

    Both snapshot columns are nullable, and so are both sides of the comparison,
    so comparing them directly let ``None == None`` pass: an activation that
    recorded *no* BIA provenance at all counted as current forever, and later
    changes to the BIA never invalidated it. That is the whole purpose of this
    check, silently dead on that path.

    An activation that named no governing BIA cannot be shown to be current, so
    it is not. Re-activating captures the provenance and answers the question
    properly — under-claiming here is the safe direction.
    """
    recorded_provenance = (
        activation.activated_bia_assessment_id
        or activation.activated_organization_bia_baseline_id
    )
    if not recorded_provenance:
        return False
    return (
        activation.activated_bia_assessment_id == effective_bia.process_assessment_id
        and activation.activated_organization_bia_baseline_id
        == effective_bia.organization_baseline_id
    )


def _activation_is_current(
    activation: BusinessProcessActivation | None,
    effective_bia: EffectiveProcessBia,
    acceptance: ProcessOwnerAcceptance | None,
    appetite: ResolvedProcessAppetite | None,
) -> bool:
    return bool(
        activation
        and activation.activated_at
        and activation.confirmed_at
        and activation.activated_confirmation_at == activation.confirmed_at
        and _bia_snapshot_matches(activation, effective_bia)
        and acceptance
        and activation.activated_owner_acceptance_id == acceptance.id
        and appetite
        and activation.activated_appetite_policy_id == appetite.policy_id
    )
