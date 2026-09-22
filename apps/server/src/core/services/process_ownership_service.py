"""Resolve and govern accountable Business Process Owner acceptance."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from src.core.constants.leadership_authorization_enums import (
    LEADERSHIP_AUTHORIZATION_ERROR_OWNER_INVITE_REQUIRES_AUTHORIZATION,
)
from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    MandateAssignmentSubjectType,
    MandateScopeType,
)
from src.core.constants.process_ownership_enums import (
    ProcessOwnershipErrorMessage,
    ProcessOwnershipRejectionReason,
    ProcessOwnershipStatus,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.model_defs.process_ownership import ProcessOwnerAcceptance
from src.core.model_defs.tenant_identity import User
from src.core.model_defs.value_streams import BusinessService, ValueStream
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES
from src.core.services.leadership_authorization_service import (
    backfill_leadership_authorization_for_legacy_org,
    get_active_leadership_authorization,
)


class ProcessOwnershipValidationError(ValueError):
    """Raised when a process owner lifecycle transition is invalid."""


def _get_process_owner_binding(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
) -> OrgMandateScopeBinding:
    binding = next(
        iter(
            TenantRepository(db, OrgMandateScopeBinding, organization_id).filter_by(
                scope_type=MandateScopeType.BUSINESS_PROCESS.value,
                value_stream_id=process_id,
                canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
            )
        ),
        None,
    )
    if binding is None:
        raise ProcessOwnershipValidationError(
            ProcessOwnershipErrorMessage.PROCESS_OWNER_BINDING_NOT_FOUND.value
        )
    return binding


def _get_user_bound_owner_assignment(
    db: Session,
    *,
    organization_id: int,
    binding: OrgMandateScopeBinding,
) -> OrgMandateRoleAssignment:
    assignment = TenantRepository(db, OrgMandateRoleAssignment, organization_id).get_by_id(
        binding.role_assignment_id
    )
    if (
        assignment is None
        or assignment.canonical_role != CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value
        or assignment.subject_type != MandateAssignmentSubjectType.USER.value
        or assignment.user_id is None
    ):
        raise ProcessOwnershipValidationError(
            ProcessOwnershipErrorMessage.OWNER_ACCEPTANCE_REQUIRES_USER.value
        )
    user = TenantRepository(db, User, organization_id).get_by_id(assignment.user_id)
    if user is None or not user.is_active:
        raise ProcessOwnershipValidationError(ProcessOwnershipErrorMessage.OWNER_USER_INACTIVE.value)
    return assignment


def _find_accepted_acceptance(
    db: Session,
    *,
    organization_id: int,
    binding: OrgMandateScopeBinding,
    assignment: OrgMandateRoleAssignment,
    user_id: int,
) -> ProcessOwnerAcceptance | None:
    """Return this user's accepted ownership record for the binding, if one exists.

    A scope binding records who was *offered* the mandate. Only an acceptance
    records that they took it, so every authority check reads this — not the
    binding alone.
    """
    return next(
        iter(
            TenantRepository(db, ProcessOwnerAcceptance, organization_id).filter_by(
                scope_binding_id=binding.id,
                role_assignment_id=assignment.id,
                owner_user_id=user_id,
                status=ProcessOwnershipStatus.ACCEPTED.value,
            )
        ),
        None,
    )


def require_process_editor(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
    actor_user_id: int,
) -> None:
    """Allow organisation admins, or the user who *accepted* ownership, to edit.

    The scope binding alone is not authority: it is the offer. A candidate who
    has not yet responded, or who rejected the invitation with a structured
    reason, holds no editing rights over the process.
    """
    user = TenantRepository(db, User, organization_id).get_by_id(actor_user_id)
    if user is not None and user.is_active and user.role in ADMIN_ROLES:
        return

    binding = next(
        iter(
            TenantRepository(db, OrgMandateScopeBinding, organization_id).filter_by(
                scope_type=MandateScopeType.BUSINESS_PROCESS.value,
                value_stream_id=process_id,
                canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
            )
        ),
        None,
    )
    if binding is None:
        raise ProcessOwnershipValidationError(
            ProcessOwnershipErrorMessage.PROCESS_OWNER_BINDING_NOT_FOUND.value
        )
    assignment = _get_user_bound_owner_assignment(
        db,
        organization_id=organization_id,
        binding=binding,
    )
    if assignment.user_id != actor_user_id:
        raise ProcessOwnershipValidationError(
            ProcessOwnershipErrorMessage.PROCESS_EDITOR_ACCESS_REQUIRED.value
        )
    if (
        _find_accepted_acceptance(
            db,
            organization_id=organization_id,
            binding=binding,
            assignment=assignment,
            user_id=actor_user_id,
        )
        is None
    ):
        raise ProcessOwnershipValidationError(
            ProcessOwnershipErrorMessage.OWNER_ACCEPTANCE_REQUIRED.value
        )


def can_process_edit(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
    actor_user_id: int,
) -> bool:
    """Return whether the actor may edit the process without raising."""
    try:
        require_process_editor(
            db,
            organization_id=organization_id,
            process_id=process_id,
            actor_user_id=actor_user_id,
        )
    except ProcessOwnershipValidationError:
        return False
    return True


@dataclass(frozen=True)
class PendingOwnerInvitation:
    """One invitation awaiting this candidate's answer, with the context to answer it.

    A candidate cannot accept what they cannot find. Accept and reject are both
    addressed by process id, so without this the only way to answer an
    invitation is to already know the id of a process nobody has told you about.
    """

    process_id: str
    process_name: str
    outcome_statement: str | None
    service_count: int
    invited_at: datetime
    invited_by_user_id: int | None


def list_pending_owner_invitations(
    db: Session,
    *,
    organization_id: int,
    user_id: int,
) -> list[PendingOwnerInvitation]:
    """Every invitation this user has been sent and not yet answered.

    Scoped to the caller by construction: an invitation belongs to the person
    named on it, and nobody — administrator included — answers on their behalf.
    """
    acceptances = [
        row
        for row in TenantRepository(db, ProcessOwnerAcceptance, organization_id).filter_by(
            owner_user_id=user_id,
            status=ProcessOwnershipStatus.INVITATION_SENT.value,
        )
    ]
    if not acceptances:
        return []

    process_ids = {row.process_id for row in acceptances}
    processes = {
        process.id: process
        for process in TenantRepository(db, ValueStream, organization_id).get_all()
        if process.id in process_ids
    }
    service_counts: dict[str, int] = {}
    for service in TenantRepository(db, BusinessService, organization_id).get_all():
        if service.archived_at is not None:
            continue
        for linked in service.value_stream_ids or []:
            if linked in process_ids:
                service_counts[linked] = service_counts.get(linked, 0) + 1

    pending: list[PendingOwnerInvitation] = []
    for row in acceptances:
        process = processes.get(row.process_id)
        if process is None:
            # The process was removed after the invitation was sent. Nothing to
            # accept, so it is not offered rather than shown as an empty row.
            continue
        pending.append(
            PendingOwnerInvitation(
                process_id=process.id,
                process_name=process.name,
                outcome_statement=process.description,
                service_count=service_counts.get(process.id, 0),
                invited_at=row.invited_at,
                invited_by_user_id=row.invited_by_user_id,
            )
        )
    return sorted(pending, key=lambda item: item.invited_at)


def invite_process_owner(
    db: Session,
    *,
    organization_id: int,
    scope_binding_id: str,
    invited_by_user_id: int,
) -> ProcessOwnerAcceptance:
    backfill_leadership_authorization_for_legacy_org(db, organization_id)
    if get_active_leadership_authorization(db, organization_id) is None:
        raise ProcessOwnershipValidationError(
            LEADERSHIP_AUTHORIZATION_ERROR_OWNER_INVITE_REQUIRES_AUTHORIZATION
        )
    binding = TenantRepository(db, OrgMandateScopeBinding, organization_id).get_by_id(scope_binding_id)
    if (
        binding is None
        or binding.scope_type != MandateScopeType.BUSINESS_PROCESS.value
        or binding.canonical_role != CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value
        or binding.value_stream_id is None
    ):
        raise ProcessOwnershipValidationError(
            ProcessOwnershipErrorMessage.PROCESS_OWNER_BINDING_NOT_FOUND.value
        )
    assignment = _get_user_bound_owner_assignment(
        db,
        organization_id=organization_id,
        binding=binding,
    )
    acceptances = TenantRepository(db, ProcessOwnerAcceptance, organization_id)
    acceptance = next(iter(acceptances.filter_by(scope_binding_id=binding.id)), None)
    if acceptance is None:
        return acceptances.create(
            process_id=binding.value_stream_id,
            scope_binding_id=binding.id,
            role_assignment_id=assignment.id,
            owner_user_id=assignment.user_id,
            status=ProcessOwnershipStatus.INVITATION_SENT.value,
            invited_by_user_id=invited_by_user_id,
        )
    if (
        acceptance.role_assignment_id == assignment.id
        and acceptance.status == ProcessOwnershipStatus.ACCEPTED.value
    ):
        raise ProcessOwnershipValidationError(
            ProcessOwnershipErrorMessage.OWNER_ALREADY_ACCEPTED.value
        )

    acceptances.update(
        acceptance,
        process_id=binding.value_stream_id,
        role_assignment_id=assignment.id,
        owner_user_id=assignment.user_id,
        status=ProcessOwnershipStatus.INVITATION_SENT.value,
        invited_by_user_id=invited_by_user_id,
        invited_at=utcnow(),
        accepted_at=None,
        rejected_at=None,
        rejection_reason=None,
    )
    return acceptance


def _get_pending_owner_invitation(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
    actor_user_id: int,
) -> ProcessOwnerAcceptance:
    binding = _get_process_owner_binding(
        db,
        organization_id=organization_id,
        process_id=process_id,
    )
    assignment = _get_user_bound_owner_assignment(
        db,
        organization_id=organization_id,
        binding=binding,
    )
    if assignment.user_id != actor_user_id:
        raise ProcessOwnershipValidationError(ProcessOwnershipErrorMessage.OWNER_ACTOR_MISMATCH.value)
    acceptance = next(
        iter(
            TenantRepository(db, ProcessOwnerAcceptance, organization_id).filter_by(
                scope_binding_id=binding.id,
                role_assignment_id=assignment.id,
                owner_user_id=actor_user_id,
            )
        ),
        None,
    )
    if acceptance is None:
        raise ProcessOwnershipValidationError(
            ProcessOwnershipErrorMessage.OWNER_INVITATION_NOT_FOUND.value
        )
    if acceptance.status != ProcessOwnershipStatus.INVITATION_SENT.value:
        raise ProcessOwnershipValidationError(
            ProcessOwnershipErrorMessage.OWNER_INVITATION_NOT_PENDING.value
        )
    return acceptance


def accept_process_ownership(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
    actor_user_id: int,
) -> ProcessOwnerAcceptance:
    acceptance = _get_pending_owner_invitation(
        db,
        organization_id=organization_id,
        process_id=process_id,
        actor_user_id=actor_user_id,
    )
    TenantRepository(db, ProcessOwnerAcceptance, organization_id).update(
        acceptance,
        status=ProcessOwnershipStatus.ACCEPTED.value,
        accepted_at=utcnow(),
        rejected_at=None,
        rejection_reason=None,
    )
    return acceptance


def reject_process_ownership(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
    actor_user_id: int,
    reason: ProcessOwnershipRejectionReason,
) -> ProcessOwnerAcceptance:
    acceptance = _get_pending_owner_invitation(
        db,
        organization_id=organization_id,
        process_id=process_id,
        actor_user_id=actor_user_id,
    )
    TenantRepository(db, ProcessOwnerAcceptance, organization_id).update(
        acceptance,
        status=ProcessOwnershipStatus.REJECTED.value,
        rejected_at=utcnow(),
        rejection_reason=reason.value,
    )
    return acceptance


def require_accepted_process_owner(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
    user_id: int,
) -> ProcessOwnerAcceptance:
    """Return the authoritative acceptance for the current scoped BPO binding."""
    binding = _get_process_owner_binding(
        db,
        organization_id=organization_id,
        process_id=process_id,
    )
    assignment = _get_user_bound_owner_assignment(
        db,
        organization_id=organization_id,
        binding=binding,
    )
    acceptance = _find_accepted_acceptance(
        db,
        organization_id=organization_id,
        binding=binding,
        assignment=assignment,
        user_id=user_id,
    )
    if acceptance is None:
        raise ProcessOwnershipValidationError(
            ProcessOwnershipErrorMessage.OWNER_ACCEPTANCE_REQUIRED.value
        )
    return acceptance
