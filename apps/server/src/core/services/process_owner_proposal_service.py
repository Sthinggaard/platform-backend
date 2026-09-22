"""Read-only accountable-owner proposal for prepared Business Processes."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    MandateAssignmentSubjectType,
    MandateScopeType,
)
from src.core.constants.process_ownership_enums import (
    ProcessOwnerProposalSource,
    ProcessOwnerProposalStatus,
    ProcessOwnershipStatus,
)
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.model_defs.process_ownership import ProcessOwnerAcceptance
from src.core.model_defs.tenant_identity import User
from src.core.model_defs.value_streams import BusinessService
from src.core.repository import TenantRepository
from src.core.services.user_display_service import user_display_name


@dataclass(frozen=True)
class ProcessOwnerProposalCandidate:
    user_id: int
    name: str
    email: str
    title: str | None
    source: ProcessOwnerProposalSource


@dataclass(frozen=True)
class ProcessOwnerProposal:
    status: ProcessOwnerProposalStatus
    recommended_user_id: int | None
    current_owner_user_id: int | None
    acceptance_status: ProcessOwnershipStatus | None
    candidates: list[ProcessOwnerProposalCandidate]


def propose_process_owner(
    db: Session,
    *,
    organization_id: int,
    process_id: str,
) -> ProcessOwnerProposal:
    """Return a ranked recommendation without mutating mandates."""
    bindings = TenantRepository(db, OrgMandateScopeBinding, organization_id)
    assignments = TenantRepository(db, OrgMandateRoleAssignment, organization_id)
    users = TenantRepository(db, User, organization_id)
    services = TenantRepository(db, BusinessService, organization_id).get_all()
    candidates: list[ProcessOwnerProposalCandidate] = []
    seen_user_ids: set[int] = set()
    current_owner_user_id: int | None = None
    acceptance_status: ProcessOwnershipStatus | None = None

    process_binding = next(
        iter(
            bindings.filter_by(
                scope_type=MandateScopeType.BUSINESS_PROCESS.value,
                value_stream_id=process_id,
                canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
            )
        ),
        None,
    )
    if process_binding is not None:
        assignment = assignments.get_by_id(process_binding.role_assignment_id)
        owner = users.get_by_id(assignment.user_id) if assignment and assignment.user_id else None
        if owner is not None and owner.is_active:
            current_owner_user_id = owner.id
            candidates.append(
                ProcessOwnerProposalCandidate(
                    user_id=owner.id,
                    name=user_display_name(owner),
                    email=owner.email,
                    title=owner.title,
                    source=ProcessOwnerProposalSource.EXISTING_PROCESS_BINDING,
                )
            )
            seen_user_ids.add(owner.id)
        acceptance = next(
            iter(
                TenantRepository(db, ProcessOwnerAcceptance, organization_id).filter_by(
                    scope_binding_id=process_binding.id,
                )
            ),
            None,
        )
        if acceptance is not None:
            acceptance_status = ProcessOwnershipStatus(acceptance.status)

    service_owner_ids = {
        service.owner_user_id
        for service in services
        if service.archived_at is None
        and process_id in (service.value_stream_ids or [])
        and service.owner_user_id is not None
    }
    for owner_id in sorted(service_owner_ids):
        owner = users.get_by_id(owner_id)
        if owner is None or not owner.is_active or owner.id in seen_user_ids:
            continue
        candidates.append(
            ProcessOwnerProposalCandidate(
                user_id=owner.id,
                name=user_display_name(owner),
                email=owner.email,
                title=owner.title,
                source=ProcessOwnerProposalSource.SERVICE_OWNER,
            )
        )
        seen_user_ids.add(owner.id)

    eligible_assignments = assignments.filter_by(
        canonical_role=CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        subject_type=MandateAssignmentSubjectType.USER.value,
    )
    for assignment in eligible_assignments:
        if assignment.user_id is None:
            continue
        owner = users.get_by_id(assignment.user_id)
        if owner is None or not owner.is_active or owner.id in seen_user_ids:
            continue
        candidates.append(
            ProcessOwnerProposalCandidate(
                user_id=owner.id,
                name=user_display_name(owner),
                email=owner.email,
                title=owner.title,
                source=ProcessOwnerProposalSource.ORG_BPO_MANDATE,
            )
        )
        seen_user_ids.add(owner.id)

    status = (
        ProcessOwnerProposalStatus.ASSIGNED
        if current_owner_user_id is not None
        else ProcessOwnerProposalStatus.CANDIDATES_AVAILABLE
        if candidates
        else ProcessOwnerProposalStatus.NEEDS_ADMIN_ASSIGNMENT
    )
    return ProcessOwnerProposal(
        status=status,
        recommended_user_id=candidates[0].user_id if candidates else None,
        current_owner_user_id=current_owner_user_id,
        acceptance_status=acceptance_status,
        candidates=candidates,
    )
