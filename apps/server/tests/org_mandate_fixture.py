"""Shared factories for the org mandate model.

Imported bare (`import org_mandate_fixture`), matching `discovery_boundary_fixture`
next door — `tests` is not a package here.

⚠️ **One assignment per (organisation, role, user).** The schema enforces it: a
person holds a canonical role once, and the *scope bindings* attach it to each
process or service. Owning two processes is one assignment with two bindings —
minting a second assignment raises an IntegrityError, which is how this factory
came to exist rather than being copied a third time (AGENTS.md §11.5).
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    MandateAssignmentSubjectType,
    MandateScopeType,
)
from src.core.constants.process_ownership_enums import ProcessOwnershipStatus
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.model_defs.process_ownership import ProcessOwnerAcceptance
from src.core.models import BusinessService, Organization, User, ValueStream
from src.core.roles import UserRole


def make_organisation(db: Session, organization_id: int, *, slug: str | None = None) -> Organization:
    org = Organization(
        id=organization_id, name=f"Org {organization_id}",
        slug=slug or f"org-{organization_id}", plan_tier="enterprise",
        subscription_status="active", onboarding_completed=False,
    )
    db.add(org)
    db.flush()
    return org


def make_user(db: Session, user_id: int, *, organization_id: int, role: str | None = None) -> User:
    """A person in the organisation.

    ⚠️ **A member by default, not an administrator.** This defaulted to
    `org_admin`, which meant an authorisation test could pass through the admin
    shortcut while appearing to prove that ownership granted the act. A test
    that needs an administrator now says so.
    """
    user = User(
        id=user_id, organization_id=organization_id, email=f"u{user_id}@risklence.test",
        email_verified=True, role=role or UserRole.MEMBER.value, is_active=True,
        status="active", mfa_enabled=False, mfa_enforced_by_policy=False,
    )
    db.add(user)
    db.flush()
    return user


def make_process(db: Session, process_id: str, *, organization_id: int) -> ValueStream:
    stream = ValueStream(id=process_id, organization_id=organization_id, name=process_id)
    db.add(stream)
    db.flush()
    return stream


def make_service(
    db: Session, service_id: str, *, organization_id: int, processes: list[str],
    archetype: str | None = "transactional_system",
) -> BusinessService:
    service = BusinessService(
        id=service_id, organization_id=organization_id, name=service_id,
        archetype=archetype, value_stream_ids=processes,
    )
    db.add(service)
    db.flush()
    return service


def grant_mandate(
    db: Session, *, organization_id: int, user_id: int, role: CanonicalMandateRole,
    process_id: str | None = None, service_id: str | None = None,
) -> OrgMandateScopeBinding:
    """Bind a canonical role to one scope, reusing the user's assignment.

    Both rows are required for a mandate: the assignment owns eligibility, the
    binding owns the scope. Neither alone grants anything.
    """
    assignment = (
        db.query(OrgMandateRoleAssignment)
        .filter(
            OrgMandateRoleAssignment.organization_id == organization_id,
            OrgMandateRoleAssignment.canonical_role == role.value,
            OrgMandateRoleAssignment.user_id == user_id,
        )
        .first()
    )
    if assignment is None:
        assignment = OrgMandateRoleAssignment(
            id=str(uuid.uuid4()), organization_id=organization_id,
            canonical_role=role.value,
            subject_type=MandateAssignmentSubjectType.USER.value, user_id=user_id,
        )
        db.add(assignment)
        db.flush()

    binding = OrgMandateScopeBinding(
        id=str(uuid.uuid4()), organization_id=organization_id,
        scope_type=(
            MandateScopeType.BUSINESS_PROCESS.value if process_id
            else MandateScopeType.BUSINESS_SERVICE.value
        ),
        value_stream_id=process_id, business_service_id=service_id,
        canonical_role=role.value, role_assignment_id=assignment.id,
    )
    db.add(binding)
    db.flush()
    return binding


def accept_process_ownership(
    db: Session, *, organization_id: int, user_id: int, process_id: str,
) -> ProcessOwnerAcceptance:
    """Record that the offered process owner actually took the mandate.

    ⚠️ **A scope binding is the offer, not the authority.** `require_process_editor`
    reads this record, so a binding alone leaves the candidate unable to edit —
    which is what #403 means by *"the **accepted** process owner"*. A fixture
    that grants the binding and stops is testing a person who never said yes.
    """
    binding = (
        db.query(OrgMandateScopeBinding)
        .filter(
            OrgMandateScopeBinding.organization_id == organization_id,
            OrgMandateScopeBinding.value_stream_id == process_id,
            OrgMandateScopeBinding.canonical_role
            == CanonicalMandateRole.BUSINESS_PROCESS_OWNER.value,
        )
        .one()
    )
    acceptance = ProcessOwnerAcceptance(
        id=str(uuid.uuid4()), organization_id=organization_id, process_id=process_id,
        scope_binding_id=binding.id, role_assignment_id=binding.role_assignment_id,
        owner_user_id=user_id, status=ProcessOwnershipStatus.ACCEPTED.value,
    )
    db.add(acceptance)
    db.flush()
    return acceptance
