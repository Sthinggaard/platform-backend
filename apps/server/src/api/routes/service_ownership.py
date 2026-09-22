"""Delegating accountability for one Business Service.

Søren's ruling, 2026-09-04:

    "If a service has no owner but has a process owner, that process owner owns
    the service. If the service is maintained in the process, the process owner
    is the owner and is always the owner. The process owner may choose to
    delegate ownership of the service to a team member, but the process owner
    will always be accountable for the process and therefore the service."

So this route **delegates**, it does not assign an owner to something ownerless.
A service always resolves to someone (``service_accountability_service``); naming
a delegate changes who answers day to day, and changes nothing about who remains
accountable.

⚠️ **Two rows, one act.** A mandate is an eligibility assignment *plus* a scope
binding, and neither alone grants anything. Delegating to somebody who holds no
``BUSINESS_SERVICE_OWNER`` assignment yet needs both — which through the generic
``PUT /org-access/scope-bindings`` would be two calls, both restricted to an
Organisation Administrator. #403's decision is *"the accepted process owner **or**
an Organisation Administrator"*, so the act lives here, authorised once.

⚠️ **Removing a delegate is not removing an owner.** Clearing it drops the
binding and the service resolves back through its process — which is why the
control offers "Unassigned" rather than "None".
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    MandateAssignmentSubjectType,
    MandateScopeType,
)
from src.core.database import get_db
from src.core.exceptions import ResourceNotFoundError, ValidationError
from src.core.model_defs.org_access import OrgMandateRoleAssignment, OrgMandateScopeBinding
from src.core.models import BusinessService, User
from src.core.repository import TenantRepository
from src.core.services.service_accountability_service import (
    ServiceAccountabilitySource,
    resolve_service_accountability,
)

from .bundle_common import require_service_process_editor

router = APIRouter(prefix="/api/v1/service-ownership", tags=["Service ownership"])


class DelegateServiceOwnerRequest(BaseModel):
    #: ``None`` clears the delegation and lets the service resolve through its
    #: process again. Not "no owner" — there is no such state.
    user_id: int | None = None


class ServiceOwnerResponse(BaseModel):
    service_id: str
    holder_user_id: int | None
    holder_name: str | None
    holder_title: str | None
    #: ``delegated`` | ``process_owner`` | ``unresolved`` — how it resolved after
    #: the change, so the caller never has to infer it.
    source: str


def _accountability_response(db: Session, *, organization_id: int, service: BusinessService) -> ServiceOwnerResponse:
    resolved = resolve_service_accountability(
        db, organization_id=organization_id, services=[service]
    ).get(service.id)
    holder = (
        db.get(User, resolved.holder_user_id)
        if resolved is not None and resolved.holder_user_id is not None
        else None
    )
    return ServiceOwnerResponse(
        service_id=service.id,
        holder_user_id=holder.id if holder else None,
        holder_name=(f"{holder.first_name or ''} {holder.last_name or ''}".strip() or holder.email) if holder else None,
        holder_title=holder.title if holder else None,
        source=(
            ServiceAccountabilitySource.UNRESOLVED.value
            if resolved is None or resolved.holder_user_id is None
            else resolved.source.value
        ),
    )


@router.put(
    "/services/{service_id}/owner",
    response_model=ServiceOwnerResponse,
    status_code=status.HTTP_200_OK,
    summary="Delegate accountability for a service, or clear the delegation",
)
def delegate_service_owner(
    service_id: str,
    body: DelegateServiceOwnerRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ServiceOwnerResponse:
    service = TenantRepository(db, BusinessService, ctx.organization_id).get_by_id(service_id)
    if service is None:
        raise ResourceNotFoundError("Business Service not found in this organisation")

    # The accepted process owner of a linked process, or an organisation
    # administrator (#403). A viewer of an unrelated process is refused, and a
    # service linked to no process fails closed.
    require_service_process_editor(
        service,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        db=db,
    )

    bindings = db.query(OrgMandateScopeBinding).filter(
        OrgMandateScopeBinding.organization_id == ctx.organization_id,
        OrgMandateScopeBinding.business_service_id == service.id,
        OrgMandateScopeBinding.canonical_role == CanonicalMandateRole.BUSINESS_SERVICE_OWNER.value,
    )

    if body.user_id is None:
        for binding in bindings.all():
            db.delete(binding)
        db.commit()
        db.refresh(service)
        return _accountability_response(db, organization_id=ctx.organization_id, service=service)

    delegate = TenantRepository(db, User, ctx.organization_id).get_by_id(body.user_id)
    if delegate is None or not delegate.is_active:
        raise ValidationError("That person is not an active member of this organisation.")

    # One assignment per (organisation, role, user) — the schema enforces it, so
    # the person's existing eligibility is reused and only the scope is bound.
    assignment = (
        db.query(OrgMandateRoleAssignment)
        .filter(
            OrgMandateRoleAssignment.organization_id == ctx.organization_id,
            OrgMandateRoleAssignment.canonical_role == CanonicalMandateRole.BUSINESS_SERVICE_OWNER.value,
            OrgMandateRoleAssignment.user_id == delegate.id,
        )
        .first()
    )
    if assignment is None:
        assignment = OrgMandateRoleAssignment(
            id=str(uuid.uuid4()),
            organization_id=ctx.organization_id,
            canonical_role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER.value,
            subject_type=MandateAssignmentSubjectType.USER.value,
            user_id=delegate.id,
        )
        db.add(assignment)
        db.flush()

    # One holder per service, so an existing delegation is replaced rather than
    # joined — the schema's unique index says the same thing.
    existing = bindings.first()
    if existing is not None:
        existing.role_assignment_id = assignment.id
        db.add(existing)
    else:
        db.add(OrgMandateScopeBinding(
            id=str(uuid.uuid4()),
            organization_id=ctx.organization_id,
            scope_type=MandateScopeType.BUSINESS_SERVICE.value,
            business_service_id=service.id,
            canonical_role=CanonicalMandateRole.BUSINESS_SERVICE_OWNER.value,
            role_assignment_id=assignment.id,
        ))

    db.commit()
    db.refresh(service)
    return _accountability_response(db, organization_id=ctx.organization_id, service=service)
