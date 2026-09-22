"""Organisation administrator APIs for canonical mandate and visibility setup."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.schemas.org_access import (
    MandateRoleAssignmentResponse,
    MandateRoleAssignmentWriteRequest,
    MandateScopeBindingResponse,
    MandateScopeBindingWriteRequest,
    OrgAccessConfigurationResponse,
    ReportingLineExceptionResponse,
    ReportingLineExceptionWriteRequest,
    VisibilityPolicyResponse,
    VisibilityPolicyWriteRequest,
)
from src.core.constants.org_access_enums import (
    CanonicalMandateRole,
    MandateAssignmentSubjectType,
    MandateScopeType,
    OrgAccessAuditEvent,
    OrgAccessErrorMessage,
)
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.org_access import (
    OrgMandateRoleAssignment,
    OrgMandateScopeBinding,
    OrgReportingLineException,
    OrgVisibilityPolicy,
)
from src.core.models import AuditEvent, BusinessService, User, ValueStream
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES
from src.core.services.org_access_policy_service import (
    OrgAccessPolicyValidationError,
    normalize_policy_roles,
    validate_assignment_subject,
    validate_scope_role,
)

router = APIRouter(prefix="/api/v1/settings/org-access", tags=["Organisation access"])

MANDATE_SCOPE_MODEL_BY_TYPE = {
    MandateScopeType.BUSINESS_PROCESS: ValueStream,
    MandateScopeType.BUSINESS_SERVICE: BusinessService,
}
MANDATE_SCOPE_ID_FIELD_BY_TYPE = {
    MandateScopeType.BUSINESS_PROCESS: "value_stream_id",
    MandateScopeType.BUSINESS_SERVICE: "business_service_id",
}


def _require_org_admin(db: Session, ctx: TenantContext) -> None:
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or user.role not in ADMIN_ROLES:
        raise AuthorizationError(OrgAccessErrorMessage.ADMIN_REQUIRED.value)


def _assignment_response(assignment: OrgMandateRoleAssignment) -> MandateRoleAssignmentResponse:
    return MandateRoleAssignmentResponse(
        id=assignment.id,
        canonical_role=CanonicalMandateRole(assignment.canonical_role),
        subject_type=MandateAssignmentSubjectType(assignment.subject_type),
        user_id=assignment.user_id,
        identity_group_id=assignment.identity_group_id,
        identity_provider=assignment.identity_provider,
    )


def _scope_binding_response(binding: OrgMandateScopeBinding) -> MandateScopeBindingResponse:
    return MandateScopeBindingResponse(
        id=binding.id,
        scope_type=MandateScopeType(binding.scope_type),
        value_stream_id=binding.value_stream_id,
        business_service_id=binding.business_service_id,
        canonical_role=CanonicalMandateRole(binding.canonical_role),
        role_assignment_id=binding.role_assignment_id,
    )


def _resolve_mandate_scope(
    db: Session,
    *,
    ctx: TenantContext,
    scope_type: MandateScopeType,
    scope_id: str,
) -> dict[str, str]:
    model_class = MANDATE_SCOPE_MODEL_BY_TYPE[scope_type]
    target = TenantRepository(db, model_class, ctx.organization_id).get_by_id(scope_id)
    if target is None:
        raise ResourceNotFoundError(OrgAccessErrorMessage.MANDATE_SCOPE_NOT_FOUND.value)
    return {MANDATE_SCOPE_ID_FIELD_BY_TYPE[scope_type]: target.id}


def _visibility_policy_response(policy: OrgVisibilityPolicy | None) -> VisibilityPolicyResponse:
    if policy is None:
        return VisibilityPolicyResponse(overview_role_keys=[], full_detail_role_keys=[])
    return VisibilityPolicyResponse(
        overview_role_keys=[CanonicalMandateRole(role) for role in policy.overview_role_keys],
        full_detail_role_keys=[CanonicalMandateRole(role) for role in policy.full_detail_role_keys],
    )


def _reporting_line_exception_response(
    exception: OrgReportingLineException,
) -> ReportingLineExceptionResponse:
    return ReportingLineExceptionResponse(
        id=exception.id,
        employee_user_id=exception.employee_user_id,
        manager_user_id=exception.manager_user_id,
        exception_reason=exception.exception_reason,
    )


def _write_audit_event(
    db: Session,
    *,
    ctx: TenantContext,
    event_type: OrgAccessAuditEvent,
    metadata: dict,
) -> None:
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=event_type.value,
            metadata_json=metadata,
        )
    )


@router.get("", response_model=OrgAccessConfigurationResponse)
def get_org_access_configuration(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> OrgAccessConfigurationResponse:
    _require_org_admin(db, ctx)
    assignments = TenantRepository(db, OrgMandateRoleAssignment, ctx.organization_id).get_all()
    scope_bindings = TenantRepository(db, OrgMandateScopeBinding, ctx.organization_id).get_all()
    policies = TenantRepository(db, OrgVisibilityPolicy, ctx.organization_id).get_all()
    return OrgAccessConfigurationResponse(
        role_assignments=[_assignment_response(assignment) for assignment in assignments],
        scope_bindings=[_scope_binding_response(binding) for binding in scope_bindings],
        visibility_policy=_visibility_policy_response(policies[0] if policies else None),
    )


@router.post("/role-assignments", response_model=MandateRoleAssignmentResponse)
def create_role_assignment(
    body: MandateRoleAssignmentWriteRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> MandateRoleAssignmentResponse:
    _require_org_admin(db, ctx)
    try:
        validate_assignment_subject(
            subject_type=body.subject_type,
            user_id=body.user_id,
            identity_group_id=body.identity_group_id,
            identity_provider=body.identity_provider,
        )
    except OrgAccessPolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc

    if (
        body.user_id is not None
        and TenantRepository(db, User, ctx.organization_id).get_by_id(body.user_id) is None
    ):
        raise ResourceNotFoundError(OrgAccessErrorMessage.USER_NOT_FOUND.value)

    assignments = TenantRepository(db, OrgMandateRoleAssignment, ctx.organization_id)
    duplicate = assignments.filter_by(
        canonical_role=body.canonical_role.value,
        subject_type=body.subject_type.value,
        user_id=body.user_id,
        identity_group_id=body.identity_group_id,
        identity_provider=body.identity_provider.value if body.identity_provider else None,
    )
    if duplicate:
        raise ValidationError(OrgAccessErrorMessage.DUPLICATE_ROLE_ASSIGNMENT.value)

    assignment = assignments.create(
        canonical_role=body.canonical_role.value,
        subject_type=body.subject_type.value,
        user_id=body.user_id,
        identity_group_id=body.identity_group_id,
        identity_provider=body.identity_provider.value if body.identity_provider else None,
        created_by_user_id=ctx.user_id,
    )
    # Generate the stable assignment ID before the audit record references it.
    db.flush()
    _write_audit_event(
        db,
        ctx=ctx,
        event_type=OrgAccessAuditEvent.MANDATE_ROLE_ASSIGNED,
        metadata={"assignment_id": assignment.id, "canonical_role": assignment.canonical_role},
    )
    db.commit()
    db.refresh(assignment)
    return _assignment_response(assignment)


@router.delete(
    "/role-assignments/{assignment_id}",
    status_code=204,
    response_class=Response,
    response_model=None,
)
def delete_role_assignment(
    assignment_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> None:
    _require_org_admin(db, ctx)
    assignments = TenantRepository(db, OrgMandateRoleAssignment, ctx.organization_id)
    assignment = assignments.get_by_id(assignment_id)
    if assignment is None:
        raise ResourceNotFoundError(OrgAccessErrorMessage.ROLE_ASSIGNMENT_NOT_FOUND.value)
    bindings = TenantRepository(db, OrgMandateScopeBinding, ctx.organization_id)
    if bindings.filter_by(role_assignment_id=assignment.id):
        raise ValidationError(OrgAccessErrorMessage.ROLE_ASSIGNMENT_HAS_SCOPE_BINDINGS.value)
    _write_audit_event(
        db,
        ctx=ctx,
        event_type=OrgAccessAuditEvent.MANDATE_ROLE_UNASSIGNED,
        metadata={"assignment_id": assignment.id, "canonical_role": assignment.canonical_role},
    )
    assignments.delete(assignment)
    db.commit()


@router.put("/scope-bindings", response_model=MandateScopeBindingResponse)
def upsert_scope_binding(
    body: MandateScopeBindingWriteRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> MandateScopeBindingResponse:
    """Bind an eligible canonical role to the selected tenant-owned scope."""
    _require_org_admin(db, ctx)
    try:
        validate_scope_role(
            scope_type=body.scope_type,
            canonical_role=body.canonical_role,
        )
    except OrgAccessPolicyValidationError as exc:
        raise ValidationError(str(exc)) from exc

    assignments = TenantRepository(db, OrgMandateRoleAssignment, ctx.organization_id)
    assignment = assignments.get_by_id(body.role_assignment_id)
    if assignment is None:
        raise ResourceNotFoundError(OrgAccessErrorMessage.ROLE_ASSIGNMENT_NOT_FOUND.value)
    if assignment.canonical_role != body.canonical_role.value:
        raise ValidationError(OrgAccessErrorMessage.MANDATE_ASSIGNMENT_ROLE_MISMATCH.value)

    scope_filter = _resolve_mandate_scope(
        db,
        ctx=ctx,
        scope_type=body.scope_type,
        scope_id=body.scope_id,
    )
    bindings = TenantRepository(db, OrgMandateScopeBinding, ctx.organization_id)
    existing = bindings.filter_by(
        scope_type=body.scope_type.value,
        canonical_role=body.canonical_role.value,
        **scope_filter,
    )
    previous_role_assignment_id = existing[0].role_assignment_id if existing else None
    binding = existing[0] if existing else bindings.create(
        scope_type=body.scope_type.value,
        canonical_role=body.canonical_role.value,
        role_assignment_id=assignment.id,
        created_by_user_id=ctx.user_id,
        **scope_filter,
    )
    if existing:
        bindings.update(binding, role_assignment_id=assignment.id)

    db.flush()
    _write_audit_event(
        db,
        ctx=ctx,
        event_type=OrgAccessAuditEvent.MANDATE_SCOPE_BOUND,
        metadata={
            "scope_binding_id": binding.id,
            "scope_type": binding.scope_type,
            "canonical_role": binding.canonical_role,
            "role_assignment_id": binding.role_assignment_id,
            "previous_role_assignment_id": previous_role_assignment_id,
            **scope_filter,
        },
    )
    db.commit()
    db.refresh(binding)
    return _scope_binding_response(binding)


@router.delete(
    "/scope-bindings/{binding_id}",
    status_code=204,
    response_class=Response,
    response_model=None,
)
def delete_scope_binding(
    binding_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> None:
    _require_org_admin(db, ctx)
    bindings = TenantRepository(db, OrgMandateScopeBinding, ctx.organization_id)
    binding = bindings.get_by_id(binding_id)
    if binding is None:
        raise ResourceNotFoundError(OrgAccessErrorMessage.MANDATE_SCOPE_BINDING_NOT_FOUND.value)
    _write_audit_event(
        db,
        ctx=ctx,
        event_type=OrgAccessAuditEvent.MANDATE_SCOPE_UNBOUND,
        metadata={
            "scope_binding_id": binding.id,
            "scope_type": binding.scope_type,
            "canonical_role": binding.canonical_role,
            "role_assignment_id": binding.role_assignment_id,
            "value_stream_id": binding.value_stream_id,
            "business_service_id": binding.business_service_id,
        },
    )
    bindings.delete(binding)
    db.commit()


@router.get(
    "/reporting-line-exceptions",
    response_model=list[ReportingLineExceptionResponse],
)
def get_reporting_line_exceptions(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[ReportingLineExceptionResponse]:
    _require_org_admin(db, ctx)
    exceptions = TenantRepository(db, OrgReportingLineException, ctx.organization_id).get_all()
    return [_reporting_line_exception_response(exception) for exception in exceptions]


@router.put(
    "/reporting-line-exceptions/{employee_user_id}",
    response_model=ReportingLineExceptionResponse,
)
def set_reporting_line_exception(
    employee_user_id: int,
    body: ReportingLineExceptionWriteRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ReportingLineExceptionResponse:
    _require_org_admin(db, ctx)
    if employee_user_id == body.manager_user_id:
        raise ValidationError(OrgAccessErrorMessage.INVALID_REPORTING_LINE_EXCEPTION.value)

    users = TenantRepository(db, User, ctx.organization_id)
    if users.get_by_id(employee_user_id) is None or users.get_by_id(body.manager_user_id) is None:
        raise ResourceNotFoundError(OrgAccessErrorMessage.USER_NOT_FOUND.value)

    exceptions = TenantRepository(db, OrgReportingLineException, ctx.organization_id)
    existing = exceptions.filter_by(employee_user_id=employee_user_id)
    exception = existing[0] if existing else exceptions.create(
        employee_user_id=employee_user_id,
        manager_user_id=body.manager_user_id,
        exception_reason=body.exception_reason,
        created_by_user_id=ctx.user_id,
    )
    if existing:
        exceptions.update(
            exception,
            manager_user_id=body.manager_user_id,
            exception_reason=body.exception_reason,
        )
    db.flush()
    _write_audit_event(
        db,
        ctx=ctx,
        event_type=OrgAccessAuditEvent.REPORTING_LINE_EXCEPTION_SET,
        metadata={
            "reporting_line_exception_id": exception.id,
            "employee_user_id": employee_user_id,
            "manager_user_id": body.manager_user_id,
            "source": "manual_exception",
        },
    )
    db.commit()
    db.refresh(exception)
    return _reporting_line_exception_response(exception)


@router.delete(
    "/reporting-line-exceptions/{employee_user_id}",
    status_code=204,
    response_class=Response,
    response_model=None,
)
def delete_reporting_line_exception(
    employee_user_id: int,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> None:
    _require_org_admin(db, ctx)
    exceptions = TenantRepository(db, OrgReportingLineException, ctx.organization_id)
    matching = exceptions.filter_by(employee_user_id=employee_user_id)
    if not matching:
        raise ResourceNotFoundError(OrgAccessErrorMessage.REPORTING_LINE_EXCEPTION_NOT_FOUND.value)
    exception = matching[0]
    _write_audit_event(
        db,
        ctx=ctx,
        event_type=OrgAccessAuditEvent.REPORTING_LINE_EXCEPTION_CLEARED,
        metadata={
            "reporting_line_exception_id": exception.id,
            "employee_user_id": exception.employee_user_id,
            "manager_user_id": exception.manager_user_id,
            "source": "manual_exception",
        },
    )
    exceptions.delete(exception)
    db.commit()


@router.put("/visibility-policy", response_model=VisibilityPolicyResponse)
def update_visibility_policy(
    body: VisibilityPolicyWriteRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> VisibilityPolicyResponse:
    _require_org_admin(db, ctx)
    policies = TenantRepository(db, OrgVisibilityPolicy, ctx.organization_id)
    policy_rows = policies.get_all()
    overview_role_keys = normalize_policy_roles(body.overview_role_keys)
    full_detail_role_keys = normalize_policy_roles(body.full_detail_role_keys)
    policy = policy_rows[0] if policy_rows else policies.create(created_by_user_id=ctx.user_id)
    policies.update(
        policy,
        overview_role_keys=overview_role_keys,
        full_detail_role_keys=full_detail_role_keys,
    )
    _write_audit_event(
        db,
        ctx=ctx,
        event_type=OrgAccessAuditEvent.VISIBILITY_POLICY_UPDATED,
        metadata={
            "overview_role_keys": overview_role_keys,
            "full_detail_role_keys": full_detail_role_keys,
        },
    )
    db.commit()
    db.refresh(policy)
    return _visibility_policy_response(policy)
