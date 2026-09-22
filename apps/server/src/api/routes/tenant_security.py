"""Tenant security policy endpoints."""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import get_tenant_context
from src.api.schemas.tenant_security import MfaPolicyOut, MfaPolicyUpdate
from src.core.database import get_db
from src.core.exceptions import AuthorizationError
from src.core.services.auth_service import get_auth_settings
from src.core.services.audit_service import log_audit_event

router = APIRouter(prefix="/api/v1/tenant/security", tags=["TenantSecurity"])


@router.get("/mfa", response_model=MfaPolicyOut)
def get_mfa_policy(request: Request, db: Session = Depends(get_db)) -> MfaPolicyOut:
    tenant = get_tenant_context(request)
    if not tenant.is_admin():
        raise AuthorizationError("Admin role required")
    settings = get_auth_settings(db, tenant.organization_id)
    return MfaPolicyOut(
        mfa_sms_enabled=settings.mfa_sms_enabled,
        mfa_required_for_all=settings.mfa_required_for_all,
        mfa_required_for_admins=settings.mfa_required_for_admins,
    )


@router.patch("/mfa", response_model=MfaPolicyOut)
def update_mfa_policy(
    payload: MfaPolicyUpdate,
    request: Request,
    db: Session = Depends(get_db),
) -> MfaPolicyOut:
    tenant = get_tenant_context(request)
    if not tenant.is_admin():
        raise AuthorizationError("Admin role required")
    settings = get_auth_settings(db, tenant.organization_id)

    if payload.mfa_sms_enabled is not None:
        settings.mfa_sms_enabled = payload.mfa_sms_enabled
    if payload.mfa_required_for_all is not None:
        settings.mfa_required_for_all = payload.mfa_required_for_all
    if payload.mfa_required_for_admins is not None:
        settings.mfa_required_for_admins = payload.mfa_required_for_admins

    db.add(settings)
    db.commit()

    log_audit_event(
        db,
        organization_id=tenant.organization_id,
        event_type="MFA_POLICY_UPDATED",
        actor_user_id=tenant.user_id,
        metadata={
            "mfa_sms_enabled": settings.mfa_sms_enabled,
            "mfa_required_for_all": settings.mfa_required_for_all,
            "mfa_required_for_admins": settings.mfa_required_for_admins,
        },
    )

    return MfaPolicyOut(
        mfa_sms_enabled=settings.mfa_sms_enabled,
        mfa_required_for_all=settings.mfa_required_for_all,
        mfa_required_for_admins=settings.mfa_required_for_admins,
    )
