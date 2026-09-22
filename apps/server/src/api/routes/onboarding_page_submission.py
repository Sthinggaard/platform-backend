"""Explicit, atomic submit commands for route-addressable onboarding pages."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.schemas.onboarding_page_submission import (
    OnboardingPageSubmissionResponse,
    OperatingContextPageSubmissionRequest,
    OrganizationUnitScopePageSubmissionRequest,
    OrganizationUnitsPageSubmissionRequest,
)
from src.core.constants.onboarding_page_submission_enums import (
    ONBOARDING_PAGE_SUBMISSION_ADMIN_REQUIRED,
    ONBOARDING_PAGE_SUBMISSION_PREFIX,
    OPERATING_CONTEXT_SUBMISSION_PATH,
    ORGANIZATION_UNIT_SCOPE_SUBMISSION_PATH,
    ORGANIZATION_UNITS_SUBMISSION_PATH,
)
from src.core.database import get_db
from src.core.services.operating_context_onboarding_page_submission import (
    OperatingContextDecisionCommand,
    OperatingContextPageSubmission,
    submit_operating_context_page,
)
from src.core.services.org_admin_authorization_service import require_active_org_admin
from src.core.services.organization_structure_onboarding_page_submission import (
    OrganizationUnitAdditionCommand,
    OrganizationUnitDecisionCommand,
    OrganizationUnitScopeCommand,
    submit_organization_unit_decisions,
    submit_organization_unit_scope,
)

router = APIRouter(prefix=ONBOARDING_PAGE_SUBMISSION_PREFIX, tags=["Onboarding page submission"])


@router.post(OPERATING_CONTEXT_SUBMISSION_PATH, response_model=OnboardingPageSubmissionResponse)
def submit_operating_context_page_route(
    body: OperatingContextPageSubmissionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> OnboardingPageSubmissionResponse:
    _require_admin(db, ctx)
    submitted_count = submit_operating_context_page(
        db,
        organization_id=ctx.organization_id,
        user_id=ctx.user_id,
        submission=OperatingContextPageSubmission(
            decisions=tuple(
                OperatingContextDecisionCommand(item.suggestion_id, item.status)
                for item in body.decisions
            ),
            added_characteristic_keys=tuple(body.added_characteristic_keys),
        ),
    )
    db.commit()
    return OnboardingPageSubmissionResponse(submitted_count=submitted_count)


@router.post(ORGANIZATION_UNITS_SUBMISSION_PATH, response_model=OnboardingPageSubmissionResponse)
def submit_organization_units_page_route(
    body: OrganizationUnitsPageSubmissionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> OnboardingPageSubmissionResponse:
    _require_admin(db, ctx)
    submitted_count = submit_organization_unit_decisions(
        db,
        organization_id=ctx.organization_id,
        user_id=ctx.user_id,
        commands=tuple(
            OrganizationUnitDecisionCommand(item.unit_id, item.decision) for item in body.decisions
        ),
        additions=tuple(
            OrganizationUnitAdditionCommand(item.name, item.unit_type) for item in body.additions
        ),
    )
    db.commit()
    return OnboardingPageSubmissionResponse(submitted_count=submitted_count)


@router.post(ORGANIZATION_UNIT_SCOPE_SUBMISSION_PATH, response_model=OnboardingPageSubmissionResponse)
def submit_organization_unit_scope_page_route(
    body: OrganizationUnitScopePageSubmissionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> OnboardingPageSubmissionResponse:
    _require_admin(db, ctx)
    submitted_count = submit_organization_unit_scope(
        db,
        organization_id=ctx.organization_id,
        user_id=ctx.user_id,
        commands=tuple(
            OrganizationUnitScopeCommand(item.unit_id, item.scope_status) for item in body.scope
        ),
    )
    db.commit()
    return OnboardingPageSubmissionResponse(submitted_count=submitted_count)


def _require_admin(db: Session, ctx: TenantContext) -> None:
    require_active_org_admin(
        db,
        organization_id=ctx.organization_id,
        user_id=ctx.user_id,
        error_message=ONBOARDING_PAGE_SUBMISSION_ADMIN_REQUIRED,
    )
