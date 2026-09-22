"""Organisation-wide Business Impact Assessment baseline routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.schemas.timestamps import UtcTimestamp
from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.database import get_db
from src.core.exceptions import ValidationError
from src.core.model_defs.organization_bia_baseline import (
    ORGANIZATION_BIA_AUDIT_SET,
    ORGANIZATION_BIA_ERROR_ADMIN_REQUIRED,
    OrganizationBiaBaseline,
)
from src.core.models import AuditEvent
from src.core.services.org_admin_authorization_service import require_active_org_admin
from src.core.services.organization_bia_baseline_service import (
    OrganizationBiaBaselineValidationError,
    get_current_organization_bia_baseline,
    set_organization_bia_baseline,
)

router = APIRouter(prefix="/api/v1/organisation/bia", tags=["Organisation BIA"])


class OrganizationBiaAnswers(BaseModel):
    impact1h: str
    impact4h: str
    impact24h: str
    mtd: str
    workaround: str
    alternativeChannel: str
    dataSensitivity: str

    model_config = {"extra": "forbid"}


class OrganizationBiaBaselineWriteRequest(BaseModel):
    answers: OrganizationBiaAnswers


class OrganizationBiaBaselineResponse(BaseModel):
    baseline_id: str = Field(alias="baselineId")
    status: str
    answers: OrganizationBiaAnswers
    source: str
    confidence: str
    assumption_state: str = Field(alias="assumptionState")
    set_by_user_id: int | None = Field(alias="setByUserId")
    set_at: UtcTimestamp = Field(alias="setAt")

    model_config = {"populate_by_name": True}


class OrganizationBiaBaselineStatusResponse(BaseModel):
    baseline: OrganizationBiaBaselineResponse | None


def _baseline_response(baseline: OrganizationBiaBaseline) -> OrganizationBiaBaselineResponse:
    return OrganizationBiaBaselineResponse(
        baselineId=baseline.id,
        status=baseline.status,
        answers=OrganizationBiaAnswers(**baseline.answers),
        source=baseline.source,
        confidence=baseline.confidence,
        assumptionState=baseline.assumption_state,
        setByUserId=baseline.set_by_user_id,
        setAt=baseline.set_at,
    )


def _require_org_admin(db: Session, ctx: TenantContext) -> None:
    require_active_org_admin(
        db,
        organization_id=ctx.organization_id,
        user_id=ctx.user_id,
        error_message=ORGANIZATION_BIA_ERROR_ADMIN_REQUIRED,
    )


@router.get("", response_model=OrganizationBiaBaselineStatusResponse)
def get_organization_bia(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> OrganizationBiaBaselineStatusResponse:
    baseline = get_current_organization_bia_baseline(db, organization_id=ctx.organization_id)
    return OrganizationBiaBaselineStatusResponse(
        baseline=_baseline_response(baseline) if baseline is not None else None
    )


@router.put("", response_model=OrganizationBiaBaselineStatusResponse)
def set_organization_bia(
    payload: OrganizationBiaBaselineWriteRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> OrganizationBiaBaselineStatusResponse:
    _require_org_admin(db, ctx)
    try:
        baseline = set_organization_bia_baseline(
            db,
            organization_id=ctx.organization_id,
            answers=payload.answers.model_dump(),
            set_by_user_id=ctx.user_id,
        )
    except OrganizationBiaBaselineValidationError as exc:
        raise ValidationError(str(exc)) from exc

    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=ORGANIZATION_BIA_AUDIT_SET,
            metadata_json={"baseline_id": baseline.id, "status": baseline.status},
        )
    )
    db.commit()
    return OrganizationBiaBaselineStatusResponse(baseline=_baseline_response(baseline))
