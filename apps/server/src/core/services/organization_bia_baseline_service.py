"""Lifecycle operations for the organisation-wide BIA baseline."""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.model_defs.organization_bia_baseline import (
    ORGANIZATION_BIA_BASELINE_ACTIVE,
    ORGANIZATION_BIA_BASELINE_ASSUMPTION_CONFIRMED,
    ORGANIZATION_BIA_BASELINE_CONFIDENCE_HIGH,
    ORGANIZATION_BIA_BASELINE_SOURCE_LEADERSHIP,
    ORGANIZATION_BIA_BASELINE_SUPERSEDED,
    ORGANIZATION_BIA_ERROR_INCOMPLETE,
    OrganizationBiaBaseline,
)
from src.core.repository import TenantRepository
from src.core.services.bia_inheritance_service import bia_is_complete


class OrganizationBiaBaselineValidationError(ValueError):
    """Raised when the organisation BIA baseline cannot be published."""


def get_current_organization_bia_baseline(
    db: Session,
    *,
    organization_id: int,
) -> OrganizationBiaBaseline | None:
    records = TenantRepository(db, OrganizationBiaBaseline, organization_id).get_all()
    active_records = [
        record for record in records if record.status == ORGANIZATION_BIA_BASELINE_ACTIVE
    ]
    return max(active_records, key=lambda record: record.created_at, default=None)


def set_organization_bia_baseline(
    db: Session,
    *,
    organization_id: int,
    answers: dict,
    set_by_user_id: int,
) -> OrganizationBiaBaseline:
    """Append a leadership-confirmed baseline and supersede the prior version."""
    if not bia_is_complete(answers):
        raise OrganizationBiaBaselineValidationError(ORGANIZATION_BIA_ERROR_INCOMPLETE)

    repository = TenantRepository(db, OrganizationBiaBaseline, organization_id)
    predecessor = get_current_organization_bia_baseline(db, organization_id=organization_id)
    baseline = repository.create(
        status=ORGANIZATION_BIA_BASELINE_ACTIVE,
        answers=dict(answers),
        source=ORGANIZATION_BIA_BASELINE_SOURCE_LEADERSHIP,
        confidence=ORGANIZATION_BIA_BASELINE_CONFIDENCE_HIGH,
        assumption_state=ORGANIZATION_BIA_BASELINE_ASSUMPTION_CONFIRMED,
        set_by_user_id=set_by_user_id,
    )
    db.flush()
    if predecessor is not None:
        repository.update(
            predecessor,
            status=ORGANIZATION_BIA_BASELINE_SUPERSEDED,
            superseded_by_id=baseline.id,
        )
    return baseline
