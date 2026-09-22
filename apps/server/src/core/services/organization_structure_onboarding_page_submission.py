"""Atomic submissions for organisation-unit onboarding pages."""

from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.onboarding_page_submission_enums import (
    ONBOARDING_PAGE_SUBMISSION_DUPLICATE_DECISION,
    ONBOARDING_PAGE_SUBMISSION_UNIT_NAME_REQUIRED,
    ONBOARDING_PAGE_SUBMISSION_UNIT_NOT_FOUND,
)
from src.core.constants.organization_structure_enums import (
    ORG_STRUCTURE_AUDIT_SCOPE_CHANGED,
    ORG_STRUCTURE_AUDIT_UNIT_CONFIRMED,
    ORG_STRUCTURE_AUDIT_UNIT_CREATED,
    ORG_STRUCTURE_AUDIT_UNIT_EXCLUDED,
    ORG_STRUCTURE_AUDIT_UNIT_RESTORED,
    OrganizationUnitReviewDecision,
    OrganizationUnitScopeStatus,
    OrganizationUnitType,
)
from src.core.exceptions import ResourceNotFoundError, ValidationError
from src.core.model_defs.organization_structure import OrganizationUnit
from src.core.repository import TenantRepository
from src.core.services.audit_service import append_audit_event
from src.core.services.organization_structure_service import (
    confirm_unit,
    create_unit,
    exclude_unit,
    restore_unit,
    set_unit_scope_status,
)


@dataclass(frozen=True)
class OrganizationUnitDecisionCommand:
    unit_id: str
    decision: OrganizationUnitReviewDecision


@dataclass(frozen=True)
class OrganizationUnitAdditionCommand:
    name: str
    unit_type: OrganizationUnitType


@dataclass(frozen=True)
class OrganizationUnitScopeCommand:
    unit_id: str
    scope_status: OrganizationUnitScopeStatus


UNIT_DECISION_AUDIT_EVENTS: dict[OrganizationUnitReviewDecision, str] = {
    OrganizationUnitReviewDecision.CONFIRM: ORG_STRUCTURE_AUDIT_UNIT_CONFIRMED,
    OrganizationUnitReviewDecision.EXCLUDE: ORG_STRUCTURE_AUDIT_UNIT_EXCLUDED,
    OrganizationUnitReviewDecision.RESTORE: ORG_STRUCTURE_AUDIT_UNIT_RESTORED,
}


def submit_organization_unit_decisions(
    db: Session,
    *,
    organization_id: int,
    user_id: int,
    commands: tuple[OrganizationUnitDecisionCommand, ...],
    additions: tuple[OrganizationUnitAdditionCommand, ...],
) -> int:
    units = _resolve_units(db, organization_id, tuple(command.unit_id for command in commands))
    if any(not addition.name.strip() for addition in additions):
        raise ValidationError(ONBOARDING_PAGE_SUBMISSION_UNIT_NAME_REQUIRED)
    for unit, command in zip(units, commands, strict=True):
        if command.decision == OrganizationUnitReviewDecision.CONFIRM:
            confirm_unit(db, unit, confirmed_by_user_id=user_id)
        elif command.decision == OrganizationUnitReviewDecision.EXCLUDE:
            exclude_unit(db, unit)
        else:
            restore_unit(db, unit)
        append_audit_event(
            db,
            organization_id,
            UNIT_DECISION_AUDIT_EVENTS[command.decision],
            actor_user_id=user_id,
            metadata={"unit_id": unit.id},
        )
    for addition in additions:
        unit = create_unit(
            db,
            organization_id=organization_id,
            name=addition.name,
            unit_type=addition.unit_type,
        )
        confirm_unit(db, unit, confirmed_by_user_id=user_id)
        append_audit_event(
            db,
            organization_id,
            ORG_STRUCTURE_AUDIT_UNIT_CREATED,
            actor_user_id=user_id,
            metadata={"unit_id": unit.id},
        )
    db.flush()
    return len(commands) + len(additions)


def submit_organization_unit_scope(
    db: Session,
    *,
    organization_id: int,
    user_id: int,
    commands: tuple[OrganizationUnitScopeCommand, ...],
) -> int:
    units = _resolve_units(db, organization_id, tuple(command.unit_id for command in commands))
    for unit, command in zip(units, commands, strict=True):
        previous_status = unit.scope_status
        set_unit_scope_status(db, unit, scope_status=command.scope_status.value)
        append_audit_event(
            db,
            organization_id,
            ORG_STRUCTURE_AUDIT_SCOPE_CHANGED,
            actor_user_id=user_id,
            metadata={
                "unit_id": unit.id,
                "previous_scope_status": previous_status,
                "scope_status": command.scope_status.value,
            },
        )
    db.flush()
    return len(commands)


def _resolve_units(
    db: Session,
    organization_id: int,
    unit_ids: tuple[str, ...],
) -> list[OrganizationUnit]:
    if len(unit_ids) != len(set(unit_ids)):
        raise ValidationError(ONBOARDING_PAGE_SUBMISSION_DUPLICATE_DECISION)
    repository = TenantRepository(db, OrganizationUnit, organization_id)
    units: list[OrganizationUnit] = []
    for unit_id in unit_ids:
        unit = repository.get_by_id(unit_id)
        if unit is None:
            raise ResourceNotFoundError(ONBOARDING_PAGE_SUBMISSION_UNIT_NOT_FOUND)
        units.append(unit)
    return units
