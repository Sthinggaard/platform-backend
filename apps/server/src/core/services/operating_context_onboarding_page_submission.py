"""Atomic submission of one operating-context onboarding page."""

from dataclasses import dataclass

from sqlalchemy.orm import Session

from src.core.constants.onboarding_page_submission_enums import (
    ONBOARDING_PAGE_SUBMISSION_DUPLICATE_DECISION,
    ONBOARDING_PAGE_SUBMISSION_OPERATING_CONTEXT_NOT_FOUND,
    ONBOARDING_PAGE_SUBMISSION_OPERATING_CONTEXT_STALE,
)
from src.core.constants.organization_identity_enums import (
    OPERATING_CONTEXT_AUDIT_EVENTS,
    ORG_IDENTITY_ERROR_OPERATING_CONTEXT_DECISION_REQUIRED,
    ORG_IDENTITY_ERROR_OPERATING_CONTEXT_SELECTION_INVALID,
    OrganizationOperatingContextSuggestionType,
    SuggestionDecision,
)
from src.core.exceptions import ResourceNotFoundError, ValidationError
from src.core.model_defs.organization_identity import OrganizationOperatingContextSuggestion
from src.core.repository import TenantRepository
from src.core.services.audit_service import append_audit_event
from src.core.services.organization_operating_context_service import (
    OPERATING_CONTEXT_CATALOG,
    add_operating_context_suggestion,
    decide_operating_context_suggestion,
)


@dataclass(frozen=True)
class OperatingContextDecisionCommand:
    suggestion_id: str
    status: SuggestionDecision


@dataclass(frozen=True)
class OperatingContextPageSubmission:
    decisions: tuple[OperatingContextDecisionCommand, ...]
    added_characteristic_keys: tuple[str, ...]


def submit_operating_context_page(
    db: Session,
    *,
    organization_id: int,
    user_id: int,
    submission: OperatingContextPageSubmission,
) -> int:
    decision_ids = [decision.suggestion_id for decision in submission.decisions]
    if len(decision_ids) != len(set(decision_ids)):
        raise ValidationError(ONBOARDING_PAGE_SUBMISSION_DUPLICATE_DECISION)
    if len(submission.added_characteristic_keys) != len(set(submission.added_characteristic_keys)):
        raise ValidationError(ONBOARDING_PAGE_SUBMISSION_DUPLICATE_DECISION)

    characteristic_catalog = OPERATING_CONTEXT_CATALOG[
        OrganizationOperatingContextSuggestionType.OPERATING_CHARACTERISTIC
    ]
    if any(key not in characteristic_catalog for key in submission.added_characteristic_keys):
        raise ValidationError(ORG_IDENTITY_ERROR_OPERATING_CONTEXT_SELECTION_INVALID)

    repository = TenantRepository(db, OrganizationOperatingContextSuggestion, organization_id)
    suggestions: list[OrganizationOperatingContextSuggestion] = []
    for decision in submission.decisions:
        if decision.status == SuggestionDecision.SUGGESTED:
            raise ValidationError(ORG_IDENTITY_ERROR_OPERATING_CONTEXT_DECISION_REQUIRED)
        suggestion = repository.get_by_id(decision.suggestion_id)
        if suggestion is None:
            raise ResourceNotFoundError(ONBOARDING_PAGE_SUBMISSION_OPERATING_CONTEXT_NOT_FOUND)
        if suggestion.superseded_by_id is not None:
            raise ValidationError(ONBOARDING_PAGE_SUBMISSION_OPERATING_CONTEXT_STALE)
        suggestions.append(suggestion)

    submitted_count = 0
    for suggestion, command in zip(suggestions, submission.decisions, strict=True):
        decision = decide_operating_context_suggestion(
            db,
            suggestion,
            status=command.status,
            decided_by_user_id=user_id,
        )
        _append_operating_context_audit(db, organization_id, user_id, decision)
        submitted_count += 1

    for suggestion_key in submission.added_characteristic_keys:
        suggestion = add_operating_context_suggestion(
            db,
            organization_id=organization_id,
            suggestion_type=OrganizationOperatingContextSuggestionType.OPERATING_CHARACTERISTIC,
            suggestion_key=suggestion_key,
        )
        decision = decide_operating_context_suggestion(
            db,
            suggestion,
            status=SuggestionDecision.CONFIRMED,
            decided_by_user_id=user_id,
        )
        _append_operating_context_audit(db, organization_id, user_id, decision)
        submitted_count += 1

    db.flush()
    return submitted_count


def _append_operating_context_audit(
    db: Session,
    organization_id: int,
    user_id: int,
    decision: OrganizationOperatingContextSuggestion,
) -> None:
    event_type = OPERATING_CONTEXT_AUDIT_EVENTS[
        (
            OrganizationOperatingContextSuggestionType(decision.suggestion_type),
            SuggestionDecision(decision.status),
        )
    ]
    append_audit_event(
        db,
        organization_id,
        event_type,
        actor_user_id=user_id,
        metadata={
            "suggestion_id": decision.id,
            "suggestion_key": decision.suggestion_key,
            "source_type": decision.source_type,
        },
    )
