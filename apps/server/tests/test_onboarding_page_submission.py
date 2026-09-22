"""Transactional onboarding page submission routes."""

import pytest
from sqlalchemy import ARRAY, create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from src.api.middleware.tenant_context import TenantContext
from src.api.routes.onboarding_page_submission import (
    submit_operating_context_page_route,
    submit_organization_unit_scope_page_route,
    submit_organization_units_page_route,
)
from src.api.schemas.onboarding_page_submission import (
    OperatingContextDecisionRequest,
    OperatingContextPageSubmissionRequest,
    OrganizationUnitAdditionRequest,
    OrganizationUnitDecisionRequest,
    OrganizationUnitScopePageSubmissionRequest,
    OrganizationUnitScopeRequest,
    OrganizationUnitsPageSubmissionRequest,
)
from src.core.constants.organization_identity_enums import (
    OrganizationOperatingContextSource,
    OrganizationOperatingContextSuggestionType,
    SuggestionDecision,
)
from src.core.constants.organization_structure_enums import (
    ORG_STRUCTURE_AUDIT_SCOPE_CHANGED,
    OrganizationUnitReviewDecision,
    OrganizationUnitScopeStatus,
    OrganizationUnitSource,
    OrganizationUnitStatus,
    OrganizationUnitType,
)
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ResourceNotFoundError
from src.core.model_defs.organization_identity import OrganizationOperatingContextSuggestion
from src.core.model_defs.organization_structure import OrganizationUnit
from src.core.models import AuditEvent, Organization, User


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, JSONB):
                column.type = SqliteJSON()
            if isinstance(column.type, ARRAY):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            User.__table__,
            OrganizationOperatingContextSuggestion.__table__,
            OrganizationUnit.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org", country="DK"),
            Organization(id=2, name="Other", slug="other", country="DK"),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
            User(id=2, organization_id=1, email="member@example.com", role="member"),
            User(id=3, organization_id=2, email="other@example.com", role="org_admin"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _context(*, user_id: int = 1, organization_id: int = 1) -> TenantContext:
    return TenantContext(
        user_id=user_id,
        organization_id=organization_id,
        email="user@example.com",
        roles=["org_admin"],
        permissions=[],
    )


def _suggestion(db: Session, *, organization_id: int = 1, key: str) -> OrganizationOperatingContextSuggestion:
    suggestion = OrganizationOperatingContextSuggestion(
        organization_id=organization_id,
        suggestion_type=OrganizationOperatingContextSuggestionType.OPERATING_CHARACTERISTIC.value,
        suggestion_key=key,
        source_type=OrganizationOperatingContextSource.NACE_INFERENCE.value,
        status=SuggestionDecision.SUGGESTED.value,
    )
    db.add(suggestion)
    db.commit()
    return suggestion


def _unit(db: Session, *, organization_id: int = 1, name: str) -> OrganizationUnit:
    unit = OrganizationUnit(
        organization_id=organization_id,
        name=name,
        unit_type=OrganizationUnitType.BUSINESS_UNIT.value,
        status=OrganizationUnitStatus.SUGGESTED.value,
        scope_status=OrganizationUnitScopeStatus.UNRESOLVED.value,
        source=OrganizationUnitSource.RISKLENCE_SUGGESTION.value,
    )
    db.add(unit)
    db.commit()
    return unit


def test_operating_context_page_commits_all_decisions_once(db: Session) -> None:
    first = _suggestion(db, key="cloud_based_delivery")
    second = _suggestion(db, key="regulated_data_handling")

    response = submit_operating_context_page_route(
        OperatingContextPageSubmissionRequest(
            decisions=[
                OperatingContextDecisionRequest(
                    suggestion_id=first.id, status=SuggestionDecision.CONFIRMED
                ),
                OperatingContextDecisionRequest(
                    suggestion_id=second.id, status=SuggestionDecision.REJECTED
                ),
            ],
        ),
        _context(),
        db,
    )

    assert response.submitted_count == 2
    current = (
        db.query(OrganizationOperatingContextSuggestion)
        .filter(
            OrganizationOperatingContextSuggestion.organization_id == 1,
            OrganizationOperatingContextSuggestion.superseded_by_id.is_(None),
        )
        .all()
    )
    assert {item.status for item in current} == {
        SuggestionDecision.CONFIRMED.value,
        SuggestionDecision.REJECTED.value,
    }
    assert db.query(AuditEvent).filter(AuditEvent.organization_id == 1).count() == 2


def test_operating_context_page_fails_closed_for_another_tenant(db: Session) -> None:
    local = _suggestion(db, key="cloud_based_delivery")
    foreign = _suggestion(db, organization_id=2, key="regulated_data_handling")

    with pytest.raises(ResourceNotFoundError):
        submit_operating_context_page_route(
            OperatingContextPageSubmissionRequest(
                decisions=[
                    OperatingContextDecisionRequest(
                        suggestion_id=local.id, status=SuggestionDecision.CONFIRMED
                    ),
                    OperatingContextDecisionRequest(
                        suggestion_id=foreign.id, status=SuggestionDecision.REJECTED
                    ),
                ]
            ),
            _context(),
            db,
        )

    db.rollback()
    assert db.get(OrganizationOperatingContextSuggestion, local.id).status == SuggestionDecision.SUGGESTED.value
    assert db.query(AuditEvent).count() == 0


def test_unit_review_and_scope_pages_submit_as_batches(db: Session) -> None:
    first = _unit(db, name="Sales")
    second = _unit(db, name="Operations")

    review_response = submit_organization_units_page_route(
        OrganizationUnitsPageSubmissionRequest(
            decisions=[
                OrganizationUnitDecisionRequest(
                    unit_id=first.id, decision=OrganizationUnitReviewDecision.CONFIRM
                ),
                OrganizationUnitDecisionRequest(
                    unit_id=second.id, decision=OrganizationUnitReviewDecision.EXCLUDE
                ),
            ],
            additions=[
                OrganizationUnitAdditionRequest(
                    name="Customer Success",
                    unit_type=OrganizationUnitType.DEPARTMENT,
                )
            ],
        ),
        _context(),
        db,
    )
    assert review_response.submitted_count == 3
    assert db.get(OrganizationUnit, first.id).status == OrganizationUnitStatus.CONFIRMED.value
    assert db.get(OrganizationUnit, second.id).status == OrganizationUnitStatus.EXCLUDED.value
    added = db.query(OrganizationUnit).filter(OrganizationUnit.name == "Customer Success").one()
    assert added.status == OrganizationUnitStatus.CONFIRMED.value

    scope_response = submit_organization_unit_scope_page_route(
        OrganizationUnitScopePageSubmissionRequest(
            scope=[
                OrganizationUnitScopeRequest(
                    unit_id=first.id, scope_status=OrganizationUnitScopeStatus.IN_SCOPE
                )
            ]
        ),
        _context(),
        db,
    )
    assert scope_response.submitted_count == 1
    assert db.get(OrganizationUnit, first.id).scope_status == OrganizationUnitScopeStatus.IN_SCOPE.value
    assert (
        db.query(AuditEvent)
        .filter(AuditEvent.event_type == ORG_STRUCTURE_AUDIT_SCOPE_CHANGED)
        .count()
        == 1
    )


def test_page_submission_requires_an_active_org_admin(db: Session) -> None:
    unit = _unit(db, name="Sales")
    with pytest.raises(AuthorizationError):
        submit_organization_units_page_route(
            OrganizationUnitsPageSubmissionRequest(
                decisions=[
                    OrganizationUnitDecisionRequest(
                        unit_id=unit.id, decision=OrganizationUnitReviewDecision.CONFIRM
                    )
                ]
            ),
            _context(user_id=2),
            db,
        )
