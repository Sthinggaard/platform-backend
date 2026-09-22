"""CA-07.0 — the operating mode and the standing default are governed decisions.

One test per acceptance criterion on #241, plus the two rules the story exists
to protect: a decision nobody made never reads as one somebody did, and a
standing default never removes a choice.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import contextual_access_policies as routes
from src.core.constants.contextual_access_enums import (
    CONTEXTUAL_ACCESS_AUDIT_APPROVED,
    CONTEXTUAL_ACCESS_AUDIT_DRAFT_CREATED,
    AccessOperatingMode,
    ArtefactAccessChoice,
    ContextualAccessDecision,
    ContextualAccessPolicyStatus,
)
from src.core.constants.leadership_authorization_enums import LeadershipAuthorizationStatus
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ValidationError
from src.core.model_defs.common import utcnow
from src.core.model_defs.contextual_access_policy import ContextualAccessPolicy
from src.core.model_defs.leadership_authorization import LeadershipAuthorization
from src.core.models import AuditEvent, Organization, User
from src.core.services import contextual_access_policy_service as service
from src.core.services.contextual_access_policy_service import (
    ContextualAccessPolicyValidationError,
    available_artefact_access_choices,
    create_policy_draft,
    deviates_from_standing_default,
    resolve_deeper_access_default,
    resolve_operating_mode,
)

ADMIN_USER_ID = 1
SPONSOR_USER_ID = 2
OTHER_ORG_ID = 2


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            User.__table__,
            LeadershipAuthorization.__table__,
            ContextualAccessPolicy.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org"),
            Organization(id=OTHER_ORG_ID, name="Other", slug="other"),
            User(id=ADMIN_USER_ID, organization_id=1, email="admin@example.com", role="org_admin"),
            User(id=SPONSOR_USER_ID, organization_id=1, email="sponsor@example.com", role="org_admin"),
            LeadershipAuthorization(
                id="auth-1",
                organization_id=1,
                status=LeadershipAuthorizationStatus.ACTIVE.value,
                sponsor_user_id=SPONSOR_USER_ID,
                approving_body="board_risk_committee",
                authorized_scope="Authorise the onboarding programme.",
            ),
        ]
    )
    session.commit()
    yield session
    session.close()


def _ctx(user_id: int, organization_id: int = 1) -> TenantContext:
    return TenantContext(
        user_id=user_id,
        organization_id=organization_id,
        email="user@example.com",
        roles=["org_admin"],
        permissions=[],
    )


def _future(days: int = 90):
    return utcnow() + timedelta(days=days)


def _approve(
    db: Session,
    *,
    decision: ContextualAccessDecision,
    choice: str,
    review_at=None,
) -> ContextualAccessPolicy:
    """Drive one decision all the way through the governance lifecycle."""
    policy = routes.create_draft(
        routes.ContextualAccessDraftRequest(
            decision=decision, choice=choice, review_at=review_at
        ),
        ctx=_ctx(ADMIN_USER_ID),
        db=db,
    )
    routes.submit_draft(policy.id, ctx=_ctx(ADMIN_USER_ID), db=db)
    routes.approve_draft(
        policy.id,
        routes.ContextualAccessApprovalRequest(consequence_acknowledged=True),
        ctx=_ctx(SPONSOR_USER_ID),
        db=db,
    )
    return db.query(ContextualAccessPolicy).filter_by(id=policy.id).one()


# --- Criterion 1: explicit, never inferred, never silently defaulted -------


def test_an_undecided_operating_mode_resolves_to_nothing_rather_than_a_default(db: Session):
    assert resolve_operating_mode(db, 1) is None
    assert resolve_deeper_access_default(db, 1) is None
    assert routes.get_operating_mode(ctx=_ctx(ADMIN_USER_ID), db=db).resolved is False


def test_a_draft_that_was_never_approved_does_not_resolve(db: Session):
    create_policy_draft(
        db,
        organization_id=1,
        decision=ContextualAccessDecision.ACCESS_OPERATING_MODE.value,
        choice=AccessOperatingMode.PROCESS_TRIGGERED.value,
        prepared_by="1",
    )
    db.commit()

    assert resolve_operating_mode(db, 1) is None


# --- Criterion 2: versioned, attributed, effective-dated, superseded -------


def test_approving_a_new_mode_supersedes_the_previous_one_instead_of_editing_it(db: Session):
    first = _approve(
        db,
        decision=ContextualAccessDecision.ACCESS_OPERATING_MODE,
        choice=AccessOperatingMode.PROCESS_TRIGGERED.value,
    )
    assert first.version == 1
    assert first.approved_by == str(SPONSOR_USER_ID)
    assert first.approved_at is not None
    assert first.effective_from is not None

    second = _approve(
        db,
        decision=ContextualAccessDecision.ACCESS_OPERATING_MODE,
        choice=AccessOperatingMode.SCHEDULED_AUTONOMOUS.value,
        review_at=_future(),
    )

    db.refresh(first)
    assert second.version == 2
    assert first.status == ContextualAccessPolicyStatus.SUPERSEDED.value
    assert first.superseded_by_id == second.id
    # The superseded record keeps everything it said — history, not a tombstone.
    assert first.choice == AccessOperatingMode.PROCESS_TRIGGERED.value
    assert first.approved_by == str(SPONSOR_USER_ID)


def test_there_is_no_update_path_for_an_approved_decision(db: Session):
    """Changing the decision must mean a new version, so no route may edit one."""
    paths = {route.path for route in routes.router.routes}
    methods = {method for route in routes.router.routes for method in route.methods}
    assert "PATCH" not in methods
    assert "PUT" not in methods
    assert "DELETE" not in methods
    assert paths  # sanity: the router is actually populated


# --- Criterion 3: both modes supported; choosing one keeps the other -------


def test_an_organisation_can_run_mode_b_while_a_mode_a_draft_awaits_review(db: Session):
    _approve(
        db,
        decision=ContextualAccessDecision.ACCESS_OPERATING_MODE,
        choice=AccessOperatingMode.PROCESS_TRIGGERED.value,
    )
    routes.create_draft(
        routes.ContextualAccessDraftRequest(
            decision=ContextualAccessDecision.ACCESS_OPERATING_MODE,
            choice=AccessOperatingMode.SCHEDULED_AUTONOMOUS.value,
            review_at=_future(),
        ),
        ctx=_ctx(ADMIN_USER_ID),
        db=db,
    )

    status = routes.get_status(
        decision=ContextualAccessDecision.ACCESS_OPERATING_MODE, ctx=_ctx(ADMIN_USER_ID), db=db
    )
    assert status.active.choice == AccessOperatingMode.PROCESS_TRIGGERED.value
    assert status.pending.choice == AccessOperatingMode.SCHEDULED_AUTONOMOUS.value
    # Evaluating Mode A changes nothing about what is running today.
    assert resolve_operating_mode(db, 1) == AccessOperatingMode.PROCESS_TRIGGERED.value


# --- Criterion 4: the consequence is stated before approval ---------------


def test_the_consequence_is_snapshotted_on_the_draft_in_business_language(db: Session):
    policy = create_policy_draft(
        db,
        organization_id=1,
        decision=ContextualAccessDecision.ACCESS_OPERATING_MODE.value,
        choice=AccessOperatingMode.SCHEDULED_AUTONOMOUS.value,
        prepared_by="1",
        review_at=_future(),
    )
    db.commit()

    assert "nobody watching" in policy.consequence_statement
    assert policy.consequence_acknowledged is False


def test_approval_is_refused_when_the_consequence_was_not_acknowledged(db: Session):
    policy = routes.create_draft(
        routes.ContextualAccessDraftRequest(
            decision=ContextualAccessDecision.DEEPER_ACCESS_DEFAULT,
            choice=ArtefactAccessChoice.NETWORK_ONLY.value,
        ),
        ctx=_ctx(ADMIN_USER_ID),
        db=db,
    )
    routes.submit_draft(policy.id, ctx=_ctx(ADMIN_USER_ID), db=db)

    with pytest.raises(ValidationError, match="acknowledged"):
        routes.approve_draft(
            policy.id,
            routes.ContextualAccessApprovalRequest(consequence_acknowledged=False),
            ctx=_ctx(SPONSOR_USER_ID),
            db=db,
        )
    assert resolve_deeper_access_default(db, 1) is None


# --- Criterion 5: Mode A carries a mandatory review date -------------------


def test_scheduled_autonomous_access_cannot_be_prepared_without_a_review_date(db: Session):
    with pytest.raises(ContextualAccessPolicyValidationError, match="review date"):
        create_policy_draft(
            db,
            organization_id=1,
            decision=ContextualAccessDecision.ACCESS_OPERATING_MODE.value,
            choice=AccessOperatingMode.SCHEDULED_AUTONOMOUS.value,
            prepared_by="1",
        )


def test_process_triggered_access_needs_no_review_date(db: Session):
    policy = create_policy_draft(
        db,
        organization_id=1,
        decision=ContextualAccessDecision.ACCESS_OPERATING_MODE.value,
        choice=AccessOperatingMode.PROCESS_TRIGGERED.value,
        prepared_by="1",
    )
    assert policy.review_at is None


def test_an_approval_that_has_lapsed_stops_resolving(db: Session):
    policy = _approve(
        db,
        decision=ContextualAccessDecision.ACCESS_OPERATING_MODE,
        choice=AccessOperatingMode.PROCESS_TRIGGERED.value,
    )
    policy.effective_to = utcnow() - timedelta(days=1)
    db.commit()

    assert resolve_operating_mode(db, 1) is None


# --- Mode A is honest about what this platform can actually run (#242) -----


def test_mode_a_cannot_be_approved_when_no_recurrence_schedule_exists(db: Session, monkeypatch):
    """The guard itself, independent of whether #242 has landed.

    Approving a cadence the platform cannot honour would tell an organisation
    its systems are scanned every 30 days while nothing ever runs.
    """
    monkeypatch.setattr(service, "recurrence_primitive_available", lambda: False)

    policy = routes.create_draft(
        routes.ContextualAccessDraftRequest(
            decision=ContextualAccessDecision.ACCESS_OPERATING_MODE,
            choice=AccessOperatingMode.SCHEDULED_AUTONOMOUS.value,
            review_at=_future(),
        ),
        ctx=_ctx(ADMIN_USER_ID),
        db=db,
    )
    routes.submit_draft(policy.id, ctx=_ctx(ADMIN_USER_ID), db=db)

    with pytest.raises(ValidationError, match="never actually run"):
        routes.approve_draft(
            policy.id,
            routes.ContextualAccessApprovalRequest(consequence_acknowledged=True),
            ctx=_ctx(SPONSOR_USER_ID),
            db=db,
        )
    assert resolve_operating_mode(db, 1) is None


def test_mode_a_is_approvable_now_that_the_recurrence_primitive_exists(db: Session):
    """#242 landed, so the guard is satisfied and Mode A can be approved.

    The payoff of keeping the guard in one predicate: this flipped without any
    other change to the epic.
    """
    assert service.recurrence_primitive_available() is True

    policy = _approve(
        db,
        decision=ContextualAccessDecision.ACCESS_OPERATING_MODE,
        choice=AccessOperatingMode.SCHEDULED_AUTONOMOUS.value,
        review_at=_future(),
    )

    assert policy.status == ContextualAccessPolicyStatus.ACTIVE.value
    assert resolve_operating_mode(db, 1) == AccessOperatingMode.SCHEDULED_AUTONOMOUS.value
    # The review date survives approval — standing permission that never expires
    # is a default, not a decision.
    assert policy.review_at is not None


# --- The standing default is a default, not a gate (CLAUDE.md:217) --------


def test_every_access_choice_stays_available_once_a_standing_default_is_approved(db: Session):
    _approve(
        db,
        decision=ContextualAccessDecision.DEEPER_ACCESS_DEFAULT,
        choice=ArtefactAccessChoice.NETWORK_ONLY.value,
    )

    response = routes.get_artefact_choices(ctx=_ctx(ADMIN_USER_ID), db=db)
    offered = {option.choice for option in response.choices}

    assert offered == {choice.value for choice in ArtefactAccessChoice}
    assert len(offered) == 5
    assert response.standing_default == ArtefactAccessChoice.NETWORK_ONLY.value


def test_the_default_answer_is_free_and_every_other_answer_owes_a_reason(db: Session):
    _approve(
        db,
        decision=ContextualAccessDecision.DEEPER_ACCESS_DEFAULT,
        choice=ArtefactAccessChoice.NETWORK_ONLY.value,
    )

    assert deviates_from_standing_default(db, 1, ArtefactAccessChoice.NETWORK_ONLY.value) is False
    assert deviates_from_standing_default(db, 1, ArtefactAccessChoice.CONNECT_HOST.value) is True

    response = routes.get_artefact_choices(ctx=_ctx(ADMIN_USER_ID), db=db)
    by_choice = {option.choice: option for option in response.choices}
    assert by_choice[ArtefactAccessChoice.NETWORK_ONLY.value].requires_reasoning is False
    assert by_choice[ArtefactAccessChoice.CONNECT_HOST.value].requires_reasoning is True
    # Every option can state its own consequence, default or not.
    assert all(option.consequence for option in response.choices)


def test_with_no_standing_default_every_choice_is_offered_and_none_is_penalised(db: Session):
    response = routes.get_artefact_choices(ctx=_ctx(ADMIN_USER_ID), db=db)

    assert response.standing_default is None
    assert len(response.choices) == 5
    assert not any(option.requires_reasoning for option in response.choices)
    assert set(available_artefact_access_choices()) == {c.value for c in ArtefactAccessChoice}


# --- Authority and tenancy -------------------------------------------------


def test_only_the_named_leadership_sponsor_may_approve(db: Session):
    policy = routes.create_draft(
        routes.ContextualAccessDraftRequest(
            decision=ContextualAccessDecision.DEEPER_ACCESS_DEFAULT,
            choice=ArtefactAccessChoice.NETWORK_ONLY.value,
        ),
        ctx=_ctx(ADMIN_USER_ID),
        db=db,
    )
    routes.submit_draft(policy.id, ctx=_ctx(ADMIN_USER_ID), db=db)

    with pytest.raises(AuthorizationError, match="leadership sponsor"):
        routes.approve_draft(
            policy.id,
            routes.ContextualAccessApprovalRequest(consequence_acknowledged=True),
            ctx=_ctx(ADMIN_USER_ID),
            db=db,
        )


def test_one_organisations_decision_is_invisible_to_another(db: Session):
    _approve(
        db,
        decision=ContextualAccessDecision.DEEPER_ACCESS_DEFAULT,
        choice=ArtefactAccessChoice.NETWORK_ONLY.value,
    )

    assert resolve_deeper_access_default(db, 1) == ArtefactAccessChoice.NETWORK_ONLY.value
    assert resolve_deeper_access_default(db, OTHER_ORG_ID) is None


def test_an_invalid_choice_for_a_decision_is_refused(db: Session):
    with pytest.raises(ContextualAccessPolicyValidationError, match="not a valid answer"):
        create_policy_draft(
            db,
            organization_id=1,
            decision=ContextualAccessDecision.ACCESS_OPERATING_MODE.value,
            choice=ArtefactAccessChoice.NETWORK_ONLY.value,
            prepared_by="1",
        )


# --- Audit ----------------------------------------------------------------


def test_preparing_and_approving_are_both_audited(db: Session):
    _approve(
        db,
        decision=ContextualAccessDecision.DEEPER_ACCESS_DEFAULT,
        choice=ArtefactAccessChoice.NETWORK_ONLY.value,
    )

    events = [event.event_type for event in db.query(AuditEvent).all()]
    assert CONTEXTUAL_ACCESS_AUDIT_DRAFT_CREATED in events
    assert CONTEXTUAL_ACCESS_AUDIT_APPROVED in events
