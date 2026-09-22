"""#463 slice C — the service BIA exception routes, and the old whole-questionnaire save.

Søren, 2026-09-15: an exception belongs to the service in one process, so it needs edit access to
that process; the old save refuses a differing answer, clearly, and changes nothing when it does.

Postgres, inside the conftest transaction: a route's commit lands in a savepoint that is rolled back.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import service_bia_exceptions as routes
from src.api.routes import services
from src.core.exceptions import AuthorizationError, ResourceNotFoundError
from src.core.models import BusinessService, Organization, User, ValueStream
from src.core.services.process_ownership_service import ProcessOwnershipValidationError

PROCESS_ANSWERS = {
    "impact1h": "high",
    "impact4h": "high",
    "impact24h": "medium",
    "mtd": "short",
    "dataSensitivity": "high",
    "workaround": "manual",
    "alternativeChannel": "none",
}


@pytest.fixture
def actor(db_session: Session, sample_organization: Organization) -> User:
    user = User(
        organization_id=sample_organization.id,
        email=f"owner-{uuid4().hex[:8]}@org.test",
        role="org_admin",
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture
def process(db_session: Session, sample_organization: Organization) -> ValueStream:
    row = ValueStream(
        id=str(uuid4()),
        organization_id=sample_organization.id,
        name="Order to Cash",
        bia_answers=dict(PROCESS_ANSWERS),
    )
    db_session.add(row)
    db_session.flush()
    return row


@pytest.fixture
def service(
    db_session: Session, sample_organization: Organization, process: ValueStream
) -> BusinessService:
    row = BusinessService(
        id=str(uuid4()),
        organization_id=sample_organization.id,
        name="Order processing",
        value_stream_ids=[process.id],
    )
    db_session.add(row)
    db_session.flush()
    return row


@pytest.fixture
def ctx(actor: User, sample_organization: Organization) -> TenantContext:
    return TenantContext(
        user_id=actor.id,
        organization_id=sample_organization.id,
        email=actor.email,
        roles=["admin"],
        permissions=[],
    )


@pytest.fixture(autouse=True)
def editor_checks(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Process ownership is its own suite; here, record which process was checked."""
    checked: list[str] = []

    def _allow(_db, *, organization_id, process_id, actor_user_id):
        checked.append(process_id)

    monkeypatch.setattr(routes, "require_process_editor", _allow)
    return checked


def _record(ctx, db, service, process, field="impact1h", **body):
    request = routes.RecordBiaExceptionRequest(
        **{"value": "low", "reasonCode": "part_of_process", **body}
    )
    return routes.record_service_bia_exception(
        service.id, process.id, field, request, ctx=ctx, db=db
    )


def _questionnaire(**changes) -> services.BiaAnswers:
    return services.BiaAnswers(
        **{
            **PROCESS_ANSWERS,
            "serviceOwnerTitle": "Head of Billing",
            "impactPath": ["revenue_stop"],
            **changes,
        }
    )


def test_the_service_inherits_the_process_bia_until_it_differs(ctx, db_session, service, process):
    response = routes.get_service_process_bia(service.id, process.id, ctx=ctx, db=db_session)

    assert response.answers == PROCESS_ANSWERS
    assert set(response.provenance.values()) == {"inherited"}
    assert response.complete is True
    assert response.exceptions == []
    assert response.reasonPrompt == "Why does this service differ from the process?"
    assert [reason.code for reason in response.reasons if reason.noteRequired] == ["other"]


def test_recording_an_exception_changes_only_that_question_and_checks_this_process(
    ctx, db_session, service, process, editor_checks
):
    response = _record(ctx, db_session, service, process)

    assert response.answers["impact1h"] == "low"
    assert response.answers["mtd"] == PROCESS_ANSWERS["mtd"]
    assert response.provenance["impact1h"] == "exception"
    [exception] = response.exceptions
    assert (exception.previousValue, exception.reasonLabel, exception.recordedByUserId) == (
        "high",
        "It supports only part of the process",
        ctx.user_id,
    )
    assert editor_checks == [process.id]


def test_someone_who_cannot_edit_the_process_is_refused(
    ctx, db_session, service, process, monkeypatch
):
    def _deny(_db, **_kwargs):
        raise ProcessOwnershipValidationError("not an editor of this process")

    monkeypatch.setattr(routes, "require_process_editor", _deny)

    with pytest.raises(AuthorizationError):
        _record(ctx, db_session, service, process)


def test_an_invalid_exception_is_a_422_that_says_why(ctx, db_session, service, process):
    with pytest.raises(HTTPException) as refused:
        _record(ctx, db_session, service, process, reasonCode="other")

    assert refused.value.status_code == 422
    assert "Explain in a note" in refused.value.detail


def test_withdrawing_returns_the_question_to_inherited(ctx, db_session, service, process):
    _record(ctx, db_session, service, process)

    response = routes.withdraw_service_bia_exception(
        service.id, process.id, "impact1h", ctx=ctx, db=db_session
    )

    assert response.provenance["impact1h"] == "inherited"
    assert response.answers["impact1h"] == PROCESS_ANSWERS["impact1h"]


def test_withdrawing_an_exception_that_is_not_there_is_a_404(ctx, db_session, service, process):
    with pytest.raises(HTTPException) as missing:
        routes.withdraw_service_bia_exception(
            service.id, process.id, "impact1h", ctx=ctx, db=db_session
        )

    assert missing.value.status_code == 404


def test_a_process_the_service_is_not_part_of_is_a_422(
    ctx, db_session, sample_organization, service
):
    other = ValueStream(
        id=str(uuid4()), organization_id=sample_organization.id, name="Record to Report"
    )
    db_session.add(other)
    db_session.flush()

    with pytest.raises(HTTPException) as refused:
        routes.get_service_process_bia(service.id, other.id, ctx=ctx, db=db_session)

    assert refused.value.status_code == 422


def test_a_process_outside_the_organisation_is_not_found(ctx, db_session, service):
    with pytest.raises(ResourceNotFoundError):
        routes.get_service_process_bia(service.id, str(uuid4()), ctx=ctx, db=db_session)


def test_the_old_save_keeps_identical_answers_and_only_the_setup_facts(ctx, db_session, service):
    response = services.update_service(
        service.id,
        services.UpdateServiceRequest(biaAnswers=_questionnaire()),
        ctx=ctx,
        db=db_session,
    )
    db_session.refresh(service)

    assert service.bia_answers == {
        "serviceOwnerTitle": "Head of Billing",
        "impactPath": ["revenue_stop"],
    }
    assert response.biaAnswers.serviceOwnerTitle == "Head of Billing"
    assert response.biaAnswers.mtd == PROCESS_ANSWERS["mtd"]


def test_the_old_save_refuses_a_differing_answer_and_changes_nothing(ctx, db_session, service):
    with pytest.raises(HTTPException) as refused:
        services.update_service(
            service.id,
            services.UpdateServiceRequest(
                name="Renamed", biaAnswers=_questionnaire(impact1h="low")
            ),
            ctx=ctx,
            db=db_session,
        )

    assert refused.value.status_code == 422
    assert "impact1h" in refused.value.detail
    assert "exception with a reason" in refused.value.detail
    db_session.refresh(service)
    assert service.name == "Order processing"


def test_the_old_save_accepts_an_answer_that_matches_a_recorded_exception(
    ctx, db_session, service, process
):
    _record(ctx, db_session, service, process)

    services.update_service(
        service.id,
        services.UpdateServiceRequest(biaAnswers=_questionnaire(impact1h="low")),
        ctx=ctx,
        db=db_session,
    )


def test_creating_a_service_refuses_a_differing_answer(ctx, db_session, process):
    with pytest.raises(HTTPException) as refused:
        services.create_service(
            services.CreateServiceRequest(
                name="Invoicing",
                valueStreamIds=[process.id],
                biaAnswers=_questionnaire(mtd="long"),
            ),
            ctx=ctx,
            db=db_session,
        )

    assert refused.value.status_code == 422
    assert "mtd" in refused.value.detail


def test_the_other_processes_relying_on_the_service_carry_their_own_impact(
    ctx, db_session, sample_organization, service, process
):
    """#463 AC 10–11 (Søren, 2026-09-15): ownership may sit outside this process, so the owner sees
    every other process that relies on the service, with the impact there — in levels until #479."""
    billing = ValueStream(
        id=str(uuid4()),
        organization_id=sample_organization.id,
        name="Billing & Subscription",
        bia_answers={**PROCESS_ANSWERS, "impact1h": "severe", "mtd": "immediate"},
    )
    db_session.add(billing)
    service.value_stream_ids = [process.id, billing.id]
    db_session.flush()
    _record(ctx, db_session, service, billing, field="impact4h", value="medium")

    response = routes.get_service_process_bia(service.id, process.id, ctx=ctx, db=db_session)

    [other] = response.otherProcesses
    assert (other.processId, other.processName) == (billing.id, "Billing & Subscription")
    assert (other.impact1h, other.impact4h, other.mtd) == ("severe", "medium", "immediate")
    assert other.hasExceptions is True
    # This process's own answers are untouched by the other process's exception.
    assert response.answers["impact4h"] == PROCESS_ANSWERS["impact4h"]


def test_a_service_in_one_process_has_no_other_processes(ctx, db_session, service, process):
    response = routes.get_service_process_bia(service.id, process.id, ctx=ctx, db=db_session)

    assert response.otherProcesses == []
