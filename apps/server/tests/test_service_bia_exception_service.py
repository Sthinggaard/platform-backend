"""#463 slice C — recording and withdrawing a service's BIA exceptions, and the old save's refusal.

Søren, 2026-09-15 (option B): a service records only where it differs from a process, in that process,
with a structured reason; every change is kept and audited. The old whole-questionnaire save refuses
a differing answer, clearly.

Postgres, inside the conftest transaction: the partial unique index is part of what is tested.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from src.core.models import AuditEvent, BusinessService, Organization, User, ValueStream
from src.core.services.service_bia_exception_service import (
    AUDIT_BIA_EXCEPTION_RECORDED,
    AUDIT_BIA_EXCEPTION_WITHDRAWN,
    BiaExceptionError,
    BiaExceptionNotFoundError,
    active_bia_exceptions,
    record_bia_exception,
    refuse_differing_questionnaire_answers,
    withdraw_bia_exception,
)

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


def _record(db: Session, service: BusinessService, process: ValueStream, actor: User, **overrides):
    arguments = {
        "service": service,
        "process_id": process.id,
        "field": "impact1h",
        "value": "low",
        "reason_code": "part_of_process",
        "reason_note": None,
        "process_answers": PROCESS_ANSWERS,
        "actor_user_id": actor.id,
    }
    arguments.update(overrides)
    return record_bia_exception(db, **arguments)


def _audit(db: Session, organization: Organization, event_type: str) -> list[AuditEvent]:
    return (
        db.query(AuditEvent)
        .filter(AuditEvent.organization_id == organization.id, AuditEvent.event_type == event_type)
        .all()
    )


def test_an_exception_records_what_differs_why_who_and_when(
    db_session: Session, sample_organization: Organization, service, process, actor
) -> None:
    exception = _record(db_session, service, process, actor)

    assert (
        exception.value,
        exception.previous_value,
        exception.reason_code,
        exception.recorded_by_user_id,
        exception.recorded_before_reasons,
    ) == ("low", "high", "part_of_process", actor.id, False)
    assert exception.recorded_at is not None
    [audit] = _audit(db_session, sample_organization, AUDIT_BIA_EXCEPTION_RECORDED)
    assert audit.actor_user_id == actor.id
    assert (audit.metadata_json["previous_value"], audit.metadata_json["new_value"]) == (
        "high",
        "low",
    )
    assert audit.metadata_json["reason_code"] == "part_of_process"


def test_a_new_exception_for_the_same_question_withdraws_the_old_one(
    db_session: Session, sample_organization: Organization, service, process, actor
) -> None:
    first = _record(db_session, service, process, actor)
    second = _record(
        db_session, service, process, actor, value="medium", reason_code="different_recovery"
    )

    assert second.previous_value == "low"
    assert first.withdrawn_at is not None
    assert first.withdrawn_by_user_id == actor.id
    active = active_bia_exceptions(
        db_session, organization_id=sample_organization.id, service_ids=[service.id]
    )
    assert [exception.id for exception in active[(service.id, process.id)]] == [second.id]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"field": "serviceOwnerTitle"}, "not a Business Impact Assessment question"),
        ({"value": "  "}, "needs the answer that applies to this service"),
        ({"reason_code": "because"}, "Choose why this service differs"),
        ({"reason_code": "other", "reason_note": " "}, "Explain in a note"),
        ({"value": "high"}, "the Business Process's own answer"),
    ],
)
def test_an_exception_that_cannot_be_recorded_says_why(
    db_session: Session, service, process, actor, overrides, message
) -> None:
    with pytest.raises(BiaExceptionError, match=message):
        _record(db_session, service, process, actor, **overrides)


def test_other_is_recorded_with_its_note(db_session: Session, service, process, actor) -> None:
    exception = _record(
        db_session,
        service,
        process,
        actor,
        reason_code="other",
        reason_note="  Runs only in the EU region  ",
    )

    assert exception.reason_note == "Runs only in the EU region"


def test_a_process_the_service_is_not_part_of_is_refused(
    db_session: Session, sample_organization: Organization, service, process, actor
) -> None:
    other = ValueStream(
        id=str(uuid4()), organization_id=sample_organization.id, name="Record to Report"
    )
    db_session.add(other)
    db_session.flush()

    with pytest.raises(BiaExceptionError, match="not part of that Business Process"):
        _record(db_session, service, process, actor, process_id=other.id)


def test_withdrawing_returns_the_question_to_inherited_and_is_audited(
    db_session: Session, sample_organization: Organization, service, process, actor
) -> None:
    exception = _record(db_session, service, process, actor)

    withdrawn = withdraw_bia_exception(
        db_session,
        service=service,
        process_id=process.id,
        field="impact1h",
        process_answers=PROCESS_ANSWERS,
        actor_user_id=actor.id,
    )

    assert withdrawn.id == exception.id
    assert withdrawn.withdrawn_at is not None
    assert (
        active_bia_exceptions(
            db_session, organization_id=sample_organization.id, service_ids=[service.id]
        )
        == {}
    )
    [audit] = _audit(db_session, sample_organization, AUDIT_BIA_EXCEPTION_WITHDRAWN)
    assert (audit.metadata_json["previous_value"], audit.metadata_json["new_value"]) == (
        "low",
        "high",
    )


def test_withdrawing_an_exception_that_does_not_exist_says_so(
    db_session: Session, service, process, actor
) -> None:
    with pytest.raises(BiaExceptionNotFoundError, match="already inherits"):
        withdraw_bia_exception(
            db_session,
            service=service,
            process_id=process.id,
            field="impact1h",
            process_answers=PROCESS_ANSWERS,
            actor_user_id=actor.id,
        )


def test_the_old_save_lets_identical_answers_and_setup_facts_through() -> None:
    refuse_differing_questionnaire_answers(
        {**PROCESS_ANSWERS, "serviceOwnerTitle": "Head of Billing", "impactPath": ["revenue_stop"]},
        answers_in_force=PROCESS_ANSWERS,
    )


def test_the_old_save_refuses_a_differing_answer_and_names_it() -> None:
    with pytest.raises(
        BiaExceptionError,
        match=r"differ from the Business Process: impact1h, mtd\. Record each as an exception",
    ):
        refuse_differing_questionnaire_answers(
            {**PROCESS_ANSWERS, "impact1h": "low", "mtd": "long"}, answers_in_force=PROCESS_ANSWERS
        )


def test_the_old_save_refuses_an_answer_the_process_has_not_given() -> None:
    in_force = {field: value for field, value in PROCESS_ANSWERS.items() if field != "workaround"}

    with pytest.raises(BiaExceptionError, match="has not answered: workaround"):
        refuse_differing_questionnaire_answers(PROCESS_ANSWERS, answers_in_force=in_force)
