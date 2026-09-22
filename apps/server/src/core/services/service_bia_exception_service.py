"""#463 — a Business Service's BIA exceptions, per process: reading and recording them.

Søren, 2026-09-15 (option B): a service inherits each process's BIA and records only where it
genuinely differs, in that one process, with a structured reason. Every reader of "the answers in
force for a service" takes the exceptions for its (service, process) pair from here and resolves
them with `bia_inheritance_service.effective_service_bia`.

Read once per request for all the services in view, never per service, and always scoped to the
organisation. Nothing here commits; the caller owns the transaction.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime

from sqlalchemy.orm import Session

from src.core.constants.bia_exception_reasons import (
    BIA_EXCEPTION_REASON_CODES,
    BIA_EXCEPTION_REASONS_REQUIRING_NOTE,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.service_bia_exception import ServiceBiaException
from src.core.services.audit_service import append_audit_event
from src.core.services.bia_inheritance_service import BIA_FIELD_KEYS

AUDIT_BIA_EXCEPTION_RECORDED = "SERVICE_BIA_EXCEPTION_RECORDED"
AUDIT_BIA_EXCEPTION_WITHDRAWN = "SERVICE_BIA_EXCEPTION_WITHDRAWN"


class BiaExceptionError(ValueError):
    """An exception that cannot be recorded, said in words the owner can act on."""


class BiaExceptionNotFoundError(BiaExceptionError):
    """There is no active exception to withdraw."""


#: (service_id, process_id) → that pair's active exceptions.
BiaExceptionsByPair = dict[tuple[str, str], list[ServiceBiaException]]


def active_bia_exceptions(
    db: Session,
    *,
    organization_id: int,
    service_ids: Iterable[str] | None = None,
    process_ids: Iterable[str] | None = None,
) -> BiaExceptionsByPair:
    """Active (not withdrawn) exceptions in the organisation, grouped by service and process.

    `service_ids` and `process_ids` narrow the read; `None` means no narrowing on that side. An
    empty collection narrows to nothing.
    """
    query = db.query(ServiceBiaException).filter(
        ServiceBiaException.organization_id == organization_id,
        ServiceBiaException.withdrawn_at.is_(None),
    )
    if service_ids is not None:
        service_ids = list(service_ids)
        if not service_ids:
            return {}
        query = query.filter(ServiceBiaException.service_id.in_(service_ids))
    if process_ids is not None:
        process_ids = list(process_ids)
        if not process_ids:
            return {}
        query = query.filter(ServiceBiaException.process_id.in_(process_ids))

    grouped: BiaExceptionsByPair = {}
    for exception in query.order_by(ServiceBiaException.field.asc()).all():
        grouped.setdefault((exception.service_id, exception.process_id), []).append(exception)
    return grouped


def exceptions_for(
    exceptions: BiaExceptionsByPair, service_id: str, process_id: str | None
) -> list[ServiceBiaException]:
    """The pair's exceptions, or none. A service with no process has nothing to depart from."""
    if process_id is None:
        return []
    return exceptions.get((service_id, process_id), [])


def _active_exception(
    db: Session, *, organization_id: int, service_id: str, process_id: str, field: str
) -> ServiceBiaException | None:
    return (
        db.query(ServiceBiaException)
        .filter(
            ServiceBiaException.organization_id == organization_id,
            ServiceBiaException.service_id == service_id,
            ServiceBiaException.process_id == process_id,
            ServiceBiaException.field == field,
            ServiceBiaException.withdrawn_at.is_(None),
        )
        .one_or_none()
    )


def _require_linked_process(service, process_id: str) -> None:
    if process_id not in (service.value_stream_ids or []):
        raise BiaExceptionError("This service is not part of that Business Process.")


def _require_bia_field(field: str) -> None:
    if field not in BIA_FIELD_KEYS:
        raise BiaExceptionError(f"'{field}' is not a Business Impact Assessment question.")


def record_bia_exception(
    db: Session,
    *,
    service,
    process_id: str,
    field: str,
    value: str,
    reason_code: str,
    reason_note: str | None,
    process_answers: Mapping[str, object] | None,
    actor_user_id: int,
    now: datetime | None = None,
) -> ServiceBiaException:
    """Record that this service, in this process, answers one BIA question differently, and why.

    An earlier exception for the same question is withdrawn, not overwritten, so the history stays.
    `previous_value` is the value in force before: that earlier exception, or the process's answer.
    """
    _require_linked_process(service, process_id)
    _require_bia_field(field)
    value = (value or "").strip()
    if not value:
        raise BiaExceptionError("An exception needs the answer that applies to this service.")
    if reason_code not in BIA_EXCEPTION_REASON_CODES:
        raise BiaExceptionError("Choose why this service differs from the process.")
    note = (reason_note or "").strip() or None
    if reason_code in BIA_EXCEPTION_REASONS_REQUIRING_NOTE and note is None:
        raise BiaExceptionError("Explain in a note why this service differs from the process.")

    process_value = (process_answers or {}).get(field)
    if value == process_value:
        raise BiaExceptionError(
            "That is the Business Process's own answer. The service already inherits it, so there "
            "is no exception to record."
        )

    now = now or utcnow()
    current = _active_exception(
        db,
        organization_id=service.organization_id,
        service_id=service.id,
        process_id=process_id,
        field=field,
    )
    previous_value = current.value if current is not None else process_value
    if current is not None:
        current.withdrawn_at = now
        current.withdrawn_by_user_id = actor_user_id
        # The partial unique index allows one active row, so the old one leaves before the new one.
        db.flush()

    exception = ServiceBiaException(
        organization_id=service.organization_id,
        service_id=service.id,
        process_id=process_id,
        field=field,
        value=value,
        previous_value=None if previous_value is None else str(previous_value),
        reason_code=reason_code,
        reason_note=note,
        recorded_before_reasons=False,
        recorded_by_user_id=actor_user_id,
        recorded_at=now,
    )
    db.add(exception)
    append_audit_event(
        db,
        service.organization_id,
        AUDIT_BIA_EXCEPTION_RECORDED,
        actor_user_id=actor_user_id,
        metadata={
            "service_id": service.id,
            "process_id": process_id,
            "field": field,
            "previous_value": exception.previous_value,
            "new_value": value,
            "reason_code": reason_code,
            "reason_note": note,
            "replaced_exception_id": current.id if current is not None else None,
        },
    )
    db.flush()
    return exception


def withdraw_bia_exception(
    db: Session,
    *,
    service,
    process_id: str,
    field: str,
    process_answers: Mapping[str, object] | None,
    actor_user_id: int,
    now: datetime | None = None,
) -> ServiceBiaException:
    """Withdraw this service's exception for one question in one process; it inherits again."""
    _require_linked_process(service, process_id)
    _require_bia_field(field)
    current = _active_exception(
        db,
        organization_id=service.organization_id,
        service_id=service.id,
        process_id=process_id,
        field=field,
    )
    if current is None:
        raise BiaExceptionNotFoundError(
            "This service has no exception for that question; it already inherits the process's answer."
        )
    current.withdrawn_at = now or utcnow()
    current.withdrawn_by_user_id = actor_user_id
    inherited = (process_answers or {}).get(field)
    append_audit_event(
        db,
        service.organization_id,
        AUDIT_BIA_EXCEPTION_WITHDRAWN,
        actor_user_id=actor_user_id,
        metadata={
            "service_id": service.id,
            "process_id": process_id,
            "field": field,
            "previous_value": current.value,
            "new_value": None if inherited is None else str(inherited),
            "withdrawn_exception_id": current.id,
        },
    )
    db.flush()
    return current


def refuse_differing_questionnaire_answers(
    submitted: Mapping[str, object] | None, *, answers_in_force: Mapping[str, object] | None
) -> None:
    """Søren, 2026-09-15: the old whole-questionnaire save refuses a differing answer, clearly.

    An answer identical to the one in force saves as before. One that differs, or one the process has
    not answered, is refused: a difference is recorded as an exception with a reason, never stored
    without one. Setup metadata (`serviceOwnerTitle`, `impactPath`) is not a BIA answer and passes.
    """
    in_force = answers_in_force or {}
    differing: list[str] = []
    unanswered: list[str] = []
    for field in sorted(BIA_FIELD_KEYS):
        answer = (submitted or {}).get(field)
        if answer is None or (isinstance(answer, str) and not answer.strip()):
            continue
        if in_force.get(field) is None:
            unanswered.append(field)
        elif answer != in_force.get(field):
            differing.append(field)
    if not differing and not unanswered:
        return
    parts: list[str] = []
    if differing:
        parts.append(
            "These answers differ from the Business Process: "
            f"{', '.join(differing)}. Record each as an exception with a reason."
        )
    if unanswered:
        parts.append(
            "The Business Process has not answered: "
            f"{', '.join(unanswered)}. Its owner answers these in the process BIA."
        )
    raise BiaExceptionError(" ".join(parts))
