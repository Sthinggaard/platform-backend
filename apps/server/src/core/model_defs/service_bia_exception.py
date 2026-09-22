"""#463 — one Business Service's exception to one Business Process's BIA answer.

Søren, 2026-09-15 (option B): a service inherits each process's Business Impact Assessment and
records only where it genuinely differs. The same service can matter less to one process than to
another, so an exception belongs to the service **in that one process**: one row per service,
process and BIA field.

A row records what #463 asks of a permitted exception:
- `value`, the answer in force for this service in this process;
- `previous_value`, the value it departs from when it was recorded;
- a structured reason (`core/constants/bia_exception_reasons.py`), with a note where one is needed;
- who recorded it, and when.

Withdrawing an exception returns the field to inherited. The row is kept, so the history stays.

`recorded_before_reasons` marks an answer a service held before reasons were required, carried over
by migration `20260915_service_bia_exceptions`. Such a row has no reason and no actor, and says so
rather than inventing either.

At most one active row per service, process and field (`uq_service_bia_exceptions_active`).
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow


class ServiceBiaException(Base):
    __tablename__ = "service_bia_exceptions"
    __table_args__ = (
        Index("ix_service_bia_exceptions_org_service", "organization_id", "service_id"),
        Index("ix_service_bia_exceptions_process", "process_id"),
        Index(
            "uq_service_bia_exceptions_active",
            "service_id",
            "process_id",
            "field",
            unique=True,
            postgresql_where=text("withdrawn_at IS NULL"),
        ),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    service_id: Mapped[str] = Column(
        String(36), ForeignKey("business_services.id", ondelete="CASCADE"), nullable=False
    )
    process_id: Mapped[str] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="CASCADE"), nullable=False
    )
    #: One of `bia_inheritance_service.BIA_FIELD_KEYS`.
    field: Mapped[str] = Column(String(40), nullable=False)
    value: Mapped[str] = Column(Text, nullable=False)
    #: The value in force before this exception: the process's answer, or an earlier exception's.
    #: Null when there was none.
    previous_value: Mapped[str | None] = Column(Text, nullable=True)
    reason_code: Mapped[str | None] = Column(String(40), nullable=True)
    reason_note: Mapped[str | None] = Column(Text, nullable=True)
    recorded_before_reasons: Mapped[bool] = Column(Boolean, nullable=False, default=False)
    recorded_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    recorded_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    withdrawn_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    withdrawn_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
