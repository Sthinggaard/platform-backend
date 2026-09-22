"""Acceptance lifecycle for the accountable owner of a Business Process."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped

from src.core.constants.process_ownership_enums import ProcessOwnershipStatus
from src.core.database import Base
from src.core.model_defs.common import utcnow

PROCESS_OWNERSHIP_STATUS_SQL = ", ".join(
    f"'{status.value}'" for status in ProcessOwnershipStatus
)


class ProcessOwnerAcceptance(Base):
    """An invitation and response for one scoped Business Process Owner binding.

    The role assignment identifier is deliberately a snapshot rather than a
    foreign key. Rebinding the same scope invalidates an old acceptance while
    preserving its audit history.
    """

    __tablename__ = "process_owner_acceptances"
    __table_args__ = (
        CheckConstraint(
            f"status IN ({PROCESS_OWNERSHIP_STATUS_SQL})",
            name="ck_process_owner_acceptance_status",
        ),
        UniqueConstraint(
            "organization_id",
            "scope_binding_id",
            name="uq_process_owner_acceptances_org_scope_binding",
        ),
        Index("ix_process_owner_acceptances_org_process", "organization_id", "process_id"),
        Index("ix_process_owner_acceptances_process_status", "process_id", "status"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    process_id: Mapped[str] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="CASCADE"), nullable=False
    )
    scope_binding_id: Mapped[str] = Column(
        String(36),
        ForeignKey("org_mandate_scope_bindings.id", ondelete="CASCADE"),
        nullable=False,
    )
    role_assignment_id: Mapped[str] = Column(String(36), nullable=False)
    owner_user_id: Mapped[int] = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = Column(
        String(30), nullable=False, default=ProcessOwnershipStatus.INVITATION_SENT.value
    )
    invited_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    invited_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    accepted_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    rejected_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    rejection_reason: Mapped[str | None] = Column(String(80), nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
