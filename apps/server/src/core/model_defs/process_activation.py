"""Human confirmation and activation evidence for a Business Process."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow


class BusinessProcessActivation(Base):
    """Stores human confirmation and the exact inputs used for activation.

    Current readiness remains derived from the canonical process, mandate, BIA,
    and appetite records. The snapshots make historic activation explainable
    and invalidate it automatically when any governed input changes.
    """

    __tablename__ = "business_process_activations"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "process_id",
            name="uq_business_process_activations_org_process",
        ),
        Index("ix_business_process_activations_org_process", "organization_id", "process_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    process_id: Mapped[str] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="CASCADE"), nullable=False
    )
    confirmed_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    confirmed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    confirmation_outcome: Mapped[str] = Column(String(30), nullable=False, default="pending")
    confirmation_reason_code: Mapped[str | None] = Column(String(80), nullable=True)
    confirmation_reason_detail: Mapped[str | None] = Column(String(500), nullable=True)
    successor_process_id: Mapped[str | None] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="SET NULL"), nullable=True
    )
    activated_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    activated_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    activated_bia_assessment_id: Mapped[str | None] = Column(String(36), nullable=True)
    activated_organization_bia_baseline_id: Mapped[str | None] = Column(String(36), nullable=True)
    activated_owner_acceptance_id: Mapped[str | None] = Column(String(36), nullable=True)
    activated_appetite_policy_id: Mapped[str | None] = Column(String(36), nullable=True)
    activated_confirmation_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
