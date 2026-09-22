"""Structured Business Service Risk Appetite reassessment (ONB-GOV-11).

A Service Owner never re-answers the full six-category questionnaire; they
request a reassessment of one category, with a structured reason and
optional evidence. The Process Owner of the process this service belongs to
approves or rejects it. Append-only per (organization, service, category):
a new request supersedes the previous one at that category, history is
preserved, never mutated.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.constants.appetite_reassessment_enums import AppetiteReassessmentStatus
from src.core.model_defs.common import utcnow


class ServiceAppetiteReassessment(Base):
    __tablename__ = "service_appetite_reassessments"
    __table_args__ = (
        Index(
            "ix_service_appetite_reassessments_service_category",
            "business_service_id",
            "category",
            "status",
        ),
        Index("ix_service_appetite_reassessments_process", "process_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    business_service_id: Mapped[str] = Column(
        String(36), ForeignKey("business_services.id", ondelete="CASCADE"), nullable=False
    )
    # The process whose accountable owner approves this — a service can sit
    # in more than one process, so the request names which process's owner
    # is being asked.
    process_id: Mapped[str] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="CASCADE"), nullable=False
    )
    category: Mapped[str] = Column(String(30), nullable=False)
    requested_level: Mapped[int] = Column(Integer, nullable=False)
    reason: Mapped[str] = Column(Text, nullable=False)
    evidence: Mapped[str | None] = Column(Text, nullable=True)
    requested_by: Mapped[str] = Column(String(255), nullable=False)
    status: Mapped[str] = Column(
        String(20), nullable=False, default=AppetiteReassessmentStatus.PENDING.value
    )
    version: Mapped[int] = Column(Integer, nullable=False, default=1)
    reviewed_by: Mapped[str | None] = Column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    rejection_reason: Mapped[str | None] = Column(Text, nullable=True)
    effective_from: Mapped[datetime | None] = Column(DateTime, nullable=True)
    review_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    superseded_by_id: Mapped[str | None] = Column(
        String(36), ForeignKey("service_appetite_reassessments.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
