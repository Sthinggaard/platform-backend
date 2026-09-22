"""Versioned Business Process BIA assessments and human attestation."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow

BIA_ASSESSMENT_PREPARED = "prepared"
BIA_ASSESSMENT_IN_PROGRESS = "in_progress"
BIA_ASSESSMENT_ATTESTED = "attested"
BIA_ASSESSMENT_SUPERSEDED = "superseded"

BIA_AUDIT_PREPARED = "process_bia_prepared"
BIA_AUDIT_UPDATED = "process_bia_updated"
BIA_AUDIT_ATTESTED = "process_bia_attested"


class ProcessBiaAssessment(Base):
    """The authoritative process-level BIA lifecycle record.

    ``ValueStream.bia_answers`` is a compatibility projection written only
    once an assessment has been attested. Services inherit that projection and
    store only material overrides.
    """

    __tablename__ = "process_bia_assessments"
    __table_args__ = (
        Index("ix_process_bia_assessments_org_process", "organization_id", "process_id"),
        Index("ix_process_bia_assessments_process_status", "process_id", "status"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    process_id: Mapped[str] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = Column(String(30), nullable=False, default=BIA_ASSESSMENT_PREPARED)
    answers: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    source: Mapped[str] = Column(String(80), nullable=False)
    confidence: Mapped[str] = Column(String(20), nullable=False)
    assumption_state: Mapped[str] = Column(String(30), nullable=False)
    prepared_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    prepared_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    attested_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    attested_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    review_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    superseded_by_id: Mapped[str | None] = Column(
        String(36), ForeignKey("process_bia_assessments.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
