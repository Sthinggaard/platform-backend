"""Review reopenings (dashboard epic, slice 4).

Contract (risklence-domain-decision-model): every decision that routes to
execution or accepts risk carries a review date. If the date passes without
verified evidence of completion, the Risk Evaluation reopens automatically at
the affected Business Process, an auditable Scenario Snapshot records the
consequence of the exposure continuing, and the mandate holder is notified.
The original human decision is never modified — the reopening is a new,
linked record.

The unique constraint makes the pass idempotent: one lapsed review reopens
exactly once.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow

REOPENING_SOURCE_DECISION_REVIEW = "decision_review"
REOPENING_SOURCE_APPETITE_EXCEPTION = "appetite_exception"


class ReviewReopening(Base):
    __tablename__ = "review_reopenings"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "process_id",
            "source",
            "decision_reference",
            "review_due_at",
            name="uq_review_reopenings_reference_due",
        ),
        Index("ix_review_reopenings_org_process", "organization_id", "process_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    process_id: Mapped[str] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[str] = Column(String(30), nullable=False)
    # The lapsed decision: DecisionRecord id or the appetite exception's reference.
    decision_reference: Mapped[str] = Column(String(100), nullable=False)
    review_due_at: Mapped[str] = Column(String(30), nullable=False)
    # The person who made the original decision — the review owner to notify.
    review_owner: Mapped[str | None] = Column(String(255), nullable=True)
    # The fresh evaluation created by the reopening.
    evaluation_id: Mapped[str | None] = Column(
        String(36), ForeignKey("risk_evaluations.id", ondelete="SET NULL"), nullable=True
    )
    # Auditable consequence snapshot: what continuing the exposure means.
    scenario_snapshot: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    reopened_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
