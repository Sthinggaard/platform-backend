"""Versioned organisation-wide BIA baselines set by organisation leadership."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow

ORGANIZATION_BIA_BASELINE_ACTIVE = "active"
ORGANIZATION_BIA_BASELINE_SUPERSEDED = "superseded"

ORGANIZATION_BIA_BASELINE_SOURCE_LEADERSHIP = "leadership_entered"
ORGANIZATION_BIA_BASELINE_CONFIDENCE_HIGH = "high"
ORGANIZATION_BIA_BASELINE_ASSUMPTION_CONFIRMED = "confirmed"

ORGANIZATION_BIA_AUDIT_SET = "organization_bia_baseline_set"
ORGANIZATION_BIA_ERROR_ADMIN_REQUIRED = "Organisation administrator access is required to set the organisation Business Impact Assessment"
ORGANIZATION_BIA_ERROR_INCOMPLETE = (
    "A complete organisation Business Impact Assessment is required."
)


class OrganizationBiaBaseline(Base):
    """The organisation-level BIA baseline every process initially inherits.

    Each change creates a new active version and supersedes the preceding
    baseline. Process Owners may later create explicit process-level overrides;
    this record never represents an attestation on their behalf.
    """

    __tablename__ = "organization_bia_baselines"
    __table_args__ = (
        Index("ix_organization_bia_baselines_org_status", "organization_id", "status"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = Column(
        String(30), nullable=False, default=ORGANIZATION_BIA_BASELINE_ACTIVE
    )
    answers: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    source: Mapped[str] = Column(
        String(80), nullable=False, default=ORGANIZATION_BIA_BASELINE_SOURCE_LEADERSHIP
    )
    confidence: Mapped[str] = Column(
        String(20), nullable=False, default=ORGANIZATION_BIA_BASELINE_CONFIDENCE_HIGH
    )
    assumption_state: Mapped[str] = Column(
        String(30), nullable=False, default=ORGANIZATION_BIA_BASELINE_ASSUMPTION_CONFIRMED
    )
    set_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    set_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    superseded_by_id: Mapped[str | None] = Column(
        String(36), ForeignKey("organization_bia_baselines.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
