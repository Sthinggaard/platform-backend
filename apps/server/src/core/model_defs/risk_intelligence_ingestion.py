from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, relationship

from src.core.database import Base
from src.core.model_defs.common import utcnow


class RiskIngestionBatchStatus(enum.Enum):
    RECEIVED = "received"
    NORMALIZED = "normalized"
    ANALYZED = "analyzed"
    NEEDS_REVIEW = "needs_review"
    REVIEWED = "reviewed"
    FAILED = "failed"


class RiskIngestionBatch(Base):
    __tablename__ = "risk_intelligence_ingestion_batches"
    __table_args__ = (
        Index("ix_risk_intel_ingestion_batches_org_status", "organization_id", "status"),
        Index("ix_risk_intel_ingestion_batches_org_created", "organization_id", "received_at"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    source_name: Mapped[str] = Column(String(150), nullable=False, index=True)
    collector_profile: Mapped[str] = Column(String(150), nullable=False, index=True)
    file_name: Mapped[str | None] = Column(String(255))
    content_type: Mapped[str | None] = Column(String(100))
    payload_checksum: Mapped[str] = Column(String(64), nullable=False, index=True)
    raw_payload: Mapped[dict[str, Any] | list[Any]] = Column(JSONB, nullable=False)
    raw_payload_size_bytes: Mapped[int] = Column(Integer, nullable=False, default=0)
    status: Mapped[RiskIngestionBatchStatus] = Column(
        Enum(RiskIngestionBatchStatus, native_enum=False, validate_strings=True),
        default=RiskIngestionBatchStatus.RECEIVED,
        nullable=False,
        index=True,
    )
    received_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False, index=True)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    error_message: Mapped[str | None] = Column(Text)
    decision_evidence: Mapped[dict[str, Any] | None] = Column(JSONB, nullable=True)
    # CA-06.2 — the evidence package this batch was built from, when it came
    # from the discovery execution pipeline. Nullable and stays that way: a
    # batch uploaded by hand has no package, and saying so is the honest
    # answer. This is what carries provenance through to each signal
    # normalization writes, so an inventory claim can be traced back to the
    # evidence without re-parsing a raw payload.
    evidence_package_id: Mapped[str | None] = Column(
        String(36), ForeignKey("evidence_packages.id", ondelete="SET NULL"), nullable=True, index=True
    )

    organization: Mapped["Organization"] = relationship("Organization")


__all__ = ["RiskIngestionBatch", "RiskIngestionBatchStatus"]
