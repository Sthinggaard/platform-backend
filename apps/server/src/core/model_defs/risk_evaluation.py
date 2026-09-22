"""Persisted Risk Evaluation and Forecast Impact (dashboard epic, slice 3).

Contract (risklence-domain-decision-model): the Risk Evaluation is the
central analytical object — it combines observed-risk evidence, resolved BIA
and appetite (with provenance), dependency and recovery gaps, residual state,
a Forecast Impact snapshot, confidence, and an explanation. Dashboards
project these stored records; they never calculate a replacement posture.

Both records are append-only immutable snapshots (decision/audit rules): a
re-evaluation creates a new row, the previous one remains the audit history.
A Forecast Impact is an explainable *estimate* with its inputs, assumptions,
confidence, and source retained — never a confirmed loss, and never derived
from tier defaults.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow

# Canonical risk status (contract §Risk Evaluation rules).
RISK_STATUS_WITHIN_APPETITE = "within_appetite"
RISK_STATUS_APPROACHING_APPETITE = "approaching_appetite"
RISK_STATUS_OUTSIDE_APPETITE = "outside_appetite"
RISK_STATUS_NOT_PROVEN = "not_proven"

# Canonical preparedness outcome.
PREPAREDNESS_PREPARED = "prepared"
PREPAREDNESS_PARTIALLY_PREPARED = "partially_prepared"
PREPAREDNESS_NOT_PREPARED = "not_prepared"
PREPAREDNESS_CANNOT_PROVE = "cannot_prove"


class ForecastImpact(Base):
    __tablename__ = "forecast_impacts"
    __table_args__ = (
        Index("ix_forecast_impacts_org_process", "organization_id", "process_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    process_id: Mapped[str] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="CASCADE"), nullable=False
    )
    # The consequence estimate itself (e.g. BIA-derived impact profile).
    estimate: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    # Exactly what the estimate was calculated from — retained verbatim.
    inputs: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    assumptions: Mapped[list] = Column(JSONB, nullable=False, default=list)
    confidence: Mapped[str] = Column(String(10), nullable=False)  # high | medium | low
    source: Mapped[str] = Column(String(60), nullable=False)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


class RiskEvaluation(Base):
    __tablename__ = "risk_evaluations"
    __table_args__ = (
        Index("ix_risk_evaluations_org_process", "organization_id", "process_id", "evaluated_at"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    process_id: Mapped[str] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = Column(String(30), nullable=False)  # canonical risk status
    preparedness: Mapped[str] = Column(String(30), nullable=False)  # canonical preparedness
    confidence: Mapped[str] = Column(String(10), nullable=False)  # high | medium | low
    # Frozen input snapshots — what was true when this evaluation was made.
    bia_snapshot: Mapped[dict | None] = Column(JSONB, nullable=True)
    appetite_snapshot: Mapped[dict | None] = Column(JSONB, nullable=True)
    evidence_snapshot: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    dependency_snapshot: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    recovery_snapshot: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    residual: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    # The contract's eight-part structured explanation.
    explanation: Mapped[list] = Column(JSONB, nullable=False, default=list)
    forecast_id: Mapped[str | None] = Column(
        String(36), ForeignKey("forecast_impacts.id", ondelete="SET NULL"), nullable=True
    )
    evaluated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
