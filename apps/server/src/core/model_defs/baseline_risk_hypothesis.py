"""Baseline Risk Hypothesis — the assumption-based cold-start model (BSP-10).

Canonical contract (risklence-domain-decision-model): the hypothesis is
generated from company context, industry archetypes, templates, frameworks,
and any available imported evidence. It carries provenance, confidence,
assumptions, validation status, and refinement history — and is never
presented as verified fact.

``organizations.org_value_stream_profile`` remains as a *projection* of the
validated hypothesis items (no parallel source of truth): validating a
hypothesis rewrites the projection; nothing else writes it.
"""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow

# Hypothesis lifecycle (contract: generated → under_review → validated → superseded).
HYPOTHESIS_STATUS_GENERATED = "generated"
HYPOTHESIS_STATUS_UNDER_REVIEW = "under_review"
HYPOTHESIS_STATUS_VALIDATED = "validated"
HYPOTHESIS_STATUS_SUPERSEDED = "superseded"

# Per-assumption validation states (human decides; dismissal is first-class).
ASSUMPTION_PROPOSED = "proposed"
ASSUMPTION_CONFIRMED = "confirmed"
ASSUMPTION_DISMISSED = "dismissed"


class BaselineRiskHypothesis(Base):
    """One generated draft of the organisation's business model.

    ``assumptions`` is a JSONB list of structured assumption items:

    .. code-block:: python

        {
            "kind": "business_process" | "business_service",
            "key": str,            # value-stream key or service key
            "name": str,           # display name
            "parent_key": str | None,  # owning process key for services
            "provenance": "inferred" | "template" | "scanner" | "public_onboarding",
            "confidence": "high" | "medium" | "low",
            "reason": str,         # explainable inference reason
            "suggested_priority": "critical" | "important" | "standard" | None,
            "validation": "proposed" | "confirmed" | "dismissed",
            "decided_by": str | None,
            "decided_at": str | None,  # ISO timestamp
        }
    """

    __tablename__ = "baseline_risk_hypotheses"

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = Column(String(20), nullable=False, default=HYPOTHESIS_STATUS_GENERATED)
    # Snapshot of the company context the hypothesis was generated from
    # (nace_code, industry, company_size, country, required_frameworks) —
    # the nearest existing equivalent of the contract's companyContextRef.
    company_context = Column(JSONB, nullable=False, default=dict)
    assumptions = Column(JSONB, nullable=False, default=list)
    generated_at = Column(DateTime, nullable=False, default=utcnow)
    validated_by: Mapped[str | None] = Column(String(100), nullable=True)
    validated_at = Column(DateTime, nullable=True)
    # Refinement history: a regenerated hypothesis supersedes this one.
    superseded_by_id: Mapped[str | None] = Column(
        String(36), ForeignKey("baseline_risk_hypotheses.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ix_baseline_risk_hypotheses_org_status", "organization_id", "status"),
    )
