"""Risk appetite policies at the canonical decision scopes (dashboard epic, slice 2).

Contract (risklence-domain-decision-model): appetite resolves as

    Active Organisation Policy
    → active Business Process override
    → approved temporary decision-specific exception

Every scope keeps the same six-dimension ``answers`` vocabulary the service
configs already use, carries approval provenance, and is versioned append-only:
writing a new policy supersedes the previous active row rather than mutating
history. A decision exception is temporary by definition — it must carry an
expiry (``effective_to``) and a review date, and it never outlives them.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow

APPETITE_SCOPE_ORGANISATION = "organisation"
APPETITE_SCOPE_BUSINESS_PROCESS = "business_process"
APPETITE_SCOPE_DECISION_EXCEPTION = "decision_exception"

APPETITE_SCOPES = (
    APPETITE_SCOPE_ORGANISATION,
    APPETITE_SCOPE_BUSINESS_PROCESS,
    APPETITE_SCOPE_DECISION_EXCEPTION,
)

APPETITE_POLICY_ACTIVE = "active"
APPETITE_POLICY_SUPERSEDED = "superseded"
APPETITE_POLICY_DRAFT = "draft"
APPETITE_POLICY_LEADERSHIP_REVIEW = "leadership_review"
APPETITE_POLICY_WITHDRAWN = "withdrawn"

APPETITE_AUDIT_DRAFT_CREATED = "risk_appetite_draft_created"
APPETITE_AUDIT_SUBMITTED = "risk_appetite_submitted_for_leadership_review"
APPETITE_AUDIT_APPROVED = "risk_appetite_approved"
APPETITE_AUDIT_REJECTED = "risk_appetite_rejected"
# The Process Owner accepted the organisation-wide appetite for their process
# rather than proposing a deviation. Leadership already approved that policy,
# so nothing new is approved here — but the decision to inherit is still a
# human decision and is recorded as one.
APPETITE_AUDIT_ORGANISATION_ACCEPTED = "risk_appetite_organisation_accepted"

APPETITE_ERROR_ADMIN_REQUIRED = "Organisation administrator access is required to prepare appetite policy"
# Organisation appetite and changed Business Process proposals are approved
# by the organisation's named leadership sponsor
# (LeadershipAuthorization.sponsor_user_id) — the same real, named account
# that authorised the onboarding programme — not the generic Approver/
# Escalation Contact mandate role appetite used before this cascade redesign.
APPETITE_ERROR_LEADERSHIP_SPONSOR_REQUIRED = (
    "Only the organisation's named leadership sponsor may approve or reject risk appetite"
)
APPETITE_ERROR_POLICY_NOT_FOUND = "Organisation appetite policy not found"
APPETITE_ERROR_ORGANISATION_DRAFT_REQUIRED = "Organisation appetite must be prepared as a draft before leadership approval"
APPETITE_ERROR_PROCESS_DRAFT_REQUIRED = "Process Risk Appetite must be proposed as a draft by the Process Owner before leadership approval"


class RiskAppetitePolicy(Base):
    __tablename__ = "risk_appetite_policies"
    __table_args__ = (
        Index("ix_risk_appetite_policies_org_scope", "organization_id", "scope", "status"),
        Index("ix_risk_appetite_policies_process", "process_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    scope: Mapped[str] = Column(String(30), nullable=False)
    # Required for business_process and decision_exception scopes.
    process_id: Mapped[str | None] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="CASCADE"), nullable=True
    )
    # The decision the exception belongs to (decision record / threat reference).
    decision_reference: Mapped[str | None] = Column(String(100), nullable=True)
    # Six-dimension appetite answers — same vocabulary as service-level configs.
    answers: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = Column(String(20), nullable=False, default=APPETITE_POLICY_ACTIVE)
    version: Mapped[int] = Column(Integer, nullable=False, default=1)
    prepared_by: Mapped[str | None] = Column(String(255), nullable=True)
    submitted_by: Mapped[str | None] = Column(String(255), nullable=True)
    submitted_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    approved_by: Mapped[str | None] = Column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    rejected_by: Mapped[str | None] = Column(String(255), nullable=True)
    rejected_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    rejection_reason: Mapped[str | None] = Column(Text, nullable=True)
    approval_reference: Mapped[str | None] = Column(String(500), nullable=True)
    note: Mapped[str | None] = Column(Text, nullable=True)
    effective_from: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    # Exceptions are temporary: effective_to and review_at are mandatory there.
    effective_to: Mapped[datetime | None] = Column(DateTime, nullable=True)
    review_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    superseded_by_id: Mapped[str | None] = Column(
        String(36), ForeignKey("risk_appetite_policies.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
