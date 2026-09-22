"""CA-07.0 — the organisation's own governed decisions about contextual access.

Contract (CA-07): *"Allow restricted deeper access when network evidence is
insufficient."* Whether that access runs unattended on a cadence or only when a
person triggers it is not a product default someone else picks — it is a
governance decision about the organisation's own risk, and the two modes demand
different credential models. That is why this record **gates** CA-07.2 and
CA-07.5 rather than being an assumption inside them.

Reuses ``RiskAppetitePolicy``'s governance shape rather than inventing a second
one: versioned, attributed (``prepared_by`` / ``submitted_by`` / ``approved_by``
with timestamps), effective-dated, and **superseded rather than overwritten**, so
"what did we decide, when, and who approved it" stays answerable after the
decision changes. No update path exists by design — changing the decision means
approving a new version.

Two things this model deliberately does *not* do:

- **It holds no cadence.** "Every 30 days" belongs to the recurrence schedule
  (#242), which must honour this record's ``effective_to``. A schedule that
  outlives its approval is the failure that separation prevents.
- **It holds no permitted-choice set.** The ``deeper_access_default`` decision
  supplies the default answer for the five per-artefact access choices; it never
  removes any of them (``CLAUDE.md:217`` — the user is never locked out).
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped

from src.core.constants.contextual_access_enums import ContextualAccessPolicyStatus
from src.core.database import Base
from src.core.model_defs.common import utcnow


class ContextualAccessPolicy(Base):
    __tablename__ = "contextual_access_policies"
    __table_args__ = (
        Index(
            "ix_contextual_access_policies_org_decision",
            "organization_id",
            "decision",
            "status",
        ),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # ContextualAccessDecision — which decision this record carries. Each
    # decision is versioned independently, so an organisation can supersede its
    # default answer without reopening its operating mode.
    decision: Mapped[str] = Column(String(40), nullable=False)
    # The chosen value, validated against the decision it belongs to
    # (CONTEXTUAL_ACCESS_DECISION_CHOICES).
    choice: Mapped[str] = Column(String(40), nullable=False)
    status: Mapped[str] = Column(
        String(20), nullable=False, default=ContextualAccessPolicyStatus.DRAFT.value
    )
    version: Mapped[int] = Column(Integer, nullable=False, default=1)

    # The consequence text as it was actually shown at approval time, not a
    # reference to today's copy. The audit question is "what were they told?",
    # and that answer must not drift when the wording is later improved.
    consequence_statement: Mapped[str] = Column(Text, nullable=False)
    # Set by the approver, never by the preparer — the acknowledgement belongs
    # to whoever accepted the consequence, not whoever wrote it down.
    consequence_acknowledged: Mapped[bool] = Column(Boolean, nullable=False, default=False)

    prepared_by: Mapped[str | None] = Column(String(255), nullable=True)
    submitted_by: Mapped[str | None] = Column(String(255), nullable=True)
    submitted_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    approved_by: Mapped[str | None] = Column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    approval_reference: Mapped[str | None] = Column(String(500), nullable=True)
    rejected_by: Mapped[str | None] = Column(String(255), nullable=True)
    rejected_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    rejection_reason: Mapped[str | None] = Column(Text, nullable=True)
    note: Mapped[str | None] = Column(Text, nullable=True)

    effective_from: Mapped[datetime | None] = Column(DateTime, nullable=True)
    # Nullable in general; mandatory for scheduled autonomous access, where a
    # standing permission with no expiry would stop being a decision.
    effective_to: Mapped[datetime | None] = Column(DateTime, nullable=True)
    review_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    superseded_by_id: Mapped[str | None] = Column(
        String(36), ForeignKey("contextual_access_policies.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


__all__ = ["ContextualAccessPolicy"]
