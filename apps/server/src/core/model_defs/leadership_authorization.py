"""Leadership authorisation of the onboarding programme (onboarding governance, phase 1).

Contract (risklence-onboarding-governance): "leadership alignment and
organisation authority" is the first gate in the canonical staged onboarding
sequence — before a Technical Setup Owner is assigned, before any process
workspace is prepared. Leadership or an authorised governance body sponsors
the implementation and approves its scope; the Organisation Administrator
only coordinates and prepares the record for approval.

Mirrors RiskAppetitePolicy's append-only draft -> leadership_review -> active
-> superseded/withdrawn lifecycle: the administrator prepares a draft, submits
it, and a mapped Approver/Escalation Contact approves or rejects on the
governing body's behalf. Writing a new active version supersedes the previous
one rather than mutating history.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.constants.leadership_authorization_enums import LeadershipAuthorizationStatus
from src.core.model_defs.common import utcnow


class LeadershipAuthorization(Base):
    __tablename__ = "leadership_authorizations"
    __table_args__ = (
        Index("ix_leadership_authorizations_org_status", "organization_id", "status"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = Column(
        String(20), nullable=False, default=LeadershipAuthorizationStatus.DRAFT.value
    )
    version: Mapped[int] = Column(Integer, nullable=False, default=1)
    # The accountable sponsor must be a real Risklence user, and only that
    # user may approve or reject this record (see leadership_authorization.py
    # routes) — accountability requires the ability to actually see and act
    # on what you're named accountable for, not just be named in free text.
    # Display name/title are derived from the User record, never duplicated
    # here (see user_display_service.user_display_name). Nullable because a
    # backfilled/legacy record must never invent a sponsor that was never
    # actually named — those show "Not recorded" instead.
    sponsor_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    approving_body: Mapped[str] = Column(String(30), nullable=False)
    authorized_scope: Mapped[str] = Column(Text, nullable=False)
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
    superseded_by_id: Mapped[str | None] = Column(
        String(36), ForeignKey("leadership_authorizations.id", ondelete="SET NULL"), nullable=True
    )
    # True for a record synthesised for an organisation that already had
    # process owners before this gate existed — an honest, visible flag,
    # never silently indistinguishable from a real leadership decision.
    backfilled: Mapped[bool] = Column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
