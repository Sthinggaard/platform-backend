"""CA-05.B — the human-approved discovery boundary.

One row is one proposed boundary and its approval decision. The proposal is
never edited once approved: changing scope means proposing again and superseding
the old row, so what a human signed off stays exactly recoverable.
"""

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow
from src.core.constants.discovery_scope_proposal_enums import DiscoveryScopeProposalStatus


class DiscoveryScopeProposal(Base):
    __tablename__ = "discovery_scope_proposals"
    __table_args__ = (
        Index(
            "ix_discovery_scope_proposals_org_source_status",
            "organization_id",
            "evidence_source_id",
            "status",
        ),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    evidence_source_id: Mapped[str] = Column(
        String(36), ForeignKey("evidence_sources.id", ondelete="CASCADE"), nullable=False
    )
    permission_subject_id: Mapped[str] = Column(
        String(36), ForeignKey("permission_subjects.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    permission_profile_id: Mapped[str] = Column(
        String(36), ForeignKey("permission_profiles.id", ondelete="CASCADE"), nullable=False, unique=True
    )

    status: Mapped[str] = Column(String(30), nullable=False)

    # The proposed boundary. Stored as snapshots rather than references so an
    # approved boundary cannot drift when the underlying target rows change —
    # same principle as DiscoveryRun's own profile/target snapshots.
    inclusions: Mapped[list] = Column(JSONB, nullable=False, default=list)
    exclusions: Mapped[list] = Column(JSONB, nullable=False, default=list)
    checks: Mapped[list] = Column(JSONB, nullable=False, default=list)
    # Why each inclusion is here, carried from environment detection so the
    # reviewer can answer "why am I being asked to approve this?" without
    # re-deriving it.
    rationale: Mapped[dict] = Column(JSONB, nullable=False, default=dict)

    proposed_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)

    # Only the Technical Setup Owner may approve (contract, CA-05 rules).
    decided_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    decided_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    decision_note: Mapped[str | None] = Column(Text, nullable=True)

    superseded_by_proposal_id: Mapped[str | None] = Column(String(36), nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(
        DateTime, nullable=False, default=utcnow, onupdate=utcnow
    )

    @property
    def permission_subject_inactive_reason(self) -> str | None:
        if self.status in {
            DiscoveryScopeProposalStatus.REJECTED.value,
            DiscoveryScopeProposalStatus.SUPERSEDED.value,
        }:
            return f"The discovery scope proposal is {self.status}."
        return None


__all__ = ["DiscoveryScopeProposal"]
