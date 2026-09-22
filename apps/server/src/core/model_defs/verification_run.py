"""CA-08.1 (#289) — what was verified, under whose approval, and what came of it.

One row per run. The lifecycle records that an artefact reached ``RUNNING``;
this records the run itself, because a state is not an account of what was done
and CA-08's contract is about evidence.

**Three things are snapshotted rather than looked up.** The approval source, the
approving person and the permission profile are copied onto the row at the
moment the run begins. All three are versioned or supersedable elsewhere, and
"what was this run allowed to do?" must not change its answer when a policy is
later replaced — which is exactly what a foreign key read at display time would
do.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped

from src.core.constants.verification_run_enums import VerificationRunStatus
from src.core.database import Base
from src.core.model_defs.common import utcnow


class VerificationRun(Base):
    """A deep verification that began, because a person allowed it to."""

    __tablename__ = "verification_runs"
    __table_args__ = (
        Index("ix_verification_runs_org_status", "organization_id", "status"),
        # An artefact's history, newest first — the query the surface (#294) runs.
        Index("ix_verification_runs_asset", "organization_id", "asset_id", "began_at"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[int] = Column(
        Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    # The access journey this run belongs to. RESTRICT rather than CASCADE: a
    # completed verification must outlive the journey that permitted it, which is
    # the instinct CA-07.5 already recorded about connectors.
    lifecycle_id: Mapped[str] = Column(
        String(36),
        ForeignKey("artefact_access_lifecycles.id", ondelete="RESTRICT"),
        nullable=False,
    )

    # --- The approval this run acted on, snapshotted ---
    approval_source: Mapped[str] = Column(String(30), nullable=False)
    approved_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    #: Null only where a standing approval carried it and no person was named.
    approved_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    # --- What it was allowed to do, snapshotted ---
    permission_profile_id: Mapped[str] = Column(
        String(36), ForeignKey("permission_profiles.id", ondelete="RESTRICT"), nullable=False
    )

    status: Mapped[str] = Column(
        String(20), nullable=False, default=VerificationRunStatus.RUNNING.value
    )
    began_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    finished_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    #: Why it did not finish, in words a person reads. Set for FAILED, and for
    #: CANCELLED where somebody gave a reason.
    failure_reason: Mapped[str | None] = Column(Text, nullable=True)

    began_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(
        DateTime, nullable=False, default=utcnow, onupdate=utcnow
    )
