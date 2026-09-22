"""CA-07.5 — one artefact's journey towards deeper access, and where it stopped.

A second, independent state on an artefact. CA-06 already gives it an *identity*
lifecycle; this is a different question about the same row, and the two do not
line up — an artefact can be confirmed with no access, or unconfirmed with access
already approved. Overloading one column would make two questions look like one
answer, so this is its own table.

**The columns that carry the contract's headline rule are
``verification_ready_at`` and ``verification_approved_at``, and the fact that
they are two columns.** Being ready is not being allowed. If readiness and
permission shared a column, arriving at readiness would *be* permission, and the
rule *"access does not start verification"* would have nowhere left to live.

``verification_approved_source`` records which kind of human "yes" it was — this
artefact, now, or the organisation's standing Mode A decision, which Søren ruled
satisfies the contract. Both are genuine; an auditor deserves to know which.

One row per artefact, enforced by a unique constraint on
``(organization_id, asset_id)``: an artefact whose access journey could exist
twice would have two answers to "may this be verified?", and nothing to say which
one governs.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped

from src.core.constants.artefact_access_lifecycle_enums import ArtefactAccessState
from src.core.database import Base
from src.core.model_defs.common import utcnow


class ArtefactAccessLifecycle(Base):
    __tablename__ = "artefact_access_lifecycles"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "asset_id", name="uq_artefact_access_lifecycle_artefact"
        ),
        # The contract's rule, held by the database as well as by the service: an
        # artefact cannot be running or complete unless a human approval is
        # stamped on the row. A future writer that bypasses ``mark_running``
        # still cannot record a run nobody authorised.
        CheckConstraint(
            "state NOT IN ('running', 'complete') OR verification_approved_at IS NOT NULL",
            name="ck_artefact_access_run_requires_approval",
        ),
        # And approval cannot be stamped without saying which kind of "yes" it
        # was, so "who approved this?" is always answerable.
        CheckConstraint(
            "verification_approved_at IS NULL OR verification_approved_source IS NOT NULL",
            name="ck_artefact_access_approval_names_its_source",
        ),
        Index("ix_artefact_access_lifecycles_org_state", "organization_id", "state"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[int] = Column(
        Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )

    state: Mapped[str] = Column(
        String(30), nullable=False, default=ArtefactAccessState.ACCESS_REQUESTED.value
    )

    # Which of the five choices started this. Only two of them ask for deeper
    # access; the other three are recorded decisions that never reach here, and
    # keeping the choice on the row is how a reader sees which one it was.
    requested_choice: Mapped[str] = Column(String(30), nullable=False)
    # Why this artefact departed from the organisation's standing default, when
    # it did. Empty when it agreed with it — the common case costs no words.
    deviation_reason: Mapped[str | None] = Column(Text, nullable=True)
    requested_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    requested_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # The Connector this artefact is reached through, once one is named. Nullable
    # because ACCESS_REQUESTED precedes it: a person asks for access before
    # anybody has built the route to it.
    connector_id: Mapped[str | None] = Column(
        String(36), ForeignKey("access_connectors.id", ondelete="SET NULL"), nullable=True
    )
    configured_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    # The test that proved it works, so "tested" names evidence rather than an
    # assertion somebody typed.
    access_test_id: Mapped[str | None] = Column(
        String(36), ForeignKey("connector_access_tests.id", ondelete="SET NULL"), nullable=True
    )
    tested_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    # Two columns, and the distance between them is the contract's rule.
    verification_ready_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    verification_approved_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    verification_approved_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    verification_approved_source: Mapped[str | None] = Column(String(30), nullable=True)
    #: The standing decision a run inherited its approval from, when it did — so
    #: "who approved this?" resolves to a record rather than to a policy name.
    verification_approval_policy_id: Mapped[str | None] = Column(
        String(36), ForeignKey("contextual_access_policies.id", ondelete="SET NULL"), nullable=True
    )

    # CA-08's, not this module's. Recorded here because the states are one
    # sequence and splitting the last two elsewhere would make the journey
    # unreadable in one place.
    running_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(
        DateTime, nullable=False, default=utcnow, onupdate=utcnow
    )


__all__ = ["ArtefactAccessLifecycle"]
