"""CA-07.1 (#235) — every answer a person gave about deeper access, kept.

The story's fourth criterion is the reason this exists: *"the choice is recorded
as a decision with attribution — **including network-only and review later,
which are answers, not absence of one**."*

Before this, three of the five choices could not be recorded anywhere.
``request_access`` (CA-07.5) refuses ``network_only``, ``exclude`` and
``review_later`` by name, correctly — they do not start an access journey — but
that left the platform unable to say that anybody had answered at all. "We
decided network-only in August" and "nobody has looked at this" were the same
absence of data, which is precisely the failure the standing-policy amendment
warns about: a default that turns a real gap into an invisible one.

**Distinct from ``ArtefactAccessLifecycle``, deliberately.** That table is the
*journey*: one row per artefact, a state machine from ACCESS_REQUESTED to
COMPLETE, with CHECK constraints that only make sense for access that is being
sought. This is the *history*: many rows per artefact, one per answer, including
answers that ask for nothing. A person may choose "review later" today and
"connect host" next month, and both are real decisions with different authors —
the journey cannot hold two, and should not try.

Nothing here is a scan and nothing here starts one. The row is the record that
a person answered, and for the two access-seeking choices the lifecycle is
started alongside it by the same call.
"""

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow


class ArtefactAccessDecision(Base):
    __tablename__ = "artefact_access_decisions"
    __table_args__ = (
        # "What is the current answer for this artefact, and what came before?"
        # is the only question this table is read for.
        # The organization_id index comes from `index=True` on the column below,
        # which SQLAlchemy names ix_artefact_access_decisions_organization_id —
        # declaring it here as well creates it twice.
        Index("ix_artefact_access_decisions_org_asset", "organization_id", "asset_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id"), nullable=False, index=True
    )
    asset_id: Mapped[int] = Column(
        Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    #: One of the five ``ArtefactAccessChoice`` members. All five are storable —
    #: the whole point of the record.
    choice: Mapped[str] = Column(String(30), nullable=False)

    #: What the organisation's standing policy said at the moment of the answer,
    #: snapshotted rather than looked up later. The policy is versioned and can be
    #: superseded; an auditor asking "was this a deviation?" must get the answer
    #: that was true when the person decided, not the one true today.
    standing_default: Mapped[str | None] = Column(String(30), nullable=True)
    #: Required when the choice departs from ``standing_default``, per the
    #: platform's existing idiom — accepting the recommended route is a single
    #: confirm, taking any other owes a recorded reason. Enforced in the service,
    #: because "deviates" is a comparison the database cannot make.
    deviation_reason: Mapped[str | None] = Column(Text, nullable=True)

    #: Why the platform could not name the artefact when the decision was taken,
    #: as an ``ArtefactIdentityUndetermined`` member, or null if it could.
    #: Snapshotted for the same reason as the default above: it is the evidence
    #: the person was shown, and a later scan must not rewrite what they saw.
    identity_undetermined_reason: Mapped[str | None] = Column(String(40), nullable=True)

    decided_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    #: Nullable only because a user row can be deleted; ON DELETE SET NULL keeps
    #: the decision rather than the attribution, on the precedent CA-07.5 set. A
    #: decision that loses its author is still a decision that was taken.
    decided_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
