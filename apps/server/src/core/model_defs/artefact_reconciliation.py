"""CA-06.4 — the uncertain matches a person has to resolve, and the merges they decide.

Two records, because they answer two different questions:

* ``ArtefactIdentityConflict`` — "the platform is unsure whether these two are
  the same thing, and here is why." Raised by reconciliation, resolved only by a
  person. Its resolution is **durable**: a dismissed conflict is not re-raised by
  the next scan, or the platform would be asking the same question forever.
* ``ArtefactMergeRecord`` — "a person decided they were the same thing, and this
  is exactly what moved." The snapshot is what makes a merge reversible: without
  a record of which rows moved and which were collapsed as duplicates, an undo
  would be guesswork.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, relationship

from src.core.database import Base
from src.core.model_defs.common import utcnow


class ArtefactIdentityConflict(Base):
    """A question about two artefacts that only a person can answer.

    The pair is stored **ordered** (``lower_asset_id`` < ``higher_asset_id``) so
    that A-vs-B and B-vs-A are one conflict rather than two. Without that, a
    person could dismiss the pair in one direction and be asked again in the
    other.
    """

    __tablename__ = "artefact_identity_conflicts"
    __table_args__ = (
        Index(
            "uq_artefact_identity_conflicts_pair",
            "organization_id",
            "lower_asset_id",
            "higher_asset_id",
            unique=True,
        ),
        Index("ix_artefact_identity_conflicts_org_state", "organization_id", "state"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    lower_asset_id: Mapped[int] = Column(
        Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    higher_asset_id: Mapped[int] = Column(
        Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    state: Mapped[str] = Column(String(30), nullable=False)
    #: Why the platform is unsure, in words a reviewer can act on. Never a bare
    #: "these might match" — the AC's own wording, and the difference between a
    #: question someone can answer and one they can only guess at.
    reason: Mapped[str] = Column(Text, nullable=False)
    #: What the two sides actually have in common, and where each was seen, so
    #: the reviewer is not sent hunting through other screens to decide. A
    #: snapshot of the evidence at the moment the question was raised.
    evidence: Mapped[dict | None] = Column(JSONB)

    raised_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    #: Bumped when reconciliation sees the same ambiguity again while the
    #: conflict is still open — the question is not new, but it is not stale
    #: either, and a reviewer deserves to know it is still live.
    last_raised_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    resolved_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    resolved_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    resolution_reason: Mapped[str | None] = Column(Text)

    organization: Mapped["Organization"] = relationship("Organization")


class ArtefactMergeRecord(Base):
    """What a merge did, in enough detail to undo it.

    ``moved`` holds the ids that were re-pointed and full snapshots of anything
    that had to be collapsed because the survivor already held the equivalent
    row (a duplicate identifier, port, or relationship edge). Ids alone are not
    enough for those: the row is gone, so restoring it needs its contents.

    A reversed merge keeps its record. "This was merged on the 3rd and undone on
    the 5th" is exactly the kind of thing an audit asks about, and deleting the
    record would erase the decision as well as its reversal.
    """

    __tablename__ = "artefact_merge_records"
    __table_args__ = (
        Index("ix_artefact_merge_records_org_survivor", "organization_id", "survivor_asset_id"),
        Index("ix_artefact_merge_records_org_merged", "organization_id", "merged_asset_id"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    #: The record that remains the artefact.
    survivor_asset_id: Mapped[int] = Column(
        Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: The record that became an alias of it. Still present, in state MERGED —
    #: a merge never deletes anything.
    merged_asset_id: Mapped[int] = Column(
        Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    conflict_id: Mapped[int | None] = Column(
        Integer, ForeignKey("artefact_identity_conflicts.id", ondelete="SET NULL"), nullable=True
    )

    decided_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    decided_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    reason: Mapped[str | None] = Column(Text)

    #: The lifecycle state the merged record held before the merge, so undoing
    #: restores what it was rather than assuming ACTIVE.
    previous_lifecycle_state: Mapped[str] = Column(String(20), nullable=False)
    moved: Mapped[dict] = Column(JSONB, nullable=False)

    reversed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    reversed_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reversal_reason: Mapped[str | None] = Column(Text)

    organization: Mapped["Organization"] = relationship("Organization")


__all__ = ["ArtefactIdentityConflict", "ArtefactMergeRecord"]
