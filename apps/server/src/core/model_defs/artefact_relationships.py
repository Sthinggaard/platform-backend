"""CA-06.3 — the edges between artefacts.

One table, deliberately: a relationship is a claim about two artefacts, and
splitting it by type would turn "what is connected to this?" into a union across
tables. The vocabulary lives in ``constants/artefact_relationship_enums.py``.

Strictly artefact-to-artefact. Business Service dependency mapping is CA-09A's
``SlotInstance``, not this.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, relationship

from src.core.database import Base
from src.core.model_defs.common import utcnow


class ArtefactRelationship(Base):
    """One directed, typed claim that two artefacts are related.

    Direction matters and is read from the source's side: *source RUNS_ON
    target* is not the same statement as the reverse, and storing it
    symmetrically would lose which artefact is the host and which is the guest.

    Uniqueness is on (source, target, type) rather than on the pair alone,
    because two artefacts can legitimately be related in more than one way — a
    service both RESOLVES_TO and CONNECTS_TO the same address is two facts, not
    a contradiction.
    """

    __tablename__ = "artefact_relationships"
    __table_args__ = (
        Index(
            "uq_artefact_relationships_source_target_type",
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            unique=True,
        ),
        # The two lookups this table exists to serve: "what does this artefact
        # depend on" and "what depends on this artefact". Tenant scoping leads.
        Index("ix_artefact_relationships_org_source", "organization_id", "source_asset_id"),
        Index("ix_artefact_relationships_org_target", "organization_id", "target_asset_id"),
        Index("ix_artefact_relationships_org_state", "organization_id", "state"),
        # An artefact cannot run on itself. Enforced in the database because a
        # self-edge is not a data-quality nuisance — it is a cycle that any
        # traversal built on this table would have to defend against forever.
        CheckConstraint("source_asset_id <> target_asset_id", name="ck_artefact_relationship_not_self"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    source_asset_id: Mapped[int] = Column(
        Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_asset_id: Mapped[int] = Column(
        Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Controlled vocabularies validated at the service layer, matching the
    # String-not-Enum precedent this domain already sets (AssetEvidenceSignal.kind,
    # AssetIdentifier.identifier_type).
    relationship_type: Mapped[str] = Column(String(40), nullable=False)
    #: observed / inferred / asserted_by_person. Never defaulted: a relationship
    #: that cannot say who claimed it is exactly the ambiguity CA-06.3 exists to
    #: prevent, so the caller must state it.
    origin: Mapped[str] = Column(String(30), nullable=False)
    confidence: Mapped[str] = Column(String(10), nullable=False)
    state: Mapped[str] = Column(String(20), nullable=False)

    #: Free text, and deliberately so: this is the human-readable *because*,
    #: shown next to the claim. It explains a specific pair, so a controlled
    #: vocabulary would either be useless or would have to grow forever.
    reason: Mapped[str | None] = Column(Text)

    # Provenance. Same shape and same rule as CA-06.2's: nullable, never
    # backfilled, absent reads as absent. A relationship a person asserted has
    # no evidence package, and one read from a scan has no asserting user.
    evidence_package_id: Mapped[str | None] = Column(
        String(36), ForeignKey("evidence_packages.id", ondelete="SET NULL"), nullable=True
    )
    scanner_instance_id: Mapped[str | None] = Column(
        String(36), ForeignKey("scanner_instances.id", ondelete="SET NULL"), nullable=True
    )
    observed_by_source: Mapped[str | None] = Column(String(255))
    asserted_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    first_seen_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    #: When it stopped being held true. Set alongside a non-ACTIVE state; the
    #: row itself is never deleted, so "they were connected until the 14th"
    #: stays answerable.
    withdrawn_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    source_asset: Mapped["Asset"] = relationship(
        "Asset", foreign_keys=[source_asset_id], back_populates="outgoing_relationships"
    )
    target_asset: Mapped["Asset"] = relationship(
        "Asset", foreign_keys=[target_asset_id], back_populates="incoming_relationships"
    )
    organization: Mapped["Organization"] = relationship("Organization")


__all__ = ["ArtefactRelationship"]
