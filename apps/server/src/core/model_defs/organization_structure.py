"""Organisation Structure — sufficient operational structure (post-ORG-ID stage).

``OrganizationUnit`` is a plain self-referential adjacency list (no fixed
depth, no materialized path/nested-set — this codebase has no deep trees
elsewhere and one isn't needed at this scale). Non-hierarchical
relationships (supported_by/governed_by/shared_with/...) live separately in
``OrganizationUnitRelationship`` so the platform never forces every real
relationship into one tree. Locations are separate from units (a unit with
35 stores gets 35 location rows, not 35 tree nodes). Duplicate-unit
detection is pairwise (confirmed with Søren) via
``OrganizationUnitMatchSuggestion`` — merging re-points every referencing
row rather than deleting anything, and is reversible.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Float, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow


class OrganizationUnit(Base):
    __tablename__ = "organization_units"
    __table_args__ = (
        Index("ix_organization_units_org_status", "organization_id", "status"),
        Index("ix_organization_units_org_parent", "organization_id", "parent_unit_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        "organization_id", ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = Column(String(255), nullable=False)
    code: Mapped[str | None] = Column(String(50), nullable=True)
    description: Mapped[str | None] = Column(Text, nullable=True)
    unit_type: Mapped[str] = Column(String(30), nullable=False)
    parent_unit_id: Mapped[str | None] = Column(
        String(36), ForeignKey("organization_units.id", ondelete="SET NULL"), nullable=True
    )
    legal_entity_id: Mapped[str | None] = Column(
        String(36), ForeignKey("organization_legal_entities.id", ondelete="SET NULL"), nullable=True
    )
    country_code: Mapped[str | None] = Column(String(2), nullable=True)
    # Free-text pointer, not a hard FK — a unit can span many OrganizationLocation rows.
    location_reference: Mapped[str | None] = Column(String(255), nullable=True)
    status: Mapped[str] = Column(String(20), nullable=False)
    scope_status: Mapped[str] = Column(String(30), nullable=False, default="unresolved")
    source: Mapped[str] = Column(String(30), nullable=False)
    source_reference: Mapped[str | None] = Column(String(255), nullable=True)
    confidence: Mapped[float | None] = Column(Float, nullable=True)
    # Set when this unit is archived via a confirmed merge — never deleted.
    merged_into_unit_id: Mapped[str | None] = Column(
        String(36), ForeignKey("organization_units.id", ondelete="SET NULL"), nullable=True
    )
    aliases: Mapped[list[str] | None] = Column(JSONB, nullable=True)
    confirmed_by_user_id: Mapped[int | None] = Column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    confirmed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class OrganizationUnitRelationship(Base):
    __tablename__ = "organization_unit_relationships"
    __table_args__ = (
        Index("ix_org_unit_relationships_org_source", "organization_id", "source_unit_id"),
        UniqueConstraint(
            "source_unit_id", "target_unit_id", "relationship_type", name="uq_org_unit_relationship"
        ),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    source_unit_id: Mapped[str] = Column(
        String(36), ForeignKey("organization_units.id", ondelete="CASCADE"), nullable=False
    )
    target_unit_id: Mapped[str] = Column(
        String(36), ForeignKey("organization_units.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type: Mapped[str] = Column(String(30), nullable=False)
    status: Mapped[str] = Column(String(20), nullable=False)
    source: Mapped[str] = Column(String(30), nullable=False)
    confidence: Mapped[float | None] = Column(Float, nullable=True)
    confirmed_by_user_id: Mapped[int | None] = Column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    confirmed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


class OrganizationLocation(Base):
    __tablename__ = "organization_locations"
    __table_args__ = (Index("ix_organization_locations_org_unit", "organization_id", "organization_unit_id"),)

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    organization_unit_id: Mapped[str | None] = Column(
        String(36), ForeignKey("organization_units.id", ondelete="SET NULL"), nullable=True
    )
    name: Mapped[str] = Column(String(255), nullable=False)
    location_type: Mapped[str] = Column(String(20), nullable=False)
    country_code: Mapped[str | None] = Column(String(2), nullable=True)
    region: Mapped[str | None] = Column(String(100), nullable=True)
    city: Mapped[str | None] = Column(String(100), nullable=True)
    address_reference: Mapped[str | None] = Column(String(255), nullable=True)
    status: Mapped[str] = Column(String(20), nullable=False)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


class OrganizationUnitMembership(Base):
    __tablename__ = "organization_unit_memberships"
    __table_args__ = (
        Index("ix_org_unit_memberships_org_unit", "organization_id", "organization_unit_id"),
        Index("ix_org_unit_memberships_org_user", "organization_id", "user_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    organization_unit_id: Mapped[str] = Column(
        String(36), ForeignKey("organization_units.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[int] = Column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    membership_role: Mapped[str] = Column(String(30), nullable=False)
    source: Mapped[str] = Column(String(30), nullable=False)
    status: Mapped[str] = Column(String(20), nullable=False)
    effective_from: Mapped[datetime | None] = Column(DateTime, nullable=True)
    effective_to: Mapped[datetime | None] = Column(DateTime, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


class OrganizationUnitMatchSuggestion(Base):
    __tablename__ = "organization_unit_match_suggestions"
    __table_args__ = (
        UniqueConstraint("organization_id", "unit_a_id", "unit_b_id", name="uq_org_unit_match_pair"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    unit_a_id: Mapped[str] = Column(
        String(36), ForeignKey("organization_units.id", ondelete="CASCADE"), nullable=False
    )
    unit_b_id: Mapped[str] = Column(
        String(36), ForeignKey("organization_units.id", ondelete="CASCADE"), nullable=False
    )
    match_confidence: Mapped[float] = Column(Float, nullable=False)
    matching_reasons: Mapped[list[str]] = Column(JSONB, nullable=False, default=list)
    status: Mapped[str] = Column(String(20), nullable=False)
    decided_by_user_id: Mapped[int | None] = Column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    decided_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


__all__ = [
    "OrganizationLocation",
    "OrganizationUnit",
    "OrganizationUnitMatchSuggestion",
    "OrganizationUnitMembership",
    "OrganizationUnitRelationship",
]
