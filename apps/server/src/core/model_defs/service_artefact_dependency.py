"""Human-confirmed reusable Artefact links for Business Services (#493)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow


class ServiceArtefactDependencyLink(Base):
    """A category-level library Artefact used by one service.

    This is not a logical-slot decision: the Intelligence Engine may later
    recommend a slot relationship from this confirmed service evidence.
    """

    __tablename__ = "service_artefact_dependency_links"
    __table_args__ = (
        UniqueConstraint("organization_id", "service_id", "asset_id", name="uq_service_artefact_dependency_link"),
        Index("ix_service_artefact_dependency_links_org_service", "organization_id", "service_id"),
        Index("ix_service_artefact_dependency_links_org_asset", "organization_id", "asset_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    service_id: Mapped[str] = Column(String(36), ForeignKey("business_services.id", ondelete="CASCADE"), nullable=False)
    asset_id: Mapped[int] = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    dependency_category: Mapped[str] = Column(String(30), nullable=False)
    linked_by_user_id: Mapped[int | None] = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    linked_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
