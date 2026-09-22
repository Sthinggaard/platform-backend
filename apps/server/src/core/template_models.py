"""Persisted template-library ORM models.

These tables back the versioned template-driven dependency mapping library.
They are org-agnostic reference data and must never store tenant runtime state.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    ARRAY,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, relationship

from src.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ProcessTemplate(Base):
    """Versioned business-process template definition."""

    __tablename__ = "process_templates"
    __table_args__ = (
        UniqueConstraint("template_key", "version", name="uq_process_templates_key_version"),
        Index("ix_process_templates_key_active", "template_key", "is_active"),
        Index("ix_process_templates_family_active", "process_family", "is_active"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True)
    template_key: Mapped[str] = Column(String(100), nullable=False)
    name: Mapped[str] = Column(String(200), nullable=False)
    description: Mapped[str] = Column(Text, nullable=False)
    process_family: Mapped[str] = Column(String(50), nullable=False)
    version: Mapped[int] = Column(Integer, nullable=False, default=1)
    status: Mapped[str] = Column(String(20), nullable=False, default="published")
    is_active: Mapped[bool] = Column(Boolean, nullable=False, default=True)
    service_slots: Mapped[list] = Column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<ProcessTemplate(key='{self.template_key}', version={self.version}, active={self.is_active})>"


class ServiceTemplate(Base):
    """Versioned business-service template definition."""

    __tablename__ = "service_templates"
    __table_args__ = (
        UniqueConstraint("service_key", "version", name="uq_service_templates_key_version"),
        Index("ix_service_templates_key_active", "service_key", "is_active"),
        Index("ix_service_templates_archetype_active", "archetype", "is_active"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True)
    service_key: Mapped[str] = Column(String(100), nullable=False)
    service_name: Mapped[str] = Column(String(200), nullable=False)
    archetype: Mapped[str] = Column(String(100), nullable=False)
    version: Mapped[int] = Column(Integer, nullable=False, default=1)
    status: Mapped[str] = Column(String(20), nullable=False, default="published")
    is_active: Mapped[bool] = Column(Boolean, nullable=False, default=True)
    capability_groups: Mapped[list] = Column(JSONB, nullable=False, default=list)
    seeded_from: Mapped[str | None] = Column(String(100), nullable=True)
    # Business Service Profile layer (internal knowledge model — never
    # exposed to customers as "profile versions").
    capability_statement: Mapped[str | None] = Column(Text, nullable=True)
    default_impact_model: Mapped[dict | None] = Column(JSONB, nullable=True)
    operational_expectations: Mapped[list] = Column(JSONB, nullable=False, default=list)
    common_risk_patterns: Mapped[list] = Column(JSONB, nullable=False, default=list)
    override_policy: Mapped[dict | None] = Column(JSONB, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    slot_templates: Mapped[list["SlotTemplate"]] = relationship(
        "SlotTemplate",
        back_populates="service_template",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<ServiceTemplate(key='{self.service_key}', version={self.version}, active={self.is_active})>"


class SlotTemplate(Base):
    """Immutable slot definition within a specific service-template version."""

    __tablename__ = "slot_templates"
    __table_args__ = (
        UniqueConstraint("service_template_id", "slot_id", name="uq_slot_templates_service_slot"),
        Index("ix_slot_templates_service_template", "service_template_id"),
        Index("ix_slot_templates_slot_id", "slot_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True)
    service_template_id: Mapped[str] = Column(
        String(36),
        ForeignKey("service_templates.id", ondelete="CASCADE"),
        nullable=False,
    )
    slot_id: Mapped[str] = Column(String(100), nullable=False)
    label: Mapped[str] = Column(String(200), nullable=False)
    purpose: Mapped[str] = Column(Text, nullable=False)
    expected_asset_types: Mapped[list[str]] = Column(ARRAY(String), nullable=False, default=list)
    required: Mapped[bool] = Column(Boolean, nullable=False, default=False)
    capability_group_key: Mapped[str] = Column(String(100), nullable=False)
    dependency_category: Mapped[str | None] = Column(String(30), nullable=True)
    display_order: Mapped[int] = Column(Integer, nullable=False, default=0)
    # Profile enrichment: intelligence-engine matching inputs.
    matching_hints: Mapped[list] = Column(JSONB, nullable=False, default=list)
    expected_evidence_types: Mapped[list] = Column(JSONB, nullable=False, default=list)
    risk_patterns: Mapped[list] = Column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    service_template: Mapped[ServiceTemplate] = relationship(
        "ServiceTemplate",
        back_populates="slot_templates",
    )

    def __repr__(self) -> str:
        return f"<SlotTemplate(slot_id='{self.slot_id}', service_template_id='{self.service_template_id}')>"
