"""Organisation Identity Setup — post-signup identity confirmation & scoping.

Establishes: legal identity + registration country + organisation type +
a primary legal entity + a confirmed Risklence implementation scope +
identity confirmation and provenance. Deliberately does not model asset or
process criticality, business impact, risk appetite, or resilience — those
belong to other bounded contexts.

``OrganizationIdentityConfirmation`` mirrors ``LeadershipAuthorization``'s
proven pattern: a real ``User`` FK as the accountable actor (never free
text), append-only history via ``superseded_by_id`` rather than mutating a
status column on ``Organization`` directly, and a correction reason
required whenever a confirmed record is superseded.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.constants.organization_identity_enums import (
    OrganizationIdentityConfirmationStatus,
)
from src.core.database import Base
from src.core.model_defs.common import utcnow


class OrganizationLegalEntity(Base):
    __tablename__ = "organization_legal_entities"
    __table_args__ = (Index("ix_organization_legal_entities_org", "organization_id"),)

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    legal_name: Mapped[str] = Column(String(255), nullable=False)
    registration_number: Mapped[str | None] = Column(String(50), nullable=True)
    registration_country: Mapped[str] = Column(String(2), nullable=False)
    entity_type: Mapped[str] = Column(String(30), nullable=False)
    status: Mapped[str] = Column(String(20), nullable=False)
    is_primary: Mapped[bool] = Column(Boolean, nullable=False, default=False)
    parent_entity_id: Mapped[str | None] = Column(
        String(36), ForeignKey("organization_legal_entities.id", ondelete="SET NULL"), nullable=True
    )
    source_evidence_id: Mapped[str | None] = Column(
        String(36),
        ForeignKey("organization_identity_evidence.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class OrganizationScope(Base):
    __tablename__ = "organization_scopes"
    __table_args__ = (Index("ix_organization_scopes_org_status", "organization_id", "status"),)

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    scope_type: Mapped[str] = Column(String(30), nullable=False)
    name: Mapped[str] = Column(String(255), nullable=False)
    description: Mapped[str | None] = Column(Text, nullable=True)
    status: Mapped[str] = Column(String(20), nullable=False)
    included_entity_ids: Mapped[list[str] | None] = Column(JSONB, nullable=True)
    excluded_entity_ids: Mapped[list[str] | None] = Column(JSONB, nullable=True)
    included_countries: Mapped[list[str] | None] = Column(JSONB, nullable=True)
    confirmed_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    confirmed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class OrganizationIdentityEvidence(Base):
    __tablename__ = "organization_identity_evidence"
    __table_args__ = (Index("ix_organization_identity_evidence_org", "organization_id"),)

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    source_type: Mapped[str] = Column(String(30), nullable=False)
    source_reference: Mapped[str | None] = Column(String(100), nullable=True)
    observed_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    raw_legal_name: Mapped[str | None] = Column(String(255), nullable=True)
    raw_industry_code: Mapped[str | None] = Column(String(20), nullable=True)
    raw_legal_form: Mapped[str | None] = Column(String(100), nullable=True)
    raw_address: Mapped[dict | None] = Column(JSONB, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


class OrganizationIdentityConfirmation(Base):
    __tablename__ = "organization_identity_confirmations"
    __table_args__ = (
        Index("ix_organization_identity_confirmations_org_status", "organization_id", "status"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = Column(
        String(20), nullable=False, default=OrganizationIdentityConfirmationStatus.DRAFT.value
    )
    version: Mapped[int] = Column(Integer, nullable=False, default=1)
    confirmed_legal_name: Mapped[str | None] = Column(String(255), nullable=True)
    confirmed_registration_country: Mapped[str | None] = Column(String(2), nullable=True)
    confirmed_organization_type: Mapped[str | None] = Column(String(30), nullable=True)
    evidence_id: Mapped[str | None] = Column(
        String(36),
        ForeignKey("organization_identity_evidence.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Real actor FK, never free text — mirrors LeadershipAuthorization's
    # sponsor_user_id. Nullable only for a legacy/backfilled row that must
    # never invent a confirming user.
    confirmed_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    confirmed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    superseded_by_id: Mapped[str | None] = Column(
        String(36),
        ForeignKey("organization_identity_confirmations.id", ondelete="SET NULL"),
        nullable=True,
    )
    correction_reason: Mapped[str | None] = Column(Text, nullable=True)
    backfilled: Mapped[bool] = Column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class OrganizationDomain(Base):
    __tablename__ = "organization_domains"
    __table_args__ = (Index("ix_organization_domains_org", "organization_id"),)

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    domain: Mapped[str] = Column(String(255), nullable=False)
    domain_type: Mapped[str] = Column(String(20), nullable=False)
    verification_status: Mapped[str] = Column(String(30), nullable=False)
    verification_method: Mapped[str | None] = Column(String(50), nullable=True)
    verified_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    verified_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


class OrganizationOperatingContextSuggestion(Base):
    """Append-only human decisions over prepared operating-context suggestions."""

    __tablename__ = "organization_operating_context_suggestions"
    __table_args__ = (
        Index(
            "ix_organization_operating_context_org_current", "organization_id", "superseded_by_id"
        ),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    suggestion_type: Mapped[str] = Column(String(40), nullable=False)
    suggestion_key: Mapped[str] = Column(String(100), nullable=False)
    source_type: Mapped[str] = Column(String(40), nullable=False)
    source_reference: Mapped[str | None] = Column(String(100), nullable=True)
    status: Mapped[str] = Column(String(20), nullable=False)
    decided_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    decided_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    superseded_by_id: Mapped[str | None] = Column(
        String(36),
        ForeignKey("organization_operating_context_suggestions.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


__all__ = [
    "OrganizationDomain",
    "OrganizationIdentityConfirmation",
    "OrganizationIdentityEvidence",
    "OrganizationLegalEntity",
    "OrganizationOperatingContextSuggestion",
    "OrganizationScope",
]
