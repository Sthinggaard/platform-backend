"""Evidence Source — at least one functioning evidence source (post-ORG-STRUCT stage).

``EvidenceReceipt`` is the single canonical "evidence was received" fact for
both v1 source types (file upload and manual) — a file import and a manual
entry both create one, so the readiness evaluator only ever has to check
one table regardless of source type. ``EvidenceSourceException`` is the
explicit, authorised, review-dated degraded path a manual source needs to
ever count as functioning (spec §19) — it is never satisfied silently.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow


class EvidenceSource(Base):
    __tablename__ = "evidence_sources"
    __table_args__ = (
        Index("ix_evidence_sources_org_status", "organization_id", "status"),
        Index("ix_evidence_sources_business_service", "business_service_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = Column(String(255), nullable=False)
    type: Mapped[str] = Column(String(20), nullable=False)
    mode: Mapped[str] = Column(String(20), nullable=False)
    status: Mapped[str] = Column(String(30), nullable=False, default="draft")
    owner_user_id: Mapped[int | None] = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    # TENANT-79 — which business process this evidence source was set up to
    # validate, if any. Null means "org-wide / not yet scoped to a process"
    # (the pre-existing Configuration/onboarding creation path). Service-
    # level granularity only — see evidence_scanner_service.py's own
    # docstring for why per-dependency-node linkage isn't built here.
    business_service_id: Mapped[str | None] = Column(
        String(36), ForeignKey("business_services.id", ondelete="SET NULL"), nullable=True
    )
    connected_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    first_evidence_received_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    last_successful_sync_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    last_attempted_sync_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    # Freshness policy (spec §13) — null means "use the type-based default"
    # (see DEFAULT_FRESHNESS_*_AFTER_HOURS), never a fabricated value.
    warning_after_hours: Mapped[int | None] = Column(Integer, nullable=True)
    stale_after_hours: Mapped[int | None] = Column(Integer, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class EvidenceSourceScope(Base):
    __tablename__ = "evidence_source_scopes"

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    evidence_source_id: Mapped[str] = Column(
        String(36), ForeignKey("evidence_sources.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    organization_id: Mapped[int] = Column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    scope_type: Mapped[str] = Column(String(30), nullable=False)
    organisation_unit_ids: Mapped[list[str] | None] = Column(JSONB, nullable=True)
    legal_entity_ids: Mapped[list[str] | None] = Column(JSONB, nullable=True)
    country_codes: Mapped[list[str] | None] = Column(JSONB, nullable=True)
    status: Mapped[str] = Column(String(20), nullable=False, default="draft")
    confirmed_by_user_id: Mapped[int | None] = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    confirmed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class EvidenceImportBatch(Base):
    __tablename__ = "evidence_import_batches"
    __table_args__ = (Index("ix_evidence_import_batches_source", "evidence_source_id", "status"),)

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    evidence_source_id: Mapped[str] = Column(
        String(36), ForeignKey("evidence_sources.id", ondelete="CASCADE"), nullable=False
    )
    filename: Mapped[str] = Column(String(255), nullable=False)
    file_type: Mapped[str] = Column(String(10), nullable=False)
    checksum: Mapped[str] = Column(String(64), nullable=False)
    status: Mapped[str] = Column(String(30), nullable=False)
    uploaded_by_user_id: Mapped[int] = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    uploaded_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    detected_columns: Mapped[list[str] | None] = Column(JSONB, nullable=True)
    column_mapping: Mapped[dict | None] = Column(JSONB, nullable=True)
    parsed_rows_json: Mapped[list[dict] | None] = Column(JSONB, nullable=True)
    total_rows: Mapped[int | None] = Column(Integer, nullable=True)
    accepted_rows: Mapped[int | None] = Column(Integer, nullable=True)
    rejected_rows: Mapped[int | None] = Column(Integer, nullable=True)
    warning_rows: Mapped[int | None] = Column(Integer, nullable=True)
    validation_summary: Mapped[dict | None] = Column(JSONB, nullable=True)
    completed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)


class EvidenceReceipt(Base):
    __tablename__ = "evidence_receipts"
    __table_args__ = (Index("ix_evidence_receipts_source", "evidence_source_id"),)

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    evidence_source_id: Mapped[str] = Column(
        String(36), ForeignKey("evidence_sources.id", ondelete="CASCADE"), nullable=False
    )
    evidence_import_batch_id: Mapped[str | None] = Column(
        String(36), ForeignKey("evidence_import_batches.id", ondelete="SET NULL"), nullable=True
    )
    received_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    record_count: Mapped[int] = Column(Integer, nullable=False, default=0)
    status: Mapped[str] = Column(String(20), nullable=False)
    validation_summary: Mapped[dict | None] = Column(JSONB, nullable=True)


class EvidenceManualEntry(Base):
    __tablename__ = "evidence_manual_entries"
    __table_args__ = (Index("ix_evidence_manual_entries_source", "evidence_source_id"),)

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    evidence_source_id: Mapped[str] = Column(
        String(36), ForeignKey("evidence_sources.id", ondelete="CASCADE"), nullable=False
    )
    description: Mapped[str] = Column(Text, nullable=False)
    entered_by_user_id: Mapped[int] = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    entered_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


class EvidenceSourceException(Base):
    __tablename__ = "evidence_source_exceptions"
    __table_args__ = (Index("ix_evidence_source_exceptions_source", "evidence_source_id", "status"),)

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    evidence_source_id: Mapped[str] = Column(
        String(36), ForeignKey("evidence_sources.id", ondelete="CASCADE"), nullable=False
    )
    reason_code: Mapped[str] = Column(String(30), nullable=False)
    description: Mapped[str] = Column(Text, nullable=False)
    approved_by_user_id: Mapped[int] = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    review_at: Mapped[datetime] = Column(DateTime, nullable=False)
    status: Mapped[str] = Column(String(20), nullable=False, default="active")


__all__ = [
    "EvidenceImportBatch",
    "EvidenceManualEntry",
    "EvidenceReceipt",
    "EvidenceSource",
    "EvidenceSourceException",
    "EvidenceSourceScope",
]
