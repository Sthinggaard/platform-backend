"""CA-04.6 — ProcessScannerLink: the missing many-to-many direction between
one ScannerInstance and the Business Processes (ValueStreams) it is
authorized to scan.

``BusinessService.value_stream_ids`` already lets one service belong to
many processes (a bare string array, no association table). This is the
reverse, currently-missing relationship: one Collector belonging to many
processes, each link independently pausable/revocable. Additive to, not a
replacement for, RISKLENCE-79's existing single-service
``EvidenceSource.business_service_id`` scoping, which continues unchanged.

Mirrors ``ScannerCredential``'s own shape (many independently-lifecycled
child rows off one ``ScannerInstance``, ``String(36)`` UUID PK, plain
``organization_id`` FK — this codebase has no separate ``tenant_id``
column anywhere in the business/process/scanner model layer, so this model
does not invent one either).
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow


class ProcessScannerLink(Base):
    __tablename__ = "process_scanner_links"
    __table_args__ = (
        Index("ix_process_scanner_links_instance", "scanner_instance_id", "status"),
        Index("ix_process_scanner_links_process", "business_process_id", "status"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    scanner_instance_id: Mapped[str] = Column(
        String(36), ForeignKey("scanner_instances.id", ondelete="CASCADE"), nullable=False
    )
    business_process_id: Mapped[str] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="CASCADE"), nullable=False
    )
    # Nullable — a link can authorize an entire process without narrowing to
    # one specific service within it. When set, link_scanner_to_process
    # requires it to be one of the linked process's own value_stream_ids,
    # never a service from an unrelated process.
    business_service_id: Mapped[str | None] = Column(
        String(36), ForeignKey("business_services.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = Column(String(20), nullable=False, default="active")
    linked_by_user_id: Mapped[int | None] = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    paused_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    revoked_by_user_id: Mapped[int | None] = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


__all__ = ["ProcessScannerLink"]
