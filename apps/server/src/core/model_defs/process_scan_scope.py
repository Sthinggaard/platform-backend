"""CA-10 (#50) — ProcessScanScope: an approved recurring assurance scope for
one active Business Process (Programme Epic G7).

Column set matches the pre-existing `process_scan_scopes` table found in the
shared dev Postgres container (2026-09-22 — see process_scan_scope_enums.py
for how it was found and why it was adopted rather than replaced). Lifecycle:
a scope is derived (``derived_at``), optionally submitted for approval
(``submitted_by_user_id``/``submitted_at``), approved (``approved_by_user_id``/
``approved_at`` — the currently-effective row for a process), and later
either marked outdated in place (``outdated_at``/``outdated_reason``, G9-style
staleness without losing authorization), revoked
(``revoked_by_user_id``/``revoked_at``, terminal), or superseded by a newer
revision (``superseded_by_scope_id``, set on the old row pointing at the
new one — same direction as ``RiskAppetitePolicy.superseded_by_id``).

``(business_process_id, revision)`` is unique at the database level — a
process's scan scopes are strictly, gaplessly versioned.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.constants.process_scan_scope_enums import ProcessScanScopeStatus
from src.core.database import Base
from src.core.model_defs.common import utcnow


class ProcessScanScope(Base):
    __tablename__ = "process_scan_scopes"
    __table_args__ = (
        Index("ix_process_scan_scopes_org_process_status", "organization_id", "business_process_id", "status"),
        UniqueConstraint("business_process_id", "revision", name="ix_process_scan_scopes_process_revision"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    business_process_id: Mapped[str] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="CASCADE"), nullable=False
    )
    revision: Mapped[int] = Column(Integer, nullable=False)
    status: Mapped[str] = Column(String(30), nullable=False, default=ProcessScanScopeStatus.DRAFT.value)

    # What is authorized — caller-supplied at draft time (this ticket does
    # not build a separate derivation engine that would compute these from
    # a published Dependency Bundle; that is future, separately-scoped work
    # this schema leaves room for via `derived_at`/`rationale`).
    bundle_version_ids: Mapped[list] = Column(JSONB, nullable=False, default=list)
    artefacts: Mapped[list] = Column(JSONB, nullable=False, default=list)
    connectors: Mapped[list] = Column(JSONB, nullable=False, default=list)
    # Values of the existing CheckKey enum (discovery_run_enums.py) — reused
    # rather than a second, parallel "evidence type" vocabulary.
    checks: Mapped[list] = Column(JSONB, nullable=False, default=list)
    profile_versions: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    rationale: Mapped[dict] = Column(JSONB, nullable=False, default=dict)
    derived_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)

    submitted_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    submitted_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    approved_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    decision_note: Mapped[str | None] = Column(Text, nullable=True)

    outdated_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    outdated_reason: Mapped[str | None] = Column(String(200), nullable=True)

    revoked_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    revoked_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    # No FK in the live table (verified 2026-09-22) — kept exactly as found
    # rather than adding a self-referential constraint it does not have.
    superseded_by_scope_id: Mapped[str | None] = Column(String(36), nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


__all__ = ["ProcessScanScope"]
