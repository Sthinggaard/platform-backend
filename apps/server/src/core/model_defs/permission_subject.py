"""CA-07.3 / Epic C4 — the thing a permission profile bounds, whatever kind it is.

The relational answer to "make this polymorphic without losing referential
integrity" (Søren's decision, 2026-08-18). A foreign key column references
exactly one table, so a `subject_type` + `subject_id` pair — the pattern usually
reached for here — buys open-endedness by giving up the database's ability to
check anything at all: nothing would stop a profile pointing at a deleted row, or
one belonging to another organisation.

A supertable buys the same open-endedness and keeps the checking. Every subject
that can be permissioned owns a row here; `PermissionProfile.subject_id` is a
real foreign key to it. Adding a new kind of subject means giving that table a
`permission_subject_id` and registering a row — **no change to
`permission_profiles`, and no change to the enforcement path**.

Note this is only the storage half. Polymorphism in the *code* is free and
independent: `assert_capability_permitted` takes anything satisfying
`PermissionSubjectBearer`, so a new subject kind needs no new branches.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped

from src.core.constants.permission_profile_enums import PermissionSubjectKind
from src.core.database import Base
from src.core.model_defs.common import utcnow


class PermissionSubject(Base):
    """One permissionable thing, of some kind, belonging to one organisation."""

    __tablename__ = "permission_subjects"
    __table_args__ = (
        Index("ix_permission_subjects_org_kind", "organization_id", "subject_kind"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # Which concrete table owns this row. Descriptive, for reading and for
    # querying "all Collector profiles" — never the integrity mechanism. The
    # foreign keys are, in both directions.
    subject_kind: Mapped[str] = Column(String(40), nullable=False)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


__all__ = ["PermissionSubject", "PermissionSubjectKind"]
