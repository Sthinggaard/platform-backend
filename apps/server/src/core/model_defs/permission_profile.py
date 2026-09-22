"""CA-07.3 — what a Connector may do, as an object a person approved.

Epic C4's `PermissionProfile`, landing here scoped to one Connector. The
programme roadmap owns the general model under C4 (*"defines what a
Collector/connector may do"*, High security, with D6 blocked on it); building a
separate connector-only profile would leave a third permission model beside that
one and the JSONB bag on `DiscoveryScopeProposal`. The subject is the
`PermissionSubject` supertable, so widening to other kinds of subject needs no
change to this table at all.

Two things are deliberately separate columns rather than one:

- `capabilities` — what was granted, validated against `ConnectorCapability` on
  every write, so an unknown string can never sit inside an approved grant.
- `docker_socket_approved_*` and `service_config_approved_*` — **not**
  capabilities. The contract makes Docker socket access its own decision, and
  Søren ruled the same for reading deployed configuration (2026-08-24), because
  that is where credentials live. Approving this profile grants neither. A
  capability in the same list would be approved by the same click, which is the
  precise failure the rule exists to prevent.

Versioned and superseded rather than edited, like every other governed record in
CA-07: a profile that could be widened in place would make "what was permitted
when this ran?" unanswerable after the fact.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.constants.permission_profile_enums import PermissionProfileStatus
from src.core.database import Base
from src.core.model_defs.common import utcnow


class PermissionProfile(Base):
    __tablename__ = "permission_profiles"
    __table_args__ = (
        Index("ix_permission_profiles_org_status", "organization_id", "status"),
        Index("ix_permission_profiles_subject", "subject_id", "status"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # The subject this profile bounds — a real foreign key to the permission
    # supertable, not a type/id pair. NOT NULL: a profile that bounds nothing
    # would be approvable without ever taking effect.
    #
    # Pointing at `permission_subjects` rather than at `access_connectors` is
    # what makes this open-ended without giving up integrity: a new kind of
    # subject needs no change here at all.
    subject_id: Mapped[str] = Column(
        String(36), ForeignKey("permission_subjects.id", ondelete="CASCADE"), nullable=False
    )
    # A profile someone can refer to in a conversation — "the read-only inventory
    # profile" — rather than a list of flags they have to re-read each time.
    name: Mapped[str] = Column(String(255), nullable=False)
    # Validated against ConnectorCapability on every write. Stored as a list
    # rather than a table because it is read whole, always, on every check.
    capabilities: Mapped[list] = Column(JSONB, nullable=False, default=list)
    # Discovery capabilities remain a separate vocabulary from ConnectorCapability.
    # They share the governed profile and enforcement seam, but are never merged.
    discovery_capabilities: Mapped[list] = Column(JSONB, nullable=False, default=list)

    status: Mapped[str] = Column(
        String(30), nullable=False, default=PermissionProfileStatus.DRAFT.value
    )
    version: Mapped[int] = Column(Integer, nullable=False, default=1)

    prepared_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    submitted_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    approved_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    rejected_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    rejected_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    rejection_reason: Mapped[str | None] = Column(Text, nullable=True)

    # Its own approval, its own approver, its own timestamp. Never set by
    # approving the profile — see the module docstring.
    docker_socket_approved_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    docker_socket_approved_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    # CA-08.3 (#291), Søren 2026-08-24: the same treatment, for the same reason.
    # Deployed configuration is where credentials live, so reading it is its own
    # decision rather than a member of the list approved in one click.
    service_config_approved_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    service_config_approved_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    note: Mapped[str | None] = Column(Text, nullable=True)
    superseded_by_id: Mapped[str | None] = Column(
        String(36), ForeignKey("permission_profiles.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(
        DateTime, nullable=False, default=utcnow, onupdate=utcnow
    )


__all__ = ["PermissionProfile"]
