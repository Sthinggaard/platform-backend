"""CA-07.4 — one attempt to prove access works, and what it reported.

A history table rather than columns on the Connector, for the same reason
``CollectorReadinessReport`` is one: *"when did this stop working, and what did
it say at the time?"* is a question an operator will ask, and the answer is
worthless if each result overwrites the last.

**The platform does not perform the test.** Credentials live on the Collector, so
the platform records a *request* and the Collector reports the outcome — the
shape ``record_test_scan_result`` already uses. `requested_at` and `completed_at`
are separate for that reason: the gap between them is the Collector's, and a test
that never comes back is a different fact from one that failed.

Reachability and permission adequacy are **two nullable booleans, not one
verdict**. A Connector can be perfectly reachable and still unable to do what its
profile grants, and collapsing that into "failed" would send an operator to the
network when the problem is an account's rights.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.constants.connector_access_test_enums import ConnectorAccessTestStatus
from src.core.database import Base
from src.core.model_defs.common import utcnow


class ConnectorAccessTest(Base):
    __tablename__ = "connector_access_tests"
    __table_args__ = (
        Index("ix_connector_access_tests_connector", "connector_id", "status"),
        Index("ix_connector_access_tests_org_status", "organization_id", "status"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    connector_id: Mapped[str] = Column(
        String(36), ForeignKey("access_connectors.id", ondelete="CASCADE"), nullable=False
    )
    # The profile the test was run against, so a later reader knows which grant
    # "permissions were adequate" was measured against — profiles supersede, and
    # a result that outlived its profile would otherwise be unreadable.
    permission_profile_id: Mapped[str | None] = Column(
        String(36), ForeignKey("permission_profiles.id", ondelete="SET NULL"), nullable=True
    )

    status: Mapped[str] = Column(
        String(20), nullable=False, default=ConnectorAccessTestStatus.REQUESTED.value
    )
    requested_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    requested_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    completed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    # Two separate answers, both nullable until the Collector reports.
    reachable: Mapped[bool | None] = Column(Boolean, nullable=True)
    permissions_adequate: Mapped[bool | None] = Column(Boolean, nullable=True)

    # Which of the profile's capabilities the Collector could actually exercise.
    # Lets "permissions were not adequate" say *which* ones, rather than leaving
    # an operator to guess.
    capabilities_confirmed: Mapped[list] = Column(JSONB, nullable=False, default=list)

    # From ConnectorAccessTestFailure — a closed vocabulary, so every failure
    # maps to a remedy someone can act on.
    failure_code: Mapped[str | None] = Column(String(50), nullable=True)
    # Free text from the Collector. Never rendered as the primary explanation,
    # and never a place for secrets: the Collector is the only party holding a
    # credential and must not echo it back here.
    failure_detail: Mapped[str | None] = Column(Text, nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


__all__ = ["ConnectorAccessTest"]
