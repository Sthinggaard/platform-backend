"""What a process owner must be told about a service they depend on but do not own.

Søren's ruling, 2026-08-31: *"the owner of this service makes the decisions and
the ones affected by this decision is informed in the overview page via a message
saying person made this decision, please click there to read more and to mark you
have read this and are informed."*

⚠️ **Reading and acknowledging are different acts, and both are recorded.**
Søren, 2026-09-04: *"why does this ticket forbid clicking to understand what the
situation of a service is? It is not to do any actions on the service, it is a
100% read action."* Quite so — so:

============  ==================================================================
``viewed_at``       The reader opened the detail. Clears the *update badge* — a
                    "new since you last looked" marker, and nothing more.
``acknowledged_at`` The reader clicked "I have read this and am informed". A
                    governance record, never inferred from a page rendering
                    (#375).
============  ==================================================================

⚠️ **An acknowledgement is a record that someone was told, never that they
agreed.** Nothing here is an approval step, and no caller may read it as one.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow


class ServiceChangeNoticeKind:
    """What kind of thing happened. Two, and they behave differently."""

    #: Something changed. Informational — the reader cannot act on it.
    UPDATE = "update"
    #: Something is broken. Persists until the OWNING team resolves it; being
    #: read or acknowledged never clears it.
    ISSUE = "issue"


class ServiceChangeNotice(Base):
    """One message owed to one person about one service, in one of their processes.

    Rows are per **recipient and per affected process**: the message names which
    process of theirs is affected, so somebody who owns two processes that both
    lean on the service is told about each rather than once, vaguely.
    """

    __tablename__ = "service_change_notices"
    __table_args__ = (
        Index("ix_service_change_notices_recipient", "organization_id", "recipient_user_id"),
        Index("ix_service_change_notices_process", "organization_id", "process_id"),
        Index("ix_service_change_notices_service", "organization_id", "service_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True)
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    #: The service that changed — the node the badge sits on.
    service_id: Mapped[str] = Column(
        String(36), ForeignKey("business_services.id", ondelete="CASCADE"), nullable=False
    )
    #: The recipient's affected process. What the message names.
    process_id: Mapped[str] = Column(
        String(36), ForeignKey("value_streams.id", ondelete="CASCADE"), nullable=False
    )
    recipient_user_id: Mapped[int] = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    kind: Mapped[str] = Column(String(20), nullable=False)
    title: Mapped[str] = Column(String(255), nullable=False)
    description: Mapped[str | None] = Column(Text, nullable=True)
    #: The deciding owner's own words, quoted to the reader rather than
    #: paraphrased — the design shows it as a callout attributed to them.
    owner_comment: Mapped[str | None] = Column(Text, nullable=True)

    #: Who acted. The message says "X decided this", so it is never anonymous.
    actor_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    #: What to open to read it in full — the decision record this concerns.
    decision_record_id: Mapped[str | None] = Column(String(36), nullable=True)

    #: Opened. Clears the update badge; means nothing more than that.
    viewed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    #: Explicitly marked read and informed. The governance record.
    acknowledged_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    #: Closed by the owning team. Only this clears an issue.
    resolved_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    def __repr__(self) -> str:
        return (
            f"<ServiceChangeNotice(org={self.organization_id}, service='{self.service_id}', "
            f"to={self.recipient_user_id}, kind='{self.kind}')>"
        )
