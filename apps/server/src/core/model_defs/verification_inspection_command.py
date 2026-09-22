"""CA-08.2 (#290) — one queued inspection, waiting for the Collector that must run it.

**Why this is not a row in ``scanner_commands``.** That was the first instinct,
and reusing it would have inherited ack, expiry and rejection whole. But
``ScannerCommand.discovery_run_id`` is ``nullable=False`` with a foreign key to
``discovery_runs``, and an inspection has no discovery run — it belongs to a
``VerificationRun``. Making that column nullable would change a heavily indexed
table that many readers already assume is non-null, to hold a row shaped
differently from every other row in it. A separate additive table is the smaller
and more honest change.

**That is not a second channel.** The criterion says *transport reuses
``command_signing`` and ``api_client``; no second channel*, and it still does:
the same ``GET /commands/next`` a Collector already polls returns this, the same
signing key signs it, the same client fetches it. What differs is which table the
work was read from, which the Collector never sees.

The signature is stored rather than recomputed on delivery. A command whose
signature is derived again at read time would silently re-sign whatever the row
happens to say *now*, which defeats the point of signing it at all.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.constants.verification_inspection_enums import InspectionCommandStatus
from src.core.database import Base
from src.core.model_defs.common import utcnow


class VerificationInspectionCommand(Base):
    """A signed instruction to read one thing on one host, and what came back."""

    __tablename__ = "verification_inspection_commands"
    __table_args__ = (
        # The poll query: pending work for this Collector, oldest first.
        Index(
            "ix_verification_inspection_commands_instance",
            "scanner_instance_id",
            "status",
            "issued_at",
        ),
        Index("ix_verification_inspection_commands_run", "verification_run_id"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    verification_run_id: Mapped[str] = Column(
        String(36), ForeignKey("verification_runs.id", ondelete="CASCADE"), nullable=False
    )
    #: Denormalised from the run. The verification surface (#294) and identity
    #: recording both ask "what has been established about *this artefact*",
    #: and joining through the run for every such question buys nothing.
    asset_id: Mapped[int] = Column(
        Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    connector_id: Mapped[str] = Column(
        String(36), ForeignKey("access_connectors.id", ondelete="RESTRICT"), nullable=False
    )
    scanner_instance_id: Mapped[str] = Column(
        String(36), ForeignKey("scanner_instances.id", ondelete="CASCADE"), nullable=False
    )

    capability: Mapped[str] = Column(String(50), nullable=False)
    platform: Mapped[str] = Column(String(20), nullable=False)
    #: The exact argv the server resolved and signed. Stored as issued, never
    #: rebuilt — "these exact commands ran on your host" is only sayable if the
    #: command that ran is the command that was recorded.
    argv: Mapped[list] = Column(JSONB, nullable=False)
    #: Which profile version authorised it, snapshotted for the same reason the
    #: run snapshots its own (#289): a superseded policy must not change the
    #: answer to "what was this allowed to do?"
    permission_profile_id: Mapped[str] = Column(
        String(36), ForeignKey("permission_profiles.id", ondelete="RESTRICT"), nullable=False
    )

    signature: Mapped[str] = Column(String(128), nullable=False)
    signature_version: Mapped[str] = Column(String(30), nullable=False)

    status: Mapped[str] = Column(
        String(20), nullable=False, default=InspectionCommandStatus.PENDING.value
    )
    issued_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = Column(DateTime, nullable=False)
    delivered_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    # --- What the Collector reported, uninterpreted ---
    #: Facts as collected. The Collector reaches no conclusion (Søren,
    #: 2026-08-24); ``outcome`` below is the engine's reading of these.
    exit_code: Mapped[int | None] = Column(Integer, nullable=True)
    stderr: Mapped[str | None] = Column(Text, nullable=True)
    #: Deliberately no ``stdout`` column here, and CA-08.4 did not add one. What
    #: the output *established* is recorded below; the output itself is read,
    #: used, and dropped. A copy on this row would be a second place a
    #: credential read out of a config file could come to rest.
    outcome: Mapped[str | None] = Column(String(30), nullable=True)

    # --- What it established (CA-08.4) ---
    #: The name this inspection read out of the host, or NULL where it read
    #: nothing identifying. Provenance lives here rather than only on the asset:
    #: "what is this called now" and "what did this particular run establish,
    #: under whose approval" are different questions, and the surface asks both.
    identity_name: Mapped[str | None] = Column(String(200), nullable=True)
    identity_basis: Mapped[str | None] = Column(String(30), nullable=True)
    #: The line of output the name was read from — enough for a person to see
    #: why the platform believes it, never the whole output.
    identity_evidence: Mapped[str | None] = Column(String(200), nullable=True)

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = Column(
        DateTime, nullable=False, default=utcnow, onupdate=utcnow
    )
