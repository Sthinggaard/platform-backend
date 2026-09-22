"""Risklence Scanner setup — Step 3.5 (configure and validate the scanner;
see ``evidence_scanner_enums`` for the full scope note).

``ScannerInstance`` is one row per scanner evidence source (v1 supports
exactly one scanner installation per evidence source). ``tool_status`` and
``test_scan_status`` are recorded from an operator-triggered validation
call — there is no live scanner agent in this slice — so they are plain
JSONB/string columns rather than a separate append-only run history table;
a real run history belongs to Step 4, which executes actual scans.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, LargeBinary, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped

from src.core.database import Base
from src.core.model_defs.common import utcnow


class ScannerDomainTarget(Base):
    __tablename__ = "scanner_domain_targets"
    __table_args__ = (
        Index("ix_scanner_domain_targets_source", "evidence_source_id", "status"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    evidence_source_id: Mapped[str] = Column(
        String(36), ForeignKey("evidence_sources.id", ondelete="CASCADE"), nullable=False
    )
    domain: Mapped[str] = Column(String(255), nullable=False)
    source: Mapped[str] = Column(String(30), nullable=False)
    ownership_status: Mapped[str] = Column(String(30), nullable=False)
    scan_enabled: Mapped[bool] = Column(Boolean, nullable=False, default=True)
    include_subdomains: Mapped[bool] = Column(Boolean, nullable=False, default=True)
    status: Mapped[str] = Column(String(20), nullable=False, default="draft")
    approved_by_user_id: Mapped[int | None] = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


class ScannerNetworkTarget(Base):
    __tablename__ = "scanner_network_targets"
    __table_args__ = (
        Index("ix_scanner_network_targets_source", "evidence_source_id", "status"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    evidence_source_id: Mapped[str] = Column(
        String(36), ForeignKey("evidence_sources.id", ondelete="CASCADE"), nullable=False
    )
    cidr: Mapped[str] = Column(String(50), nullable=False)
    name: Mapped[str] = Column(String(255), nullable=False)
    organisation_unit_id: Mapped[str | None] = Column(
        String(36), ForeignKey("organization_units.id", ondelete="SET NULL"), nullable=True
    )
    location_id: Mapped[str | None] = Column(
        String(36), ForeignKey("organization_locations.id", ondelete="SET NULL"), nullable=True
    )
    environment: Mapped[str | None] = Column(String(50), nullable=True)
    network_type: Mapped[str] = Column(String(20), nullable=False)
    status: Mapped[str] = Column(String(20), nullable=False, default="draft")
    approved_by_user_id: Mapped[int | None] = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)


class ScannerInstance(Base):
    __tablename__ = "scanner_instances"
    __table_args__ = (
        Index("ix_scanner_instances_source", "evidence_source_id", unique=True),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    evidence_source_id: Mapped[str] = Column(
        String(36), ForeignKey("evidence_sources.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    name: Mapped[str] = Column(String(255), nullable=False)
    public_instance_id: Mapped[str] = Column(String(36), nullable=False, default=lambda: str(uuid4()))
    installation_method: Mapped[str] = Column(String(30), nullable=False)
    scanner_version: Mapped[str | None] = Column(String(50), nullable=True)
    configuration_version: Mapped[str | None] = Column(String(50), nullable=True)
    status: Mapped[str] = Column(String(20), nullable=False, default="registered")

    # CA-02 — reported by the agent's own heartbeat call (platform.system()/
    # platform.machine(), plus /etc/os-release's PRETTY_NAME on Linux where
    # available). Null until the first heartbeat from an agent build that
    # sends it — never fabricated for older/pre-existing instances.
    #: CA-02.3 slice 3 — now only ever the *host's* distribution. An agent
    #: running in a container reports NULL here rather than the image's own
    #: os-release, which is what it used to send: on a Raspberry Pi that read
    #: "Debian GNU/Linux", matching the host by coincidence because the image is
    #: also Debian, and would simply have been wrong on an Ubuntu or RHEL host
    #: with nothing able to tell (BUG-CA-02 / #171).
    os_name: Mapped[str | None] = Column(String(100), nullable=True)
    os_version: Mapped[str | None] = Column(String(100), nullable=True)
    architecture: Mapped[str | None] = Column(String(30), nullable=True)

    #: Shared with the host even inside a container — verified on real hardware
    #: that platform.release() in the container is byte-identical to the host's
    #: `uname -r`. Often more identifying than the distribution: a Raspberry Pi
    #: kernel literally says so.
    kernel_release: Mapped[str | None] = Column(String(100), nullable=True)
    #: "docker", "podman", "kubepods"… NULL on a native install. This is what
    #: makes a NULL os_name readable as "cannot be determined from in here"
    #: rather than "not reported yet".
    container_runtime: Mapped[str | None] = Column(String(30), nullable=True)
    #: #321 — the IPv4 segments this Collector is attached to, as it last
    #: reported them: ``[{"interface", "address", "network"}]``.
    #:
    #: ``None`` means the Collector has never said, which is **not** the same as
    #: "attached to nothing". Reading an unknown as a negative is the mistake
    #: this column exists to end: it is what let the platform believe a
    #: Collector could see hardware addresses on a network it could not reach.
    network_segments: Mapped[list | None] = Column(JSONB, nullable=True)
    #: The container image's own OS, kept apart from the host's so a view can
    #: say what the Collector runs *in* without implying it is the machine.
    runtime_os_name: Mapped[str | None] = Column(String(100), nullable=True)
    runtime_os_version: Mapped[str | None] = Column(String(100), nullable=True)

    activation_token_hash: Mapped[str] = Column(String(64), nullable=False)
    activated_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    activation_revoked_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    # CA-04.1 — HKDF(raw activation token, salt=instance id), Fernet-encrypted
    # at rest (src/core/crypto.py). Derived once, at the moment the raw token
    # exists (install_scanner/regenerate_activation_token), since it is never
    # persisted itself. Lets the Collector independently verify a command's
    # signature instead of blindly trusting a signed-but-unchecked envelope.
    command_signing_key_encrypted: Mapped[bytes | None] = Column(LargeBinary, nullable=True)

    scan_profile: Mapped[str | None] = Column(String(30), nullable=True)

    # Recorded from an operator-triggered validation call (spec §10) —
    # {"nmap": "available", "subfinder": "available", "nuclei": "available",
    #  "nuclei_templates": "available"}. Never populated by a live agent here.
    tool_status: Mapped[dict | None] = Column(JSONB, nullable=True)
    tool_validation_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    connection_verified_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    test_scan_status: Mapped[str | None] = Column(String(30), nullable=True)
    test_scan_completed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    scope_confirmed_by_user_id: Mapped[int | None] = Column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    scope_confirmed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    registered_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    last_heartbeat_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    last_successful_connection_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    last_scan_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    # CA-02.3 slice 3 — one pending operational instruction (CollectorInstruction),
    # delivered on the next heartbeat response.
    #
    # A single nullable column rather than a queue table, deliberately: these
    # instructions are *coalescing by nature*. A user pressing "Run self-check
    # again" five times wants one fresh answer, not five checks, and a queue
    # would faithfully deliver five. It also cannot grow unbounded while a
    # Collector is offline.
    pending_instruction: Mapped[str | None] = Column(String(30), nullable=True)
    pending_instruction_requested_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    #: Who asked. Carried onto the resulting readiness report so the answer is
    #: attributable to a person, not just to "the system".
    pending_instruction_requested_by_user_id: Mapped[int | None] = Column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class ScannerCredential(Base):
    """A named, independently-managed activation credential (spec:
    TENANT-83/84). A ``ScannerInstance`` can hold many of these; the
    instance's own legacy ``activation_token_hash`` stays untouched until
    the frontend migrates onto this table (TENANT-85), so the existing
    single-credential routes keep working unchanged in the meantime.

    Only ``token_hash`` is ever persisted — the raw key is returned once,
    at create/rotate time, and never stored or logged (spec security rule).
    """

    __tablename__ = "scanner_credentials"
    __table_args__ = (
        Index("ix_scanner_credentials_instance", "scanner_instance_id", "status"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    scanner_instance_id: Mapped[str] = Column(
        String(36), ForeignKey("scanner_instances.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = Column(String(255), nullable=False)
    token_hash: Mapped[str] = Column(String(64), nullable=False, unique=True)
    validity_policy: Mapped[str] = Column(String(20), nullable=False)
    # Only meaningful when validity_policy == "custom" — kept so a later
    # rotate can offer "keep the same duration" without re-deriving a day
    # count from timestamps.
    validity_custom_days: Mapped[int | None] = Column(Integer, nullable=True)
    status: Mapped[str] = Column(String(20), nullable=False, default="active")

    created_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    created_by_user_id: Mapped[int | None] = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    expires_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    # One-time credentials only: set the first (and only) time this
    # credential successfully authenticates. Never set for calendar-window
    # policies, which stay repeatedly usable until expiry/pause/revoke.
    consumed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    last_rotated_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    paused_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    revoked_by_user_id: Mapped[int | None] = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    deleted_at: Mapped[datetime | None] = Column(DateTime, nullable=True)


class CollectorReadinessReport(Base):
    """One completed self-check, as the Collector itself reported it (CA-02.3).

    Kept as a history table rather than a single column on ``ScannerInstance``
    because "when did this stop working, and what did it say at the time?" is a
    question an operator will ask, and the answer is worthless if each report
    overwrites the last. The latest row is the one readiness is computed from;
    the rest are why.

    Deliberately does **not** duplicate what ``ScannerInstance`` already owns
    (``os_name``, ``os_version``, ``architecture``, ``status``,
    ``last_heartbeat_at``). Those stay on the row of record and are referenced,
    not copied — two places holding the same fact is how they start disagreeing.

    Also deliberately separate from the legacy ``tool_status`` /
    ``tool_validation_at`` columns, which were written by *both* a real agent
    self-check and a user clicking "Available" with no marker distinguishing
    them. Those columns are kept for audit continuity and are never read as a
    readiness source again.
    """

    __tablename__ = "collector_readiness_reports"
    __table_args__ = (
        # Readiness always asks for "the newest report for this Collector".
        Index("ix_collector_readiness_instance_reported", "scanner_instance_id", "reported_at"),
    )

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[int] = Column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    scanner_instance_id: Mapped[str] = Column(
        String(36), ForeignKey("scanner_instances.id", ondelete="CASCADE"), nullable=False
    )

    #: Set by the platform on receipt, not taken from the payload — a Collector
    #: with a wrong clock must not be able to place its report in the future and
    #: win "latest" forever.
    reported_at: Mapped[datetime] = Column(DateTime, nullable=False, default=utcnow)
    self_check_started_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    self_check_completed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)

    overall_status: Mapped[str] = Column(String(20), nullable=False)
    platform_connectivity_status: Mapped[str] = Column(String(20), nullable=False)
    evidence_storage_status: Mapped[str] = Column(String(20), nullable=False)

    collector_version: Mapped[str | None] = Column(String(50), nullable=True)
    template_pack_version: Mapped[str | None] = Column(String(50), nullable=True)

    #: [{componentKey, status, version, reasonCode, checkedAt}] — the shape the
    #: gating rules read, kept structured rather than flattened into columns so
    #: a new bundled component does not need a migration.
    components: Mapped[list | None] = Column(JSONB, nullable=True)
    failure_reason_codes: Mapped[list | None] = Column(JSONB, nullable=True)

    #: CA-02.3 slice 3 — why this check ran. Without it a report cannot say
    #: whether it is a routine measurement or the answer to a named person
    #: pressing "Run self-check again", which is the same assertion-vs-measurement
    #: ambiguity this story exists to remove, one level up.
    trigger: Mapped[str | None] = Column(String(20), nullable=True)
    #: Only ever set when trigger is "requested" — the person who asked.
    requested_by_user_id: Mapped[int | None] = Column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    #: Required. A report with no schema version cannot be trusted to mean what
    #: this code thinks it means, and the migration rule turns on exactly this:
    #: readiness stays unknown until a genuinely new, schema-versioned report
    #: arrives from that Collector.
    schema_version: Mapped[str] = Column(String(20), nullable=False)
    report_sequence: Mapped[int | None] = Column(Integer, nullable=True)


__all__ = [
    "CollectorReadinessReport",
    "ScannerCredential",
    "ScannerDomainTarget",
    "ScannerInstance",
    "ScannerNetworkTarget",
]
