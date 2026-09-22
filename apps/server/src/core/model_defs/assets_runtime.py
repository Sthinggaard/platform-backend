import enum
from datetime import datetime, timezone
from typing import List

from sqlalchemy import (
    ARRAY,
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, relationship

from src.core.database import Base
from src.core.model_defs.common import SEVERITY_ENUM, SeverityLevel, utcnow


class AssetStatus(enum.Enum):
    NOT_CONNECTED = "NOT_CONNECTED"
    PARTIALLY_OBSERVED = "PARTIALLY_OBSERVED"
    AT_RISK = "AT_RISK"
    OPERATIONALLY_COMPLIANT = "OPERATIONALLY_COMPLIANT"


class ConnectivityStatus(enum.Enum):
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    NOT_CONNECTED = "NOT_CONNECTED"
    CONNECTED = "CONNECTED"
    DEGRADED = "DEGRADED"


class Environment(enum.Enum):
    PROD = "PROD"
    STAGING = "STAGING"
    DEV = "DEV"
    SANDBOX = "SANDBOX"


class Criticality(enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SetupConfidence(enum.Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ScanStartMode(enum.Enum):
    IMMEDIATE = "IMMEDIATE"
    AFTER_SME_CONFIRM = "AFTER_SME_CONFIRM"
    AUDIT_ONLY = "AUDIT_ONLY"


class PermissionPreset(enum.Enum):
    SECURITY_READONLY = "SECURITY_READONLY"
    COMPLIANCE_BASELINE = "COMPLIANCE_BASELINE"
    CUSTOM = "CUSTOM"


class ConnectionState(enum.Enum):
    DRAFT = "DRAFT"
    INSTRUCTIONS_ISSUED = "INSTRUCTIONS_ISSUED"
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    REVOKED = "REVOKED"


class AssetLifecycleState(enum.Enum):
    """Existence lifecycle (Step 4.1A) — distinct from AssetStatus, which
    tracks observation/health, not whether the row is the canonical record
    for what it represents."""

    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    UNCONFIRMED = "UNCONFIRMED"
    MERGED = "MERGED"
    REMOVED = "REMOVED"
    #: "This is ours, and we will never depend on it." The third disposition a
    #: reviewer needs and did not have: a company laptop or a phone on the
    #: office WiFi is genuinely the organisation's, so REMOVED ("not ours") is a
    #: false statement about it, but it will never appear in a dependency
    #: picture either. Forcing that choice into the existing two meant either
    #: lying about ownership or leaving the row undecided forever.
    #:
    #: Deliberately not the same as REMOVED: an auditor asking "what is on your
    #: network that you have chosen not to model?" gets a real answer, and the
    #: reviewer's judgement is recorded rather than inferred from an absence.
    NOT_USED = "NOT_USED"
    #: CA-06.5 — outside the discovery boundary a human approved. The artefact
    #: was genuinely observed and keeps everything it knew; what changed is the
    #: agreed scope, not the facts.
    #:
    #: Deliberately not REMOVED. That state is a person saying "not ours", and
    #: letting a boundary change overwrite it would erase their decision —
    #: worse, lifting the exclusion would then hand back a record whose
    #: rejection no longer existed. Two different statements need two states.
    WITHDRAWN = "WITHDRAWN"


#: Lifecycle states that say "do not build on this record".
#:
#: ``REMOVED`` is not ours, ``NOT_USED`` is ours but will never be depended on,
#: and ``MERGED`` is superseded by the record it was merged into. Different
#: statements, same consequence: none of them may be offered as a dependency.
#:
#: Defined once, here beside the enum, so a consumer cannot decide for itself
#: which dispositions to honour. Deliberately an exclusion set rather than an
#: allow-list of "dependable" states: a state added later is far more likely to
#: be another ordinary one than another disposition, so the default must be to
#: keep it visible rather than silently drop it from every dependency picture.
NON_DEPENDABLE_LIFECYCLE_STATES: frozenset[AssetLifecycleState] = frozenset(
    {
        AssetLifecycleState.REMOVED,
        AssetLifecycleState.NOT_USED,
        AssetLifecycleState.MERGED,
        AssetLifecycleState.WITHDRAWN,
    }
)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        Index("ix_assets_org_layer_status", "organization_id", "layer", "status"),
        Index("ix_assets_org_layer", "organization_id", "layer"),
        Index("ix_assets_org_connectivity", "organization_id", "connectivity_status"),
        Index("ix_assets_intent_gin", "intent", postgresql_using="gin"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    type: Mapped[str] = Column(String(50), nullable=False, index=True)
    provider: Mapped[str | None] = Column(String(50))
    provider_display_name: Mapped[str | None] = Column(Text)
    display_name: Mapped[str] = Column(String(200), nullable=False)
    layer: Mapped[str] = Column(String(50), nullable=False, index=True)
    # A reviewer-owned library label. It is deliberately separate from the
    # scanner's technical layer and from a service's logical dependency slot.
    dependency_category: Mapped[str | None] = Column(String(30), nullable=True, index=True)
    environment: Mapped[Environment] = Column(
        Enum(Environment, native_enum=False, validate_strings=True),
        default=Environment.PROD,
        nullable=False,
    )
    criticality: Mapped[Criticality] = Column(
        Enum(Criticality, native_enum=False, validate_strings=True),
        default=Criticality.MEDIUM,
        nullable=False,
    )
    status: Mapped[AssetStatus] = Column(
        Enum(AssetStatus, native_enum=False, validate_strings=True),
        default=AssetStatus.NOT_CONNECTED,
        nullable=False,
        index=True,
    )
    connectivity_status: Mapped[ConnectivityStatus] = Column(
        Enum(ConnectivityStatus, native_enum=False, validate_strings=True),
        default=ConnectivityStatus.PENDING_VERIFICATION,
        nullable=False,
        index=True,
    )
    setup_confidence: Mapped[SetupConfidence] = Column(
        Enum(SetupConfidence, native_enum=False, validate_strings=True),
        default=SetupConfidence.MEDIUM,
        nullable=False,
    )
    scan_start_mode: Mapped[ScanStartMode] = Column(
        Enum(ScanStartMode, native_enum=False, validate_strings=True),
        default=ScanStartMode.AFTER_SME_CONFIRM,
        nullable=False,
    )
    secondary_layers: Mapped[list[int] | None] = Column(ARRAY(Integer))
    intent: Mapped[dict | list | None] = Column(JSONB)
    business_owner_ref: Mapped[str | None] = Column(Text)
    technical_owner_ref: Mapped[str | None] = Column(Text)
    setup_assignee_ref: Mapped[str | None] = Column(Text)
    created_by_ref: Mapped[str | None] = Column(Text)
    level: Mapped[int | None] = Column(Integer, nullable=True)
    is_spof: Mapped[bool] = Column(Boolean, default=False, nullable=False)
    posture_stale: Mapped[bool] = Column(Boolean, default=False, nullable=False)
    observation_level: Mapped[str | None] = Column(String(50), default="none")
    last_observed_at: Mapped[datetime | None] = Column(DateTime)
    risk_score: Mapped[float] = Column(Float, default=0.0, nullable=False)
    findings_count: Mapped[int] = Column(Integer, default=0, nullable=False)
    confidence: Mapped[float] = Column(Float, default=0.0, nullable=False)
    # Step 4.1A — deterministic dedup identity (org id + strongest available
    # provider/hostname/domain/ip signal), never display_name alone. Nullable
    # because pre-4.1A rows and manually-created assets may not have one yet.
    canonical_identity_key: Mapped[str | None] = Column(String(500), index=True)
    lifecycle_state: Mapped[AssetLifecycleState] = Column(
        Enum(AssetLifecycleState, native_enum=False, validate_strings=True),
        default=AssetLifecycleState.ACTIVE,
        nullable=False,
    )
    merged_into_asset_id: Mapped[int | None] = Column(Integer, ForeignKey("assets.id"), nullable=True)
    # A human looked at this artefact and made a call (#150). Distinct from
    # lifecycle_state on purpose: most discovered rows are created ACTIVE, so
    # confirming one changes no state at all — without this the decision left no
    # trace on the record and the reviewer's own screen could not show that they
    # had already dealt with it.
    reviewed_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    reviewed_by_user_id: Mapped[int | None] = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # CA-06.5 — which approved exclusion took this artefact out of the
    # inventory, and when. Stored on the row rather than left to the audit
    # trail: a reviewer looking at a withdrawn artefact needs the reason in
    # front of them, and "it vanished" is not an explanation.
    withdrawn_by_exclusion: Mapped[str | None] = Column(String(255), nullable=True)
    withdrawn_at: Mapped[datetime | None] = Column(DateTime, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")
    connections: Mapped[List["AssetConnection"]] = relationship(
        "AssetConnection", back_populates="asset", cascade="all, delete-orphan"
    )
    status_history: Mapped[List["AssetStatusHistory"]] = relationship(
        "AssetStatusHistory", back_populates="asset", cascade="all, delete-orphan"
    )
    findings: Mapped[List["AssetFinding"]] = relationship(
        "AssetFinding", back_populates="asset", cascade="all, delete-orphan"
    )
    signals: Mapped[List["AssetEvidenceSignal"]] = relationship(
        "AssetEvidenceSignal", back_populates="asset", cascade="all, delete-orphan"
    )
    # CA-06.1 — every identifier this artefact has ever been observed under.
    identifiers: Mapped[List["AssetIdentifier"]] = relationship(
        "AssetIdentifier", back_populates="asset", cascade="all, delete-orphan"
    )
    # CA-06.2 — every port/protocol it has been observed serving.
    observed_ports: Mapped[List["AssetObservedPort"]] = relationship(
        "AssetObservedPort", back_populates="asset", cascade="all, delete-orphan"
    )
    # CA-06.3 — how it relates to other artefacts. Two sides, because direction
    # carries meaning: what this runs on is not what runs on this.
    outgoing_relationships: Mapped[List["ArtefactRelationship"]] = relationship(
        "ArtefactRelationship",
        foreign_keys="ArtefactRelationship.source_asset_id",
        back_populates="source_asset",
        cascade="all, delete-orphan",
    )
    incoming_relationships: Mapped[List["ArtefactRelationship"]] = relationship(
        "ArtefactRelationship",
        foreign_keys="ArtefactRelationship.target_asset_id",
        back_populates="target_asset",
        cascade="all, delete-orphan",
    )


class AssetConnection(Base):
    __tablename__ = "asset_connections"
    __table_args__ = (
        Index("ix_asset_connections_asset_state", "asset_id", "state"),
        Index("ix_asset_connections_provider_account", "provider", "provider_account_id"),
        Index("ix_asset_connections_connection_state", "connection_state"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    asset_id: Mapped[int] = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    auth_type: Mapped[str | None] = Column(String(50))
    scopes: Mapped[list | None] = Column(JSON)
    external_account_id: Mapped[str | None] = Column(String(200))
    mock_token: Mapped[str | None] = Column(String(200))
    connected_at: Mapped[datetime | None] = Column(DateTime, default=utcnow)
    last_sync_at: Mapped[datetime | None] = Column(DateTime)
    state: Mapped[str] = Column(String(50), default="DISCONNECTED", nullable=False)
    provider: Mapped[str | None] = Column(String(50))
    provider_account_id: Mapped[str | None] = Column(Text)
    external_id: Mapped[str | None] = Column(Text)
    role_arn: Mapped[str | None] = Column(Text)
    provider_resource_id: Mapped[str | None] = Column(Text)
    permission_preset: Mapped[str | None] = Column(String(100), default="SECURITY_READONLY", nullable=True)
    connection_state: Mapped[ConnectionState] = Column(
        Enum(ConnectionState, native_enum=False, validate_strings=True),
        default=ConnectionState.DRAFT,
        nullable=False,
    )
    last_error_code: Mapped[str | None] = Column(Text)
    last_error_detail: Mapped[str | None] = Column(Text)
    validated_at: Mapped[datetime | None] = Column(DateTime)
    auth_method: Mapped[str | None] = Column(String(100))
    auth_payload_json: Mapped[dict | list | None] = Column(JSON)
    error_code: Mapped[str | None] = Column(String(50))
    error_message: Mapped[str | None] = Column(Text)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="connections")


class AssetStatusHistory(Base):
    __tablename__ = "asset_status_history"
    __table_args__ = (
        Index("ix_status_history_asset_time", "asset_id", "observed_at"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    asset_id: Mapped[int] = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    status: Mapped[AssetStatus] = Column(Enum(AssetStatus, native_enum=False, validate_strings=True), nullable=False, index=True)
    risk_score: Mapped[float | None] = Column(Float)
    observation_level: Mapped[str | None] = Column(String(50))
    findings_count: Mapped[int | None] = Column(Integer)
    confidence: Mapped[float | None] = Column(Float)
    observed_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    connectivity_status: Mapped[ConnectivityStatus | None] = Column(
        Enum(ConnectivityStatus, native_enum=False, validate_strings=True), nullable=True
    )
    connection_state: Mapped[ConnectionState | None] = Column(
        Enum(ConnectionState, native_enum=False, validate_strings=True), nullable=True
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="status_history")


class AssetEvidenceSignal(Base):
    __tablename__ = "asset_evidence_signals"
    __table_args__ = (
        Index("ix_asset_signals_asset_time", "asset_id", "observed_at"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    asset_id: Mapped[int] = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    # Which pipeline produced this row (collector_host_observation /
    # risk_intelligence_ingestion, Step 4.1A) — distinct from
    # observation_type below (Step 4.1B), which is *what was observed*.
    kind: Mapped[str] = Column(String(100), nullable=False)
    payload_json: Mapped[dict] = Column(JSON, nullable=False)
    observed_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False, index=True)
    confidence: Mapped[float | None] = Column(Float)
    risk_score: Mapped[float | None] = Column(Float)
    # Step 4.1B — structured technical observation fields. Nullable: rows
    # written before this existed, and any future signal source that
    # genuinely has nothing to report here, carry no fabricated value.
    # Validated against a controlled vocabulary at the service layer
    # (artefact_identity_enums.py), not a DB-level enum — see this table's
    # existing `kind` column for the same String-not-Enum precedent.
    observation_type: Mapped[str | None] = Column(String(60))
    status: Mapped[str | None] = Column(String(20))
    # Reuses SeverityLevel's values (critical/high/medium/low/info) rather
    # than a parallel severity vocabulary.
    severity: Mapped[str | None] = Column(String(20))
    # CA-06.2 — where this observation came from, as real references rather
    # than an id buried in payload_json. All three are nullable and stay that
    # way: a signal from a manual upload, or one written before these columns
    # existed, genuinely has no evidence package, and an absent reference must
    # read as absent rather than be backfilled with a guess.
    #
    # Provenance is recorded per *observation*, not read off the artefact's
    # parent, because one artefact legitimately carries signals from different
    # Collectors and different runs — so there is no single parent to read it
    # from. (This is why it is denormalised here, where CA-04.6 deliberately
    # kept process context on DiscoveryRun alone: that was a property of the
    # run; this is a property of the sighting.)
    evidence_package_id: Mapped[str | None] = Column(
        String(36), ForeignKey("evidence_packages.id", ondelete="SET NULL"), nullable=True
    )
    provider_execution_id: Mapped[str | None] = Column(
        String(36), ForeignKey("provider_executions.id", ondelete="SET NULL"), nullable=True
    )
    #: The Collector that produced the evidence. Reachable via the package's own
    #: run, but recorded here so "which Collector said this" survives the run
    #: being cleaned up, and so the question costs one column rather than a walk.
    scanner_instance_id: Mapped[str | None] = Column(
        String(36), ForeignKey("scanner_instances.id", ondelete="SET NULL"), nullable=True
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="signals")
    organization: Mapped["Organization"] = relationship("Organization")


class AssetObservedPort(Base):
    """CA-06.2 — a port/protocol an artefact has been observed serving.

    Ports previously survived only inside ``AssetEvidenceSignal.payload_json``
    and as service-name strings in ``Asset.intent``, so "what is this thing
    exposing, and since when" could only be answered by re-parsing raw scanner
    output. They are technical facts, not findings: nothing here carries a
    severity or a judgement (that stays with ``AssetFinding``).

    A row is never deleted when the port stops answering. ``last_seen_at``
    simply stops advancing, which is what makes "closed since when" answerable —
    compare it against the artefact's own ``last_observed_at``. Deleting the row
    would erase the only evidence that it was ever open.

    Bounded by construction, unlike the signal stream BUG-DISC-18 had to put a
    retention policy on: there is one row per distinct port/protocol per
    artefact, so repeated scans update rows rather than accumulating them.
    """

    __tablename__ = "asset_observed_ports"
    __table_args__ = (
        Index(
            "uq_asset_observed_ports_asset_port_protocol",
            "asset_id",
            "port",
            "protocol",
            unique=True,
        ),
        Index("ix_asset_observed_ports_org_asset", "organization_id", "asset_id"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    asset_id: Mapped[int] = Column(
        Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port: Mapped[int] = Column(Integer, nullable=False)
    #: tcp / udp as reported. Normalised to lower case; never inferred when the
    #: scanner did not say, which is why it has an explicit "unknown" rather
    #: than defaulting to tcp.
    protocol: Mapped[str] = Column(String(10), nullable=False)
    service_name: Mapped[str | None] = Column(String(100))
    #: What the scanner claimed is running there, when it said so. Kept
    #: separate from service_name because "ssh" and "OpenSSH 8.9p1" are
    #: different strengths of claim.
    product: Mapped[str | None] = Column(String(255))
    product_version: Mapped[str | None] = Column(String(100))
    first_seen_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="observed_ports")
    organization: Mapped["Organization"] = relationship("Organization")


class AssetIdentifier(Base):
    """CA-06.1 — one identifier an artefact has been observed under.

    An artefact's identity is this set, not any single row in it. That is what
    lets a host keep its identity when its IP changes (the old IP stays here,
    with the last date it was seen, rather than being overwritten) and what lets
    two sources converge on one artefact when their identifier sets overlap.

    ``identifier_value`` is stored normalised (stripped, lower-cased) because it
    is matched on, not displayed — the display name lives on ``Asset``.
    """

    __tablename__ = "asset_identifiers"
    __table_args__ = (
        # One row per distinct identifier per artefact — re-observing an
        # identifier updates last_seen_at rather than adding a duplicate.
        Index(
            "uq_asset_identifiers_asset_type_value",
            "asset_id",
            "identifier_type",
            "identifier_value",
            unique=True,
        ),
        # The lookup identity resolution actually performs: "which artefact in
        # this organisation has ever been seen under this identifier?" Tenant
        # scoping leads, as everywhere in this codebase.
        Index(
            "ix_asset_identifiers_org_type_value",
            "organization_id",
            "identifier_type",
            "identifier_value",
        ),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    asset_id: Mapped[int] = Column(
        Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Controlled vocabulary (ArtefactIdentifierType), validated at the service
    # layer rather than as a DB enum — the same String-not-Enum precedent this
    # table's neighbours (`AssetEvidenceSignal.kind`) already set.
    identifier_type: Mapped[str] = Column(String(40), nullable=False)
    identifier_value: Mapped[str] = Column(String(500), nullable=False)
    #: Which source observed it (a collector source name, a provider). Recorded
    #: because "who says so" is part of the claim; never guessed.
    observed_by_source: Mapped[str | None] = Column(String(255))
    first_seen_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="identifiers")
    organization: Mapped["Organization"] = relationship("Organization")


class AssetFindingStatus(enum.Enum):
    OPEN = "open"
    NEEDS_REVIEW = "needs_review"
    RESOLVED = "resolved"


class AssetFinding(Base):
    __tablename__ = "asset_findings"
    __table_args__ = (
        Index("ix_asset_findings_asset_status", "asset_id", "status"),
        Index("ix_asset_findings_org_status", "organization_id", "status"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    asset_id: Mapped[int] = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    domain: Mapped[str] = Column(String(100), nullable=False)
    severity: Mapped[SeverityLevel] = Column(SEVERITY_ENUM, nullable=False, index=True)
    title: Mapped[str] = Column(String(500), nullable=False)
    description: Mapped[str | None] = Column(Text)
    evidence_refs: Mapped[list | None] = Column(JSON)
    risk_score: Mapped[float | None] = Column(Float)
    first_seen_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    status: Mapped[AssetFindingStatus] = Column(
        Enum(AssetFindingStatus, native_enum=False, validate_strings=True),
        default=AssetFindingStatus.OPEN,
        nullable=False,
        index=True,
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="findings")
    organization: Mapped["Organization"] = relationship("Organization")


class ControlCoverageStatus(enum.Enum):
    COVERED = "COVERED"
    PARTIALLY_COVERED = "PARTIALLY_COVERED"
    NOT_COVERED = "NOT_COVERED"


class Control(Base):
    __tablename__ = "controls"
    __table_args__ = (
        Index("ix_controls_framework_code", "framework", "control_code", unique=True),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    framework: Mapped[str] = Column(String(100), nullable=False, index=True)
    control_code: Mapped[str] = Column(String(50), nullable=False)
    title: Mapped[str] = Column(String(255), nullable=False)
    description: Mapped[str | None] = Column(Text)

    mappings: Mapped[List["ControlMapping"]] = relationship(
        "ControlMapping", back_populates="control", cascade="all, delete-orphan"
    )
    evidences: Mapped[List["ControlEvidence"]] = relationship(
        "ControlEvidence", back_populates="control", cascade="all, delete-orphan"
    )


class ControlMapping(Base):
    __tablename__ = "control_mappings"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    control_id: Mapped[int] = Column(Integer, ForeignKey("controls.id"), nullable=False, index=True)
    asset_type: Mapped[str] = Column(String(50), nullable=False, index=True)
    signal_kind: Mapped[str] = Column(String(100), nullable=False)
    min_confidence: Mapped[float] = Column(Float, default=0.0, nullable=False)
    evidence_rule: Mapped[str | None] = Column(String(255))

    control: Mapped["Control"] = relationship("Control", back_populates="mappings")


class ControlEvidence(Base):
    __tablename__ = "control_evidence"
    __table_args__ = (
        Index("ix_control_evidence_org_control", "organization_id", "control_id"),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    control_id: Mapped[int] = Column(Integer, ForeignKey("controls.id"), nullable=False, index=True)
    asset_id: Mapped[int] = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    status: Mapped[ControlCoverageStatus] = Column(
        Enum(ControlCoverageStatus, native_enum=False, validate_strings=True),
        default=ControlCoverageStatus.NOT_COVERED,
        nullable=False,
    )
    confidence: Mapped[float | None] = Column(Float)
    last_evaluated_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)
    evidence_refs: Mapped[list | None] = Column(JSON)

    control: Mapped["Control"] = relationship("Control", back_populates="evidences")
    organization: Mapped["Organization"] = relationship("Organization")
    asset: Mapped["Asset"] = relationship("Asset")


class ControlShareLink(Base):
    __tablename__ = "control_share_links"
    __table_args__ = (
        Index("ix_control_share_token", "token", unique=True),
    )

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    token: Mapped[str] = Column(String(200), nullable=False, unique=True)
    scope: Mapped[dict | None] = Column(JSON)
    expires_at: Mapped[datetime] = Column(DateTime, nullable=False)
    created_at: Mapped[datetime] = Column(DateTime, default=utcnow, nullable=False)

    organization: Mapped["Organization"] = relationship("Organization")

    def is_active(self) -> bool:
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return expires_at > utcnow()


__all__ = [
    "Asset",
    "AssetConnection",
    "AssetEvidenceSignal",
    "AssetFinding",
    "AssetFindingStatus",
    "AssetStatus",
    "AssetStatusHistory",
    "ConnectionState",
    "ConnectivityStatus",
    "Control",
    "ControlCoverageStatus",
    "ControlEvidence",
    "ControlMapping",
    "ControlShareLink",
    "Criticality",
    "Environment",
    "PermissionPreset",
    "ScanStartMode",
    "SetupConfidence",
]
