"""Risklence Scanner setup — Step 3.5 (configure and validate the scanner,
distinct from Step 4's actual first discovery run).

The scanner is an ``EvidenceSourceType.SCANNER`` evidence source. This
module covers only what Step 3.5 needs: approved domain/network targets, a
scan profile, and the setup-readiness vocabulary. It deliberately does not
model anything about scan *results* (hosts, services, findings) — that is
Step 4/5's job (organisation discovery → shared artefact inventory).

Real tool execution (Nmap/Subfinder/Nuclei) and the scanner-to-Risklence
network handshake are out of scope for this slice — ``tool_status``/
``connection_verified_at``/``test_scan_status`` are recorded from an
operator-triggered validation call, not a live agent, matching how the
file-import path stubs "the CMDB" by accepting a direct upload rather than
requiring a live connector.
"""

from enum import StrEnum


class ScannerInstallationMethod(StrEnum):
    DOCKER = "docker"
    LOCAL_CLI = "local_cli"
    SERVER = "server"
    CONSULTANT_ASSISTED = "consultant_assisted"


class ScannerProfile(StrEnum):
    SAFE_DISCOVERY = "safe_discovery"
    STANDARD_DISCOVERY = "standard_discovery"
    EXTENDED_DISCOVERY = "extended_discovery"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    CUSTOM = "custom"


# Capabilities implied by each profile (spec §3, §5.3) — derived, never
# stored, so there is exactly one place that decides what a profile means.
SCANNER_PROFILE_CAPABILITIES: dict[str, dict[str, bool]] = {
    ScannerProfile.SAFE_DISCOVERY.value: {
        "externalDiscoveryEnabled": True,
        "internalDiscoveryEnabled": True,
        "serviceFingerprintingEnabled": True,
        "vulnerabilityScanningEnabled": False,
    },
    ScannerProfile.STANDARD_DISCOVERY.value: {
        "externalDiscoveryEnabled": True,
        "internalDiscoveryEnabled": True,
        "serviceFingerprintingEnabled": True,
        "vulnerabilityScanningEnabled": True,
    },
    ScannerProfile.EXTENDED_DISCOVERY.value: {
        "externalDiscoveryEnabled": True,
        "internalDiscoveryEnabled": True,
        "serviceFingerprintingEnabled": True,
        "vulnerabilityScanningEnabled": True,
    },
    ScannerProfile.VULNERABILITY_ASSESSMENT.value: {
        "externalDiscoveryEnabled": True,
        "internalDiscoveryEnabled": True,
        "serviceFingerprintingEnabled": True,
        "vulnerabilityScanningEnabled": True,
    },
    ScannerProfile.CUSTOM.value: {
        "externalDiscoveryEnabled": False,
        "internalDiscoveryEnabled": False,
        "serviceFingerprintingEnabled": False,
        "vulnerabilityScanningEnabled": False,
    },
}


class ScannerInstanceStatus(StrEnum):
    """Mirrors spec §7.3's ``ScannerInstance.status`` exactly. A row only
    exists once installation/activation has happened — there is no
    "not installed" member here on purpose, matching how the rest of this
    module derives setup progress from record presence, never a stored
    step counter."""

    REGISTERED = "registered"
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    PAUSED = "paused"
    REVOKED = "revoked"
    RETIRED = "retired"


# --- Liveness (BUG-DISC-05) --------------------------------------------------
# ScannerInstance.status is only ever raised to ONLINE by record_heartbeat and
# never lowered, so a Collector that has stopped stays "Connected" forever. The
# platform must not claim a component is healthy on the strength of a historical
# event, so liveness is *derived* from last_heartbeat_at instead — see
# resolve_scanner_liveness in evidence_scanner_service.
#
# Must stay in step with the agent's own loop: scanner_agent/cli.py's
# DEFAULT_RUN_INTERVAL_SECONDS. Two missed cycles rather than one, so a single
# skipped beat (a slow network, a restart) does not flap a healthy Collector to
# offline; it is a tolerance derived from the agent's cadence, not a guess.
SCANNER_POLL_INTERVAL_SECONDS: int = 300
SCANNER_MISSED_CYCLES_BEFORE_OFFLINE: int = 2
SCANNER_HEARTBEAT_STALE_AFTER_SECONDS: int = (
    SCANNER_POLL_INTERVAL_SECONDS * SCANNER_MISSED_CYCLES_BEFORE_OFFLINE
)


class ScannerTargetSource(StrEnum):
    VERIFIED_ORGANISATION_DOMAIN = "verified_organisation_domain"
    USER_ADDED = "user_added"
    IMPORTED = "imported"


class ScannerOwnershipStatus(StrEnum):
    VERIFIED = "verified"
    DECLARED = "declared"
    VERIFICATION_REQUIRED = "verification_required"


class ScannerTargetStatus(StrEnum):
    DRAFT = "draft"
    APPROVED = "approved"
    EXCLUDED = "excluded"
    DISABLED = "disabled"


class ScannerNetworkType(StrEnum):
    CORPORATE = "corporate"
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    STORE = "store"
    OFFICE = "office"
    DATA_CENTRE = "data_centre"
    CLOUD = "cloud"
    LAB = "lab"
    OTHER = "other"


class ScannerToolName(StrEnum):
    NMAP = "nmap"
    SUBFINDER = "subfinder"
    NUCLEI = "nuclei"
    NUCLEI_TEMPLATES = "nuclei_templates"


class CollectorCapability(StrEnum):
    """What a Collector's *environment* permits, as against what is installed.

    Deliberately not a ``ScannerToolName``. A missing tool is something an
    operator installs; a missing capability is a privilege the container was
    never granted, and calling it a missing tool sends somebody looking for
    something to install that does not exist.

    Reported through the same readiness components list — the contract's
    ``componentKey`` is free-form for exactly this reason — and read with
    ``component_is_ready``. It never appears in ``_CAPABILITY_REQUIRED_TOOLS``,
    so its absence widens nothing and blocks nothing: a Collector without it
    still scans, it simply learns less.
    """

    #: Permission to send raw packets (``NET_RAW``). Without it nmap cannot ARP
    #: the local segment, so no MAC address and no hardware vendor are ever
    #: reported — and ``HARDWARE_VENDOR`` is the only identity basis that can
    #: name a device with nothing listening. Its absence also makes "no MAC
    #: here" unreadable: *no device* and *we could not look* become the same
    #: observation, which is how 242 echoes became artefacts (#175).
    RAW_PACKET_ACCESS = "raw_packet_access"


class CollectorReadinessStatus(StrEnum):
    """The Collector's own verdict on whether it can actually do work (CA-02.3).

    Distinct from ``ScannerInstanceStatus``, which stays the connection and
    lifecycle concept on the row itself. This is computed from a self-check the
    Collector ran on its own machine, and readiness computation *reads* the
    connection status rather than replacing it — a Collector can be perfectly
    reachable and still be unable to scan.
    """

    READY = "ready"
    #: A self-check is in flight, or none has been received yet. The honest
    #: state on first activation and immediately after a rerun request.
    CHECKING = "checking"
    #: Something is wrong but not everything — one component failing must not
    #: read the same as a Collector that cannot work at all.
    DEGRADED = "degraded"
    BLOCKED = "blocked"
    OFFLINE = "offline"
    UPGRADE_REQUIRED = "upgrade_required"
    #: No report has ever arrived from a Collector that should have sent one —
    #: including every instance that predates readiness reporting, whose legacy
    #: manually-entered tool answers must never be read as a verified state.
    UNKNOWN = "unknown"


class CollectorComponentStatus(StrEnum):
    """One bundled component's own state, as the Collector found it."""

    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class CollectorInstruction(StrEnum):
    """An operational instruction the platform asks a Collector to carry out.

    CA-02.3 slice 3. Deliberately a *class* rather than a
    ``self_check_requested`` boolean: rotate-credential, upload-diagnostics and
    pause are all the same shape, and adding each as its own flag is how one
    mechanism becomes four subtly different ones.

    Kept separate from ``ScannerCommandType`` on domain grounds, not
    convenience. A discovery command carries authority to act on **approved
    external targets**, which is why it is signed, scope-bound and tied to a
    discovery run (``scanner_commands.discovery_run_id`` is NOT NULL). An
    operational instruction touches nothing outside the Collector itself, so
    that envelope would contribute no security value while forcing a
    genuinely-required invariant to be dropped.

    Delivered on the heartbeat response: it is the message the Collector already
    sends most often, so the instruction arrives within one interval rather than
    waiting for a command poll.
    """

    SELF_CHECK = "self_check"


class CollectorReadinessTrigger(StrEnum):
    """Why a readiness report exists.

    Without this a report cannot say whether it is a routine measurement or the
    answer to a named person pressing a button — which is the same
    "assertion or measurement?" ambiguity this entire story exists to remove,
    one level up. ``REQUESTED`` is the only value that carries a person.
    """

    STARTUP = "startup"
    PERIODIC = "periodic"
    REQUESTED = "requested"


class ScannerToolStatus(StrEnum):
    AVAILABLE = "available"
    NOT_AVAILABLE = "not_available"
    UNKNOWN = "unknown"


class ScannerOperationStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScannerSetupState(StrEnum):
    """The current blocking step in the Step 3.5 setup sequence (spec §16),
    collapsed to what this slice actually tracks — granular install
    sub-states (``INSTALLATION_METHOD_SELECTED``/``SCANNER_INSTALLING``)
    are not separately observable since installation is a single
    operator-triggered call here, not a polled remote process."""

    ACTIVATION_REQUIRED = "activation_required"
    DOMAIN_OR_NETWORK_SCOPE_REQUIRED = "domain_or_network_scope_required"
    SCAN_PROFILE_REQUIRED = "scan_profile_required"
    SCOPE_CONFIRMATION_REQUIRED = "scope_confirmation_required"
    TOOL_VALIDATION_REQUIRED = "tool_validation_required"
    TARGET_TEST_REQUIRED = "target_test_required"
    # UX-SETUP-03 (#129) — CA-05.B made an approved discovery boundary a
    # precondition for every run, and this ladder had no state for it. Setup
    # therefore reported SCANNER_READY on a Collector that could not start
    # anything: every step DONE, "Scanner ready", and discovery refused with
    # "Approve a discovery boundary before discovery can start." Missed scope
    # from CA-02/CA-03, both closed by the time CA-05.B added the precondition.
    #
    # Placed last, immediately before SCANNER_READY, rather than beside the
    # other approvals: proposing a boundary reads the confirmed scope and the
    # selected profile, so an earlier position would block on a decision that
    # cannot yet be put to a person.
    DISCOVERY_BOUNDARY_APPROVAL_REQUIRED = "discovery_boundary_approval_required"
    SCANNER_READY = "scanner_ready"


class ScannerReadiness(StrEnum):
    MISSING = "missing"
    IN_PROGRESS = "in_progress"
    READY = "ready"
    BLOCKED = "blocked"


class ScannerCredentialValidityPolicy(StrEnum):
    """How long a named credential (spec: TENANT-83) stays usable.

    ``ONE_TIME`` is a single-use bootstrap credential — it expires the
    instant it authenticates one request, unlike every other policy, which
    grants a real calendar window of repeated use (matching how the
    scanner agent already re-authenticates on every heartbeat call).
    ``CUSTOM`` requires ``custom_days`` on the create request.
    """

    ONE_TIME = "one_time"
    ONE_MONTH = "one_month"
    THREE_MONTHS = "three_months"
    SIX_MONTHS = "six_months"
    CUSTOM = "custom"


class ScannerCredentialStatus(StrEnum):
    """Independent of the parent ``ScannerInstance.status`` — a scanner can
    be online while individual keys are paused/revoked, and a key can be
    revoked without touching the instance's own connection state.
    Expiry (``expires_at`` in the past) is computed at read/auth time, not
    stored as a status, so nothing needs a background sweep to keep it
    accurate."""

    ACTIVE = "active"
    PAUSED = "paused"
    REVOKED = "revoked"
    DELETED = "deleted"


SCANNER_CREDENTIAL_VALIDITY_DAYS: dict[str, int | None] = {
    ScannerCredentialValidityPolicy.ONE_TIME.value: None,
    ScannerCredentialValidityPolicy.ONE_MONTH.value: 30,
    ScannerCredentialValidityPolicy.THREE_MONTHS.value: 90,
    ScannerCredentialValidityPolicy.SIX_MONTHS.value: 180,
    # CUSTOM has no fixed entry — the caller-supplied day count is used directly.
}

SCANNER_CREDENTIAL_MAX_CUSTOM_DAYS = 3650


#: CA-02.3 — readiness is reported by the Collector, never asserted by a user.
#: SCANNER_AUDIT_TOOLS_VALIDATED stays defined for historical rows and is
#: deliberately not written by any new code path.
SCANNER_AUDIT_READINESS_REPORTED = "evidence_scanner.readiness_reported"
SCANNER_AUDIT_SELF_CHECK_REQUESTED = "evidence_scanner.self_check_requested"
SCANNER_AUDIT_READINESS_DEGRADED = "evidence_scanner.readiness_degraded"

#: Søren, 2026-08-24 — a Collector can be renamed and have its recorded
#: installation method corrected. Its own event: "somebody changed what this is
#: called" and "somebody installed this" are different facts, and an audit trail
#: that could not tell them apart would lose the one that identifies a person.
SCANNER_AUDIT_UPDATED = "evidence_scanner.updated"
SCANNER_AUDIT_INSTALLED = "evidence_scanner.installed"
SCANNER_AUDIT_ACTIVATED = "evidence_scanner.activated"
SCANNER_AUDIT_DOMAIN_TARGET_ADDED = "evidence_scanner.domain_target_added"
SCANNER_AUDIT_DOMAIN_TARGET_APPROVED = "evidence_scanner.domain_target_approved"
SCANNER_AUDIT_DOMAIN_TARGET_EXCLUDED = "evidence_scanner.domain_target_excluded"
SCANNER_AUDIT_NETWORK_TARGET_ADDED = "evidence_scanner.network_target_added"
SCANNER_AUDIT_NETWORK_TARGET_APPROVED = "evidence_scanner.network_target_approved"
SCANNER_AUDIT_NETWORK_TARGET_EXCLUDED = "evidence_scanner.network_target_excluded"
SCANNER_AUDIT_PROFILE_SELECTED = "evidence_scanner.profile_selected"
SCANNER_AUDIT_SCOPE_CONFIRMED = "evidence_scanner.scope_confirmed"
SCANNER_AUDIT_TOOLS_VALIDATED = "evidence_scanner.tools_validated"
SCANNER_AUDIT_TEST_SCAN_RECORDED = "evidence_scanner.test_scan_recorded"
SCANNER_AUDIT_REVOKED = "evidence_scanner.revoked"
SCANNER_AUDIT_PAUSED = "evidence_scanner.paused"
SCANNER_AUDIT_RESUMED = "evidence_scanner.resumed"
SCANNER_AUDIT_TOKEN_REGENERATED = "evidence_scanner.token_regenerated"
SCANNER_AUDIT_RETIRED = "evidence_scanner.retired"
SCANNER_AUDIT_CREATED = "evidence_scanner.created"
SCANNER_AUDIT_LINKED_TO_BUSINESS_SERVICE = "evidence_scanner.linked_to_business_service"

SCANNER_CREDENTIAL_AUDIT_CREATED = "evidence_scanner.credential_created"
SCANNER_CREDENTIAL_AUDIT_ROTATED = "evidence_scanner.credential_rotated"
SCANNER_CREDENTIAL_AUDIT_PAUSED = "evidence_scanner.credential_paused"
SCANNER_CREDENTIAL_AUDIT_RESUMED = "evidence_scanner.credential_resumed"
SCANNER_CREDENTIAL_AUDIT_REVOKED = "evidence_scanner.credential_revoked"
SCANNER_CREDENTIAL_AUDIT_DELETED = "evidence_scanner.credential_deleted"

SCANNER_ERROR_NOT_FOUND = "Scanner instance not found — install the scanner for this evidence source first"
SCANNER_ERROR_WRONG_SOURCE_TYPE = "This evidence source is not a scanner source"
SCANNER_ERROR_ALREADY_INSTALLED = "A scanner is already installed for this evidence source"
SCANNER_ERROR_ALREADY_RETIRED = "This scanner has already been removed"
SCANNER_ERROR_NOT_PAUSED = "This scanner is not paused"
SCANNER_ERROR_PAUSED_OR_RETIRED = "This scanner is paused or has been removed"
SCANNER_ERROR_DOMAIN_TARGET_NOT_FOUND = "Scanner domain target not found"
SCANNER_ERROR_NETWORK_TARGET_NOT_FOUND = "Scanner network target not found"
SCANNER_ERROR_INVALID_DOMAIN = "Enter a valid domain name"
SCANNER_ERROR_DUPLICATE_DOMAIN = "This domain is already configured for this scanner"
SCANNER_ERROR_INVALID_CIDR = "Enter a valid CIDR network range, e.g. 10.20.0.0/24"
SCANNER_ERROR_DUPLICATE_CIDR = "This network range is already configured for this scanner"
SCANNER_ERROR_OVERLAPPING_CIDR = "This network range overlaps an already-configured range"
SCANNER_ERROR_SCOPE_EMPTY = (
    "At least one approved domain or network range is required before the scope can be confirmed"
)
SCANNER_ERROR_PROFILE_REQUIRED = "A scan profile must be selected before the scope can be confirmed"

SCANNER_CREDENTIAL_ERROR_NOT_FOUND = "Scanner credential not found"
SCANNER_CREDENTIAL_ERROR_NAME_REQUIRED = "Enter a name for this credential"
SCANNER_CREDENTIAL_ERROR_CUSTOM_DAYS_REQUIRED = "Enter the number of days this credential should stay valid"
SCANNER_CREDENTIAL_ERROR_CUSTOM_DAYS_INVALID = "Custom validity must be between 1 and 3650 days"
SCANNER_CREDENTIAL_ERROR_NOT_ACTIVE = "This credential is not active"
SCANNER_CREDENTIAL_ERROR_ALREADY_REVOKED = "This credential has already been revoked"
SCANNER_CREDENTIAL_ERROR_ALREADY_DELETED = "This credential has already been deleted"
SCANNER_CREDENTIAL_ERROR_DELETE_WHILE_ACTIVE = (
    "An active credential must be paused or revoked before it can be deleted"
)

# Large ranges get a warning, not a rejection (spec §5.2) — /16 or wider
# (65,536+ addresses) is the threshold used for that warning.
LARGE_NETWORK_WARNING_PREFIX_THRESHOLD = 16
