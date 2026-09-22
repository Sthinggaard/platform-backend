"""Step 4.1 — Discovery Orchestration Foundation.

Establishes the vocabulary for governing a discovery run: who requested it,
what scope/profile it covers, whether it needs approval, and its lifecycle
up to and including scanner acknowledgement — never the technical results
of the scan itself. Real Nmap/Subfinder/Nuclei execution, stage-by-stage
progress reporting from a live worker loop, and any parsing of returned
evidence are Step 4.2+'s job; this module only carries the enums a
*request to scan* needs, mirroring how ``evidence_scanner_enums`` scoped
Step 3.5 to configuration/validation and left real execution undefined.
"""

from enum import StrEnum


class DiscoveryRunStatus(StrEnum):
    DRAFT = "draft"
    VALIDATING = "validating"
    BLOCKED = "blocked"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    QUEUED = "queued"
    COMMAND_AVAILABLE = "command_available"
    ACKNOWLEDGED = "acknowledged"
    RUNNING = "running"
    CANCELLATION_REQUESTED = "cancellation_requested"
    CANCELLED = "cancelled"
    PARTIALLY_COMPLETED = "partially_completed"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


# A terminal run can never transition again — retrying creates a new row
# linked via retry_of_discovery_run_id instead of mutating this one.
TERMINAL_DISCOVERY_RUN_STATUSES: frozenset[str] = frozenset(
    {
        DiscoveryRunStatus.CANCELLED.value,
        DiscoveryRunStatus.PARTIALLY_COMPLETED.value,
        DiscoveryRunStatus.COMPLETED.value,
        DiscoveryRunStatus.FAILED.value,
        DiscoveryRunStatus.EXPIRED.value,
    }
)

# The guarded transition table, matching spec §11 exactly. BLOCKED has no
# listed outgoing transition anywhere in the spec's own recommended-transitions
# list — a blocked request doesn't self-heal, the requester must fix the
# underlying blocker and submit a new request (a new DiscoveryRun row, same
# principle as retry). Treated here as a soft-terminal state distinct from
# the five official terminal statuses above (it's not listed as terminal in
# spec §11, but nothing transitions out of it either).
ALLOWED_DISCOVERY_RUN_TRANSITIONS: dict[str, frozenset[str]] = {
    DiscoveryRunStatus.DRAFT.value: frozenset(
        {DiscoveryRunStatus.VALIDATING.value, DiscoveryRunStatus.CANCELLED.value}
    ),
    DiscoveryRunStatus.VALIDATING.value: frozenset(
        {
            DiscoveryRunStatus.BLOCKED.value,
            DiscoveryRunStatus.AWAITING_APPROVAL.value,
            DiscoveryRunStatus.APPROVED.value,
            DiscoveryRunStatus.CANCELLED.value,
        }
    ),
    DiscoveryRunStatus.AWAITING_APPROVAL.value: frozenset(
        {
            DiscoveryRunStatus.APPROVED.value,
            DiscoveryRunStatus.BLOCKED.value,
            DiscoveryRunStatus.EXPIRED.value,
            DiscoveryRunStatus.CANCELLED.value,
        }
    ),
    # CANCELLED is reachable from every pre-command status, not just
    # QUEUED — spec §11's own transition table omits it here, but §17
    # explicitly requires "before acknowledgement" cancellation to work
    # from any state before a command has been delivered, which includes
    # APPROVED (command not yet created).
    # RUNNING (Step 4.2 Part 2, DISC-24): the execution-pipeline path —
    # generate_execution_plan() creates a DiscoveryExecutionPlan and moves
    # the run straight to RUNNING, skipping QUEUED/COMMAND_AVAILABLE/
    # ACKNOWLEDGED entirely (those exist only for the original Step 4.1
    # whole-run scanner-command handshake, still intact and still used by
    # create_command_for_run — kept, not removed, since retiring it
    # entirely is a separate, deliberate follow-up, not bundled into this
    # plumbing fix).
    DiscoveryRunStatus.APPROVED.value: frozenset(
        {DiscoveryRunStatus.QUEUED.value, DiscoveryRunStatus.RUNNING.value, DiscoveryRunStatus.CANCELLED.value}
    ),
    DiscoveryRunStatus.QUEUED.value: frozenset(
        {
            DiscoveryRunStatus.COMMAND_AVAILABLE.value,
            DiscoveryRunStatus.BLOCKED.value,
            DiscoveryRunStatus.CANCELLED.value,
            DiscoveryRunStatus.EXPIRED.value,
        }
    ),
    # CANCELLED (not CANCELLATION_REQUESTED) — spec §17: "before
    # acknowledgement: invalidate the command and mark the run cancelled."
    # A command that exists but hasn't been acknowledged yet is still
    # "before acknowledgement."
    DiscoveryRunStatus.COMMAND_AVAILABLE.value: frozenset(
        {
            DiscoveryRunStatus.ACKNOWLEDGED.value,
            DiscoveryRunStatus.CANCELLED.value,
            DiscoveryRunStatus.EXPIRED.value,
            DiscoveryRunStatus.FAILED.value,
        }
    ),
    DiscoveryRunStatus.ACKNOWLEDGED.value: frozenset(
        {
            DiscoveryRunStatus.RUNNING.value,
            DiscoveryRunStatus.CANCELLATION_REQUESTED.value,
            DiscoveryRunStatus.FAILED.value,
        }
    ),
    DiscoveryRunStatus.RUNNING.value: frozenset(
        {
            DiscoveryRunStatus.CANCELLATION_REQUESTED.value,
            DiscoveryRunStatus.PARTIALLY_COMPLETED.value,
            DiscoveryRunStatus.COMPLETED.value,
            DiscoveryRunStatus.FAILED.value,
        }
    ),
    DiscoveryRunStatus.CANCELLATION_REQUESTED.value: frozenset(
        {
            DiscoveryRunStatus.CANCELLED.value,
            DiscoveryRunStatus.PARTIALLY_COMPLETED.value,
            DiscoveryRunStatus.FAILED.value,
        }
    ),
    DiscoveryRunStatus.BLOCKED.value: frozenset(),
    DiscoveryRunStatus.CANCELLED.value: frozenset(),
    DiscoveryRunStatus.PARTIALLY_COMPLETED.value: frozenset(),
    DiscoveryRunStatus.COMPLETED.value: frozenset(),
    DiscoveryRunStatus.FAILED.value: frozenset(),
    DiscoveryRunStatus.EXPIRED.value: frozenset(),
}


class DiscoveryStage(StrEnum):
    """Business-readable stage labels, spec §12. This prompt only tracks
    which stage a run reports itself at — no worker actually drives a run
    through these stages yet (Step 4.2)."""

    PREPARING = "preparing"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    WAITING_FOR_SCANNER = "waiting_for_scanner"
    COMMAND_DELIVERY = "command_delivery"
    EXTERNAL_DISCOVERY = "external_discovery"
    INTERNAL_DISCOVERY = "internal_discovery"
    SERVICE_FINGERPRINTING = "service_fingerprinting"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    RESULT_UPLOAD = "result_upload"
    RESULT_PROCESSING = "result_processing"
    FINALISING = "finalising"
    COMPLETE = "complete"


# Which stages a given scan profile may legitimately report, derived from
# SCANNER_PROFILE_CAPABILITIES the same way evidence_scanner_readiness_service
# derives tool requirements per profile — never trust an arbitrary
# scanner-reported stage string (spec §12/§27 security requirement).
STAGES_ALWAYS_ALLOWED: frozenset[str] = frozenset(
    {
        DiscoveryStage.PREPARING.value,
        DiscoveryStage.WAITING_FOR_APPROVAL.value,
        DiscoveryStage.WAITING_FOR_SCANNER.value,
        DiscoveryStage.COMMAND_DELIVERY.value,
        DiscoveryStage.RESULT_UPLOAD.value,
        DiscoveryStage.RESULT_PROCESSING.value,
        DiscoveryStage.FINALISING.value,
        DiscoveryStage.COMPLETE.value,
    }
)

# Which profile capability flag enables each *technical* stage — shared by
# discovery_command_service.py (validates a scanner-reported stage against
# it) and, from Step 4.2, discovery_execution_plan_service.py (decides
# which stages a DiscoveryExecutionPlan should even include). One mapping,
# two consumers — promoted here rather than left as discovery_command_service's
# own private constant once a second module needed the exact same thing.
STAGE_REQUIRES_CAPABILITY: dict[str, str] = {
    DiscoveryStage.EXTERNAL_DISCOVERY.value: "allowsExternalDiscovery",
    DiscoveryStage.INTERNAL_DISCOVERY.value: "allowsInternalDiscovery",
    DiscoveryStage.SERVICE_FINGERPRINTING.value: "allowsFingerprinting",
    DiscoveryStage.VULNERABILITY_DISCOVERY.value: "allowsVulnerabilityChecks",
}


class DiscoveryRequestSource(StrEnum):
    ONBOARDING = "onboarding"
    SCANNER_PAGE = "scanner_page"
    SCHEDULE = "schedule"
    API = "api"


class DiscoveryPurpose(StrEnum):
    FIRST_ORGANISATION_DISCOVERY = "first_organisation_discovery"
    MANUAL_DISCOVERY = "manual_discovery"
    SCHEDULED_DISCOVERY = "scheduled_discovery"
    RETRY = "retry"


class DiscoveryApprovalStatus(StrEnum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"


class ScannerCommandType(StrEnum):
    RUN_DISCOVERY = "run_discovery"
    # CA-04.8 — the same command envelope, real command_type distinction:
    # set when the command's own business_process_id (CA-04.7) is not
    # None, so a process/service-scoped assurance job is identifiable by
    # its command_type alone, not only by inspecting business_process_id
    # separately. Neither value is ever removed/repurposed.
    RUN_PROCESS_SCOPED_DISCOVERY = "run_process_scoped_discovery"


# CA-04.2 — the kinds of scope a discovery command can carry, as they appear
# on ``DiscoveryRun.target_snapshot`` (discovery_run_snapshots.py). These two
# values were written as bare literals in three places before CA-09V needed a
# fourth; a target type decides how scope containment is checked, so it is a
# dependency between modules and belongs in one typed definition.
class DiscoveryTargetType(StrEnum):
    DOMAIN = "DOMAIN"
    NETWORK_RANGE = "NETWORK_RANGE"


class ScannerCommandStatus(StrEnum):
    PENDING = "pending"
    DELIVERED = "delivered"
    ACKNOWLEDGED = "acknowledged"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


# CA-04.2 — one member per registered DiscoveryProvider (discovery_providers/
# __init__.py's _PROVIDERS_BY_ID), kept in sync by hand rather than imported
# from there, to avoid a low-level enums module depending on the services
# package. Exactly NMAP today, matching what CA-01 confirmed is actually
# registered — CA-04.3/04.4 add SUBFINDER/NUCLEI here once those providers
# are for real, not fabricated ahead of them. A command must name one of
# these values; nothing else is a registered, known check.
class CheckKey(StrEnum):
    NMAP = "nmap"
    SUBFINDER = "subfinder"
    NUCLEI = "nuclei"


class CommandRejectionCode(StrEnum):
    COMMAND_EXPIRED = "command_expired"
    COMMAND_SIGNATURE_INVALID = "command_signature_invalid"
    SCANNER_INSTANCE_MISMATCH = "scanner_instance_mismatch"
    ORGANISATION_MISMATCH = "organisation_mismatch"
    PROFILE_UNSUPPORTED = "profile_unsupported"
    TARGET_NOT_LOCALLY_APPROVED = "target_not_locally_approved"
    MAINTENANCE_WINDOW_CLOSED = "maintenance_window_closed"
    SCANNER_LOCALLY_PAUSED = "scanner_locally_paused"
    SCANNER_BUSY = "scanner_busy"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    CHECK_KEY_UNKNOWN = "check_key_unknown"
    # The run itself has moved on (cancelling, or already finished) and
    # cannot take this command's work, whatever the Collector says about it.
    RUN_NOT_ACCEPTING_WORK = "run_not_accepting_work"


# DISC-46 — Step 4.2 Part 3 spec §16's structured cancellation reasonCode.
# A closed, business-language vocabulary rather than free text, so
# cancellation history can be reported on; OTHER always requires
# ``cancellation_reason_note`` (enforced in request_cancellation), matching
# this codebase's existing "other requires a note" convention (see the
# decision-workbench modal).
class DiscoveryCancellationReasonCode(StrEnum):
    CUSTOMER_REQUESTED = "customer_requested"
    SCOPE_CHANGED = "scope_changed"
    SECURITY_CONCERN = "security_concern"
    DUPLICATE_RUN = "duplicate_run"
    SCANNER_UNAVAILABLE = "scanner_unavailable"
    OTHER = "other"


# Deliberately narrow, evidence-based approval policy (spec §13 lists more
# conditions than this repo currently models data for — maintenance windows,
# an org-level dual-control flag, and "never scanned before" are not
# implemented; see evaluate_approval_requirement's docstring). Only two
# checks are backed by real, existing fields: the profile type, and whether
# any included network target is classified PRODUCTION.
DISCOVERY_APPROVAL_REASON_VULNERABILITY_PROFILE = "vulnerability_profile"
DISCOVERY_APPROVAL_REASON_PRODUCTION_NETWORK = "production_network_target"

# Retryable vs non-retryable failure codes (spec §18's own examples).
RETRYABLE_FAILURE_CODES: frozenset[str] = frozenset(
    {
        "scanner_offline",
        "provider_timeout",
        "command_delivery_failed",
        "scanner_busy",
        "upload_interrupted",
        CommandRejectionCode.SCANNER_BUSY.value,
        CommandRejectionCode.SCANNER_LOCALLY_PAUSED.value,
    }
)
NON_RETRYABLE_FAILURE_CODES: frozenset[str] = frozenset(
    {
        "scope_not_approved",
        "permission_denied",
        "scanner_activation_revoked",
        "profile_unsupported",
        "invalid_organisation_binding",
        "maintenance_approval_expired",
        CommandRejectionCode.PROFILE_UNSUPPORTED.value,
        CommandRejectionCode.TARGET_NOT_LOCALLY_APPROVED.value,
        CommandRejectionCode.ORGANISATION_MISMATCH.value,
        CommandRejectionCode.SCANNER_INSTANCE_MISMATCH.value,
    }
)

DISCOVERY_RUN_ERROR_TECHNICAL_OWNER_REQUIRED = "A Technical Setup Owner must be assigned before discovery can start."
DISCOVERY_RUN_ERROR_SCANNER_CONNECTION_REQUIRED = "No scanner is installed for this evidence source yet."
DISCOVERY_RUN_ERROR_SCANNER_NOT_ACTIVATED = "The scanner has not been activated yet."
DISCOVERY_RUN_ERROR_SCANNER_OFFLINE = (
    "The scanner hasn't connected yet — run the scanner CLI's `activate` command using the activation token "
    "shown when the scanner was installed, then try again."
)
DISCOVERY_RUN_ERROR_SCANNER_CAPABILITY_REQUIRED = "The scanner has not validated the tools this profile requires."
DISCOVERY_RUN_ERROR_DISCOVERY_SCOPE_REQUIRED = "Select at least one approved domain or network range."
DISCOVERY_RUN_ERROR_DISCOVERY_SCOPE_NOT_APPROVED = (
    "One or more selected targets are not approved scope for this scanner."
)
DISCOVERY_RUN_ERROR_DISCOVERY_PROFILE_REQUIRED = "Select a scan profile before starting discovery."

# CA-05.B — a target the Technical Setup Owner explicitly excluded from the
# approved boundary. Distinct from DISCOVERY_SCOPE_NOT_APPROVED (a target never
# approved at all): this one *was* considered and deliberately ruled out, so the
# fix is to change the boundary, not to approve the target.
DISCOVERY_RUN_ERROR_TARGET_EXCLUDED_BY_BOUNDARY = (
    "One or more selected targets are excluded by the approved discovery boundary."
)

# CA-05.B — no boundary has been approved for this evidence source yet. Made a
# readiness blocker rather than a bare refusal so an organisation sees the thing
# it must do, alongside technical_owner_required, instead of hitting an error.
# Every discovery run must trace back to an explicitly approved boundary; that
# traceability is the audit argument.
DISCOVERY_RUN_ERROR_BOUNDARY_APPROVAL_REQUIRED = (
    "Approve a discovery boundary before discovery can start."
)
DISCOVERY_RUN_ERROR_DISCOVERY_PROFILE_UNSUPPORTED = "The scanner does not support the selected scan profile."
DISCOVERY_RUN_ERROR_DISCOVERY_APPROVAL_REQUIRED = "This discovery request requires approval before it can start."
DISCOVERY_RUN_ERROR_DISCOVERY_PERMISSION_REQUIRED = "You do not have permission to perform this action."
DISCOVERY_RUN_ERROR_DISCOVERY_ALREADY_RUNNING = "A discovery run is already active for this scanner."
DISCOVERY_RUN_ERROR_DISCOVERY_NOT_RETRYABLE = "This failure is not retryable until the underlying issue is resolved."
DISCOVERY_RUN_ERROR_DISCOVERY_RUN_NOT_FOUND = "Discovery run not found."
DISCOVERY_RUN_ERROR_INVALID_TRANSITION = "This action is not valid for the discovery run's current state."
# CA-04.7
DISCOVERY_RUN_ERROR_PROCESS_NOT_LINKED = "The scanner is not actively linked to this business process."
DISCOVERY_RUN_ERROR_SERVICE_REQUIRES_PROCESS = "A business service requires a business process to be specified."
# CA-10
DISCOVERY_RUN_ERROR_PROCESS_SCAN_SCOPE_NOT_APPROVED = (
    "This business process has no approved, currently-effective scan scope."
)

DISCOVERY_RUN_AUDIT_REQUESTED = "discovery_run.requested"
DISCOVERY_RUN_AUDIT_BLOCKED = "discovery_run.blocked"
DISCOVERY_RUN_AUDIT_APPROVAL_REQUIRED = "discovery_run.approval_required"
DISCOVERY_RUN_AUDIT_APPROVED = "discovery_run.approved"
DISCOVERY_RUN_AUDIT_QUEUED = "discovery_run.queued"
DISCOVERY_RUN_AUDIT_COMMAND_CREATED = "discovery_run.command_created"
DISCOVERY_RUN_AUDIT_COMMAND_DELIVERED = "discovery_run.command_delivered"
DISCOVERY_RUN_AUDIT_COMMAND_ACKNOWLEDGED = "discovery_run.command_acknowledged"
DISCOVERY_RUN_AUDIT_COMMAND_REJECTED = "discovery_run.command_rejected"
DISCOVERY_RUN_AUDIT_STAGE_CHANGED = "discovery_run.stage_changed"
DISCOVERY_RUN_AUDIT_CANCELLATION_REQUESTED = "discovery_run.cancellation_requested"
DISCOVERY_RUN_AUDIT_CANCELLED = "discovery_run.cancelled"
DISCOVERY_RUN_AUDIT_COMPLETED = "discovery_run.completed"
DISCOVERY_RUN_AUDIT_FAILED = "discovery_run.failed"
DISCOVERY_RUN_AUDIT_EXPIRED = "discovery_run.expired"
DISCOVERY_RUN_AUDIT_RETRY_REQUESTED = "discovery_run.retry_requested"

# Command envelopes expire quickly — short-lived by design (spec §14).
DISCOVERY_COMMAND_EXPIRY_SECONDS = 15 * 60

#: How long a Collector may have been down and still have its queued work
#: revived when it returns (UX-DISC-06). Time spent offline does not count
#: toward command expiry — the Collector could not have taken the command — but
#: this bounds that indefinitely: reviving a week-old discovery because an agent
#: came back would be exactly the unannounced scan expiry exists to prevent.
MAX_COMMAND_REVIVAL_DOWNTIME_SECONDS = 24 * 60 * 60
DISCOVERY_COMMAND_SIGNATURE_VERSION = "v1"
