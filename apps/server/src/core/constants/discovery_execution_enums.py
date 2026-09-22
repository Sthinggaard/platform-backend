"""Step 4.2 Part 2 — Discovery Execution Pipeline.

Vocabulary for the execution engine that turns an *approved* ``DiscoveryRun``
(Step 4.1) into real, provider-driven technical discovery: how a
``DiscoveryExecutionPlan``/``ExecutionStage``/``ProviderExecution`` progress,
what an evidence package's own storage/normalization state looks like, and
the audit event names this domain writes. Deliberately does not add a second
stage taxonomy — ``ExecutionStage.stage_key`` reuses ``DiscoveryStage``
(``discovery_run_enums.py``) values directly. Design record: TASKS.md
DISC-17, ``tasks/active/DISC-17-discovery-execution-pipeline-design.md``.
"""

from enum import StrEnum


class ExecutionMode(StrEnum):
    """How a registered DiscoveryProvider actually runs a job — see
    discovery_providers.py. DIRECT providers (cloud connectors calling an
    API Risklence's own backend can reach) execute synchronously in a
    worker. DELEGATED providers (Nmap/Subfinder/Nuclei) must run on the
    customer's own scanner agent — Risklence's backend cannot reach a
    customer's network directly, and must never attempt to (a genuine
    security/correctness boundary, not a simplification). A DELEGATED
    provider's "execute" call only creates a ScannerCommand and returns
    immediately; the job stays open until the scanner reports a real
    result via the new per-job result route."""

    DIRECT = "direct"
    DELEGATED = "delegated"


class ExecutionPlanStatus(StrEnum):
    """A plan is generated once per approved DiscoveryRun and is immutable
    once execution starts — a change requires a new DiscoveryRun (and thus
    a new plan), not a mutated one."""

    GENERATED = "generated"
    EXECUTING = "executing"
    COMPLETED = "completed"
    # Every REQUIRED stage completed, but at least one OPTIONAL
    # (ExecutionStage.required=False) stage did not — distinct from
    # PARTIALLY_COMPLETED, which means a REQUIRED stage itself fell short
    # (DISC-30). A finer-grained outcome than DiscoveryRun's own status set
    # can represent; the cascade to DiscoveryRun maps this to
    # DiscoveryRunStatus.PARTIALLY_COMPLETED, the closest existing run-level
    # status, rather than adding a new run-level status only this pipeline
    # could ever produce — a disclosed adaptation, not lost information,
    # since the finer-grained detail still lives on the plan/stage rows.
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    PARTIALLY_COMPLETED = "partially_completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_EXECUTION_PLAN_STATUSES: frozenset[str] = frozenset(
    {
        ExecutionPlanStatus.COMPLETED.value,
        ExecutionPlanStatus.COMPLETED_WITH_WARNINGS.value,
        ExecutionPlanStatus.PARTIALLY_COMPLETED.value,
        ExecutionPlanStatus.FAILED.value,
        ExecutionPlanStatus.CANCELLED.value,
    }
)

ALLOWED_EXECUTION_PLAN_TRANSITIONS: dict[str, frozenset[str]] = {
    ExecutionPlanStatus.GENERATED.value: frozenset(
        {ExecutionPlanStatus.EXECUTING.value, ExecutionPlanStatus.CANCELLED.value}
    ),
    ExecutionPlanStatus.EXECUTING.value: frozenset(
        {
            ExecutionPlanStatus.COMPLETED.value,
            ExecutionPlanStatus.COMPLETED_WITH_WARNINGS.value,
            ExecutionPlanStatus.PARTIALLY_COMPLETED.value,
            ExecutionPlanStatus.FAILED.value,
            ExecutionPlanStatus.CANCELLED.value,
        }
    ),
    ExecutionPlanStatus.COMPLETED.value: frozenset(),
    ExecutionPlanStatus.COMPLETED_WITH_WARNINGS.value: frozenset(),
    ExecutionPlanStatus.PARTIALLY_COMPLETED.value: frozenset(),
    ExecutionPlanStatus.FAILED.value: frozenset(),
    ExecutionPlanStatus.CANCELLED.value: frozenset(),
}


class ExecutionStageStatus(StrEnum):
    """PENDING = still blocked on an unmet dependency edge; READY = every
    dependency satisfied but not yet started — the scheduler's own
    queryable "what could run next" signal, distinct from PENDING."""

    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


TERMINAL_EXECUTION_STAGE_STATUSES: frozenset[str] = frozenset(
    {
        ExecutionStageStatus.COMPLETED.value,
        ExecutionStageStatus.PARTIALLY_COMPLETED.value,
        ExecutionStageStatus.FAILED.value,
        ExecutionStageStatus.SKIPPED.value,
        ExecutionStageStatus.CANCELLED.value,
    }
)


class ProviderExecutionStatus(StrEnum):
    """Mirrors ScannerCommandStatus's shape (no full guarded-transition
    table at this level — same precedent as ScannerCommandStatus, which
    also has none; only the governance-level DiscoveryRunStatus needs
    one). A retried job is a brand-new row (``retry_of_provider_execution_id``),
    never a status reset on this one."""

    PENDING = "pending"
    LEASED = "leased"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    # A retryable failure lands here with next_retry_at set, rather than
    # FAILED — the scheduler spawns the next attempt as a new sibling row
    # once next_retry_at elapses (DISC-27/28). Deliberately non-terminal.
    RETRY_SCHEDULED = "retry_scheduled"


TERMINAL_PROVIDER_EXECUTION_STATUSES: frozenset[str] = frozenset(
    {
        ProviderExecutionStatus.COMPLETED.value,
        ProviderExecutionStatus.PARTIALLY_COMPLETED.value,
        ProviderExecutionStatus.FAILED.value,
        ProviderExecutionStatus.CANCELLED.value,
        ProviderExecutionStatus.EXPIRED.value,
    }
)

#: Statuses a Collector's acknowledgement can no longer move.
#:
#: Terminal statuses, **plus ``RETRY_SCHEDULED``** — which is not terminal and
#: must not be treated as such (cancellation still applies to it), but is
#: equally not this command's to advance. Once the retry engine spawns the next
#: attempt as a new sibling row, the original is a historical record that will
#: never be worked again; the same "superseded rows are excluded" rule
#: ``_current_jobs_for_stage`` already applies to the stage rollup.
#:
#: Observed live on run 6fcadc3c, 2026-08-25: a Collector acknowledged a command
#: whose execution had since been retry-scheduled, the transition to ``RUNNING``
#: was refused, and the resulting 422 put the agent into a permanent retry loop —
#: *"could not be completed, will retry next cycle"*, every cycle, for ever. The
#: acknowledgement is late news about a job somebody else has already moved on
#: from, which is exactly what DISC-31 established must be absorbed rather than
#: raised on.
PROVIDER_EXECUTION_STATUSES_AN_ACK_CANNOT_ADVANCE: frozenset[str] = TERMINAL_PROVIDER_EXECUTION_STATUSES | {
    ProviderExecutionStatus.RETRY_SCHEDULED.value
}

ALLOWED_PROVIDER_EXECUTION_TRANSITIONS: dict[str, frozenset[str]] = {
    ProviderExecutionStatus.PENDING.value: frozenset(
        {
            ProviderExecutionStatus.LEASED.value,
            ProviderExecutionStatus.RETRY_SCHEDULED.value,
            ProviderExecutionStatus.FAILED.value,
            ProviderExecutionStatus.CANCELLED.value,
            ProviderExecutionStatus.EXPIRED.value,
        }
    ),
    ProviderExecutionStatus.LEASED.value: frozenset(
        {
            ProviderExecutionStatus.RUNNING.value,
            ProviderExecutionStatus.RETRY_SCHEDULED.value,
            ProviderExecutionStatus.FAILED.value,
            ProviderExecutionStatus.CANCELLED.value,
            ProviderExecutionStatus.EXPIRED.value,
        }
    ),
    ProviderExecutionStatus.RUNNING.value: frozenset(
        {
            ProviderExecutionStatus.COMPLETED.value,
            ProviderExecutionStatus.PARTIALLY_COMPLETED.value,
            ProviderExecutionStatus.RETRY_SCHEDULED.value,
            ProviderExecutionStatus.FAILED.value,
            ProviderExecutionStatus.CANCELLED.value,
            ProviderExecutionStatus.EXPIRED.value,
        }
    ),
    ProviderExecutionStatus.RETRY_SCHEDULED.value: frozenset(
        {ProviderExecutionStatus.CANCELLED.value}
    ),
    ProviderExecutionStatus.COMPLETED.value: frozenset(),
    ProviderExecutionStatus.PARTIALLY_COMPLETED.value: frozenset(),
    ProviderExecutionStatus.FAILED.value: frozenset(),
    ProviderExecutionStatus.CANCELLED.value: frozenset(),
    ProviderExecutionStatus.EXPIRED.value: frozenset(),
}

# Retryable vs non-retryable provider-execution failure codes — same
# separation as discovery_run_enums.RETRYABLE_FAILURE_CODES/
# NON_RETRYABLE_FAILURE_CODES, scoped to a single job rather than a whole run.
RETRYABLE_PROVIDER_FAILURE_CODES: frozenset[str] = frozenset(
    {
        "provider_timeout",
        "worker_lease_expired",
        "worker_crashed",
        "transient_network_error",
        "rate_limited",
        "evidence_storage_failed",
    }
)
NON_RETRYABLE_PROVIDER_FAILURE_CODES: frozenset[str] = frozenset(
    {
        "provider_not_registered",
        "credentials_invalid",
        "capability_unsupported",
        "target_invalid",
        "checkpoint_corrupt",
    }
)


class EvidenceFormat(StrEnum):
    """Controlled vocabulary for EvidencePackage.evidence_format — a
    normalization adapter dispatches on this, so it is never a free
    string."""

    NMAP_XML = "nmap_xml"
    JSON = "json"
    CSV = "csv"
    TEXT = "text"
    BINARY = "binary"


class EvidencePackageProcessingStatus(StrEnum):
    """About the upload/storage step only — distinct from
    EvidenceNormalizationStatus, which is about Step 4.1A consumption."""

    RECEIVED = "received"
    STORED = "stored"
    STORAGE_FAILED = "storage_failed"
    CORRUPT = "corrupt"


class EvidenceNormalizationStatus(StrEnum):
    """Whether Step 4.1A's normalize_execution() has consumed this package
    yet. A package can be safely STORED long before it is NORMALIZED."""

    PENDING = "pending"
    QUEUED = "queued"
    NORMALIZED = "normalized"
    NORMALIZATION_FAILED = "normalization_failed"


ALLOWED_EVIDENCE_NORMALIZATION_TRANSITIONS: dict[str, frozenset[str]] = {
    EvidenceNormalizationStatus.PENDING.value: frozenset(
        {
            EvidenceNormalizationStatus.QUEUED.value,
            EvidenceNormalizationStatus.NORMALIZED.value,
            EvidenceNormalizationStatus.NORMALIZATION_FAILED.value,
        }
    ),
    EvidenceNormalizationStatus.QUEUED.value: frozenset(
        {
            EvidenceNormalizationStatus.NORMALIZED.value,
            EvidenceNormalizationStatus.NORMALIZATION_FAILED.value,
        }
    ),
    EvidenceNormalizationStatus.NORMALIZED.value: frozenset(),
    EvidenceNormalizationStatus.NORMALIZATION_FAILED.value: frozenset(),
}


DISCOVERY_EXECUTION_ERROR_PLAN_ALREADY_EXISTS = (
    "An execution plan already exists for this discovery run."
)
DISCOVERY_EXECUTION_ERROR_RUN_NOT_APPROVED = (
    "The discovery run must be approved before an execution plan can start."
)
DISCOVERY_EXECUTION_ERROR_NO_PROVIDER_REGISTERED = (
    "No provider is registered for one or more required stages."
)
#: CA-02.3 slice 3 — every stage this profile needs was removed because the
#: Collector reported it cannot run the components they depend on. Distinct
#: from NO_PROVIDER_REGISTERED on purpose: the providers exist and the platform
#: is fine, so telling an operator "no provider is registered" would send them
#: looking in entirely the wrong place.
DISCOVERY_EXECUTION_ERROR_COLLECTOR_CANNOT_RUN_ANY_STAGE = (
    "This Collector reported that it cannot run any of the checks this scan profile needs."
)
DISCOVERY_EXECUTION_ERROR_STAGE_NOT_READY = (
    "This stage has unmet dependencies and cannot start yet."
)
DISCOVERY_EXECUTION_ERROR_LEASE_ALREADY_HELD = "This job is already leased by another worker."
DISCOVERY_EXECUTION_ERROR_LEASE_EXPIRED = "This worker's lease on the job has expired."
DISCOVERY_EXECUTION_ERROR_JOB_NOT_RETRYABLE = (
    "This job failure is not retryable until the underlying issue is resolved."
)
DISCOVERY_EXECUTION_ERROR_PROVIDER_EXECUTION_NOT_FOUND = (
    "Provider execution not found for this scanner instance."
)
DISCOVERY_EXECUTION_ERROR_EVIDENCE_STORAGE_FAILED = "The evidence payload could not be stored."

EXECUTION_PLAN_AUDIT_GENERATED = "discovery_execution_plan.generated"
EXECUTION_PLAN_AUDIT_STARTED = "discovery_execution_plan.started"
EXECUTION_PLAN_AUDIT_COMPLETED = "discovery_execution_plan.completed"
EXECUTION_PLAN_AUDIT_PARTIALLY_COMPLETED = "discovery_execution_plan.partially_completed"
# DISC-30/35: ExecutionPlanStatus.COMPLETED_WITH_WARNINGS predates a
# matching audit constant — added alongside completing the rest of this
# domain's audit coverage rather than silently reusing COMPLETED's event
# name for a status that is deliberately distinct.
EXECUTION_PLAN_AUDIT_COMPLETED_WITH_WARNINGS = "discovery_execution_plan.completed_with_warnings"
EXECUTION_PLAN_AUDIT_FAILED = "discovery_execution_plan.failed"
EXECUTION_PLAN_AUDIT_CANCELLED = "discovery_execution_plan.cancelled"

EXECUTION_STAGE_AUDIT_STARTED = "execution_stage.started"
EXECUTION_STAGE_AUDIT_COMPLETED = "execution_stage.completed"
EXECUTION_STAGE_AUDIT_PARTIALLY_COMPLETED = "execution_stage.partially_completed"
EXECUTION_STAGE_AUDIT_FAILED = "execution_stage.failed"
EXECUTION_STAGE_AUDIT_SKIPPED = "execution_stage.skipped"
# DISC-31/35: ExecutionStageStatus.CANCELLED predates a matching audit
# constant — same reason as the plan-level one above.
EXECUTION_STAGE_AUDIT_CANCELLED = "execution_stage.cancelled"

PROVIDER_EXECUTION_AUDIT_LEASED = "provider_execution.leased"
PROVIDER_EXECUTION_AUDIT_STARTED = "provider_execution.started"
PROVIDER_EXECUTION_AUDIT_COMPLETED = "provider_execution.completed"
PROVIDER_EXECUTION_AUDIT_FAILED = "provider_execution.failed"
# DISC-31/35: ProviderExecutionStatus.CANCELLED predates a matching audit
# constant — same reason as the two above.
PROVIDER_EXECUTION_AUDIT_CANCELLED = "provider_execution.cancelled"
PROVIDER_EXECUTION_AUDIT_RETRY_QUEUED = "provider_execution.retry_queued"
PROVIDER_EXECUTION_AUDIT_LEASE_RECLAIMED = "provider_execution.lease_reclaimed"

EVIDENCE_PACKAGE_AUDIT_RECEIVED = "evidence_package.received"
EVIDENCE_PACKAGE_AUDIT_STORAGE_FAILED = "evidence_package.storage_failed"
EVIDENCE_PACKAGE_AUDIT_NORMALIZED = "evidence_package.normalized"
EVIDENCE_PACKAGE_AUDIT_NORMALIZATION_FAILED = "evidence_package.normalization_failed"

# Worker leases expire quickly by design — a dead worker's job must become
# reclaimable soon, not after a long silent gap (spec's "Failure Isolation").
WORKER_LEASE_DEFAULT_SECONDS = 5 * 60
WORKER_LEASE_HEARTBEAT_INTERVAL_SECONDS = 60


class DiscoveryCollectorStatus(StrEnum):
    """Step 4.2 Part 3 (DISC-38) — customer-safety projection of a
    DELEGATED-provider run's ScannerInstance state (spec §29-31). Mirrors
    packages/design-system's DiscoveryCollectorStatus exactly.

    UPGRADE_REQUIRED and PERMISSION_REQUIRED are real members of this
    vocabulary but this codebase has no version-comparison concept (no
    "required version" is tracked anywhere) and no access-scope concept
    to confidently derive either one (DISC-36's own confirmed gap) — the
    resolver in discovery_execution_summary_service.py never produces
    them today, disclosed rather than fabricated from a guess.
    """

    NOT_REQUIRED = "not_required"
    READY = "ready"
    OFFLINE = "offline"
    UPGRADE_REQUIRED = "upgrade_required"
    PERMISSION_REQUIRED = "permission_required"
    UNAVAILABLE = "unavailable"
