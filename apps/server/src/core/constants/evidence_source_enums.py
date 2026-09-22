"""Evidence Source — at least one functioning evidence source (post-ORG-STRUCT stage).

v1 scope covers three source types — file/CMDB upload, manual evidence
entry (a degraded, exception-gated path), and the Risklence Scanner (Step
3.5, see ``evidence_scanner_enums``/``evidence_scanner_service``) —
deliberately, per the spec's own instruction not to implement every source
type/installation method in one release. Live CMDB/cloud/identity/
security-platform integrations, versioned secret configuration, freshness
policy, and source-quality scoring remain out of scope for v1 (see
TASKS.md's ORG-EVID follow-ups) — this enum module only encodes the
vocabulary v1 actually uses, not the full spec vocabulary.
"""

from enum import StrEnum


class EvidenceSourceType(StrEnum):
    FILE_IMPORT = "file_import"
    MANUAL = "manual"
    SCANNER = "scanner"


class EvidenceSourceMode(StrEnum):
    SNAPSHOT = "snapshot"
    MANUAL = "manual"
    SCANNER = "scanner"


# 1:1 with EvidenceSourceType — file_import is always a snapshot import,
# manual is always a manual mode, scanner is always a scanner mode. No
# source type in v1 has more than one possible mode.
SOURCE_TYPE_MODE: dict[str, str] = {
    EvidenceSourceType.FILE_IMPORT.value: EvidenceSourceMode.SNAPSHOT.value,
    EvidenceSourceType.MANUAL.value: EvidenceSourceMode.MANUAL.value,
    EvidenceSourceType.SCANNER.value: EvidenceSourceMode.SCANNER.value,
}


class EvidenceSourceStatus(StrEnum):
    DRAFT = "draft"
    CONFIGURATION_REQUIRED = "configuration_required"
    RECEIVING_DATA = "receiving_data"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    DISABLED = "disabled"
    ARCHIVED = "archived"


class EvidenceSourceScopeType(StrEnum):
    ENTIRE_ORGANISATION = "entire_organisation"
    ORGANISATION_UNITS = "organisation_units"
    LEGAL_ENTITIES = "legal_entities"
    COUNTRIES = "countries"
    CUSTOM = "custom"


class EvidenceSourceScopeStatus(StrEnum):
    DRAFT = "draft"
    SUGGESTED = "suggested"
    CONFIRMED = "confirmed"


class EvidenceImportStatus(StrEnum):
    UPLOADED = "uploaded"
    VALIDATING = "validating"
    MAPPING_REQUIRED = "mapping_required"
    READY_TO_IMPORT = "ready_to_import"
    IMPORTING = "importing"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EvidenceReceiptStatus(StrEnum):
    RECEIVED = "received"
    VALIDATED = "validated"
    PARTIALLY_VALID = "partially_valid"
    REJECTED = "rejected"
    PROCESSED = "processed"


class EvidenceSourceExceptionReasonCode(StrEnum):
    APPROVAL_PENDING = "approval_pending"
    TECHNICAL_BLOCKER = "technical_blocker"
    SOURCE_UNAVAILABLE = "source_unavailable"
    PILOT_SCOPE = "pilot_scope"
    OTHER = "other"


class EvidenceSourceExceptionStatus(StrEnum):
    ACTIVE = "active"
    RESOLVED = "resolved"
    EXPIRED = "expired"


class EvidenceSourceReadiness(StrEnum):
    MISSING = "missing"
    IN_PROGRESS = "in_progress"
    REVIEW_REQUIRED = "review_required"
    READY = "ready"
    DEGRADED = "degraded"
    BLOCKED = "blocked"


# Explainable per-source health (spec §12) — a flat status alone can't say
# *why* a source is degraded. connectivity_healthy/authorisation_healthy/
# permissions_sufficient are ``None`` (not applicable, never fabricated
# True) for v1's source types, none of which hold a live connection to
# check — only file_import/manual/scanner exist, and scanner's own
# connection state is tracked separately by evidence_scanner_*.
class EvidenceSourceHealthStatus(StrEnum):
    UNKNOWN = "unknown"
    PENDING = "pending"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    OFFLINE = "offline"
    DISABLED = "disabled"


# Default freshness policy per source type (spec §13's own example
# policies), used whenever a source has no explicit override set. A
# "periodic import" (file_import) and a manual entry both go stale on very
# different cadences — there is no single sane default across both.
DEFAULT_FRESHNESS_WARNING_AFTER_HOURS: dict[str, int] = {
    "file_import": 30 * 24,
    "manual": 90 * 24,
}
DEFAULT_FRESHNESS_STALE_AFTER_HOURS: dict[str, int] = {
    "file_import": 90 * 24,
    "manual": 180 * 24,
}


# Standard evidence attribute vocabulary a source column can map onto
# (spec §7.3). Column-mapping suggestion matches detected headers against
# this list case-insensitively.
STANDARD_EVIDENCE_FIELDS: tuple[str, ...] = (
    "displayName",
    "sourceType",
    "environment",
    "supportGroup",
    "declaredOwner",
    "declaredCriticality",
    "relationshipTarget",
    "sourceReviewedAt",
)

# A row without a displayName carries no identifiable evidence.
REQUIRED_EVIDENCE_FIELDS: frozenset[str] = frozenset({"displayName"})

# Column-header synonyms for auto-mapping suggestion, beyond an exact match
# on the standard field name itself. Deliberately conservative — only terms
# that are unambiguous in a genuine CMDB/asset-inventory export. Governance-
# only terms (e.g. "review_date" on a risk-appetite decision, "record_type"
# distinguishing entity kinds in a multi-entity seed file) are intentionally
# excluded: a real-world file using those words for something other than a
# technical asset fact would otherwise get silently, wrongly auto-mapped.
EVIDENCE_FIELD_SYNONYMS: dict[str, str] = {
    "name": "displayName",
    "asset_name": "displayName",
    "application_name": "displayName",
    "ci_name": "displayName",
    "system_name": "displayName",
    "host_name": "displayName",
    "hostname": "displayName",
    "artefact_name": "displayName",
    "artifact_name": "displayName",
    "type": "sourceType",
    "asset_type": "sourceType",
    "ci_type": "sourceType",
    "ci_class": "sourceType",
    "artefact_type": "sourceType",
    "artifact_type": "sourceType",
    "env": "environment",
    "support_group": "supportGroup",
    "team": "supportGroup",
    "owning_group": "supportGroup",
    "managed_by_group": "supportGroup",
    "managed_by": "supportGroup",
    "owner": "declaredOwner",
    "business_owner": "declaredOwner",
    "technical_owner": "declaredOwner",
    "asset_owner": "declaredOwner",
    "owner_email": "declaredOwner",
    "criticality": "declaredCriticality",
    "business_criticality": "declaredCriticality",
    "tier": "declaredCriticality",
    "priority": "declaredCriticality",
    "depends_on": "relationshipTarget",
    "dependency": "relationshipTarget",
    "dependencies": "relationshipTarget",
    "parent": "relationshipTarget",
    "last_reviewed": "sourceReviewedAt",
    "reviewed_at": "sourceReviewedAt",
    "last_updated": "sourceReviewedAt",
}

MAX_IMPORT_FILE_SIZE_BYTES = 5 * 1024 * 1024
MAX_IMPORT_ROW_COUNT = 5_000

EVIDENCE_SOURCE_AUDIT_CREATED = "evidence_source.created"
EVIDENCE_SOURCE_AUDIT_OWNER_ASSIGNED = "evidence_source.owner_assigned"
EVIDENCE_SOURCE_AUDIT_SCOPE_SAVED = "evidence_source.scope_saved"
EVIDENCE_SOURCE_AUDIT_SCOPE_CONFIRMED = "evidence_source.scope_confirmed"
EVIDENCE_SOURCE_AUDIT_IMPORT_UPLOADED = "evidence_import.uploaded"
EVIDENCE_SOURCE_AUDIT_IMPORT_MAPPING_CONFIRMED = "evidence_import.mapping_confirmed"
EVIDENCE_SOURCE_AUDIT_IMPORT_COMPLETED = "evidence_import.completed"
EVIDENCE_SOURCE_AUDIT_IMPORT_FAILED = "evidence_import.failed"
EVIDENCE_SOURCE_AUDIT_MANUAL_ENTRY_ADDED = "evidence_source.manual_entry_added"
EVIDENCE_SOURCE_AUDIT_EXCEPTION_APPROVED = "evidence_source.exception_approved"
EVIDENCE_SOURCE_AUDIT_EXCEPTION_RESOLVED = "evidence_source.exception_resolved"
EVIDENCE_SOURCE_AUDIT_DISABLED = "evidence_source.disabled"
EVIDENCE_SOURCE_AUDIT_ARCHIVED = "evidence_source.archived"
EVIDENCE_SOURCE_AUDIT_COMPLETED = "evidence_source.completed"
EVIDENCE_SOURCE_AUDIT_FRESHNESS_POLICY_SET = "evidence_source.freshness_policy_set"

EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED = "Organisation administrator access is required to manage evidence sources"
EVIDENCE_SOURCE_ERROR_NOT_FOUND = "Evidence source not found"
EVIDENCE_SOURCE_ERROR_BATCH_NOT_FOUND = "Evidence import batch not found"
EVIDENCE_SOURCE_ERROR_EXCEPTION_NOT_FOUND = "Evidence source exception not found"
EVIDENCE_SOURCE_ERROR_UNSUPPORTED_TYPE = "This evidence source type is not yet supported"
EVIDENCE_SOURCE_ERROR_OWNER_REQUIRED = (
    "An owner is required — assign a Technical Setup Owner in organisation structure first"
)
EVIDENCE_SOURCE_ERROR_FILE_TOO_LARGE = "The uploaded file exceeds the 5 MB size limit"
EVIDENCE_SOURCE_ERROR_TOO_MANY_ROWS = "The uploaded file exceeds the 5,000 row limit"
EVIDENCE_SOURCE_ERROR_FILE_UNREADABLE = "The uploaded file could not be read as CSV or XLSX"
EVIDENCE_SOURCE_ERROR_MAPPING_MISSING_REQUIRED = "The column mapping must map a source column to displayName"
EVIDENCE_SOURCE_ERROR_SCOPE_NOT_CONFIRMED = "Evidence source scope must be confirmed first"
EVIDENCE_SOURCE_ERROR_SCOPE_NOT_FOUND = "No scope has been saved for this evidence source yet"
