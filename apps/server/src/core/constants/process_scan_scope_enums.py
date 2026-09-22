"""CA-10 (#50) — status vocabulary and audit/error constants for
ProcessScanScope: an approved recurring assurance scope per active Business
Process (Programme Epic G7).

Schema note: the `process_scan_scopes` table already existed in the shared
dev Postgres container before this ticket's own migration was written — 0
rows, not referenced anywhere in git history on any branch, but a more
mature design than a from-spec-alone first draft (ties scope to
`bundle_version_ids`/`artefacts`/`connectors`/`checks` rather than a
hand-authored JSON blob, has `derived_at` for provenance, `outdated_at` for
G9-style staleness, and a DB-enforced `UNIQUE(business_process_id,
revision)`). Søren chose to adopt it (2026-09-22) rather than keep the
first draft's schema. The status/error vocabulary below is new code written
to fit that adopted schema, not recovered from anywhere.
"""

from __future__ import annotations

from enum import StrEnum


class ProcessScanScopeStatus(StrEnum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    ACTIVE = "active"
    OUTDATED = "outdated"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"


PROCESS_SCAN_SCOPE_AUDIT_DRAFT_CREATED = "process_scan_scope.draft_created"
PROCESS_SCAN_SCOPE_AUDIT_SUBMITTED = "process_scan_scope.submitted"
PROCESS_SCAN_SCOPE_AUDIT_APPROVED = "process_scan_scope.approved"
PROCESS_SCAN_SCOPE_AUDIT_MARKED_OUTDATED = "process_scan_scope.marked_outdated"
PROCESS_SCAN_SCOPE_AUDIT_REVOKED = "process_scan_scope.revoked"

PROCESS_SCAN_SCOPE_ERROR_NOT_FOUND = "Process scan scope not found."
PROCESS_SCAN_SCOPE_ERROR_NOT_DRAFT = "Only a draft process scan scope may be submitted."
PROCESS_SCAN_SCOPE_ERROR_NOT_SUBMITTED = "Only a submitted process scan scope may be approved."
PROCESS_SCAN_SCOPE_ERROR_ALREADY_REVOKED = "This process scan scope has already been revoked."
PROCESS_SCAN_SCOPE_ERROR_NOT_ACTIVE = "Only an active process scan scope may be marked outdated."
PROCESS_SCAN_SCOPE_ERROR_UNKNOWN_CHECK_KEY = "One or more checks are not a registered CheckKey."
