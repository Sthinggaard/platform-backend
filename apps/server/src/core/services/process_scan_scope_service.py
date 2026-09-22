"""CA-10 (#50) — service layer for ProcessScanScope: derive a draft, submit
it, approve it, and resolve the currently-effective recurring assurance
scope for a Business Process.

Lifecycle: draft (derived) -> submitted -> active (approved) -> either
outdated (flagged in place, still authorizing) or revoked (terminal) or
superseded (a newer revision was approved). Mirrors
risk_appetite_resolution_service.py's draft -> approve -> supersede shape,
and reuses process_scanner_link_service.require_business_process rather
than revalidating a process id a second way.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.constants.discovery_run_enums import CheckKey
from src.core.constants.process_scan_scope_enums import (
    PROCESS_SCAN_SCOPE_ERROR_ALREADY_REVOKED,
    PROCESS_SCAN_SCOPE_ERROR_NOT_ACTIVE,
    PROCESS_SCAN_SCOPE_ERROR_NOT_DRAFT,
    PROCESS_SCAN_SCOPE_ERROR_NOT_FOUND,
    PROCESS_SCAN_SCOPE_ERROR_NOT_SUBMITTED,
    PROCESS_SCAN_SCOPE_ERROR_UNKNOWN_CHECK_KEY,
    ProcessScanScopeStatus,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.process_scan_scope import ProcessScanScope
from src.core.repository import TenantRepository
from src.core.services.process_scanner_link_service import require_business_process


class ProcessScanScopeValidationError(ValueError):
    """Raised when a ProcessScanScope lifecycle action is invalid."""


class ProcessScanScopeNotFoundError(ValueError):
    """Raised when the referenced ProcessScanScope does not exist for this org."""


def _validate_checks(checks: list[str]) -> None:
    known = {key.value for key in CheckKey}
    if any(check not in known for check in checks):
        raise ProcessScanScopeValidationError(PROCESS_SCAN_SCOPE_ERROR_UNKNOWN_CHECK_KEY)


def _next_revision(db: Session, *, organization_id: int, business_process_id: str) -> int:
    existing = (
        db.query(ProcessScanScope)
        .filter(
            ProcessScanScope.organization_id == organization_id,
            ProcessScanScope.business_process_id == business_process_id,
        )
        .order_by(ProcessScanScope.revision.desc())
        .first()
    )
    return (existing.revision + 1) if existing else 1


def create_process_scan_scope_draft(
    db: Session,
    *,
    organization_id: int,
    business_process_id: str,
    bundle_version_ids: list[str] | None = None,
    artefacts: list[str] | None = None,
    connectors: list[str] | None = None,
    checks: list[str] | None = None,
    profile_versions: dict | None = None,
    rationale: dict | None = None,
) -> ProcessScanScope:
    require_business_process(db, organization_id=organization_id, business_process_id=business_process_id)
    checks = checks or []
    _validate_checks(checks)

    scope = ProcessScanScope(
        organization_id=organization_id,
        business_process_id=business_process_id,
        revision=_next_revision(db, organization_id=organization_id, business_process_id=business_process_id),
        status=ProcessScanScopeStatus.DRAFT.value,
        bundle_version_ids=bundle_version_ids or [],
        artefacts=artefacts or [],
        connectors=connectors or [],
        checks=checks,
        profile_versions=profile_versions or {},
        rationale=rationale or {},
        derived_at=utcnow(),
    )
    db.add(scope)
    db.flush()
    return scope


def submit_process_scan_scope(
    db: Session, scope: ProcessScanScope, *, submitted_by_user_id: int, decision_note: str | None = None
) -> ProcessScanScope:
    if scope.status != ProcessScanScopeStatus.DRAFT.value:
        raise ProcessScanScopeValidationError(PROCESS_SCAN_SCOPE_ERROR_NOT_DRAFT)
    scope.status = ProcessScanScopeStatus.SUBMITTED.value
    scope.submitted_by_user_id = submitted_by_user_id
    scope.submitted_at = utcnow()
    if decision_note is not None:
        scope.decision_note = decision_note
    db.add(scope)
    db.flush()
    return scope


def approve_process_scan_scope(
    db: Session, scope: ProcessScanScope, *, approved_by_user_id: int, decision_note: str | None = None
) -> ProcessScanScope:
    if scope.status != ProcessScanScopeStatus.SUBMITTED.value:
        raise ProcessScanScopeValidationError(PROCESS_SCAN_SCOPE_ERROR_NOT_SUBMITTED)

    prior_active = (
        db.query(ProcessScanScope)
        .filter(
            ProcessScanScope.organization_id == scope.organization_id,
            ProcessScanScope.business_process_id == scope.business_process_id,
            ProcessScanScope.status == ProcessScanScopeStatus.ACTIVE.value,
        )
        .first()
    )
    if prior_active is not None:
        prior_active.status = ProcessScanScopeStatus.SUPERSEDED.value
        prior_active.superseded_by_scope_id = scope.id
        db.add(prior_active)

    scope.status = ProcessScanScopeStatus.ACTIVE.value
    scope.approved_by_user_id = approved_by_user_id
    scope.approved_at = utcnow()
    if decision_note is not None:
        scope.decision_note = decision_note
    db.add(scope)
    db.flush()

    # Local import — process_scanner_link_service imports
    # require_business_process from this module at load time, so importing
    # it back here at module level would cycle. This is the one place the
    # dependency runs the other way.
    from src.core.services.process_scanner_link_service import activate_pending_links_for_process

    activate_pending_links_for_process(db, business_process_id=scope.business_process_id)
    return scope


def mark_process_scan_scope_outdated(db: Session, scope: ProcessScanScope, *, reason: str) -> ProcessScanScope:
    """G9 — a material change (new/removed service, republished dependency
    bundle, changed appetite/permission profile) flags the currently-active
    scope for reassessment. Deliberately does not revoke authorization —
    the same "under-claiming is the safe direction" reasoning
    process_activation_readiness_service.py uses for a stale BIA snapshot:
    the process keeps scanning under its last-approved scope until a human
    reviews and re-approves, rather than silently going dark."""
    if scope.status != ProcessScanScopeStatus.ACTIVE.value:
        raise ProcessScanScopeValidationError(PROCESS_SCAN_SCOPE_ERROR_NOT_ACTIVE)
    scope.outdated_at = utcnow()
    scope.outdated_reason = reason
    db.add(scope)
    db.flush()
    return scope


def revoke_process_scan_scope(db: Session, scope: ProcessScanScope, *, revoked_by_user_id: int) -> ProcessScanScope:
    if scope.status == ProcessScanScopeStatus.REVOKED.value:
        raise ProcessScanScopeValidationError(PROCESS_SCAN_SCOPE_ERROR_ALREADY_REVOKED)
    scope.status = ProcessScanScopeStatus.REVOKED.value
    scope.revoked_by_user_id = revoked_by_user_id
    scope.revoked_at = utcnow()
    db.add(scope)
    db.flush()
    return scope


def resolve_effective_process_scan_scope(
    db: Session, *, organization_id: int, business_process_id: str
) -> ProcessScanScope | None:
    """The one lookup that answers "what, if anything, is this process
    currently authorized to have scanned" — the ACTIVE row. Outdated is
    deliberately not excluded here (see mark_process_scan_scope_outdated);
    only an explicit revoke or a newer approval (which supersedes this row
    out of ACTIVE) removes authorization."""
    return db.execute(
        select(ProcessScanScope).where(
            ProcessScanScope.organization_id == organization_id,
            ProcessScanScope.business_process_id == business_process_id,
            ProcessScanScope.status == ProcessScanScopeStatus.ACTIVE.value,
        )
    ).scalar_one_or_none()


def require_process_scan_scope(db: Session, *, organization_id: int, scope_id: str) -> ProcessScanScope:
    scope = TenantRepository(db, ProcessScanScope, organization_id).get_by_id(scope_id)
    if scope is None:
        raise ProcessScanScopeNotFoundError(PROCESS_SCAN_SCOPE_ERROR_NOT_FOUND)
    return scope
