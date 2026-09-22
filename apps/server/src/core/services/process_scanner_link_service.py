"""CA-04.6 — service layer for ProcessScannerLink: linking one
ScannerInstance to a Business Process (ValueStream), optionally narrowed to
one Business Service within it, with independent pause/revoke lifecycle.

Additive to RISKLENCE-79's existing single-service
``EvidenceSource.business_service_id`` scoping (``scanner_management.py``'s
``link_business_service_route``) — that route and its own "one scanner, one
process" relinking guard are untouched by this module.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.process_scanner_link_enums import (
    PROCESS_SCANNER_LINK_ERROR_ALREADY_REVOKED,
    PROCESS_SCANNER_LINK_ERROR_DUPLICATE,
    PROCESS_SCANNER_LINK_ERROR_NOT_ACTIVE,
    PROCESS_SCANNER_LINK_ERROR_SERVICE_NOT_IN_PROCESS,
    ProcessScannerLinkStatus,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.process_scanner_link import ProcessScannerLink
from src.core.model_defs.value_streams import BusinessService, ValueStream
from src.core.repository import TenantRepository


class ProcessScannerLinkValidationError(ValueError):
    """Raised when a ProcessScannerLink creation or lifecycle action is invalid."""


class ProcessScannerLinkNotFoundError(ValueError):
    """Raised when the referenced business process or business service does not exist for this org."""


def require_business_process(db: Session, *, organization_id: int, business_process_id: str) -> ValueStream:
    """Public — also used by discovery_run_service.create_discovery_run
    (CA-04.7) to validate a run's own business_process_id, not just at
    link-creation time here."""
    process = TenantRepository(db, ValueStream, organization_id).get_by_id(business_process_id)
    if process is None:
        raise ProcessScannerLinkNotFoundError("Business process not found")
    return process


def require_service_belongs_to_process(
    db: Session, *, organization_id: int, business_service_id: str, business_process_id: str
) -> None:
    """Public — the one place "does this business service belong to this
    business process" is checked (a bare value_stream_ids array membership
    test, no association table). Reused by discovery_run_service.
    create_discovery_run (CA-04.7) rather than reimplemented a second time."""
    service = TenantRepository(db, BusinessService, organization_id).get_by_id(business_service_id)
    if service is None:
        raise ProcessScannerLinkNotFoundError("Business service not found")
    if business_process_id not in (service.value_stream_ids or []):
        raise ProcessScannerLinkValidationError(PROCESS_SCANNER_LINK_ERROR_SERVICE_NOT_IN_PROCESS)


def get_active_link(
    db: Session, *, scanner_instance_id: str, business_process_id: str
) -> ProcessScannerLink | None:
    """CA-04.7 — a discovery run scoped to a business process must be
    backed by a real, currently ACTIVE link (not merely a past one that
    was later paused/revoked) — this is the one lookup that answers that."""
    return (
        db.query(ProcessScannerLink)
        .filter(
            ProcessScannerLink.scanner_instance_id == scanner_instance_id,
            ProcessScannerLink.business_process_id == business_process_id,
            ProcessScannerLink.status == ProcessScannerLinkStatus.ACTIVE.value,
        )
        .first()
    )


def link_scanner_to_process(
    db: Session,
    *,
    organization_id: int,
    scanner_instance_id: str,
    business_process_id: str,
    business_service_id: str | None = None,
    linked_by_user_id: int | None = None,
) -> ProcessScannerLink:
    require_business_process(db, organization_id=organization_id, business_process_id=business_process_id)
    if business_service_id is not None:
        require_service_belongs_to_process(
            db,
            organization_id=organization_id,
            business_service_id=business_service_id,
            business_process_id=business_process_id,
        )

    existing = (
        db.query(ProcessScannerLink)
        .filter(
            ProcessScannerLink.scanner_instance_id == scanner_instance_id,
            ProcessScannerLink.business_process_id == business_process_id,
            ProcessScannerLink.status != ProcessScannerLinkStatus.REVOKED.value,
        )
        .first()
    )
    if existing is not None:
        raise ProcessScannerLinkValidationError(PROCESS_SCANNER_LINK_ERROR_DUPLICATE)

    link = ProcessScannerLink(
        organization_id=organization_id,
        scanner_instance_id=scanner_instance_id,
        business_process_id=business_process_id,
        business_service_id=business_service_id,
        # CA-10 — a link starts PENDING unless the process already has an
        # approved, currently-effective ProcessScanScope; approving one
        # later self-heals any PENDING links via
        # activate_pending_links_for_process, so no manual reconciliation
        # step is needed either way.
        status=_initial_link_status(db, organization_id=organization_id, business_process_id=business_process_id),
        linked_by_user_id=linked_by_user_id,
        created_at=utcnow(),
    )
    db.add(link)
    db.flush()
    return link


def _initial_link_status(db: Session, *, organization_id: int, business_process_id: str) -> str:
    # Deferred import — process_scan_scope_service imports
    # require_business_process from this module at load time, so importing
    # it back at module level here would cycle. This is the one place the
    # dependency runs the other way.
    from src.core.services.process_scan_scope_service import resolve_effective_process_scan_scope

    scope = resolve_effective_process_scan_scope(
        db, organization_id=organization_id, business_process_id=business_process_id
    )
    return ProcessScannerLinkStatus.ACTIVE.value if scope is not None else ProcessScannerLinkStatus.PENDING.value


def activate_pending_links_for_process(db: Session, *, business_process_id: str) -> list[ProcessScannerLink]:
    """CA-10 — called after a ProcessScanScope becomes effective for this
    process: any link created before that (and left PENDING) is now
    authorized, so it flips to ACTIVE without a separate manual step."""
    pending_links = (
        db.query(ProcessScannerLink)
        .filter(
            ProcessScannerLink.business_process_id == business_process_id,
            ProcessScannerLink.status == ProcessScannerLinkStatus.PENDING.value,
        )
        .all()
    )
    for link in pending_links:
        link.status = ProcessScannerLinkStatus.ACTIVE.value
        db.add(link)
    return pending_links


def list_links_for_instance(db: Session, scanner_instance_id: str) -> list[ProcessScannerLink]:
    return (
        db.query(ProcessScannerLink)
        .filter(ProcessScannerLink.scanner_instance_id == scanner_instance_id)
        .order_by(ProcessScannerLink.created_at.desc())
        .all()
    )


def pause_link(db: Session, link: ProcessScannerLink) -> ProcessScannerLink:
    if link.status != ProcessScannerLinkStatus.ACTIVE.value:
        raise ProcessScannerLinkValidationError(PROCESS_SCANNER_LINK_ERROR_NOT_ACTIVE)
    link.status = ProcessScannerLinkStatus.PAUSED.value
    link.paused_at = utcnow()
    db.add(link)
    return link


def revoke_link(db: Session, link: ProcessScannerLink, *, revoked_by_user_id: int | None = None) -> ProcessScannerLink:
    """Permanent — unlike pause, revoke is not resumable. A revoked link can
    never authorize new work again: it stays REVOKED, and
    link_scanner_to_process's own duplicate check treats REVOKED as the one
    status that frees the (scanner_instance_id, business_process_id) pair
    up for a brand-new link, never this row reactivating."""
    if link.status == ProcessScannerLinkStatus.REVOKED.value:
        raise ProcessScannerLinkValidationError(PROCESS_SCANNER_LINK_ERROR_ALREADY_REVOKED)
    link.status = ProcessScannerLinkStatus.REVOKED.value
    link.revoked_at = utcnow()
    link.revoked_by_user_id = revoked_by_user_id
    db.add(link)
    return link
