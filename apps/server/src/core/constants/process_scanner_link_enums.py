"""CA-04.6 — status vocabulary and audit/error constants for
ProcessScannerLink, the many-to-many link between one ScannerInstance and
the Business Processes (ValueStreams) it is authorized to scan.

PENDING is produced by process_scanner_link_service.link_scanner_to_process
(CA-10) when the target process has no approved, currently-effective
ProcessScanScope yet; approving one flips any PENDING links for that process
to ACTIVE via activate_pending_links_for_process.
"""

from __future__ import annotations

from enum import StrEnum


class ProcessScannerLinkStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    PAUSED = "paused"
    REVOKED = "revoked"


PROCESS_SCANNER_LINK_AUDIT_CREATED = "process_scanner_link.created"
PROCESS_SCANNER_LINK_AUDIT_PAUSED = "process_scanner_link.paused"
PROCESS_SCANNER_LINK_AUDIT_REVOKED = "process_scanner_link.revoked"

PROCESS_SCANNER_LINK_ERROR_DUPLICATE = "This scanner is already linked to this business process."
PROCESS_SCANNER_LINK_ERROR_SERVICE_NOT_IN_PROCESS = (
    "This business service does not belong to the linked business process."
)
PROCESS_SCANNER_LINK_ERROR_NOT_ACTIVE = "This link is not active."
PROCESS_SCANNER_LINK_ERROR_ALREADY_REVOKED = "This link has already been revoked."
