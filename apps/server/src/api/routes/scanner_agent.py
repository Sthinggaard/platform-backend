"""Risklence Scanner agent routes — called by the standalone scanner
process itself (apps/scanner/), never a logged-in browser user.

Authenticated by a per-instance credential (the same activation token
issued at install time — see evidence_scanner_service.install_scanner),
checked here against ScannerInstance.activation_token_hash, never by the
platform's user JWT. These paths are listed in TenantContextMiddleware's
PUBLIC_PATHS (exempting them from JWT enforcement) precisely so this
module can enforce its own, different authentication — "treat scanner
credentials as service credentials, not user sessions."

Also accepts named ScannerCredential tokens (TENANT-83/84) — checked
first, since a scanner may hold several. This is the actual enforcement
point for "expired/paused/revoked keys cannot authenticate": the
lifecycle API (scanner_management.py) only changes a credential's state,
this function is what makes that state matter.
"""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from sqlalchemy.orm import Session

from src.core.constants.evidence_scanner_enums import ScannerCredentialValidityPolicy, ScannerInstanceStatus
from src.core.database import get_db
from src.core.services.worker_lease_renewal_service import renew_leases_for_scanner
from src.core.exceptions import AuthenticationError
from datetime import timedelta

from src.core.constants.evidence_scanner_enums import SCANNER_HEARTBEAT_STALE_AFTER_SECONDS
from src.core.logging_config import get_logger
from src.core.model_defs.common import utcnow
from src.core.constants.evidence_scanner_enums import (
    SCANNER_AUDIT_READINESS_DEGRADED,
    SCANNER_AUDIT_READINESS_REPORTED,
    CollectorInstruction,
    CollectorReadinessStatus,
    CollectorReadinessTrigger,
)
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.services.collector_readiness_service import (
    latest_readiness_report,
    record_readiness_report,
    resolve_collector_readiness,
)
from src.core.services.collector_instruction_service import (
    clear_instruction,
    pending_instruction_for,
)
from src.core.services.discovery_command_service import revive_commands_after_downtime
from src.core.model_defs.evidence_scanner import ScannerCredential, ScannerInstance
from src.core.services.evidence_scanner_service import (
    EvidenceScannerValidationError,
    credential_can_authenticate,
    _naive_utc,
    record_heartbeat,
    record_test_scan_result,
    record_tool_validation,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/scanner-agent", tags=["Scanner agent"])


class HeartbeatRequest(BaseModel):
    # CA-02 — reported by the agent itself, optional so older agent builds
    # (or a heartbeat sent before the first `run`/`heartbeat` collects this)
    # keep working unchanged.
    os_name: str | None = None
    os_version: str | None = None
    architecture: str | None = None
    # CA-02.3 slice 3 — the host/container split. `kernel_release` is the
    # marker for an agent that understands it: os_name then means the *host's*
    # distribution and may legitimately be null, where before it silently
    # carried the container image's own.
    kernel_release: str | None = None
    container_runtime: str | None = None
    runtime_os_name: str | None = None
    runtime_os_version: str | None = None
    # #321 — the IPv4 segments the Collector is attached to, as it sees them.
    # `None` from an older build that does not report; an empty list is the
    # Collector positively saying it found none. The two must not be conflated:
    # one is silence, the other is an answer.
    network_segments: list[dict] | None = None


class HeartbeatResponse(BaseModel):
    scanner_instance_id: str
    status: str
    #: CA-02.3 slice 3 — an operational instruction for the Collector to carry
    #: out now (``CollectorInstruction``), or None. Additive and optional: an
    #: older agent simply ignores a field it does not read, so this cannot
    #: break a Collector that has not been upgraded.
    pending_instruction: str | None = None


class ToolValidationRequest(BaseModel):
    tool_status: dict[str, str]
    scanner_version: str | None = None


class CollectorComponentReadinessRequest(BaseModel):
    componentKey: str
    status: str
    version: str | None = None
    reasonCode: str | None = None
    checkedAt: str | None = None


class CollectorReadinessRequest(BaseModel):
    """A completed self-check, reported by the Collector through its own
    credential (CA-02.3).

    ``reportedAt`` is deliberately absent: the platform stamps receipt itself,
    so a Collector with a wrong clock cannot date its report into the future and
    win "latest" permanently.
    """

    schemaVersion: str
    components: list[CollectorComponentReadinessRequest] = []
    platformConnectivityStatus: str | None = None
    evidenceStorageStatus: str | None = None
    collectorVersion: str | None = None
    templatePackVersion: str | None = None
    failureReasonCodes: list[str] = []
    overallStatus: str | None = None
    #: Why this check ran. The Collector reports what it was asked to do; the
    #: *person* who asked is resolved server-side from the pending instruction,
    #: never taken from the payload — an agent must not be able to attribute a
    #: report to an arbitrary user.
    trigger: str | None = None
    reportSequence: int | None = None


class TestScanRequest(BaseModel):
    status: str
    connection_verified: bool = True


class AgentInstanceResponse(BaseModel):
    scanner_instance_id: str
    status: str
    scan_profile: str | None
    tool_status: dict[str, str]
    test_scan_status: str | None


def require_scanner_instance(request: Request, db: Session) -> ScannerInstance:
    """Public — also used by discovery_command_agent.py (Step 4.1), the
    other module authenticating the standalone scanner process by this
    same per-instance Bearer credential."""
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise AuthenticationError("Missing scanner credential.")
    token = auth_header[len("bearer ") :].strip()
    if not token:
        raise AuthenticationError("Missing scanner credential.")
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    credential = db.query(ScannerCredential).filter(ScannerCredential.token_hash == token_hash).first()
    if credential is not None:
        if not credential_can_authenticate(credential):
            raise AuthenticationError("Invalid, expired, or revoked scanner credential.")
        if (
            credential.validity_policy == ScannerCredentialValidityPolicy.ONE_TIME.value
            and credential.consumed_at is None
        ):
            credential.consumed_at = utcnow()
            db.add(credential)
        instance = (
            db.query(ScannerInstance).filter(ScannerInstance.id == credential.scanner_instance_id).first()
        )
        if instance is None or instance.status == ScannerInstanceStatus.REVOKED.value:
            raise AuthenticationError("Invalid or revoked scanner credential.")
        return instance

    instance = (
        db.query(ScannerInstance).filter(ScannerInstance.activation_token_hash == token_hash).first()
    )
    if instance is None or instance.status == ScannerInstanceStatus.REVOKED.value:
        raise AuthenticationError("Invalid or revoked scanner credential.")
    return instance


#: Worst to best. Only used to answer "did readiness drop since last time?",
#: which is what makes SCANNER_AUDIT_READINESS_DEGRADED meaningful rather than
#: a second copy of every report.
_READINESS_SEVERITY_ORDER = [
    CollectorReadinessStatus.BLOCKED.value,
    CollectorReadinessStatus.OFFLINE.value,
    CollectorReadinessStatus.UNKNOWN.value,
    CollectorReadinessStatus.UPGRADE_REQUIRED.value,
    CollectorReadinessStatus.DEGRADED.value,
    CollectorReadinessStatus.CHECKING.value,
    CollectorReadinessStatus.READY.value,
]


def _audit_readiness(db, instance, *, report, previous_status: str) -> None:
    """Every accepted report is audited; a *drop* is audited additionally.

    The second event exists for operator visibility — "this Collector got worse
    at 03:14" is the thing someone needs to find later, and it is invisible in a
    stream where every report looks alike.
    """
    db.add(
        AuditEvent(
            organization_id=instance.organization_id,
            actor_user_id=None,
            event_type=SCANNER_AUDIT_READINESS_REPORTED,
            metadata_json={
                "scanner_instance_id": instance.id,
                "readiness_report_id": report.id,
                "overall_status": report.overall_status,
                "schema_version": report.schema_version,
            },
        )
    )

    def rank(status: str) -> int:
        try:
            return _READINESS_SEVERITY_ORDER.index(status)
        except ValueError:
            return 0

    if rank(report.overall_status) < rank(previous_status):
        db.add(
            AuditEvent(
                organization_id=instance.organization_id,
                actor_user_id=None,
                event_type=SCANNER_AUDIT_READINESS_DEGRADED,
                metadata_json={
                    "scanner_instance_id": instance.id,
                    "readiness_report_id": report.id,
                    "previous_status": previous_status,
                    "overall_status": report.overall_status,
                },
            )
        )


def _downtime_before_this_heartbeat(instance: ScannerInstance) -> timedelta | None:
    """How long this Collector had been unreachable, or None if it had not been.

    "Unreachable" uses the same staleness threshold the rest of the platform
    reads a Collector's liveness with, so the panel that told the user they were
    offline and the rule that gives their work back can never disagree about
    what offline means.
    """
    if instance.last_heartbeat_at is None:
        return None
    # Both sides normalised: utcnow() is timezone-aware and stored heartbeats
    # are naive UTC, and subtracting the two raises rather than comparing.
    gap = _naive_utc(utcnow()) - _naive_utc(instance.last_heartbeat_at)
    if gap.total_seconds() <= SCANNER_HEARTBEAT_STALE_AFTER_SECONDS:
        return None
    return gap


@router.post("/heartbeat", response_model=HeartbeatResponse)
def heartbeat_route(
    request: Request, body: HeartbeatRequest | None = None, db: Session = Depends(get_db)
) -> HeartbeatResponse:
    instance = require_scanner_instance(request, db)

    # Read before record_heartbeat overwrites it: this is the only moment the
    # platform can tell that the Collector had been away. The agent's own loop
    # heartbeats and *then* polls for work (apps/scanner/scanner_agent/cli.py's
    # run loop), so by the time the command poll arrives this fact is gone.
    offline_for = _downtime_before_this_heartbeat(instance)

    record_heartbeat(
        db,
        instance,
        os_name=body.os_name if body else None,
        os_version=body.os_version if body else None,
        architecture=body.architecture if body else None,
        kernel_release=body.kernel_release if body else None,
        container_runtime=body.container_runtime if body else None,
        runtime_os_name=body.runtime_os_name if body else None,
        runtime_os_version=body.runtime_os_version if body else None,
        network_segments=body.network_segments if body else None,
    )

    # A heartbeat is the Collector saying it is alive, so it is also the only
    # honest moment to extend the leases it is holding. WORKER_LEASE_DEFAULT_
    # SECONDS is five minutes and a /24 sweep with service fingerprinting takes
    # far longer, so a healthy Collector had its job reclaimed mid-scan,
    # retried, and reclaimed again — the run never finished. Renewing here keeps
    # the original intent exactly: heartbeats stop, the lease still expires on
    # schedule and the job is reclaimed.
    renew_leases_for_scanner(db, scanner_instance_id=instance.id)

    # UX-DISC-06 — time the Collector spent offline is time it could not have
    # taken its queued work, so it does not count toward command expiry. Done
    # here rather than inside record_heartbeat: command lifecycle is not the
    # scanner service's responsibility, and this route is the layer that already
    # composes the two.
    if offline_for is not None:
        revived = revive_commands_after_downtime(db, instance, offline_for=offline_for)
        if revived:
            logger.info(
                "discovery_commands_revived_after_downtime",
                scanner_instance_id=instance.id,
                offline_seconds=int(offline_for.total_seconds()),
                command_ids=[command.id for command in revived],
            )

    db.commit()
    db.refresh(instance)
    return HeartbeatResponse(
        scanner_instance_id=instance.id,
        status=instance.status,
        # Read, never cleared here: handing an instruction over is not evidence
        # it was carried out. It clears when the resulting report arrives.
        pending_instruction=pending_instruction_for(instance),
    )


@router.post("/readiness", response_model=AgentInstanceResponse)
def readiness_route(
    body: CollectorReadinessRequest, request: Request, db: Session = Depends(get_db)
) -> AgentInstanceResponse:
    """CA-02.3 — the Collector's own self-check.

    Authenticated by the Collector's credential, exactly like every other agent
    route: a readiness report is only worth anything because of *who* sent it,
    and there is no user-facing way to write one.

    Kept separate from the heartbeat on purpose. A missed heartbeat should read
    as offline within minutes; a full self-check is comparatively expensive to
    run, so merging them would either make liveness slow or self-checks
    wasteful.
    """
    instance = require_scanner_instance(request, db)
    previous = resolve_collector_readiness(db, instance)

    # Resolved from the pending instruction, never from the payload: the agent
    # says *what* it was asked to do, the platform decides *who* asked. Letting
    # a Collector name the user would make the audit trail forgeable by the one
    # party it is meant to hold accountable.
    was_requested = (
        body.trigger == CollectorReadinessTrigger.REQUESTED.value
        and instance.pending_instruction == CollectorInstruction.SELF_CHECK.value
    )
    requested_by_user_id = instance.pending_instruction_requested_by_user_id if was_requested else None

    report = record_readiness_report(
        db,
        instance,
        report=body.model_dump(),
        requested_by_user_id=requested_by_user_id,
    )
    if was_requested:
        # The result is in, so the instruction is genuinely done — this is the
        # only place it clears.
        clear_instruction(db, instance)
    if body.collectorVersion:
        instance.scanner_version = body.collectorVersion
        db.add(instance)
    record_heartbeat(db, instance)
    _audit_readiness(db, instance, report=report, previous_status=previous.status)
    db.commit()
    db.refresh(instance)
    return AgentInstanceResponse(
        scanner_instance_id=instance.id,
        status=instance.status,
        scan_profile=instance.scan_profile,
        tool_status=instance.tool_status or {},
        test_scan_status=instance.test_scan_status,
    )


@router.post("/tools/validate", response_model=AgentInstanceResponse)
def tools_validate_route(
    body: ToolValidationRequest, request: Request, db: Session = Depends(get_db)
) -> AgentInstanceResponse:
    """The Collector's existing self-check, which already runs the real binaries.

    Kept working, and now *also* recorded as a readiness report. The measurement
    was always genuine — it simply predates the richer shape — so an already
    deployed Collector keeps producing verified readiness instead of reading
    "unknown" until its binary is upgraded. Only the user-facing path that let a
    person type the same answer has been removed.
    """
    instance = require_scanner_instance(request, db)
    previous = resolve_collector_readiness(db, instance)
    try:
        record_tool_validation(db, instance, tool_status=body.tool_status)
    except EvidenceScannerValidationError as exc:
        raise AuthenticationError(str(exc)) from exc
    if body.scanner_version:
        instance.scanner_version = body.scanner_version
        db.add(instance)

    report = latest_readiness_report(db, instance)
    record_heartbeat(db, instance)
    _audit_readiness(db, instance, report=report, previous_status=previous.status)
    db.commit()
    db.refresh(instance)
    return AgentInstanceResponse(
        scanner_instance_id=instance.id,
        status=instance.status,
        scan_profile=instance.scan_profile,
        tool_status=instance.tool_status or {},
        test_scan_status=instance.test_scan_status,
    )


@router.post("/test-scan", response_model=AgentInstanceResponse)
def test_scan_route(
    body: TestScanRequest, request: Request, db: Session = Depends(get_db)
) -> AgentInstanceResponse:
    instance = require_scanner_instance(request, db)
    record_test_scan_result(db, instance, status=body.status, connection_verified=body.connection_verified)
    record_heartbeat(db, instance)
    db.commit()
    db.refresh(instance)
    return AgentInstanceResponse(
        scanner_instance_id=instance.id,
        status=instance.status,
        scan_profile=instance.scan_profile,
        tool_status=instance.tool_status or {},
        test_scan_status=instance.test_scan_status,
    )
