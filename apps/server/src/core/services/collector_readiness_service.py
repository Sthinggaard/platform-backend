"""What the Collector itself reports about its ability to work (CA-02.3).

Until now the platform could not tell a real self-check from a user answering a
form: ``scanner_agent.py``'s agent route and ``evidence_scanner.py``'s
user-facing route both wrote ``ScannerInstance.tool_status`` through the same
service, with no marker between them. Readiness was therefore assertable by
whoever happened to be doing the onboarding, for a technical state the Collector
can verify directly by running the binary.

**The product principle, from the design spec:** Risklence must not ask the user
to be the source of truth for something the Collector can check. A user may
review readiness, rerun the self-check, and act on it. A user may not declare a
failed component healthy.

**Provenance is the whole point of this module.** A report exists only if it
arrived through the Collector's own authenticated credential, and it carries a
``schema_version`` so a reader knows what the payload meant. Legacy
``tool_status`` is never consulted here — not because the data is wrong, but
because nothing can tell whether it was measured or typed, and "we cannot tell"
must read as ``unknown`` rather than as ``ready``.

This module owns readiness only. The setup-wizard completion gate stays in
``evidence_scanner_readiness_service`` (a narrower, different question) and reads
from here rather than from raw columns.
"""

from __future__ import annotations

import ipaddress

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.constants.evidence_scanner_enums import (
    SCANNER_HEARTBEAT_STALE_AFTER_SECONDS,
    CollectorComponentStatus,
    CollectorReadinessStatus,
    ScannerInstanceStatus,
    CollectorCapability,
    ScannerToolName,
    ScannerToolStatus,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.evidence_scanner import CollectorReadinessReport, ScannerInstance

#: Bumped when the meaning of a report's fields changes, never for an additive
#: field. The migration rule turns on this being present at all: a Collector
#: counts as verified only once a genuinely schema-versioned report arrives.
READINESS_SCHEMA_VERSION = "1"

#: Components that must be executable for the Collector to do anything at all.
#: Used for the rollup only — per-capability discovery gating is finer-grained
#: and deliberately separate, so one optional failure never blocks unrelated
#: work.
_CORE_COMPONENTS: frozenset[str] = frozenset({ScannerToolName.NMAP.value})


@dataclass(frozen=True)
class ComponentReadiness:
    component_key: str
    status: str
    version: str | None = None
    reason_code: str | None = None


@dataclass(frozen=True)
class CollectorReadiness:
    """The answer the rest of the platform asks for."""

    status: str
    components: tuple[ComponentReadiness, ...]
    platform_connectivity_status: str
    evidence_storage_status: str
    collector_version: str | None
    template_pack_version: str | None
    reported_at: datetime | None
    #: Why the status is what it is, in codes a view can turn into sentences.
    #: Empty for a ready Collector.
    failure_reason_codes: tuple[str, ...] = ()

    @property
    def has_report(self) -> bool:
        return self.reported_at is not None


def _component_status_for_tool(tool_status_value: str | None) -> str:
    if tool_status_value == ScannerToolStatus.AVAILABLE.value:
        return CollectorComponentStatus.READY.value
    if tool_status_value is None:
        return CollectorComponentStatus.UNKNOWN.value
    return CollectorComponentStatus.UNAVAILABLE.value


def readiness_from_tool_statuses(
    tool_status: dict[str, str],
    *,
    collector_version: str | None = None,
) -> dict:
    """Adapt today's agent self-check into a readiness report.

    The Collector's existing ``validate-tools`` command already runs
    ``shutil.which`` plus a real ``--version`` subprocess per tool and checks the
    bundled template directory — a genuine measurement, posted through the
    agent's own credential. That is exactly what a readiness report is; it
    simply predates the richer shape.

    So the working agent keeps producing verified readiness from the day this
    ships, instead of every existing Collector reading ``unknown`` until its
    binary is upgraded. Storage and connectivity are reported as ``unknown``
    rather than assumed healthy — this payload genuinely does not say, and
    inventing a value here would be the same failure this whole story exists to
    remove.
    """
    components = [
        {
            "componentKey": tool,
            "status": _component_status_for_tool(tool_status.get(tool)),
            "version": None,
            "reasonCode": None,
        }
        for tool in (t.value for t in ScannerToolName)
    ]
    return {
        "schemaVersion": READINESS_SCHEMA_VERSION,
        "collectorVersion": collector_version,
        "components": components,
        # Not claimed, because this payload does not carry them.
        "platformConnectivityStatus": CollectorComponentStatus.UNKNOWN.value,
        "evidenceStorageStatus": CollectorComponentStatus.UNKNOWN.value,
        "templatePackVersion": None,
        "failureReasonCodes": [],
    }


def _roll_up(
    components: list[dict],
    *,
    platform_connectivity: str,
    evidence_storage: str,
) -> str:
    """One status for the Collector as a whole.

    Rolls up *components*, never business dimensions. Discovery gating is
    per-capability on purpose (a missing subfinder must not block host
    discovery), so nothing should ever gate on this value alone.
    """
    # Connectivity first: without it no report or evidence can reach the
    # platform, whatever the local tools say.
    if platform_connectivity == CollectorComponentStatus.UNAVAILABLE.value:
        return CollectorReadinessStatus.BLOCKED.value

    statuses = {component.get("status") for component in components}
    core_broken = any(
        component.get("componentKey") in _CORE_COMPONENTS
        and component.get("status") == CollectorComponentStatus.UNAVAILABLE.value
        for component in components
    )
    if core_broken or evidence_storage == CollectorComponentStatus.UNAVAILABLE.value:
        return CollectorReadinessStatus.BLOCKED.value
    if CollectorComponentStatus.UNAVAILABLE.value in statuses:
        return CollectorReadinessStatus.DEGRADED.value
    if CollectorComponentStatus.DEGRADED.value in statuses:
        return CollectorReadinessStatus.DEGRADED.value
    # Storage and connectivity are not components, so they are not in
    # `statuses` — without this a Collector running low on disk, or on a link
    # that keeps dropping, would roll up as fully ready.
    #
    # DEGRADED only. **UNKNOWN deliberately does not degrade** (Søren's decision
    # for this slice): a Collector that has not measured these is unverified,
    # not unhealthy, and treating "we did not look" as "it is failing" would
    # mark every not-yet-upgraded Collector degraded on the day this ships.
    if CollectorComponentStatus.DEGRADED.value in {platform_connectivity, evidence_storage}:
        return CollectorReadinessStatus.DEGRADED.value
    if statuses and statuses <= {CollectorComponentStatus.READY.value}:
        return CollectorReadinessStatus.READY.value
    # Something was not reported. Not ready, and not a failure either.
    return CollectorReadinessStatus.CHECKING.value


def record_readiness_report(
    db: Session,
    instance: ScannerInstance,
    *,
    report: dict,
    requested_by_user_id: int | None = None,
) -> CollectorReadinessReport:
    """Store a self-check the Collector reported through its own credential.

    ``reported_at`` is stamped here, never read from the payload: a Collector
    with a wrong clock must not be able to date its report into the future and
    win "latest" permanently.
    """
    components = report.get("components") or []
    platform_connectivity = report.get("platformConnectivityStatus") or (
        CollectorComponentStatus.UNKNOWN.value
    )
    evidence_storage = report.get("evidenceStorageStatus") or CollectorComponentStatus.UNKNOWN.value

    overall = report.get("overallStatus") or _roll_up(
        components,
        platform_connectivity=platform_connectivity,
        evidence_storage=evidence_storage,
    )

    row = CollectorReadinessReport(
        id=str(uuid4()),
        organization_id=instance.organization_id,
        scanner_instance_id=instance.id,
        reported_at=utcnow(),
        self_check_started_at=None,
        self_check_completed_at=None,
        overall_status=overall,
        platform_connectivity_status=platform_connectivity,
        evidence_storage_status=evidence_storage,
        collector_version=report.get("collectorVersion"),
        template_pack_version=report.get("templatePackVersion"),
        components=components,
        failure_reason_codes=report.get("failureReasonCodes") or [],
        schema_version=report.get("schemaVersion") or READINESS_SCHEMA_VERSION,
        report_sequence=report.get("reportSequence"),
        # Why this check ran, and — only for a requested one — who asked. The
        # caller resolves the person from the pending instruction rather than
        # the payload; a Collector must not be able to attribute its report to
        # an arbitrary user.
        trigger=report.get("trigger"),
        requested_by_user_id=requested_by_user_id,
    )
    db.add(row)
    db.flush()
    return row


def latest_readiness_report(db: Session, instance: ScannerInstance) -> CollectorReadinessReport | None:
    return db.execute(
        select(CollectorReadinessReport)
        .where(CollectorReadinessReport.scanner_instance_id == instance.id)
        .order_by(CollectorReadinessReport.reported_at.desc(), CollectorReadinessReport.id.desc())
        .limit(1)
    ).scalars().first()


def _naive(value: datetime) -> datetime:
    return value.replace(tzinfo=None) if value.tzinfo else value


def resolve_collector_readiness(db: Session, instance: ScannerInstance) -> CollectorReadiness:
    """The Collector's readiness, derived from its own latest report.

    Two states are deliberately *not* ``ready``:

    * **No report at all** → ``unknown``. This is every instance that predates
      readiness reporting, whose stored ``tool_status`` may have been typed by a
      person. Absence of evidence is not evidence of health.
    * **A Collector that has stopped reporting** → ``offline``, whatever its last
      report said. A month-old "everything works" describes a machine, not a
      capability available now.
    """
    report = latest_readiness_report(db, instance)
    if report is None:
        return CollectorReadiness(
            status=CollectorReadinessStatus.UNKNOWN.value,
            components=(),
            platform_connectivity_status=CollectorComponentStatus.UNKNOWN.value,
            evidence_storage_status=CollectorComponentStatus.UNKNOWN.value,
            collector_version=None,
            template_pack_version=None,
            reported_at=None,
            failure_reason_codes=("no_readiness_report",),
        )

    components = tuple(
        ComponentReadiness(
            component_key=str(component.get("componentKey")),
            status=str(component.get("status") or CollectorComponentStatus.UNKNOWN.value),
            version=component.get("version"),
            reason_code=component.get("reasonCode"),
        )
        for component in (report.components or [])
    )

    status = report.overall_status
    reasons = tuple(report.failure_reason_codes or [])

    # A stopped Collector cannot be ready however good its last self-check was.
    # Same staleness threshold the rest of the platform reads liveness with, so
    # the panel that says "offline" and this cannot disagree.
    if instance.status not in {
        ScannerInstanceStatus.PAUSED.value,
        ScannerInstanceStatus.REVOKED.value,
        ScannerInstanceStatus.RETIRED.value,
    }:
        last_seen = instance.last_heartbeat_at
        if last_seen is None or (
            (_naive(utcnow()) - _naive(last_seen)).total_seconds()
            > SCANNER_HEARTBEAT_STALE_AFTER_SECONDS
        ):
            status = CollectorReadinessStatus.OFFLINE.value
            reasons = reasons + ("collector_not_reporting",)

    return CollectorReadiness(
        status=status,
        components=components,
        platform_connectivity_status=report.platform_connectivity_status,
        evidence_storage_status=report.evidence_storage_status,
        collector_version=report.collector_version,
        template_pack_version=report.template_pack_version,
        reported_at=report.reported_at,
        failure_reason_codes=reasons,
    )


def component_is_ready(readiness: CollectorReadiness, component_key: str) -> bool:
    """Whether the Collector's own self-check found this component working.

    The unit discovery gating asks about. Deliberately per-component rather than
    "is the rollup ready": a missing subfinder must block domain enumeration and
    nothing else.

    **Deliberately says nothing about whether the Collector is reachable now.**
    "Has this Collector verified nmap?" and "is this Collector online?" are
    different questions with different answers and different remedies, and
    conflating them makes the setup gate flap: complete the wizard, walk away
    for twenty minutes, and it would quietly un-complete itself as the heartbeat
    went stale. Liveness is checked where it actually matters — before dispatching
    work — and shown separately on the panel.

    ``unknown`` (no report at all) and ``blocked`` are still false: those are
    statements about the self-check, not about reachability.
    """
    if readiness.status in {
        CollectorReadinessStatus.UNKNOWN.value,
        CollectorReadinessStatus.BLOCKED.value,
    }:
        return False
    for component in readiness.components:
        if component.component_key == component_key:
            return component.status == CollectorComponentStatus.READY.value
    return False


def collector_can_see_hardware_addresses(readiness: CollectorReadiness) -> bool:
    """Whether this Collector was able to observe MAC addresses at all.

    The question that makes an *absence* of evidence readable. A discovery run
    that reports no MAC for an address means one of two opposite things — there
    is no device there, or the Collector was never permitted to look — and
    without this the platform cannot tell them apart. It guessed, and 242 echoes
    from a userspace network stack became artefacts (#175).

    Reads the Collector's own reported capability rather than inferring from
    whether any MAC turned up, for the same reason ``fingerprinting_ran`` is
    passed rather than guessed (#249): inference from absence can only ever
    conclude "we did not look", which is exactly the answer that must be earned
    rather than assumed.

    False when the Collector has never reported — an unknown capability is not
    a granted one, and treating silence as permission would put the platform
    back to reading missing MACs as missing devices.

    ⚠️ **This answers only half the question, and the weaker half.** See
    ``collector_can_see_hardware_addresses_for`` below: the privilege is not the
    constraint that actually binds.
    """
    return component_is_ready(readiness, CollectorCapability.RAW_PACKET_ACCESS.value)


def collector_can_see_hardware_addresses_for(
    readiness: CollectorReadiness,
    *,
    network_segments: list[dict] | None,
    target: str,
) -> bool:
    """Whether this Collector can observe MAC addresses **on this target**.

    #320. The privilege question above is nearly always answered yes, and that
    is not a quirk: ``CAP_NET_RAW`` is in Docker's **default** capability set for
    a root container, and the scanner image runs as root by documented
    exception. Measured on real Linux — no flags: ``available=True``;
    ``--cap-add=NET_RAW``: ``available=True``; only an explicit ``--cap-drop``
    says otherwise, and nobody does that.

    So the capability is not what varies. **Position is.** ARP does not route:
    a target outside every segment the Collector is attached to cannot be ARPed
    however much privilege is held. On Docker Desktop a ``--network host``
    container sees only Docker's own bridges — measured: the Mac's LAN address
    ``192.168.50.191`` is absent entirely — so the Collector would report the
    capability, find no MAC anywhere, and every silent address would be recorded
    as *"nothing answered on this address"*: a confident falsehood, and strictly
    worse than the honest *"we were not able to look"* it replaced.

    ``network_segments`` of ``None`` means the Collector has never said where it
    is. That is answered **False** — not because it cannot look, but because
    nothing has established that it can, and this function exists to stop an
    unearned yes.
    """
    if not collector_can_see_hardware_addresses(readiness):
        return False
    if not network_segments:
        return False
    return _target_is_on_a_local_segment(target, network_segments)


def _target_is_on_a_local_segment(target: str, network_segments: list[dict]) -> bool:
    """Whether `target` falls inside any segment the Collector is attached to.

    Accepts a single address or a CIDR, because an approved target is written
    either way. A target network wider than the Collector's own segment counts
    as reachable when they overlap at all: the Collector can ARP the part of it
    it shares, and reporting a partial reach as none would send somebody
    hunting for a permission problem that is really a scope one.
    """
    try:
        wanted = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        return False
    for segment in network_segments:
        if not isinstance(segment, dict):
            continue
        raw = segment.get("network")
        if not isinstance(raw, str):
            continue
        try:
            local = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if wanted.version == local.version and wanted.overlaps(local):
            return True
    return False
