"""Step 4.1 — immutable execution snapshots (spec §10).

A discovery run must never depend on the live, mutable
``ScannerInstance.scan_profile``/``ScannerDomainTarget``/``ScannerNetworkTarget``
rows drifting under it once created — these functions freeze exactly what
was approved at request time into plain dicts stored on the run.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.core.constants.evidence_scanner_enums import SCANNER_PROFILE_CAPABILITIES, ScannerTargetStatus
from src.core.model_defs.evidence_scanner import ScannerDomainTarget, ScannerInstance, ScannerNetworkTarget


def build_profile_snapshot(instance: ScannerInstance) -> dict:
    capabilities = SCANNER_PROFILE_CAPABILITIES.get(instance.scan_profile, {})
    return {
        "profileId": instance.scan_profile,
        "profileVersion": 1,
        "name": instance.scan_profile,
        "profileType": instance.scan_profile,
        "requiredCapabilities": [key for key, enabled in capabilities.items() if enabled],
        "allowsExternalDiscovery": bool(capabilities.get("externalDiscoveryEnabled")),
        "allowsInternalDiscovery": bool(capabilities.get("internalDiscoveryEnabled")),
        "allowsFingerprinting": bool(capabilities.get("serviceFingerprintingEnabled")),
        "allowsVulnerabilityChecks": bool(capabilities.get("vulnerabilityScanningEnabled")),
    }


def _domain_target_snapshot(target: ScannerDomainTarget) -> dict:
    return {
        "targetId": target.id,
        "targetType": "DOMAIN",
        "displayName": target.domain,
        "approvedValue": target.domain,
        "approvedAt": (target.approved_at.isoformat() if target.approved_at else None),
        "approvedByUserId": target.approved_by_user_id,
    }


def _network_target_snapshot(target: ScannerNetworkTarget) -> dict:
    return {
        "targetId": target.id,
        "targetType": "NETWORK_RANGE",
        "displayName": target.name,
        "approvedValue": target.cidr,
        "networkType": target.network_type,
        "approvedAt": (target.approved_at.isoformat() if target.approved_at else None),
        "approvedByUserId": target.approved_by_user_id,
    }


def resolve_approved_targets(
    db: Session, *, evidence_source_id: str, target_ids: list[str] | None
) -> tuple[list[str], list[dict], list[str]]:
    """Resolve the requested (or, if omitted, all) APPROVED domain/network
    targets for this evidence source into an immutable snapshot. Returns
    (resolved_ids, snapshots, blocking_reasons) — a target_id that doesn't
    resolve to an APPROVED row belonging to this source is a blocking
    reason, never silently dropped or silently widened (spec §6.4/§6.5)."""
    domain_targets = {
        t.id: t
        for t in db.query(ScannerDomainTarget).filter(
            ScannerDomainTarget.evidence_source_id == evidence_source_id,
            ScannerDomainTarget.status == ScannerTargetStatus.APPROVED.value,
        )
    }
    network_targets = {
        t.id: t
        for t in db.query(ScannerNetworkTarget).filter(
            ScannerNetworkTarget.evidence_source_id == evidence_source_id,
            ScannerNetworkTarget.status == ScannerTargetStatus.APPROVED.value,
        )
    }

    resolved_ids = list(domain_targets.keys()) + list(network_targets.keys()) if target_ids is None else target_ids

    snapshots: list[dict] = []
    blocking: list[str] = []
    for target_id in resolved_ids:
        if target_id in domain_targets:
            snapshots.append(_domain_target_snapshot(domain_targets[target_id]))
        elif target_id in network_targets:
            snapshots.append(_network_target_snapshot(network_targets[target_id]))
        else:
            blocking.append("discovery_scope_not_approved")

    if not snapshots:
        blocking.append("discovery_scope_required")

    return resolved_ids, snapshots, blocking
