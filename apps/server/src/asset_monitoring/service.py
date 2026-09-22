"""Domain services for assets, connections, signals, and findings."""

from __future__ import annotations

import random
import secrets
from datetime import datetime, timedelta, timezone
from typing import Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.logging_config import get_logger
from src.core.models import (
    Asset,
    AssetConnection,
    AssetEvidenceSignal,
    AssetFinding,
    AssetFindingStatus,
    AssetStatus,
    AssetStatusHistory,
    ConnectivityStatus,
    Control,
    ControlCoverageStatus,
    ControlEvidence,
    ControlMapping,
    ControlShareLink,
    Organization,
    SeverityLevel,
    utcnow,
)

logger = get_logger(__name__)

SEED_ASSETS: list[dict[str, str | int | float]] = [
    {"layer": "Network", "type": "Firewall", "display_name": "Main Firewall", "provider": "Palo Alto", "status": "OPERATIONALLY_COMPLIANT", "connectivity_status": "CONNECTED", "risk_score": 12.0, "findings_count": 2},
    {"layer": "Network", "type": "Cloud", "display_name": "AWS Production", "provider": "AWS", "status": "OPERATIONALLY_COMPLIANT", "connectivity_status": "CONNECTED", "risk_score": 18.0, "findings_count": 1},
    {"layer": "Data", "type": "Database", "display_name": "Primary Database", "provider": "PostgreSQL", "status": "OPERATIONALLY_COMPLIANT", "connectivity_status": "CONNECTED", "risk_score": 24.0, "findings_count": 4},
    {"layer": "Application", "type": "Endpoint", "display_name": "Corporate Endpoint", "provider": "Jamf", "status": "PARTIALLY_OBSERVED", "connectivity_status": "PENDING_VERIFICATION", "risk_score": 40.0, "findings_count": 7},
    {"layer": "Transfer", "type": "Service", "display_name": "Web Server", "provider": "NGINX", "status": "OPERATIONALLY_COMPLIANT", "connectivity_status": "CONNECTED", "risk_score": 16.0, "findings_count": 2},
    {"layer": "Identity", "type": "Gateway", "display_name": "API Gateway", "provider": "Kong", "status": "PARTIALLY_OBSERVED", "connectivity_status": "PENDING_VERIFICATION", "risk_score": 55.0, "findings_count": 10},
    {"layer": "Data", "type": "Storage", "display_name": "Backup Storage", "provider": "S3", "status": "OPERATIONALLY_COMPLIANT", "connectivity_status": "CONNECTED", "risk_score": 14.0, "findings_count": 1},
    {"layer": "Hardware", "type": "Network", "display_name": "Core Router", "provider": "Cisco", "status": "PARTIALLY_OBSERVED", "connectivity_status": "PENDING_VERIFICATION", "risk_score": 37.0, "findings_count": 5},
    {"layer": "Application", "type": "Application", "display_name": "Main Application", "provider": "Internal", "status": "OPERATIONALLY_COMPLIANT", "connectivity_status": "CONNECTED", "risk_score": 22.0, "findings_count": 3},
    {"layer": "Hardware", "type": "Endpoints", "display_name": "Remote Workforce", "provider": "Okta", "status": "PARTIALLY_OBSERVED", "connectivity_status": "DEGRADED", "risk_score": 48.0, "findings_count": 6},
    {"layer": "Hardware", "type": "Storage", "display_name": "Azure Backup", "provider": "Azure", "status": "OPERATIONALLY_COMPLIANT", "connectivity_status": "CONNECTED", "risk_score": 18.0, "findings_count": 2},
    {"layer": "Transfer", "type": "Database", "display_name": "Analytics DB", "provider": "Snowflake", "status": "PARTIALLY_OBSERVED", "connectivity_status": "DEGRADED", "risk_score": 33.0, "findings_count": 4},
    {"layer": "Transfer", "type": "Service", "display_name": "API Server", "provider": "EKS", "status": "AT_RISK", "connectivity_status": "DEGRADED", "risk_score": 72.0, "findings_count": 12},
    {"layer": "Hardware", "type": "Network", "display_name": "Core Router Edge", "provider": "Cisco", "status": "OPERATIONALLY_COMPLIANT", "connectivity_status": "CONNECTED", "risk_score": 20.0, "findings_count": 2},
]

SEED_CONTROLS: list[dict[str, str]] = [
    {"framework": "Baseline", "control_code": "BL-01", "title": "Identity hardened", "description": "Identity provider configured with MFA and SSO."},
    {"framework": "Baseline", "control_code": "BL-02", "title": "Network segmentation", "description": "Security groups restrict public ingress."},
    {"framework": "Baseline", "control_code": "BL-03", "title": "Logging enabled", "description": "Audit logs collected for cloud activity."},
    {"framework": "Baseline", "control_code": "BL-04", "title": "Data encryption", "description": "Data stores encrypted at rest and in transit."},
    {"framework": "Baseline", "control_code": "BL-05", "title": "CI/CD integrity", "description": "Pipelines enforce signed artifacts and approvals."},
    {"framework": "Baseline", "control_code": "BL-06", "title": "Backup and recovery", "description": "Critical data has recent backups with tested restores."},
    {"framework": "Baseline", "control_code": "BL-07", "title": "Least privilege", "description": "Scoped access for service principals and operators."},
    {"framework": "Baseline", "control_code": "BL-08", "title": "Change management", "description": "Infrastructure changes are reviewed and tracked."},
    {"framework": "Baseline", "control_code": "BL-09", "title": "Threat detection", "description": "Signals monitored for risky behavior."},
    {"framework": "Baseline", "control_code": "BL-10", "title": "Resilience", "description": "Systems handle degraded dependencies gracefully."},
]

SEED_MAPPINGS: list[dict[str, str | float]] = [
    {"control_code": "BL-01", "asset_type": "identity_provider", "signal_kind": "identity_event", "min_confidence": 0.6, "evidence_rule": "mfa_enabled"},
    {"control_code": "BL-02", "asset_type": "network", "signal_kind": "network_scan", "min_confidence": 0.5, "evidence_rule": "no_public_sg"},
    {"control_code": "BL-03", "asset_type": "cloud_account", "signal_kind": "logging", "min_confidence": 0.4, "evidence_rule": "audit_logs_active"},
    {"control_code": "BL-04", "asset_type": "storage", "signal_kind": "data_protection", "min_confidence": 0.6, "evidence_rule": "encryption_on"},
    {"control_code": "BL-05", "asset_type": "cicd", "signal_kind": "pipeline_event", "min_confidence": 0.5, "evidence_rule": "approvals_required"},
    {"control_code": "BL-09", "asset_type": "network", "signal_kind": "threat_signal", "min_confidence": 0.4, "evidence_rule": "alerts_zero"},
]


def ensure_seed_org(db: Session) -> Organization:
    """Return an organization and create a baseline one if missing."""
    org = db.execute(select(Organization).limit(1)).scalar_one_or_none()
    if org:
        return org
    org = Organization(
        name="Risklence Demo",
        slug="risklence-demo",
        industry="technology",
        country="US",
        plan_tier="enterprise",
        subscription_status="trial",
    )
    db.add(org)
    db.commit()
    db.refresh(org)
    logger.info("seed_org_created", organization_id=org.id)
    return org


def seed_assets(db: Session, organization_id: int) -> Sequence[Asset]:
    """Seed default assets across layers if they don't exist."""
    existing = {
        (asset.display_name.lower(), asset.layer.lower())
        for asset in db.execute(select(Asset).where(Asset.organization_id == organization_id)).scalars().all()
    }
    created: list[Asset] = []
    for seed in SEED_ASSETS:
        key = (seed["display_name"].lower(), seed["layer"].lower())
        if key in existing:
            continue
        asset = Asset(
            organization_id=organization_id,
            type=seed["type"],
            provider=seed.get("provider"),
            display_name=seed["display_name"],
            layer=seed["layer"],
            status=AssetStatus[seed.get("status", "NOT_CONNECTED")],
            connectivity_status=ConnectivityStatus[seed.get("connectivity_status", "NOT_CONNECTED")],
            observation_level="continuous" if seed.get("status") != "NOT_CONNECTED" else "none",
            risk_score=seed.get("risk_score", 0.0),
            findings_count=seed.get("findings_count", 0),
            confidence=0.8 if seed.get("status") != "NOT_CONNECTED" else 0.0,
        )
        db.add(asset)
        created.append(asset)
    if created:
        db.commit()
        for asset in created:
            db.refresh(asset)
        logger.info("seed_assets_created", count=len(created))
    return list(db.execute(select(Asset).where(Asset.organization_id == organization_id)).scalars().all())


def seed_controls(db: Session) -> Sequence[Control]:
    """Seed baseline controls and mappings."""
    existing_codes = {
        (ctrl.framework, ctrl.control_code)
        for ctrl in db.execute(select(Control)).scalars().all()
    }
    created: list[Control] = []
    for ctrl in SEED_CONTROLS:
        key = (ctrl["framework"], ctrl["control_code"])
        if key in existing_codes:
            continue
        control = Control(**ctrl)
        db.add(control)
        created.append(control)
    if created:
        db.commit()
        for ctrl in created:
            db.refresh(ctrl)
    # Refresh existing map after control insert
    controls = {ctrl.control_code: ctrl for ctrl in db.execute(select(Control)).scalars().all()}
    existing_maps = {
        (mapping.control_id, mapping.asset_type, mapping.signal_kind)
        for mapping in db.execute(select(ControlMapping)).scalars().all()
    }
    created_mappings: list[ControlMapping] = []
    for mapping in SEED_MAPPINGS:
        control = controls.get(mapping["control_code"])
        if not control:
            continue
        key = (control.id, mapping["asset_type"], mapping["signal_kind"])
        if key in existing_maps:
            continue
        cm = ControlMapping(
            control_id=control.id,
            asset_type=mapping["asset_type"],
            signal_kind=mapping["signal_kind"],
            min_confidence=float(mapping.get("min_confidence", 0.0)),
            evidence_rule=str(mapping.get("evidence_rule") or ""),
        )
        db.add(cm)
        created_mappings.append(cm)
    if created_mappings:
        db.commit()
    return list(controls.values())


def record_status(
    db: Session,
    asset: Asset,
    status: AssetStatus,
    *,
    risk_score: float | None = None,
    observation_level: str | None = None,
    findings_count: int | None = None,
    confidence: float | None = None,
    observed_at: datetime | None = None,
) -> AssetStatusHistory:
    """Update asset and append a history row."""
    observed_at = observed_at or utcnow()
    asset.status = status
    asset.last_observed_at = observed_at
    if risk_score is not None:
        asset.risk_score = risk_score
    if observation_level is not None:
        asset.observation_level = observation_level
    if findings_count is not None:
        asset.findings_count = findings_count
    if confidence is not None:
        asset.confidence = confidence

    history = AssetStatusHistory(
        asset_id=asset.id,
        status=status,
        risk_score=asset.risk_score,
        observation_level=asset.observation_level,
        findings_count=asset.findings_count,
        confidence=asset.confidence,
        observed_at=observed_at,
    )
    db.add(history)
    return history


def connect_asset(
    db: Session,
    asset_id: int,
    *,
    auth_type: str | None,
    scopes: list[str] | None,
    external_account_id: str | None,
) -> Asset:
    """Connect an asset, create connection metadata, and mark as partially observed."""
    asset = db.get(Asset, asset_id)
    if not asset:
        raise ValueError("Asset not found")
    now = utcnow()
    connection = AssetConnection(
        asset_id=asset.id,
        auth_type=auth_type or "mock",
        scopes=scopes or [],
        external_account_id=external_account_id,
        mock_token=f"mock-token-{asset.id}",
        connected_at=now,
        last_sync_at=now,
        state="CONNECTED",
    )
    db.add(connection)
    # Lift status
    record_status(
        db,
        asset,
        AssetStatus.PARTIALLY_OBSERVED,
        risk_score=25.0,
        observation_level="limited",
        findings_count=asset.findings_count,
        confidence=0.6,
        observed_at=now,
    )
    db.commit()
    db.refresh(asset)
    return asset


def disconnect_asset(db: Session, asset_id: int) -> Asset:
    """Disconnect an asset and reset telemetry."""
    asset = db.get(Asset, asset_id)
    if not asset:
        raise ValueError("Asset not found")
    record_status(
        db,
        asset,
        AssetStatus.NOT_CONNECTED,
        risk_score=0.0,
        observation_level="none",
        findings_count=0,
        confidence=0.0,
        observed_at=utcnow(),
    )
    # Mark any connections as disconnected
    for conn in asset.connections:
        conn.state = "DISCONNECTED"
        conn.last_sync_at = utcnow()
    db.commit()
    db.refresh(asset)
    return asset


def create_network_findings(db: Session, asset: Asset) -> list[AssetFinding]:
    """Seed findings for network asset to reflect the mock screenshot vibe."""
    existing = (
        db.execute(
            select(AssetFinding).where(
                AssetFinding.asset_id == asset.id,
                AssetFinding.status != AssetFindingStatus.RESOLVED,
            )
        )
        .scalars()
        .all()
    )
    if existing:
        return existing
    templates = [
        {
            "domain": "network",
            "severity": SeverityLevel.HIGH,
            "title": "Public security group discovered",
            "description": "0.0.0.0/0 ingress on port 22",
            "evidence_refs": ["sg-123", "flow-log-22"],
            "risk_score": 82.0,
        },
        {
            "domain": "network",
            "severity": SeverityLevel.MEDIUM,
            "title": "Weak egress rule",
            "description": "Wildcards allow unrestricted outbound traffic.",
            "evidence_refs": ["sg-456"],
            "risk_score": 55.0,
        },
    ]
    findings: list[AssetFinding] = []
    for template in templates:
        finding = AssetFinding(
            organization_id=asset.organization_id,
            asset_id=asset.id,
            status=AssetFindingStatus.OPEN,
            first_seen_at=utcnow(),
            last_seen_at=utcnow(),
            **template,
        )
        db.add(finding)
        findings.append(finding)
    asset.findings_count = len(findings)
    db.commit()
    for f in findings:
        db.refresh(f)
    return findings


def create_signal(
    db: Session,
    asset: Asset,
    *,
    kind: str,
    payload: dict,
    confidence: float,
    risk_score: float,
    observed_at: datetime | None = None,
) -> AssetEvidenceSignal:
    """Persist a signal for an asset."""
    signal = AssetEvidenceSignal(
        organization_id=asset.organization_id,
        asset_id=asset.id,
        kind=kind,
        payload_json=payload,
        observed_at=observed_at or utcnow(),
        confidence=confidence,
        risk_score=risk_score,
    )
    db.add(signal)
    return signal


def evaluate_control_coverage(
    db: Session,
    organization_id: int,
    *,
    persist: bool = True,
) -> list[ControlEvidence]:
    """Evaluate control coverage from signals/findings."""
    controls = db.execute(select(Control)).scalars().all()
    control_by_id = {ctrl.id: ctrl for ctrl in controls}
    mappings = db.execute(select(ControlMapping)).scalars().all()
    signals = db.execute(
        select(AssetEvidenceSignal).where(AssetEvidenceSignal.organization_id == organization_id)
    ).scalars().all()
    findings = db.execute(
        select(AssetFinding).where(
            AssetFinding.organization_id == organization_id,
            AssetFinding.status != AssetFindingStatus.RESOLVED,
        )
    ).scalars().all()
    assets = {
        asset.id: asset
        for asset in db.execute(select(Asset).where(Asset.organization_id == organization_id)).scalars().all()
    }

    evidences: list[ControlEvidence] = []

    for mapping in mappings:
        control = control_by_id.get(mapping.control_id)
        if not control:
            continue
        # Evaluate across assets of the mapped type
        relevant_assets = [a for a in assets.values() if a.type == mapping.asset_type]
        if not relevant_assets:
            continue
        for asset in relevant_assets:
            asset_signals = [
                s for s in signals if s.asset_id == asset.id and s.kind == mapping.signal_kind
            ]
            has_signal = any(s.confidence is None or s.confidence >= mapping.min_confidence for s in asset_signals)
            asset_findings = [f for f in findings if f.asset_id == asset.id]
            evidence_refs: list[str] = []
            if asset_signals:
                evidence_refs.extend([f"signal:{s.id}" for s in asset_signals])
            if asset_findings:
                evidence_refs.extend([f"finding:{f.id}" for f in asset_findings])

            if has_signal and not asset_findings:
                status = ControlCoverageStatus.COVERED
                confidence = max((s.confidence or 0.0 for s in asset_signals), default=0.0)
            elif asset_signals and asset_findings:
                status = ControlCoverageStatus.PARTIALLY_COVERED
                confidence = min(max((s.confidence or 0.0 for s in asset_signals), default=0.0), 1.0)
            else:
                status = ControlCoverageStatus.NOT_COVERED
                confidence = 0.0

            evidence = None
            if persist:
                evidence = (
                    db.execute(
                        select(ControlEvidence).where(
                            ControlEvidence.organization_id == organization_id,
                            ControlEvidence.control_id == control.id,
                            ControlEvidence.asset_id == asset.id,
                        )
                    )
                    .scalars()
                    .first()
                )
            if not evidence:
                evidence = ControlEvidence(
                    organization_id=organization_id,
                    control_id=control.id,
                    asset_id=asset.id,
                    status=status,
                    confidence=confidence,
                    evidence_refs=evidence_refs,
                    last_evaluated_at=utcnow(),
                )
                if persist:
                    db.add(evidence)
            elif persist:
                evidence.status = status
                evidence.confidence = confidence
                evidence.evidence_refs = evidence_refs
                evidence.last_evaluated_at = utcnow()
            evidences.append(evidence)
    if persist:
        db.commit()
    return evidences


def create_share_link(db: Session, organization_id: int, scope: dict | None, hours_valid: int) -> ControlShareLink:
    """Create a share token for audit exports."""
    token = secrets.token_urlsafe(24)
    link = ControlShareLink(
        organization_id=organization_id,
        token=token,
        scope=scope or {},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=hours_valid),
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return link


def list_active_share_link(db: Session, token: str) -> ControlShareLink | None:
    """Return an active share link if valid."""
    link = (
        db.execute(select(ControlShareLink).where(ControlShareLink.token == token))
        .scalars()
        .first()
    )
    if not link or not link.is_active():
        return None
    return link
