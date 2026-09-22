"""Asset-centric onboarding and monitoring endpoints (UC-01/UC-02)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from src.core.services.evidence_refresh_service import refresh_org_evidence
from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.schemas.assets import (
    CompleteAccessSetupRequest,
    CreateAssetRequest,
    CreateAssetResponse,
    VerifyConnectionResponse,
)
from src.core.constants import (
    AssetArchetype,
    Provider,
)
from src.core.services.asset_schema import (
    get_archetype_schemas_for_layer,
    get_layer_label_and_description,
)
from src.asset_monitoring.engine import AssetMonitoringEngine
from src.asset_monitoring.service import (
    connect_asset,
    create_network_findings,
    disconnect_asset,
    ensure_seed_org,
    evaluate_control_coverage,
    record_status,
    seed_assets,
)
from src.core.database import get_db
from src.core.logging_config import get_logger
from src.core.services.assets_service import (
    PayloadValidationError,
    complete_access_setup,
    create_asset_with_connection,
    notify_setup_assignee,
    start_monitoring as start_monitoring_service,
    verify_connection,
)
from src.core.services.asset_context_service import build_asset_business_context
from src.core.models import (
    Asset,
    AssetEvidenceSignal,
    AssetFinding,
    AssetFindingStatus,
    AssetStatus,
    AssetStatusHistory,
    BusinessService,
    ConnectivityStatus,
    Control,
    ControlCoverageStatus,
    ControlEvidence,
    ControlShareLink,
    Organization,
    SlotInstance,
    ValueStream,
)
from src.api.schemas.timestamps import UtcTimestamp

logger = get_logger(__name__)

HELP_URL = "https://docs.risklence.com/asset-onboarding"

router = APIRouter(tags=["Assets"])


def get_monitoring_engine(request: Request) -> AssetMonitoringEngine | None:
    """Fetch monitoring engine from app state if configured."""
    return getattr(request.app.state, "monitoring_engine", None)


class OrganizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    region: str | None = None
    industry: str | None = None
    created_at: UtcTimestamp


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    type: str
    provider: str | None = None
    provider_display_name: str | None = None
    display_name: str
    layer: str
    status: AssetStatus
    observation_level: str | None = None
    last_observed_at: UtcTimestamp | None = None
    risk_score: float
    findings_count: int
    confidence: float
    connectivity_status: ConnectivityStatus | None = None
    created_at: UtcTimestamp
    updated_at: UtcTimestamp
    environment: str | None = None
    criticality: str | None = None
    level: int | None = None
    is_spof: bool = False
    setup_confidence: str | None = None
    scan_start_mode: str | None = None
    secondary_layers: list[int] | None = None
    intent: dict | list | None = None
    business_owner_ref: str | None = None
    technical_owner_ref: str | None = None
    setup_assignee_ref: str | None = None
    created_by_ref: str | None = None


class ConnectPayload(BaseModel):
    provider: str | None = None
    auth_type: str | None = "mock"
    scopes: list[str] | None = None
    external_account_id: str | None = None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    domain: str
    severity: str
    title: str
    description: str | None = None
    evidence_refs: list[str] | None = None
    risk_score: float | None = None
    first_seen_at: UtcTimestamp
    last_seen_at: UtcTimestamp
    status: AssetFindingStatus


class SignalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    kind: str
    payload_json: dict
    observed_at: UtcTimestamp
    confidence: float | None = None
    risk_score: float | None = None


class OrgSignalOut(BaseModel):
    id: int
    asset_id: int
    asset_name: str
    asset_type: str
    kind: str
    payload_json: dict
    observed_at: UtcTimestamp
    confidence: float | None = None
    risk_score: float | None = None


class StatusHistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    status: AssetStatus
    risk_score: float | None = None
    observation_level: str | None = None
    findings_count: int | None = None
    confidence: float | None = None
    observed_at: UtcTimestamp


class ControlEvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    control_id: int
    organization_id: int
    asset_id: int
    status: ControlCoverageStatus
    confidence: float | None = None
    last_evaluated_at: UtcTimestamp
    evidence_refs: list[str] | None = None


class ShareLinkOut(BaseModel):
    token: str
    expires_at: UtcTimestamp
    scope: dict | None = None


class ArchetypeField(BaseModel):
    name: str
    label: str
    required: bool
    placeholder: str | None = None
    helper_text: str | None = None
    validation_hint: str | None = None
    example: str | None = None
    field_type: str


class ArchetypeSchema(BaseModel):
    archetype: AssetArchetype
    label: str
    description: str
    providers: list[str]
    provider_other_requires_name: bool = True
    fields: list[ArchetypeField]
    defaults: dict[str, str | list[str]]
    connection_requirements: list[str]
    optional_secondary_layers: list[str] | None = None


class LayerSchemaResponse(BaseModel):
    layer: str
    label: str
    description: str
    archetypes: list[ArchetypeSchema]


@router.get("/org/current", response_model=OrganizationOut)
def get_current_org(
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> Organization:
    """Return the current organization; seed a default one if none exist."""
    org = ensure_seed_org(db)
    return OrganizationOut(
        id=org.id,
        name=org.name,
        region=org.country,
        industry=org.industry,
        created_at=org.created_at,
    )


@router.get("/assets", response_model=list[AssetOut])
def list_assets(
    org_id: Optional[int] = None,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> List[Asset]:
    """List assets for the tenant without auto-seeding demo fixtures."""
    org = ensure_seed_org(db)
    target_org = _resolve_scoped_org_id(org_id, tenant, fallback_org_id=org.id)
    assets = db.execute(select(Asset).where(Asset.organization_id == target_org)).scalars().all()
    return assets


@router.get("/assets/signals", response_model=list[OrgSignalOut])
def list_org_signals(
    org_id: Optional[int] = None,
    since: Optional[datetime] = None,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> list[OrgSignalOut]:
    """List evidence signals across all assets in the tenant org."""
    organization_id = _resolve_scoped_org_id(org_id, tenant)
    query = (
        select(AssetEvidenceSignal)
        .options(joinedload(AssetEvidenceSignal.asset))
        .where(AssetEvidenceSignal.organization_id == organization_id)
    )
    if since:
        query = query.where(AssetEvidenceSignal.observed_at >= since)
    signals = (
        db.execute(query.order_by(AssetEvidenceSignal.observed_at.desc()))
        .scalars()
        .all()
    )
    return [
        OrgSignalOut(
            id=signal.id,
            asset_id=signal.asset_id,
            asset_name=signal.asset.display_name if signal.asset else f"Asset {signal.asset_id}",
            asset_type=signal.asset.type if signal.asset else "Asset",
            kind=signal.kind,
            payload_json=signal.payload_json,
            observed_at=signal.observed_at,
            confidence=signal.confidence,
            risk_score=signal.risk_score,
        )
        for signal in signals
    ]


# ---------- UC-01/UC-02: AWS onboarding ----------


def _ensure_org_access(org_id: int, tenant: TenantContext) -> None:
    if tenant.organization_id and tenant.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Organization mismatch")


def _resolve_scoped_org_id(
    requested_org_id: int | None,
    tenant: TenantContext,
    *,
    fallback_org_id: int | None = None,
) -> int:
    """Resolve org from session context and reject horizontal org overrides."""
    if requested_org_id is not None:
        _ensure_org_access(requested_org_id, tenant)
        return requested_org_id
    if tenant.organization_id is not None:
        return tenant.organization_id
    if fallback_org_id is not None:
        return fallback_org_id
    raise HTTPException(status_code=400, detail="Organization context missing")


def _get_asset_or_404(db: Session, asset_id: int, org_id: int) -> Asset:
    asset = db.get(Asset, asset_id)
    if not asset or asset.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.get("/orgs/{org_id}/assets", response_model=list[AssetOut])
def list_assets_for_org(
    org_id: int,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
):
    """List all assets for the given organization."""
    _ensure_org_access(org_id, tenant)
    # Seed demo assets if this is the first request
    seed_assets(db, org_id)
    assets = db.execute(select(Asset).where(Asset.organization_id == org_id).order_by(Asset.created_at.desc())).scalars().all()
    return assets


@router.post("/orgs/{org_id}/assets", response_model=CreateAssetResponse)
def create_asset_endpoint(
    org_id: int,
    payload: CreateAssetRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
):
    """Create an asset in pending verification with initial connection metadata."""
    _ensure_org_access(org_id, tenant)
    try:
        asset, connection, setup_url = create_asset_with_connection(
            db, org_id, tenant.email, payload
        )
    except PayloadValidationError as exc:
        detail = {
            "message": "Validation failed",
            "field_errors": exc.field_errors,
            "request_id": str(uuid.uuid4()),
            "help_url": HELP_URL,
        }
        raise HTTPException(status_code=422, detail=detail)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"message": str(exc)})
    notify_setup_assignee(asset, asset.setup_assignee_ref or asset.technical_owner_ref)
    # BSP-14 — new evidence arrived: refresh engine suggestions in the background.
    background_tasks.add_task(refresh_org_evidence, org_id)
    return CreateAssetResponse(
        asset_id=asset.id,
        connectivity_status=asset.connectivity_status,
        external_id=connection.external_id or "",
        complete_setup_url=setup_url,
    )


# ---------- Schema metadata for OSI layer → archetype → provider ----------
# IMPORTANT: This route must come BEFORE /orgs/{org_id}/assets/{asset_id}
# to avoid FastAPI matching "schema" as an asset_id parameter

@router.get(
    "/orgs/{org_id}/assets/schema",
    response_model=LayerSchemaResponse,
    summary="Dynamic schema for OSI layer/archetype/provider",
)
def get_asset_schema(
    org_id: int,
    primary_layer: str,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
):
    """Return metadata for the selected layer, its archetypes, and field specs."""
    _ensure_org_access(org_id, tenant)
    layer_label_desc = get_layer_label_and_description(primary_layer)
    if not layer_label_desc:
        raise HTTPException(status_code=400, detail="Unknown primary_layer")

    archetype_schemas = get_archetype_schemas_for_layer(primary_layer)
    if not archetype_schemas:
        raise HTTPException(status_code=400, detail="No archetypes for this layer")

    return LayerSchemaResponse(
        layer=primary_layer,
        label=layer_label_desc[0],
        description=layer_label_desc[1],
        archetypes=archetype_schemas,
    )


@router.get("/orgs/{org_id}/assets/{asset_id}")
def get_asset_with_org(
    org_id: int,
    asset_id: int,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
):
    _ensure_org_access(org_id, tenant)
    return _get_asset_or_404(db, asset_id, org_id)


@router.post("/orgs/{org_id}/assets/{asset_id}/complete-setup")
def complete_setup_endpoint(
    org_id: int,
    asset_id: int,
    payload: CompleteAccessSetupRequest,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
):
    _ensure_org_access(org_id, tenant)
    asset = _get_asset_or_404(db, asset_id, org_id)
    connection = complete_access_setup(db, asset, payload.role_arn, tenant.email)
    response = {
        "connection_state": connection.connection_state,
        "role_arn": connection.role_arn,
    }
    if asset.provider != Provider.AWS.value:
        response["message"] = "Adapter not available yet for this provider. We will keep the asset pending verification."
    return response


@router.post("/orgs/{org_id}/assets/{asset_id}/verify-connection", response_model=VerifyConnectionResponse)
def verify_connection_endpoint(
    org_id: int,
    asset_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
):
    _ensure_org_access(org_id, tenant)
    asset = _get_asset_or_404(db, asset_id, org_id)
    success, connection, signal, diagnostic = verify_connection(db, asset, diagnostic_on_failure=True)
    if success:
        # BSP-14 — a verified connection strengthens evidence (+0.1 confidence boost).
        background_tasks.add_task(refresh_org_evidence, org_id)
    return VerifyConnectionResponse(
        success=success,
        connectivity_status=asset.connectivity_status,
        connection_state=connection.connection_state,
        diagnostic=diagnostic,
    )


@router.get("/orgs/{org_id}/assets/{asset_id}/setup-instructions")
def get_setup_instructions(
    org_id: int,
    asset_id: int,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
):
    _ensure_org_access(org_id, tenant)
    asset = _get_asset_or_404(db, asset_id, org_id)
    connection = asset.connections[0] if asset.connections else None
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")
    return {
        "external_id": connection.external_id,
        "connection_state": connection.connection_state,
        "permission_preset": connection.permission_preset,
        "templates": {
            "cloudformation": "https://example.com/cfn-template",
            "terraform": "https://example.com/terraform-module",
        },
    }


@router.post("/orgs/{org_id}/assets/{asset_id}/start-monitoring")
def start_monitoring_endpoint(
    org_id: int,
    asset_id: int,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
):
    _ensure_org_access(org_id, tenant)
    asset = _get_asset_or_404(db, asset_id, org_id)
    started = start_monitoring_service(db, asset)
    return {"started": started}


@router.get("/assets/{asset_id}", response_model=AssetOut)
def get_asset_detail(
    asset_id: int,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> Asset:
    """Get a single asset."""
    asset = db.get(Asset, asset_id)
    if not asset or asset.organization_id != tenant.organization_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


# ─── EUC-10 — asset cross-service context ────────────────────────────────────


class AssetLinkedServiceOut(BaseModel):
    serviceId: str
    serviceName: str
    serviceTier: str
    financialExposure: str | None
    role: str  # "l1" | "l2" | "l3" | "slot_mapped"


class AssetLinkedProcessOut(BaseModel):
    processId: str
    processName: str


class AssetLinkedDependencyOut(BaseModel):
    dependencyId: str
    patternKey: str | None
    label: str | None
    serviceId: str
    serviceName: str


class AssetBlastRadiusOut(BaseModel):
    serviceCount: int
    totalExposure: float
    missionCriticalCount: int
    hasFinancialExposure: bool


class AssetContextOut(BaseModel):
    assetId: int
    displayName: str
    assetType: str | None
    isSpof: bool
    riskScore: float
    findingsCount: int
    crownJewelCandidate: bool
    linkedDependencies: list[AssetLinkedDependencyOut]
    linkedServices: list[AssetLinkedServiceOut]
    linkedProcesses: list[AssetLinkedProcessOut]
    blastRadius: AssetBlastRadiusOut


@router.get("/assets/{asset_id}/context", response_model=AssetContextOut)
def get_asset_context(
    asset_id: int,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> AssetContextOut:
    """EUC-10 — cross-service blast radius and linked process context for an asset."""
    asset = db.get(Asset, asset_id)
    if not asset or asset.organization_id != tenant.organization_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    context = build_asset_business_context(asset, tenant.organization_id, db)

    return AssetContextOut(
        assetId=context.asset_id,
        displayName=context.display_name,
        assetType=context.asset_type,
        isSpof=context.is_spof,
        riskScore=context.risk_score,
        findingsCount=context.findings_count,
        crownJewelCandidate=context.crown_jewel_candidate,
        linkedDependencies=[
            AssetLinkedDependencyOut(
                dependencyId=dependency.dependency_id,
                patternKey=dependency.pattern_key,
                label=dependency.label,
                serviceId=dependency.service_id,
                serviceName=dependency.service_name,
            )
            for dependency in context.linked_dependencies
        ],
        linkedServices=[
            AssetLinkedServiceOut(
                serviceId=service.service_id,
                serviceName=service.service_name,
                serviceTier=service.service_tier,
                financialExposure=service.financial_exposure,
                role=service.role,
            )
            for service in context.linked_services
        ],
        linkedProcesses=[
            AssetLinkedProcessOut(
                processId=process.process_id,
                processName=process.process_name,
            )
            for process in context.linked_processes
        ],
        blastRadius=AssetBlastRadiusOut(
            serviceCount=context.blast_radius.service_count,
            totalExposure=context.blast_radius.total_exposure,
            missionCriticalCount=context.blast_radius.mission_critical_count,
            hasFinancialExposure=context.blast_radius.has_financial_exposure,
        ),
    )


@router.post("/assets/{asset_id}/connect", response_model=AssetOut)
def connect_asset_endpoint(
    asset_id: int,
    payload: ConnectPayload,
    request: Request,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> Asset:
    """Connect an asset and trigger monitoring."""
    asset = db.get(Asset, asset_id)
    if not asset or asset.organization_id != tenant.organization_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset = connect_asset(
        db,
        asset_id,
        auth_type=payload.auth_type,
        scopes=payload.scopes,
        external_account_id=payload.external_account_id,
    )
    engine = get_monitoring_engine(request)
    if engine:
        engine.enqueue_initial_observation(asset.id)
    else:
        # Fallback immediate observation
        target_status = AssetStatus.OPERATIONALLY_COMPLIANT
        if asset.layer.lower() == "network":
            create_network_findings(db, asset)
            target_status = AssetStatus.AT_RISK
        record_status(
            db,
            asset,
            target_status,
            risk_score=80.0 if target_status == AssetStatus.AT_RISK else 10.0,
            observation_level="enhanced",
            findings_count=asset.findings_count,
            confidence=0.9,
        )
        db.commit()
    return asset


@router.post("/assets/{asset_id}/disconnect", response_model=AssetOut)
def disconnect_asset_endpoint(
    asset_id: int,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> Asset:
    """Disconnect an asset."""
    asset = db.get(Asset, asset_id)
    if not asset or asset.organization_id != tenant.organization_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset = disconnect_asset(db, asset_id)
    return asset


@router.delete("/assets/{asset_id}", status_code=204)
def delete_asset_endpoint(
    asset_id: int,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
):
    """Delete an asset owned by the tenant organization."""
    asset = db.get(Asset, asset_id)
    if not asset or asset.organization_id != tenant.organization_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()
    return None


class PatchAssetRequest(BaseModel):
    display_name: Optional[str] = Field(None, min_length=1, max_length=200)
    business_owner_ref: Optional[str] = Field(None, max_length=255)
    technical_owner_ref: Optional[str] = Field(None, max_length=255)
    level: Optional[int] = Field(None, ge=1, le=3)
    is_spof: Optional[bool] = None
    criticality: Optional[str] = Field(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")


@router.patch("/assets/{asset_id}", response_model=AssetOut)
def patch_asset(
    asset_id: int,
    body: PatchAssetRequest,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> Asset:
    """Update editable fields on an asset (display name, owner, level, is_spof, criticality)."""
    asset = db.get(Asset, asset_id)
    if not asset or asset.organization_id != tenant.organization_id:
        raise HTTPException(status_code=404, detail="Asset not found")

    if body.display_name is not None:
        asset.display_name = body.display_name
    if body.business_owner_ref is not None:
        asset.business_owner_ref = body.business_owner_ref
    if body.technical_owner_ref is not None:
        asset.technical_owner_ref = body.technical_owner_ref
    if body.level is not None:
        asset.level = body.level
    if body.is_spof is not None:
        asset.is_spof = body.is_spof
    if body.criticality is not None:
        asset.criticality = body.criticality

    db.commit()
    db.refresh(asset)
    return asset


@router.get("/assets/{asset_id}/findings", response_model=list[FindingOut])
def list_asset_findings(
    asset_id: int,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> List[AssetFinding]:
    """List findings for an asset."""
    asset = db.get(Asset, asset_id)
    if not asset or asset.organization_id != tenant.organization_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    findings = (
        db.execute(select(AssetFinding).where(AssetFinding.asset_id == asset_id))
        .scalars()
        .all()
    )
    return findings


@router.get("/assets/{asset_id}/signals", response_model=list[SignalOut])
def list_signals(
    asset_id: int,
    since: Optional[datetime] = None,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> List[AssetEvidenceSignal]:
    """List evidence signals for an asset."""
    asset = db.get(Asset, asset_id)
    if not asset or asset.organization_id != tenant.organization_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    query = select(AssetEvidenceSignal).where(AssetEvidenceSignal.asset_id == asset_id)
    if since:
        query = query.where(AssetEvidenceSignal.observed_at >= since)
    signals = db.execute(query.order_by(AssetEvidenceSignal.observed_at.desc())).scalars().all()
    return signals


@router.get("/assets/{asset_id}/status-history", response_model=list[StatusHistoryOut])
def get_status_history(
    asset_id: int,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> List[AssetStatusHistory]:
    """Return status history entries."""
    asset = db.get(Asset, asset_id)
    if not asset or asset.organization_id != tenant.organization_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    history = (
        db.execute(
            select(AssetStatusHistory)
            .where(AssetStatusHistory.asset_id == asset_id)
            .order_by(AssetStatusHistory.observed_at.desc())
        )
        .scalars()
        .all()
    )
    return history


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    org_id: Optional[int] = None,
    status: str = "open",
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> List[AssetFinding]:
    """Global findings feed for the organization."""
    org = _resolve_scoped_org_id(org_id, tenant)
    query = select(AssetFinding).where(AssetFinding.organization_id == org)
    if status:
        try:
            status_enum = AssetFindingStatus(status)
            query = query.where(AssetFinding.status == status_enum)
        except ValueError:
            pass
    findings = db.execute(query.order_by(AssetFinding.last_seen_at.desc())).scalars().all()
    return findings


@router.get("/audit/controls", response_model=list[ControlEvidenceOut])
def audit_controls(
    org_id: Optional[int] = None,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> List[ControlEvidence]:
    """Return control evidences for the org."""
    organization_id = _resolve_scoped_org_id(org_id, tenant)
    evidences = evaluate_control_coverage(db, organization_id, persist=False)
    return evidences


class AuditOverview(BaseModel):
    coverage_percent: float
    gaps: int
    high_risk_controls: int
    last_evaluated: UtcTimestamp | None = None


class ControlDetailOut(BaseModel):
    control_id: int
    framework: str
    control_code: str
    title: str
    description: str | None = None
    evidences: list[ControlEvidenceOut]


@router.get("/audit/overview", response_model=AuditOverview)
def audit_overview(
    org_id: Optional[int] = None,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> AuditOverview:
    """Compute simple audit coverage metrics."""
    organization_id = _resolve_scoped_org_id(org_id, tenant)
    evidences = evaluate_control_coverage(db, organization_id, persist=False)
    total = len(evidences) or 1
    covered = len([e for e in evidences if e.status == ControlCoverageStatus.COVERED])
    high_risk = len(
        [e for e in evidences if e.status == ControlCoverageStatus.NOT_COVERED]
    )
    last_eval = max((e.last_evaluated_at for e in evidences), default=None)
    return AuditOverview(
        coverage_percent=round((covered / total) * 100, 2),
        gaps=total - covered,
        high_risk_controls=high_risk,
        last_evaluated=last_eval,
    )


@router.get("/audit/controls/{control_id}", response_model=ControlDetailOut)
def audit_control_detail(
    control_id: int,
    org_id: Optional[int] = None,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> ControlDetailOut:
    """Control drill-down with evidences."""
    organization_id = _resolve_scoped_org_id(org_id, tenant)
    control = db.get(Control, control_id)
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")
    evidences = [
        ev
        for ev in evaluate_control_coverage(db, organization_id, persist=False)
        if ev.control_id == control_id
    ]
    return ControlDetailOut(
        control_id=control.id,
        framework=control.framework,
        control_code=control.control_code,
        title=control.title,
        description=control.description,
        evidences=[ControlEvidenceOut.model_validate(ev) for ev in evidences],
    )


@router.post("/audit/export")
def audit_export(
    org_id: Optional[int] = None,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> JSONResponse:
    """Export audit bundle as JSON."""
    organization_id = _resolve_scoped_org_id(org_id, tenant)
    evidences = evaluate_control_coverage(db, organization_id, persist=False)
    controls = db.execute(select(Control)).scalars().all()
    assets = db.execute(select(Asset).where(Asset.organization_id == organization_id)).scalars().all()
    findings = db.execute(
        select(AssetFinding).where(
            AssetFinding.organization_id == organization_id,
            AssetFinding.status != AssetFindingStatus.RESOLVED,
        )
    ).scalars().all()
    payload = {
        "organization_id": organization_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "controls": [control.control_code for control in controls],
        "evidences": [ControlEvidenceOut.model_validate(ev).model_dump() for ev in evidences],
        "assets": [AssetOut.model_validate(asset).model_dump() for asset in assets],
        "findings": [FindingOut.model_validate(f).model_dump() for f in findings],
    }
    headers = {"Content-Disposition": 'attachment; filename="audit_export.json"'}
    return JSONResponse(content=payload, headers=headers)


class ShareLinkRequest(BaseModel):
    scope: dict | None = None
    hours_valid: int | None = None


@router.post("/audit/share-link", response_model=ShareLinkOut)
def create_share_link_endpoint(
    payload: ShareLinkRequest,
    org_id: Optional[int] = None,
    db: Session = Depends(get_db),
    tenant: TenantContext = Depends(get_tenant_context),
) -> ShareLinkOut:
    """Create a time-limited share link."""
    from src.asset_monitoring.service import create_share_link

    organization_id = _resolve_scoped_org_id(org_id, tenant)
    ttl_hours = payload.hours_valid or 24
    link = create_share_link(db, organization_id, payload.scope, hours_valid=ttl_hours)
    return ShareLinkOut(token=link.token, expires_at=link.expires_at, scope=link.scope)


# ---------- Schema metadata for OSI layer → archetype → provider ----------


@router.get("/audit/shared/{token}", response_model=AuditOverview)
def shared_audit_view(
    token: str,
    db: Session = Depends(get_db),
) -> AuditOverview:
    """Read-only audit overview for shared links."""
    from src.asset_monitoring.service import list_active_share_link

    link = list_active_share_link(db, token)
    if not link:
        raise HTTPException(status_code=404, detail="Share link expired or invalid")
    evidences = evaluate_control_coverage(db, link.organization_id, persist=False)
    total = len(evidences) or 1
    covered = len([e for e in evidences if e.status == ControlCoverageStatus.COVERED])
    high_risk = len([e for e in evidences if e.status == ControlCoverageStatus.NOT_COVERED])
    last_eval = max((e.last_evaluated_at for e in evidences), default=None)
    return AuditOverview(
        coverage_percent=round((covered / total) * 100, 2),
        gaps=total - covered,
        high_risk_controls=high_risk,
        last_evaluated=last_eval,
    )
