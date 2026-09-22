"""Decision Layer — Per-asset risk appetite endpoints.

GET  /api/v1/assets/{asset_id}/appetite  — fetch appetite config for an asset
POST /api/v1/assets/{asset_id}/appetite  — save/update appetite config (upsert)
GET  /api/v1/appetite                    — org-wide list of all configured appetites
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.database import get_db
from src.core.logging_config import get_logger
from src.core.models import Asset, AssetAppetiteConfig
from src.api.schemas.timestamps import UtcTimestamp

logger = get_logger(__name__)

router = APIRouter(tags=["Risk Appetite"])


# ─── SCHEMAS ──────────────────────────────────────────────────────────────────

class AppetiteAnswersSchema(BaseModel):
    dataLoss: int = Field(..., ge=0, le=4)
    downtime: int = Field(..., ge=0, le=4)
    regulatory: int = Field(..., ge=0, le=4)
    financial: int = Field(..., ge=0, le=4)
    reputational: int = Field(..., ge=0, le=4)
    security: int = Field(..., ge=0, le=4)


class SaveAppetiteRequest(BaseModel):
    answers: AppetiteAnswersSchema
    approved_by: str = Field(..., min_length=1, max_length=255)
    note: str = ""


class AppetiteHistoryItem(BaseModel):
    version: int
    approvedBy: str
    timestamp: str
    note: str
    answers: dict[str, int]


class AppetiteConfigResponse(BaseModel):
    assetId: str         # "asset-{id}" — matches frontend convention
    assetName: str
    tier: str
    configured: bool
    appetite: Optional[dict[str, int]]
    approvedBy: Optional[str]
    approvedAt: Optional[UtcTimestamp]
    version: int
    note: str
    history: list[AppetiteHistoryItem]


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _get_asset_for_org(asset_id: int, org_id: int, db: Session) -> Asset:
    asset = db.get(Asset, asset_id)
    if not asset or asset.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


def _layer_to_tier(layer: str) -> str:
    """Map backend layer strings to decision-layer tier labels.

    Mirrors the layerToLevel() logic in useAssets.ts so that tier labels
    are consistent between the API response and the frontend mapper.
    """
    l = layer.lower()
    if l in ("application", "l1"):
        return "mission-critical"   # L1 assets treated as mission-critical by default
    if l in ("data", "transfer", "identity", "l2"):
        return "business-critical"
    return "operational"


def _build_response(config: AssetAppetiteConfig, asset: Asset) -> AppetiteConfigResponse:
    history = _build_history_items(config.history or [])
    return AppetiteConfigResponse(
        assetId=f"asset-{asset.id}",
        assetName=asset.display_name,
        tier=_layer_to_tier(asset.layer),
        configured=True,
        appetite=config.answers or None,
        approvedBy=config.approved_by,
        # Keep the response field as the canonical timestamp declared by the
        # schema. Human-readable formatting belongs to the client display
        # layer; sending it here makes Pydantic reject the response.
        approvedAt=config.approved_at,
        version=config.version,
        note=config.note or "",
        history=history,
    )


def _build_history_items(entries: list[dict]) -> list[AppetiteHistoryItem]:
    return [
        AppetiteHistoryItem(
            version=entry["version"],
            approvedBy=entry["approvedBy"],
            timestamp=entry["timestamp"],
            note=entry.get("note", ""),
            answers=entry.get("answers", {}),
        )
        for entry in entries
    ]


# ─── ROUTES ───────────────────────────────────────────────────────────────────

@router.get("/api/v1/assets/{asset_id}/appetite", response_model=AppetiteConfigResponse)
def get_asset_appetite(
    asset_id: int,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetiteConfigResponse:
    """Return the current risk appetite config for an asset, or a shell if not yet configured."""
    asset = _get_asset_for_org(asset_id, ctx.organization_id, db)
    config = (
        db.query(AssetAppetiteConfig)
        .filter(
            AssetAppetiteConfig.organization_id == ctx.organization_id,
            AssetAppetiteConfig.asset_id == asset_id,
        )
        .first()
    )
    if not config:
        return AppetiteConfigResponse(
            assetId=f"asset-{asset.id}",
            assetName=asset.display_name,
            tier=_layer_to_tier(asset.layer),
            configured=False,
            appetite=None,
            approvedBy=None,
            approvedAt=None,
            version=0,
            note="",
            history=[],
        )
    return _build_response(config, asset)


@router.post(
    "/api/v1/assets/{asset_id}/appetite",
    response_model=AppetiteConfigResponse,
    status_code=status.HTTP_200_OK,
)
def save_asset_appetite(
    asset_id: int,
    body: SaveAppetiteRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AppetiteConfigResponse:
    """Upsert risk appetite config for an asset.

    If a config already exists, the current values are pushed into history
    before being overwritten. Version is incremented on each update.
    """
    asset = _get_asset_for_org(asset_id, ctx.organization_id, db)
    now = datetime.now(timezone.utc)
    answers_dict = body.answers.model_dump()

    config = (
        db.query(AssetAppetiteConfig)
        .filter(
            AssetAppetiteConfig.organization_id == ctx.organization_id,
            AssetAppetiteConfig.asset_id == asset_id,
        )
        .first()
    )

    if config:
        # Push current state into history before overwriting
        history_entry = {
            "version": config.version,
            "approvedBy": config.approved_by,
            "timestamp": config.approved_at.strftime("%d %b %Y") if config.approved_at else "",
            "note": config.note or "",
            "answers": config.answers or {},
        }
        config.history = [*config.history, history_entry]
        config.answers = answers_dict
        config.approved_by = body.approved_by
        config.approved_at = now
        config.version += 1
        config.note = body.note
        config.updated_at = now
    else:
        config = AssetAppetiteConfig(
            organization_id=ctx.organization_id,
            asset_id=asset_id,
            answers=answers_dict,
            approved_by=body.approved_by,
            approved_at=now,
            version=1,
            note=body.note,
            history=[],
            created_at=now,
            updated_at=now,
        )
        db.add(config)

    db.commit()
    db.refresh(config)
    logger.info(
        "asset_appetite_saved",
        org_id=ctx.organization_id,
        asset_id=asset_id,
        version=config.version,
    )
    return _build_response(config, asset)


@router.get("/api/v1/assets/{asset_id}/appetite/history", response_model=list[AppetiteHistoryItem])
def get_asset_appetite_history(
    asset_id: int,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[AppetiteHistoryItem]:
    """Return historical appetite versions for a configured asset."""
    _get_asset_for_org(asset_id, ctx.organization_id, db)
    config = (
        db.query(AssetAppetiteConfig)
        .filter(
            AssetAppetiteConfig.organization_id == ctx.organization_id,
            AssetAppetiteConfig.asset_id == asset_id,
        )
        .first()
    )
    if not config:
        return []
    return _build_history_items(config.history or [])


@router.get("/api/v1/appetite", response_model=list[AppetiteConfigResponse])
def list_appetite_configs(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[AppetiteConfigResponse]:
    """Return all configured risk appetite records for the authenticated organisation."""
    configs = (
        db.query(AssetAppetiteConfig)
        .filter(AssetAppetiteConfig.organization_id == ctx.organization_id)
        .all()
    )
    results = []
    for config in configs:
        asset = db.get(Asset, config.asset_id)
        if asset and asset.organization_id == ctx.organization_id:
            results.append(_build_response(config, asset))
    logger.info("appetite_listed", org_id=ctx.organization_id, count=len(results))
    return results
