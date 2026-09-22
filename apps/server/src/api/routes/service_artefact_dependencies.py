"""Human-confirmed reusable Artefact links for Business Services (#493)."""

from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.routes.bundle_common import get_service, require_service_process_editor
from src.core.constants.artefact_identity_enums import ARTEFACT_AUDIT_SERVICE_LINKED
from src.core.database import get_db
from src.core.exceptions import ResourceNotFoundError, ValidationError
from src.core.model_defs.assets_runtime import Asset, AssetLifecycleState
from src.core.models import AuditEvent, ServiceArtefactDependencyLink, SlotInstance

router = APIRouter(prefix="/api/v1/services", tags=["Service Artefact dependencies"])


class LinkServiceArtefactRequest(BaseModel):
    asset_id: int


class ServiceArtefactLinkResponse(BaseModel):
    id: str
    asset_id: int
    dependency_category: str
    origin: str


@router.get("/{service_id}/artefact-dependencies", response_model=list[ServiceArtefactLinkResponse])
def list_service_artefacts(service_id: str, ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db)) -> list[ServiceArtefactLinkResponse]:
    """Return the confirmed library Artefacts already linked to this service."""
    get_service(service_id, ctx.organization_id, db)
    links = db.query(ServiceArtefactDependencyLink).filter(
        ServiceArtefactDependencyLink.organization_id == ctx.organization_id,
        ServiceArtefactDependencyLink.service_id == service_id,
    ).order_by(ServiceArtefactDependencyLink.linked_at.asc()).all()
    responses = [
        ServiceArtefactLinkResponse(
            id=link.id,
            asset_id=link.asset_id,
            dependency_category=link.dependency_category,
            origin="library",
        )
        for link in links
    ]
    # #493 must not hide a service's existing human slot decisions during the
    # library transition. They remain slot facts, rather than being promoted to
    # a library category; the response calls their origin out accordingly.
    seen = {(link.asset_id, link.dependency_category) for link in links}
    legacy_slots = db.query(SlotInstance).filter(
        SlotInstance.organization_id == ctx.organization_id,
        SlotInstance.service_id == service_id,
        SlotInstance.status == "mapped",
        SlotInstance.dependency_category.isnot(None),
    ).all()
    for slot in legacy_slots:
        asset_id = str(slot.asset_id or "").removeprefix("asset-")
        if not asset_id.isdigit():
            continue
        key = (int(asset_id), slot.dependency_category)
        if key in seen:
            continue
        seen.add(key)
        responses.append(
            ServiceArtefactLinkResponse(
                id=f"legacy-slot:{slot.id}",
                asset_id=key[0],
                dependency_category=key[1],
                origin="legacy_slot",
            )
        )
    return responses


@router.post("/{service_id}/artefact-dependencies", response_model=ServiceArtefactLinkResponse)
def link_service_artefact(service_id: str, payload: LinkServiceArtefactRequest,
    ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)) -> ServiceArtefactLinkResponse:
    """Link an existing verified library Artefact; never create or infer one."""
    service = get_service(service_id, ctx.organization_id, db)
    require_service_process_editor(service, organization_id=ctx.organization_id, actor_user_id=ctx.user_id, db=db)
    asset = db.query(Asset).filter(Asset.id == payload.asset_id, Asset.organization_id == ctx.organization_id).first()
    if asset is None:
        raise ResourceNotFoundError("That artefact does not exist in this organisation.")
    if asset.lifecycle_state != AssetLifecycleState.ACTIVE or asset.reviewed_at is None or not asset.dependency_category:
        raise ValidationError("Only confirmed, active, category-labelled library artefacts can be linked.")
    link = db.query(ServiceArtefactDependencyLink).filter(
        ServiceArtefactDependencyLink.organization_id == ctx.organization_id,
        ServiceArtefactDependencyLink.service_id == service_id,
        ServiceArtefactDependencyLink.asset_id == asset.id,
    ).first()
    if link is None:
        link = ServiceArtefactDependencyLink(id=str(uuid4()), organization_id=ctx.organization_id,
            service_id=service_id, asset_id=asset.id, dependency_category=asset.dependency_category,
            linked_by_user_id=ctx.user_id)
        db.add(link)
        db.add(AuditEvent(organization_id=ctx.organization_id, actor_user_id=ctx.user_id,
            event_type=ARTEFACT_AUDIT_SERVICE_LINKED,
            metadata_json={"assetId": asset.id, "serviceId": service_id, "dependencyCategory": asset.dependency_category}))
        db.commit()
    return ServiceArtefactLinkResponse(
        id=link.id,
        asset_id=link.asset_id,
        dependency_category=link.dependency_category,
        origin="library",
    )
