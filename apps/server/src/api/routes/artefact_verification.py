"""CA-08.6 (#294) — the verification surface, read by a person.

Its own router rather than more endpoints on ``artefact_review.py``: reviewing
what the organisation owns and reading what deep verification established are
different questions with different readers, and adding this file touches no
existing route.

**Read access, not decision authority.** Seeing what was verified is diagnostic
— the same class as reading discovery results, which every active org member may
already do. Nothing here changes anything, so it does not carry
``MANAGER_ROLES``: requiring a manager to *look* would mean the people who
operate the estate cannot see whether their own artefacts were examined.

Everything leaving here has been through CA-07.6's ``redact`` inside
``view_as_dict``. That happens in the service rather than the route so a second
caller — the BFF, an export, a future digest — cannot acquire the unredacted
shape by going around this endpoint.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.database import get_db
from src.core.exceptions import ValidationError
from src.core.model_defs.assets_runtime import Asset
from src.core.services.verification_surface_service import (
    build_artefact_verification_view,
    view_as_dict,
)

router = APIRouter(prefix="/api/v1/artefacts", tags=["Artefact verification"])


@router.get("/{asset_id}/verification")
def get_artefact_verification_route(
    asset_id: int,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> dict:
    """What was verified on this artefact, when, under whose approval, and what it found."""
    # The artefact is confirmed to belong to this organisation before anything
    # is read about it. Without this an id from another tenant would return an
    # empty-but-valid view, which discloses that the id exists.
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.organization_id == ctx.organization_id)
        .first()
    )
    if asset is None:
        raise ValidationError("No such artefact")

    view = build_artefact_verification_view(
        db, organization_id=ctx.organization_id, asset_id=asset_id
    )
    payload = view_as_dict(view)
    # The name a person currently sees, so the surface can say "discovery called
    # it this; verification established that" without a second request.
    payload["display_name"] = asset.display_name
    return payload
