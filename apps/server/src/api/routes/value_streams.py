"""Value Stream endpoints.

GET    /api/v1/value-streams/library         — canonical library grouped by process family
GET    /api/v1/value-streams/infer           — NACE-based inference for the current org
GET    /api/v1/value-streams                 — list org value streams (with derived health)
POST   /api/v1/value-streams                 — create a value stream from library or custom
PUT    /api/v1/value-streams/{id}            — update priority or name
DELETE /api/v1/value-streams/{id}            — delete a value stream
POST   /api/v1/value-streams/profile         — save confirmed OrgValueStreamProfile (onboarding)

Every endpoint is tenant-scoped: organization_id comes from JWT via TenantContext.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.value_stream_events import ValueStreamEvent
from src.core.constants.service_key_archetypes import get_archetype_for_service_key, get_service_key_name
from src.core.constants.value_stream_library import (
    VALUE_STREAM_LIBRARY,
    VALUE_STREAM_BY_KEY,
    infer_value_streams_from_nace,
)
from src.core.database import get_db
from src.core.constants.service_model import SERVICE_TIER_BUSINESS_CRITICAL
from src.core.logging_config import get_logger
from src.core.models import BusinessService, OrgProcessConfig, Organization, ValueStream, ValueStreamSignal
from src.core.services.template_library_service import get_active_service_template
from src.api.schemas.timestamps import UtcTimestamp
from src.core.exceptions import AuthorizationError
from src.core.services.process_ownership_service import (
    ProcessOwnershipValidationError,
    require_process_editor,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/value-streams", tags=["Value Streams"])

# Public router — no authentication required.  Path prefix is /public/onboarding so the
# middleware's is_public_path() check passes automatically.
public_router = APIRouter(prefix="/public/onboarding/value-streams", tags=["Value Streams (Public)"])


# ─── SCHEMAS ─────────────────────────────────────────────────────────────────


class ValueStreamLibraryItemResponse(BaseModel):
    key: str
    name: str
    description: str
    process_family: str
    business_outcome_key: str
    template_version: int
    is_active: bool
    core_service_keys: list[str]
    typical_industries: list[str]


class ValueStreamLibraryGroupResponse(BaseModel):
    process_family: str
    items: list[ValueStreamLibraryItemResponse]


class InferredValueStreamResponse(BaseModel):
    key: str
    name: str
    confidence: str
    inference_reason: str
    suggested_priority: str
    source: str


class ValueStreamResponse(BaseModel):
    id: str
    organization_id: int
    library_item_id: str | None
    name: str
    priority: str
    source: str
    # Derived at read time
    service_count: int
    configured_service_count: int
    created_at: UtcTimestamp
    updated_at: UtcTimestamp


class CreateValueStreamRequest(BaseModel):
    library_item_id: str | None = Field(None, description="Key from library, or None for custom")
    name: str = Field(..., min_length=1, max_length=200)
    priority: str = Field("standard", pattern="^(critical|important|standard)$")
    source: str = Field("in_platform", pattern="^(inferred|user_added|in_platform)$")
    excluded_service_keys: list[str] = Field(default_factory=list)


class UpdateValueStreamRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=1000)
    priority: str | None = Field(None, pattern="^(critical|important|standard)$")


class OrgValueStreamProfileRequest(BaseModel):
    nace_code: str | None = None
    streams: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of {key, name, priority, source} objects confirmed by user",
    )


class ValueStreamEventRequest(BaseModel):
    event: ValueStreamEvent
    stream_id: str | None = Field(default=None, alias="streamId")
    library_item_id: str | None = Field(default=None, alias="libraryItemId")
    stream_key: str | None = Field(default=None, alias="streamKey")
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=500)
    priority: str | None = Field(default=None, pattern="^(critical|important|standard)$")
    source: str | None = Field(default=None, pattern="^(inferred|user_added|in_platform)$")

    model_config = {"populate_by_name": True}


class ValueStreamEventResponse(BaseModel):
    accepted: bool


# ─── HELPERS ─────────────────────────────────────────────────────────────────


def _service_count(org_id: int, stream_id: str, db: Session) -> tuple[int, int]:
    """Return (total_member_services, services_with_published_bundle)."""
    services: list[BusinessService] = (
        db.query(BusinessService)
        .filter(
            BusinessService.organization_id == org_id,
        )
        .all()
    )
    services = [service for service in services if stream_id in (service.value_stream_ids or [])]
    total = len(services)
    configured = sum(1 for s in services if _has_published_bundle(s, db))
    return total, configured


def _has_published_bundle(service: BusinessService, db: Session) -> bool:
    """True if the service has at least one bundle_published dependency bundle."""
    from src.core.models import DependencyBundle
    return (
        db.query(DependencyBundle)
        .filter(
            DependencyBundle.service_id == service.id,
            DependencyBundle.lifecycle_state == "bundle_published",
        )
        .first()
        is not None
    )


def _to_response(vs: ValueStream, db: Session) -> ValueStreamResponse:
    total, configured = _service_count(vs.organization_id, vs.id, db)
    return ValueStreamResponse(
        id=vs.id,
        organization_id=vs.organization_id,
        library_item_id=vs.library_item_id,
        name=vs.name,
        priority=vs.priority,
        source=vs.source,
        service_count=total,
        configured_service_count=configured,
        created_at=vs.created_at.isoformat(),
        updated_at=vs.updated_at.isoformat(),
    )


# ─── ROUTES ──────────────────────────────────────────────────────────────────


@router.get("/library", response_model=list[ValueStreamLibraryGroupResponse])
def get_library() -> list[ValueStreamLibraryGroupResponse]:
    """Return the canonical value stream library grouped by process family.

    No auth required — the library is the same for all organisations.
    """
    families: dict[str, list[ValueStreamLibraryItemResponse]] = {}
    for item in VALUE_STREAM_LIBRARY:
        families.setdefault(item.process_family, []).append(
            ValueStreamLibraryItemResponse(
                key=item.key,
                name=item.name,
                description=item.description,
                process_family=item.process_family,
                business_outcome_key=item.business_outcome_key,
                template_version=item.template_version,
                is_active=item.is_active,
                core_service_keys=item.core_service_keys,
                typical_industries=item.typical_industries,
            )
        )
    return [
        ValueStreamLibraryGroupResponse(process_family=family, items=items)
        for family, items in families.items()
    ]


@router.get("/infer", response_model=list[InferredValueStreamResponse])
def infer_streams(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[InferredValueStreamResponse]:
    """Infer value streams for the current org from its NACE code.

    Returns the full inferred set regardless of what is already configured.
    The frontend filters out already-confirmed streams when showing suggestions.
    """
    org: Organization | None = db.query(Organization).filter(
        Organization.id == ctx.organization_id
    ).first()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")

    nace = org.nace_code or ""
    inferred = infer_value_streams_from_nace(
        nace_code=nace,
        company_form=org.settings.get("company_form", "") if org.settings else "",
        company_size=org.company_size or "",
    )
    return [
        InferredValueStreamResponse(
            key=i.key,
            name=i.name,
            confidence=i.confidence,
            inference_reason=i.inference_reason,
            suggested_priority=i.suggested_priority,
            source=i.source,
        )
        for i in inferred
    ]


@router.get("", response_model=list[ValueStreamResponse])
def list_value_streams(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[ValueStreamResponse]:
    """List all value streams for the organisation, ordered by priority then name."""
    priority_order = {"critical": 0, "important": 1, "standard": 2}
    streams: list[ValueStream] = (
        db.query(ValueStream)
        .filter(ValueStream.organization_id == ctx.organization_id)
        .all()
    )
    streams.sort(key=lambda s: (priority_order.get(s.priority, 3), s.name))
    return [_to_response(s, db) for s in streams]


@router.post("", response_model=ValueStreamResponse, status_code=status.HTTP_201_CREATED)
def create_value_stream(
    body: CreateValueStreamRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ValueStreamResponse:
    """Create a value stream from the canonical library or as a custom process."""
    # Validate library_item_id if provided
    if body.library_item_id and body.library_item_id not in VALUE_STREAM_BY_KEY:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown library_item_id: {body.library_item_id}",
        )

    # Prevent duplicates for library items
    if body.library_item_id:
        existing = (
            db.query(ValueStream)
            .filter(
                ValueStream.organization_id == ctx.organization_id,
                ValueStream.library_item_id == body.library_item_id,
            )
            .first()
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Value stream '{body.library_item_id}' already exists for this organisation",
            )

    excluded_service_keys = list(body.excluded_service_keys)
    process_config: OrgProcessConfig | None = None
    if body.library_item_id:
        lib_item = VALUE_STREAM_BY_KEY[body.library_item_id]
        unknown_excluded_keys = sorted(set(excluded_service_keys) - set(lib_item.core_service_keys))
        if unknown_excluded_keys:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unknown excluded service keys for '{body.library_item_id}': {', '.join(unknown_excluded_keys)}",
            )
        process_config = (
            db.query(OrgProcessConfig)
            .filter(
                OrgProcessConfig.organization_id == ctx.organization_id,
                OrgProcessConfig.template_key == body.library_item_id,
            )
            .first()
        )

    vs = ValueStream(
        id=str(uuid.uuid4()),
        organization_id=ctx.organization_id,
        library_item_id=body.library_item_id,
        name=body.name,
        priority=body.priority,
        source=body.source,
    )
    db.add(vs)
    db.flush()  # get vs.id without committing

    if body.library_item_id and (process_config is not None or excluded_service_keys):
        if process_config is None:
            process_config = OrgProcessConfig(
                id=str(uuid.uuid4()),
                organization_id=ctx.organization_id,
                template_key=body.library_item_id,
            )
        process_config.excluded_service_keys = excluded_service_keys
        db.add(process_config)

    # Instantiate a BusinessService for each core service key from the library template.
    # If a service with the same library_item_id already exists for this org (shared across
    # processes), add this stream to its value_stream_ids rather than creating a duplicate.
    if body.library_item_id:
        lib_item = VALUE_STREAM_BY_KEY[body.library_item_id]
        for service_key in lib_item.core_service_keys:
            if service_key in excluded_service_keys:
                logger.info(
                    "business_service_excluded_from_process_setup",
                    stream_id=vs.id,
                    template_key=body.library_item_id,
                    service_key=service_key,
                )
                continue
            existing_service: BusinessService | None = (
                db.query(BusinessService)
                .filter(
                    BusinessService.organization_id == ctx.organization_id,
                    BusinessService.library_item_id == service_key,
                )
                .first()
            )
            if existing_service:
                current_ids: list[str] = list(existing_service.value_stream_ids or [])
                if vs.id not in current_ids:
                    existing_service.value_stream_ids = current_ids + [vs.id]
                    db.add(existing_service)
                logger.info(
                    "business_service_stream_linked",
                    service_id=existing_service.id,
                    stream_id=vs.id,
                    service_key=service_key,
                )
            else:
                svc_template = get_active_service_template(db, service_key)
                svc = BusinessService(
                    id=str(uuid.uuid4()),
                    organization_id=ctx.organization_id,
                    name=get_service_key_name(service_key),
                    library_item_id=service_key,
                    archetype=get_archetype_for_service_key(service_key),
                    template_key=service_key,
                    template_version=svc_template.version if svc_template else None,
                    value_stream_ids=[vs.id],
                    tier=SERVICE_TIER_BUSINESS_CRITICAL,
                    trading_impact="",
                )
                db.add(svc)
                logger.info(
                    "business_service_created_from_template",
                    service_id=svc.id,
                    stream_id=vs.id,
                    service_key=service_key,
                )

    db.commit()
    db.refresh(vs)
    logger.info("value_stream_created", stream_id=vs.id, org_id=ctx.organization_id, source=body.source)
    return _to_response(vs, db)


@router.put("/{stream_id}", response_model=ValueStreamResponse)
def update_value_stream(
    stream_id: str,
    body: UpdateValueStreamRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ValueStreamResponse:
    """Update a value stream's name or priority."""
    vs: ValueStream | None = (
        db.query(ValueStream)
        .filter(ValueStream.id == stream_id, ValueStream.organization_id == ctx.organization_id)
        .first()
    )
    if not vs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Value stream not found")

    try:
        require_process_editor(
            db,
            organization_id=ctx.organization_id,
            process_id=vs.id,
            actor_user_id=ctx.user_id,
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(str(exc)) from exc

    if body.name is not None:
        vs.name = body.name
    if body.description is not None:
        vs.description = body.description
    if body.priority is not None:
        vs.priority = body.priority

    db.commit()
    db.refresh(vs)
    return _to_response(vs, db)


@router.delete("/{stream_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def delete_value_stream(
    stream_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a value stream stub.

    Does NOT delete member services — they become orphaned (value_stream_ids
    will no longer contain this ID). The frontend surfaces them as orphans.
    """
    vs: ValueStream | None = (
        db.query(ValueStream)
        .filter(ValueStream.id == stream_id, ValueStream.organization_id == ctx.organization_id)
        .first()
    )
    if not vs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Value stream not found")

    db.delete(vs)
    db.commit()
    logger.info("value_stream_deleted", stream_id=stream_id, org_id=ctx.organization_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/events", response_model=ValueStreamEventResponse, status_code=status.HTTP_202_ACCEPTED)
def record_value_stream_event(
    body: ValueStreamEventRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ValueStreamEventResponse:
    """Capture in-platform value stream signals as append-only learning data."""
    signal = ValueStreamSignal(
        organization_id=ctx.organization_id,
        user_id=ctx.user_id,
        event=body.event,
        stream_id=body.stream_id,
        library_item_id=body.library_item_id,
        stream_key=body.stream_key,
        name=body.name,
        priority=body.priority,
        source=body.source,
        payload=body.model_dump(mode="json", by_alias=False),
    )
    db.add(signal)
    db.commit()
    logger.info(
        "value_stream_event",
        org_id=ctx.organization_id,
        event=body.event,
        stream_id=body.stream_id,
        library_item_id=body.library_item_id,
        stream_key=body.stream_key,
    )
    return ValueStreamEventResponse(accepted=True)


@router.post("/profile", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def save_value_stream_profile(
    body: OrgValueStreamProfileRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> Response:
    """Save the confirmed OrgValueStreamProfile after www onboarding.

    Also upserts ValueStream rows for each confirmed stream so the tenant
    platform has stubs ready on first load.
    """
    org: Organization | None = db.query(Organization).filter(
        Organization.id == ctx.organization_id
    ).first()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")

    # Update NACE if provided
    if body.nace_code:
        org.nace_code = body.nace_code

    # Persist profile snapshot
    org.org_value_stream_profile = {
        "inferredFrom": "cvr",
        "naceCode": body.nace_code or org.nace_code,
        "confirmed": True,
        "streams": body.streams,
    }

    # Upsert ValueStream rows
    for stream_data in body.streams:
        key = stream_data.get("key")
        if not key:
            continue
        existing = (
            db.query(ValueStream)
            .filter(
                ValueStream.organization_id == ctx.organization_id,
                ValueStream.library_item_id == key,
            )
            .first()
        )
        if existing:
            existing.priority = stream_data.get("priority", existing.priority)
        else:
            lib_item = VALUE_STREAM_BY_KEY.get(key)
            db.add(ValueStream(
                id=str(uuid.uuid4()),
                organization_id=ctx.organization_id,
                library_item_id=key,
                name=stream_data.get("name", lib_item.name if lib_item else key),
                priority=stream_data.get("priority", "standard"),
                source=stream_data.get("source", "inferred"),
            ))

    db.commit()
    logger.info(
        "org_value_stream_profile_saved",
        org_id=ctx.organization_id,
        stream_count=len(body.streams),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ─── PUBLIC ROUTES (no auth) ──────────────────────────────────────────────────


@public_router.get("/infer", response_model=list[InferredValueStreamResponse])
def public_infer_streams(
    nace_code: str = Query("", description="NACE code from CVR enrichment"),
    company_form: str = Query("", description="Legal form, e.g. A/S, ApS, Forening"),
    company_size: str = Query("", description="Size bracket: micro | sme | large | enterprise"),
) -> list[InferredValueStreamResponse]:
    """Infer value streams from a NACE code without authentication.

    Used by the www public onboarding flow before a tenant account exists.
    Returns the same inference result as the authenticated /infer endpoint.
    """
    inferred = infer_value_streams_from_nace(
        nace_code=nace_code,
        company_form=company_form,
        company_size=company_size,
    )
    return [
        InferredValueStreamResponse(
            key=i.key,
            name=i.name,
            confidence=i.confidence,
            inference_reason=i.inference_reason,
            suggested_priority=i.suggested_priority,
            source=i.source,
        )
        for i in inferred
    ]


@public_router.get("/library", response_model=list[ValueStreamLibraryGroupResponse])
def public_get_library() -> list[ValueStreamLibraryGroupResponse]:
    """Return the canonical library without authentication (same as the auth'd endpoint)."""
    families: dict[str, list[ValueStreamLibraryItemResponse]] = {}
    for item in VALUE_STREAM_LIBRARY:
        families.setdefault(item.process_family, []).append(
            ValueStreamLibraryItemResponse(
                key=item.key,
                name=item.name,
                description=item.description,
                process_family=item.process_family,
                core_service_keys=item.core_service_keys,
                typical_industries=item.typical_industries,
            )
        )
    return [
        ValueStreamLibraryGroupResponse(process_family=family, items=items)
        for family, items in families.items()
    ]
