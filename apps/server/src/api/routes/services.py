"""Decision Layer — Business Service endpoints.

GET    /api/v1/services              — list all business services for the org
POST   /api/v1/services              — create a new business service
PUT    /api/v1/services/{id}         — update a business service
DELETE /api/v1/services/{id}         — delete a business service

Every endpoint is tenant-scoped: organization_id is taken from the JWT via
TenantContext and never accepted from the caller.
"""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field, ValidationError, model_validator
from sqlalchemy import func
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants import (
    DEFAULT_SERVICE_TIER,
    SERVICE_TIER_DEFAULT_FINANCIAL_EXPOSURE,
    SERVICE_TIER_PATTERN,
    ServiceToleranceWindow,
    normalize_service_tier,
    normalize_service_tolerance_window,
)
from src.core.database import get_db
from src.core.logging_config import get_logger
from src.core.models import (
    Asset,
    AssetEvidenceSignal,
    BusinessService,
    ServiceJourneySignal,
    Threat,
    ValueStream,
)
from src.core.services.bia_inheritance_service import (
    BIA_FIELD_KEYS,
    BiaExceptions,
    effective_service_bia,
    service_bia_provenance,
)
from src.core.services.effective_process_bia_service import (
    resolve_effective_process_bia_by_process,
)
from src.core.services.service_bia_exception_service import (
    BiaExceptionError,
    active_bia_exceptions,
    exceptions_for,
    refuse_differing_questionnaire_answers,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/services", tags=["Decision Layer"])

_SERVICE_DEPENDENCY_CACHE_TTL_SECONDS = 10
_service_dependencies_cache: dict[int, tuple[float, list["ServiceDependenciesResponse"]]] = {}
_service_dependencies_cache_lock = Lock()


# ─── SCHEMAS ──────────────────────────────────────────────────────────────────


class ServiceResponse(BaseModel):
    """Shape returned to the frontend — mirrors the TypeScript Service type."""

    id: str
    name: str
    tier: str
    toleranceWindow: ServiceToleranceWindow | None = None
    tradingImpact: str
    biaAnswers: "BiaAnswers | None" = None
    biaProvenance: dict[str, str] = Field(default_factory=dict)
    archetype: str | None = None
    libraryItemId: str | None = None
    valueStreamIds: list[str]
    l1: list[str]
    l2: list[str]
    l3: list[str]

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm(
        cls,
        s: BusinessService,
        *,
        process_bia_answers: dict | None = None,
        bia_exceptions: BiaExceptions = (),
    ) -> "ServiceResponse":
        # #463 (Søren, 2026-09-15, option B) — the answers in force are the primary process's
        # resolved BIA with this service's exceptions in that process. `s.bia_answers` still holds
        # copies of process answers, and a copy must not count as the owner's own; only its setup
        # metadata (`serviceOwnerTitle`, `impactPath`) is read from it.
        effective = effective_service_bia(process_bia_answers, bia_exceptions)
        if effective is not None:
            effective = {**_service_setup_metadata(s.bia_answers), **effective}
        return cls(
            id=s.id,
            name=s.name,
            tier=s.tier,
            toleranceWindow=normalize_service_tolerance_window(s.tolerance_window),
            tradingImpact=s.trading_impact,
            biaAnswers=_serialize_effective_bia_answers(effective),
            biaProvenance=service_bia_provenance(bia_exceptions),
            archetype=s.archetype,
            libraryItemId=s.library_item_id,
            valueStreamIds=s.value_stream_ids or [],
            l1=s.l1 or [],
            l2=s.l2 or [],
            l3=s.l3 or [],
        )


class BiaAnswers(BaseModel):
    serviceOwnerTitle: str = ""
    impactPath: list[str] = Field(default_factory=list)
    impact1h: str
    impact4h: str
    impact24h: str
    mtd: str
    workaround: str
    alternativeChannel: str
    dataSensitivity: str

    model_config = {"extra": "forbid"}

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_service_owner(cls, value):
        if not isinstance(value, dict):
            return value

        migrated = dict(value)
        legacy_owner = str(migrated.pop("serviceOwner", "") or "").strip()
        migrated.pop("serviceOwnerName", None)
        if legacy_owner and not migrated.get("serviceOwnerTitle"):
            migrated["serviceOwnerTitle"] = legacy_owner
        return migrated


_BIA_RESPONSE_INPUT_KEYS = frozenset({*BiaAnswers.model_fields, "serviceOwner", "serviceOwnerName"})


def _service_setup_metadata(service_answers: dict | None) -> dict:
    """The setup facts stored among a service's answers that are not BIA answers (#463)."""
    return {
        key: value
        for key, value in (service_answers or {}).items()
        if key in _BIA_RESPONSE_INPUT_KEYS and key not in BIA_FIELD_KEYS
    }


def _answers_in_force(
    org_id: int, db: Session, *, service_id: str | None, value_stream_ids: list[str] | None
) -> dict | None:
    """#463 — the BIA answers in force for a service in its primary process: that process's BIA
    with the service's exceptions there. A service not yet saved has no exceptions."""
    if not value_stream_ids:
        return None
    process = (
        db.query(ValueStream)
        .filter(ValueStream.organization_id == org_id, ValueStream.id == value_stream_ids[0])
        .first()
    )
    if process is None:
        return None
    process_answers = resolve_effective_process_bia_by_process(
        db, organization_id=org_id, processes=[process]
    )[process.id].answers
    exceptions = (
        active_bia_exceptions(
            db, organization_id=org_id, service_ids=[service_id], process_ids=[process.id]
        )
        if service_id
        else {}
    )
    return effective_service_bia(
        process_answers, exceptions_for(exceptions, service_id or "", process.id)
    )


def _refuse_differing_bia(submitted: dict, answers_in_force: dict | None) -> None:
    """Søren, 2026-09-15: the whole-questionnaire save refuses a differing answer, clearly."""
    try:
        refuse_differing_questionnaire_answers(submitted, answers_in_force=answers_in_force)
    except BiaExceptionError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


def _serialize_effective_bia_answers(effective_answers: dict | None) -> BiaAnswers | None:
    """Return valid BIA answers without exposing legacy setup metadata as BIA."""
    if not effective_answers:
        return None

    response_answers = {
        key: value for key, value in effective_answers.items() if key in _BIA_RESPONSE_INPUT_KEYS
    }
    try:
        return BiaAnswers.model_validate(response_answers)
    except ValidationError:
        # An incomplete assessment remains unconfigured until a process owner
        # provides the required BIA inputs; never invent an impact statement.
        return None


class CreateServiceRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    tier: str = Field(DEFAULT_SERVICE_TIER, pattern=SERVICE_TIER_PATTERN)
    tolerance_window: ServiceToleranceWindow | None = Field(default=None, alias="toleranceWindow")
    trading_impact: str = Field("", max_length=1000)
    bia_answers: BiaAnswers | None = Field(default=None, alias="biaAnswers")
    archetype: Optional[str] = Field(default=None, alias="archetype", max_length=50)
    library_item_id: str | None = Field(default=None, alias="libraryItemId", max_length=100)
    #: ⚠️ **At least one, always** (#378). Søren, 2026-08-31: *"A service in no
    #: process should not exist."* Accountability resolves dependency → service
    #: → process → owner, so a service in no process terminates that chain at
    #: nobody — and every dependency beneath it becomes unowned and undecidable.
    #: It defaulted to `[]`, which is how 57 of them came to exist.
    value_stream_ids: list[str] = Field(
        ...,
        min_length=1,
        alias="valueStreamIds",
        description="At least one process — a service in no process cannot resolve an owner",
    )
    l1: list[str] = Field(default_factory=list)
    l2: list[str] = Field(default_factory=list)
    l3: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class UpdateServiceRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    tier: Optional[str] = Field(None, pattern=SERVICE_TIER_PATTERN)
    tolerance_window: ServiceToleranceWindow | None = Field(default=None, alias="toleranceWindow")
    trading_impact: Optional[str] = Field(None, max_length=1000)
    bia_answers: BiaAnswers | None = Field(default=None, alias="biaAnswers")
    archetype: Optional[str] = Field(default=None, alias="archetype", max_length=50)
    library_item_id: str | None = Field(default=None, alias="libraryItemId", max_length=100)
    #: Omit to leave the processes alone; send a list and it replaces them. It
    #: may never be **empty**: taking away a service's last process is what
    #: orphans it, and this route could do it silently (#378). `PATCH
    #: /{id}/value-streams` has always refused an empty set — this is the same
    #: rule, on the route that could go around it.
    value_stream_ids: list[str] | None = Field(
        default=None,
        min_length=1,
        alias="valueStreamIds",
        description="Replacement set; omit to leave unchanged, never empty",
    )
    l1: Optional[list[str]] = None
    l2: Optional[list[str]] = None
    l3: Optional[list[str]] = None

    model_config = {"populate_by_name": True}


class ServiceDependencyItemResponse(BaseModel):
    id: str
    name: str
    type: str
    owner: str | None = None
    health: str
    is_spof: bool
    signal_count: int
    threat_count: int


class ServiceDependenciesResponse(BaseModel):
    serviceId: str
    serviceName: str
    tier: str
    tradingImpact: str
    financial_exposure: int | None = None
    l1: list[ServiceDependencyItemResponse]
    l2: list[ServiceDependencyItemResponse]
    l3: list[ServiceDependencyItemResponse]


class ServiceJourneyEventRequest(BaseModel):
    event: Literal[
        "recommendations_shown",
        "recommendation_accepted",
        "recommendation_rejected",
        "service_selected",
        "service_rejected",
        "service_searched",
        "service_added_from_library",
        "service_removed_after_selection",
        "custom_service_created",
        "service_tier_suggested",
        "service_tier_confirmed",
        "service_tier_changed",
        "tolerance_set",
        "archetype_confirmed",
        "archetype_override",
        "dependency_pattern_confirmed",
        "dependency_pattern_added_from_library",
        "asset_confirmed",
        "asset_linked",
        "asset_replaced",
        "fallback_defined",
        "spof_defined",
        "recovery_dependency_marked",
        "impact_type_selected",
        "business_criticality_selected",
        "validation_triggered",
        "blocker_detected",
        "warning_detected",
        "validation_completed",
        "validation_warning_accepted",
        "warning_acknowledged",
        "publish_blocked",
        "bundle_published",
        "publish_completed",
    ]
    service_id: str | None = Field(default=None, alias="serviceId")
    library_item_id: str | None = Field(default=None, alias="libraryItemId")
    service_key: str | None = Field(default=None, alias="serviceKey")
    service_name: str | None = Field(default=None, alias="serviceName")
    suggested_tier: str | None = Field(default=None, alias="suggestedTier")
    selected_tier: str | None = Field(default=None, alias="selectedTier")
    selected_tolerance_window: str | None = Field(default=None, alias="selectedToleranceWindow")
    suggested_archetype: str | None = Field(default=None, alias="suggestedArchetype")
    selected_archetype: str | None = Field(default=None, alias="selectedArchetype")
    recommended_service_keys: list[str] = Field(
        default_factory=list, alias="recommendedServiceKeys"
    )
    matched_service_keys: list[str] = Field(default_factory=list, alias="matchedServiceKeys")
    search_query: str | None = Field(default=None, alias="searchQuery")
    dependency_id: str | None = Field(default=None, alias="dependencyId")
    dependency_label: str | None = Field(default=None, alias="dependencyLabel")
    group_key: str | None = Field(default=None, alias="groupKey")
    asset_id: str | None = Field(default=None, alias="assetId")
    pattern_key: str | None = Field(default=None, alias="patternKey")
    fallback_status: str | None = Field(default=None, alias="fallbackStatus")
    business_choice: str | None = Field(default=None, alias="businessChoice")
    business_impact_level: str | None = Field(default=None, alias="businessImpactLevel")
    spof_value: bool | None = Field(default=None, alias="spofValue")
    warning_ids: list[str] = Field(default_factory=list, alias="warningIds")
    blocker_count: int | None = Field(default=None, alias="blockerCount")
    warning_count: int | None = Field(default=None, alias="warningCount")
    organization_context: dict[str, Any] = Field(default_factory=dict, alias="organizationContext")

    model_config = {"populate_by_name": True}


class ServiceJourneyEventResponse(BaseModel):
    accepted: bool


class RecommendationLearningServiceAggregateResponse(BaseModel):
    serviceKey: str
    selectionCount: int
    rejectionCount: int
    searchCount: int
    addFromLibraryCount: int
    removedAfterSelectionCount: int


class RecommendationLearningSegmentAggregateResponse(BaseModel):
    organizationType: str | None = None
    industry: str | None = None
    companySize: str | None = None
    country: str | None = None
    signalCount: int
    services: list[RecommendationLearningServiceAggregateResponse]


class RecommendationLearningAggregatesResponse(BaseModel):
    segments: list[RecommendationLearningSegmentAggregateResponse]


class RecommendationLearningSuggestionResponse(BaseModel):
    serviceKey: str
    scoreAdjustment: int
    selectionCount: int
    rejectionCount: int
    searchCount: int
    addFromLibraryCount: int
    removedAfterSelectionCount: int


class RecommendationLearningRecommendationsResponse(BaseModel):
    recommendations: list[RecommendationLearningSuggestionResponse]


# ─── ROUTES ───────────────────────────────────────────────────────────────────


@router.get("", response_model=list[ServiceResponse])
def list_services(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[ServiceResponse]:
    """Return all business services for the authenticated organisation."""
    services = _list_org_services(ctx.organization_id, db)
    logger.info("services_listed", org_id=ctx.organization_id, count=len(services))
    return _service_responses(services, ctx.organization_id, db)


@router.get("/dependencies", response_model=list[ServiceDependenciesResponse])
def list_service_dependencies(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[ServiceDependenciesResponse]:
    """Return the dependency chain for every service in the organisation."""
    cached = _get_cached_service_dependencies(ctx.organization_id)
    if cached is not None:
        logger.info(
            "service_dependencies_index_cache_hit",
            org_id=ctx.organization_id,
            services=len(cached),
        )
        return cached

    started = time.perf_counter()
    services = _list_org_services(ctx.organization_id, db)
    services_loaded_at = time.perf_counter()
    (
        asset_by_ref,
        signal_count_by_asset_id,
        threat_count_by_asset_name,
    ) = _load_dependency_support_data(
        services,
        ctx.organization_id,
        db,
    )
    support_loaded_at = time.perf_counter()
    response = [
        _build_service_dependencies_response(
            service,
            asset_by_ref,
            signal_count_by_asset_id,
            threat_count_by_asset_name,
        )
        for service in services
    ]
    built_at = time.perf_counter()
    _set_cached_service_dependencies(ctx.organization_id, response)
    logger.info(
        "service_dependencies_index_loaded",
        org_id=ctx.organization_id,
        services=len(response),
        services_query_ms=int((services_loaded_at - started) * 1000),
        support_query_ms=int((support_loaded_at - services_loaded_at) * 1000),
        build_ms=int((built_at - support_loaded_at) * 1000),
        total_ms=int((built_at - started) * 1000),
    )
    return response


@router.post(
    "/journey-events",
    response_model=ServiceJourneyEventResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def record_service_journey_event(
    body: ServiceJourneyEventRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ServiceJourneyEventResponse:
    """Capture library-driven BIA journey signals as append-only learning data."""
    fields = _service_journey_log_fields(body, ctx)
    signal = ServiceJourneySignal(
        organization_id=ctx.organization_id,
        user_id=ctx.user_id,
        event=body.event,
        service_id=body.service_id,
        library_item_id=body.library_item_id,
        service_key=body.service_key,
        service_name=body.service_name,
        search_query=body.search_query,
        recommended_service_keys=body.recommended_service_keys,
        matched_service_keys=body.matched_service_keys,
        warning_ids=body.warning_ids,
        organization_type=_context_value(body.organization_context, "organizationType"),
        industry=_context_value(body.organization_context, "industry"),
        company_size=_context_value(body.organization_context, "companySize"),
        country=_context_value(body.organization_context, "country"),
        payload=body.model_dump(mode="json", by_alias=False),
    )
    db.add(signal)
    db.commit()
    logger.info("service_journey_event", **fields)
    return ServiceJourneyEventResponse(accepted=True)


@router.get(
    "/journey-learning/aggregates",
    response_model=RecommendationLearningAggregatesResponse,
)
def get_service_journey_learning_aggregates(
    organization_type: str | None = None,
    industry: str | None = None,
    company_size: str | None = None,
    country: str | None = None,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> RecommendationLearningAggregatesResponse:
    """Return segment-level recommendation-learning aggregates for the org."""
    rows = [
        row
        for row in db.query(ServiceJourneySignal).all()
        if row.organization_id == ctx.organization_id
        and _segment_matches(
            row=row,
            organization_type=organization_type,
            industry=industry,
            company_size=company_size,
            country=country,
        )
    ]
    return RecommendationLearningAggregatesResponse(
        segments=_build_learning_segment_aggregates(rows)
    )


@router.get(
    "/journey-learning/recommendations",
    response_model=RecommendationLearningRecommendationsResponse,
)
def get_service_journey_learning_recommendations(
    organization_type: str | None = None,
    industry: str | None = None,
    company_size: str | None = None,
    country: str | None = None,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> RecommendationLearningRecommendationsResponse:
    """Return learned recommendation adjustments for the matching organisation segment."""
    rows = [
        row
        for row in db.query(ServiceJourneySignal).all()
        if row.organization_id == ctx.organization_id
        and _segment_matches(
            row=row,
            organization_type=organization_type,
            industry=industry,
            company_size=company_size,
            country=country,
        )
    ]
    return RecommendationLearningRecommendationsResponse(
        recommendations=_build_learning_recommendations(rows)
    )


@router.get("/{service_id}/dependencies", response_model=ServiceDependenciesResponse)
def get_service_dependencies(
    service_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ServiceDependenciesResponse:
    """Return the business dependency chain for one service."""
    service = _get_service(service_id, ctx.organization_id, db)
    (
        asset_by_ref,
        signal_count_by_asset_id,
        threat_count_by_asset_name,
    ) = _load_dependency_support_data(
        [service],
        ctx.organization_id,
        db,
    )
    response = _build_service_dependencies_response(
        service,
        asset_by_ref,
        signal_count_by_asset_id,
        threat_count_by_asset_name,
    )
    logger.info(
        "service_dependencies_loaded",
        org_id=ctx.organization_id,
        service_id=service.id,
        l1=len(response.l1),
        l2=len(response.l2),
        l3=len(response.l3),
    )
    return response


@router.post("", response_model=ServiceResponse, status_code=status.HTTP_201_CREATED)
def create_service(
    body: CreateServiceRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ServiceResponse:
    """Create a new business service for the authenticated organisation."""
    submitted_bia = body.bia_answers.model_dump() if body.bia_answers else None
    if submitted_bia is not None:
        # #463 — a service records only exceptions, each with a reason, through its own endpoint.
        # The questionnaire saves only where it matches what the service would inherit.
        _refuse_differing_bia(
            submitted_bia,
            _answers_in_force(
                ctx.organization_id, db, service_id=None, value_stream_ids=body.value_stream_ids
            ),
        )
    service = BusinessService(
        organization_id=ctx.organization_id,
        name=body.name,
        tier=body.tier,
        tolerance_window=body.tolerance_window,
        trading_impact=body.trading_impact,
        # Only the setup facts are the service's own; its BIA answers are inherited.
        bia_answers=_service_setup_metadata(submitted_bia) or None,
        archetype=body.archetype,
        library_item_id=body.library_item_id,
        value_stream_ids=body.value_stream_ids,
        l1=body.l1,
        l2=body.l2,
        l3=body.l3,
    )
    db.add(service)
    db.commit()
    db.refresh(service)
    _invalidate_service_dependencies_cache(ctx.organization_id)
    logger.info(
        "service_created", org_id=ctx.organization_id, service_id=service.id, name=service.name
    )
    return _service_response(service, ctx.organization_id, db)


@router.put("/{service_id}", response_model=ServiceResponse)
def update_service(
    service_id: str,
    body: UpdateServiceRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ServiceResponse:
    """Update an existing business service."""
    service = _get_service(service_id, ctx.organization_id, db)
    submitted_bia = body.bia_answers.model_dump() if body.bia_answers is not None else None
    if submitted_bia is not None:
        # #463 — refused before anything changes; compared with the primary process this request
        # leaves the service in.
        _refuse_differing_bia(
            submitted_bia,
            _answers_in_force(
                ctx.organization_id,
                db,
                service_id=service.id,
                value_stream_ids=body.value_stream_ids or service.value_stream_ids,
            ),
        )
    if body.name is not None:
        service.name = body.name
    if body.tier is not None:
        service.tier = body.tier
    if body.tolerance_window is not None:
        service.tolerance_window = body.tolerance_window
    if body.trading_impact is not None:
        service.trading_impact = body.trading_impact
    if submitted_bia is not None:
        # Only the setup facts are kept; copies of process answers are dropped with them.
        service.bia_answers = _service_setup_metadata(submitted_bia) or None
    if body.archetype is not None:
        service.archetype = body.archetype
    if body.library_item_id is not None:
        service.library_item_id = body.library_item_id
    if body.value_stream_ids is not None:
        service.value_stream_ids = body.value_stream_ids
    if body.l1 is not None:
        service.l1 = body.l1
    if body.l2 is not None:
        service.l2 = body.l2
    if body.l3 is not None:
        service.l3 = body.l3
    db.commit()
    db.refresh(service)
    _invalidate_service_dependencies_cache(ctx.organization_id)
    logger.info("service_updated", org_id=ctx.organization_id, service_id=service_id)
    return _service_response(service, ctx.organization_id, db)


class AssignValueStreamsRequest(BaseModel):
    value_stream_ids: list[str] = Field(
        ..., min_length=1, description="Full replacement set — must contain at least one ID"
    )


@router.patch("/{service_id}/value-streams", response_model=ServiceResponse)
def assign_value_streams(
    service_id: str,
    body: AssignValueStreamsRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ServiceResponse:
    """Replace the value stream membership for a business service (UC-VS-07 / UC-VS-08).

    All BIA answers, archetype, and dependency bundle data are preserved.
    At least one value_stream_id must be provided — a service cannot be left unassigned.
    All provided IDs must belong to the same organisation.
    """
    service = _get_service(service_id, ctx.organization_id, db)

    # Validate every requested stream ID belongs to this org
    valid_stream_ids = {
        row.id
        for row in db.query(ValueStream.id)
        .filter(
            ValueStream.organization_id == ctx.organization_id,
            ValueStream.id.in_(body.value_stream_ids),
        )
        .all()
    }
    invalid = [sid for sid in body.value_stream_ids if sid not in valid_stream_ids]
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown or unauthorised value stream IDs: {invalid}",
        )

    prev_stream_ids: list[str] = service.value_stream_ids or []
    service.value_stream_ids = body.value_stream_ids
    db.commit()
    db.refresh(service)
    _invalidate_service_dependencies_cache(ctx.organization_id)

    was_orphan = len(prev_stream_ids) == 0
    logger.info(
        "orphan_service_resolved" if was_orphan else "service_value_streams_updated",
        org_id=ctx.organization_id,
        service_id=service_id,
        prev_stream_ids=prev_stream_ids,
        new_stream_ids=body.value_stream_ids,
    )
    return _service_response(service, ctx.organization_id, db)


@router.delete("/{service_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def delete_service(
    service_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a business service."""
    service = _get_service(service_id, ctx.organization_id, db)
    db.delete(service)
    db.commit()
    _invalidate_service_dependencies_cache(ctx.organization_id)
    logger.info("service_deleted", org_id=ctx.organization_id, service_id=service_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ─── HELPERS ──────────────────────────────────────────────────────────────────


def _get_cached_service_dependencies(org_id: int) -> list[ServiceDependenciesResponse] | None:
    with _service_dependencies_cache_lock:
        cached = _service_dependencies_cache.get(org_id)
        if cached is None:
            return None
        expires_at, payload = cached
        if expires_at <= time.time():
            _service_dependencies_cache.pop(org_id, None)
            return None
        return payload


def _set_cached_service_dependencies(
    org_id: int, payload: list[ServiceDependenciesResponse]
) -> None:
    with _service_dependencies_cache_lock:
        _service_dependencies_cache[org_id] = (
            time.time() + _SERVICE_DEPENDENCY_CACHE_TTL_SECONDS,
            payload,
        )


def _invalidate_service_dependencies_cache(org_id: int) -> None:
    with _service_dependencies_cache_lock:
        _service_dependencies_cache.pop(org_id, None)


def _context_value(context: dict[str, Any], key: str) -> str | None:
    value = context.get(key)
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _service_journey_log_fields(
    body: ServiceJourneyEventRequest,
    ctx: TenantContext,
) -> dict[str, Any]:
    return {
        "org_id": ctx.organization_id,
        "user_id": ctx.user_id,
        "event": body.event,
        "service_id": body.service_id,
        "library_item_id": body.library_item_id,
        "service_key": body.service_key,
        "service_name": body.service_name,
        "suggested_tier": body.suggested_tier,
        "selected_tier": body.selected_tier,
        "selected_tolerance_window": body.selected_tolerance_window,
        "suggested_archetype": body.suggested_archetype,
        "selected_archetype": body.selected_archetype,
        "recommended_service_keys": body.recommended_service_keys,
        "matched_service_keys": body.matched_service_keys,
        "search_query": body.search_query,
        "dependency_id": body.dependency_id,
        "dependency_label": body.dependency_label,
        "group_key": body.group_key,
        "asset_id": body.asset_id,
        "pattern_key": body.pattern_key,
        "fallback_status": body.fallback_status,
        "business_choice": body.business_choice,
        "business_impact_level": body.business_impact_level,
        "spof_value": body.spof_value,
        "warning_ids": body.warning_ids,
        "blocker_count": body.blocker_count,
        "warning_count": body.warning_count,
        "organization_context": body.organization_context,
    }


def _segment_matches(
    *,
    row: ServiceJourneySignal,
    organization_type: str | None,
    industry: str | None,
    company_size: str | None,
    country: str | None,
) -> bool:
    if organization_type is not None and row.organization_type != organization_type:
        return False
    if industry is not None and row.industry != industry:
        return False
    if company_size is not None and row.company_size != company_size:
        return False
    if country is not None and row.country != country:
        return False
    return True


def _build_learning_segment_aggregates(
    rows: list[ServiceJourneySignal],
) -> list[RecommendationLearningSegmentAggregateResponse]:
    segments: dict[
        tuple[str | None, str | None, str | None, str | None],
        dict[str, Any],
    ] = {}

    for row in rows:
        segment_key = (row.organization_type, row.industry, row.company_size, row.country)
        segment = segments.setdefault(
            segment_key,
            {
                "organizationType": row.organization_type,
                "industry": row.industry,
                "companySize": row.company_size,
                "country": row.country,
                "signalCount": 0,
                "services": defaultdict(
                    lambda: {
                        "selectionCount": 0,
                        "rejectionCount": 0,
                        "searchCount": 0,
                        "addFromLibraryCount": 0,
                        "removedAfterSelectionCount": 0,
                    }
                ),
            },
        )
        segment["signalCount"] += 1

        if row.event in {"recommendation_accepted", "service_selected"} and row.service_key:
            segment["services"][row.service_key]["selectionCount"] += 1
        elif row.event in {"recommendation_rejected", "service_rejected"} and row.service_key:
            segment["services"][row.service_key]["rejectionCount"] += 1
        elif row.event == "service_added_from_library" and row.service_key:
            segment["services"][row.service_key]["addFromLibraryCount"] += 1
        elif row.event == "service_removed_after_selection" and row.service_key:
            segment["services"][row.service_key]["removedAfterSelectionCount"] += 1
        elif row.event == "service_searched":
            for service_key in row.matched_service_keys or []:
                normalized_key = str(service_key).strip()
                if normalized_key:
                    segment["services"][normalized_key]["searchCount"] += 1

    responses: list[RecommendationLearningSegmentAggregateResponse] = []
    for segment in segments.values():
        services_payload = [
            RecommendationLearningServiceAggregateResponse(serviceKey=service_key, **counts)
            for service_key, counts in sorted(
                segment["services"].items(),
                key=lambda item: (
                    -(
                        item[1]["selectionCount"]
                        + item[1]["rejectionCount"]
                        + item[1]["searchCount"]
                        + item[1]["addFromLibraryCount"]
                        + item[1]["removedAfterSelectionCount"]
                    ),
                    item[0],
                ),
            )
        ]
        responses.append(
            RecommendationLearningSegmentAggregateResponse(
                organizationType=segment["organizationType"],
                industry=segment["industry"],
                companySize=segment["companySize"],
                country=segment["country"],
                signalCount=segment["signalCount"],
                services=services_payload,
            )
        )

    return sorted(
        responses,
        key=lambda item: (
            item.organizationType or "",
            item.industry or "",
            item.companySize or "",
            item.country or "",
        ),
    )


def _build_learning_recommendations(
    rows: list[ServiceJourneySignal],
) -> list[RecommendationLearningSuggestionResponse]:
    service_counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "selectionCount": 0,
            "rejectionCount": 0,
            "searchCount": 0,
            "addFromLibraryCount": 0,
            "removedAfterSelectionCount": 0,
        }
    )

    for row in rows:
        if row.event in {"recommendation_accepted", "service_selected"} and row.service_key:
            service_counts[row.service_key]["selectionCount"] += 1
        elif row.event in {"recommendation_rejected", "service_rejected"} and row.service_key:
            service_counts[row.service_key]["rejectionCount"] += 1
        elif row.event == "service_added_from_library" and row.service_key:
            service_counts[row.service_key]["addFromLibraryCount"] += 1
        elif row.event == "service_removed_after_selection" and row.service_key:
            service_counts[row.service_key]["removedAfterSelectionCount"] += 1
        elif row.event == "service_searched":
            for service_key in row.matched_service_keys or []:
                normalized_key = str(service_key).strip()
                if normalized_key:
                    service_counts[normalized_key]["searchCount"] += 1

    suggestions: list[RecommendationLearningSuggestionResponse] = []
    for service_key, counts in service_counts.items():
        score_adjustment = (
            counts["selectionCount"] * 3
            + counts["addFromLibraryCount"] * 4
            + counts["searchCount"]
            - counts["rejectionCount"] * 2
            - counts["removedAfterSelectionCount"] * 3
        )
        if score_adjustment <= 0:
            continue
        suggestions.append(
            RecommendationLearningSuggestionResponse(
                serviceKey=service_key,
                scoreAdjustment=score_adjustment,
                **counts,
            )
        )

    return sorted(
        suggestions,
        key=lambda item: (-item.scoreAdjustment, -item.selectionCount, item.serviceKey),
    )


def _list_org_services(org_id: int, db: Session) -> list[BusinessService]:
    return (
        db.query(BusinessService)
        .filter(BusinessService.organization_id == org_id)
        .order_by(BusinessService.created_at.asc())
        .all()
    )


def _primary_process_by_service_id(
    services: list[BusinessService], org_id: int, db: Session
) -> dict[str, ValueStream]:
    """Batch-resolve each service's primary (first-assigned) process.

    One query for the whole list — avoids an N+1 per service on the org-wide
    listing endpoints.
    """
    stream_ids = {s.value_stream_ids[0] for s in services if s.value_stream_ids}
    if not stream_ids:
        return {}
    streams_by_id = {
        vs.id: vs
        for vs in db.query(ValueStream)
        .filter(ValueStream.organization_id == org_id, ValueStream.id.in_(stream_ids))
        .all()
    }
    return {
        s.id: streams_by_id[s.value_stream_ids[0]]
        for s in services
        if s.value_stream_ids and s.value_stream_ids[0] in streams_by_id
    }


def _service_responses(
    services: list[BusinessService], org_id: int, db: Session
) -> list[ServiceResponse]:
    """Each service against its primary process's resolved BIA and its exceptions there (#463).

    Every read is batched for the whole list: primary processes, their BIA in force (attested
    assessment, organisation baseline, then the legacy projection) and the exceptions.
    """
    process_by_service_id = _primary_process_by_service_id(services, org_id, db)
    processes = list({process.id: process for process in process_by_service_id.values()}.values())
    effective_bia = (
        resolve_effective_process_bia_by_process(db, organization_id=org_id, processes=processes)
        if processes
        else {}
    )
    exceptions = (
        active_bia_exceptions(
            db,
            organization_id=org_id,
            service_ids=[service.id for service in services],
            process_ids=[process.id for process in processes],
        )
        if processes
        else {}
    )
    responses: list[ServiceResponse] = []
    for service in services:
        process = process_by_service_id.get(service.id)
        responses.append(
            ServiceResponse.from_orm(
                service,
                process_bia_answers=effective_bia[process.id].answers if process else None,
                bia_exceptions=exceptions_for(
                    exceptions, service.id, process.id if process else None
                ),
            )
        )
    return responses


def _service_response(service: BusinessService, org_id: int, db: Session) -> ServiceResponse:
    return _service_responses([service], org_id, db)[0]


def _get_service(service_id: str, org_id: int, db: Session) -> BusinessService:
    """Fetch a service, enforcing tenant isolation."""
    service = (
        db.query(BusinessService)
        .filter(BusinessService.id == service_id, BusinessService.organization_id == org_id)
        .first()
    )
    if not service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{service_id}' not found.",
        )
    return service


def _load_dependency_support_data(
    services: list[BusinessService],
    org_id: int,
    db: Session,
) -> tuple[dict[str, Asset], dict[int, int], dict[str, int]]:
    dependency_refs = [
        ref
        for service in services
        for ref in [*(service.l1 or []), *(service.l2 or []), *(service.l3 or [])]
    ]
    asset_ids = _extract_asset_ids(dependency_refs)
    assets = (
        db.query(Asset).filter(Asset.organization_id == org_id, Asset.id.in_(asset_ids)).all()
        if asset_ids
        else []
    )
    signal_count_by_asset_id = _build_signal_count_index(org_id, asset_ids, db)
    threat_count_by_asset_name = _build_threat_count_index(org_id, assets, db)
    return _index_assets_by_ref(assets), signal_count_by_asset_id, threat_count_by_asset_name


def _extract_asset_ids(dependency_refs: list[str]) -> set[int]:
    asset_ids: set[int] = set()
    for ref in dependency_refs:
        raw = ref[6:] if ref.startswith("asset-") else ref
        if raw.isdigit():
            asset_ids.add(int(raw))
    return asset_ids


def _index_assets_by_ref(assets: list[Asset]) -> dict[str, Asset]:
    asset_by_ref: dict[str, Asset] = {}
    for asset in assets:
        asset_by_ref[str(asset.id)] = asset
        asset_by_ref[f"asset-{asset.id}"] = asset
    return asset_by_ref


def _build_signal_count_index(
    org_id: int,
    asset_ids: set[int],
    db: Session,
) -> dict[int, int]:
    if not asset_ids:
        return {}
    rows = (
        db.query(AssetEvidenceSignal)
        .with_entities(AssetEvidenceSignal.asset_id, func.count(AssetEvidenceSignal.id))
        .filter(
            AssetEvidenceSignal.organization_id == org_id,
            AssetEvidenceSignal.asset_id.in_(asset_ids),
        )
        .group_by(AssetEvidenceSignal.asset_id)
        .all()
    )
    return {asset_id: count for asset_id, count in rows}


def _build_threat_count_index(
    org_id: int,
    assets: list[Asset],
    db: Session,
) -> dict[str, int]:
    asset_name_keys = [
        asset.display_name.strip().casefold() for asset in assets if asset.display_name.strip()
    ]
    if not asset_name_keys:
        return {}
    normalized_asset_name = func.lower(func.trim(Threat.asset))
    rows = (
        db.query(Threat)
        .with_entities(normalized_asset_name.label("asset_key"), func.count(Threat.id))
        .filter(
            Threat.organization_id == org_id,
            Threat.status.in_(("detected", "in-progress")),
            normalized_asset_name.in_(asset_name_keys),
        )
        .group_by(normalized_asset_name)
        .all()
    )
    return {asset_key: count for asset_key, count in rows}


def _build_service_dependencies_response(
    service: BusinessService,
    asset_by_ref: dict[str, Asset],
    signal_count_by_asset_id: dict[int, int],
    threat_count_by_asset_name: dict[str, int],
) -> ServiceDependenciesResponse:
    return ServiceDependenciesResponse(
        serviceId=service.id,
        serviceName=service.name,
        tier=service.tier,
        tradingImpact=service.trading_impact,
        financial_exposure=SERVICE_TIER_DEFAULT_FINANCIAL_EXPOSURE.get(
            normalize_service_tier(service.tier)
        ),
        l1=_build_dependency_layer(
            service.l1 or [], asset_by_ref, signal_count_by_asset_id, threat_count_by_asset_name
        ),
        l2=_build_dependency_layer(
            service.l2 or [], asset_by_ref, signal_count_by_asset_id, threat_count_by_asset_name
        ),
        l3=_build_dependency_layer(
            service.l3 or [], asset_by_ref, signal_count_by_asset_id, threat_count_by_asset_name
        ),
    )


def _build_dependency_layer(
    dependency_refs: list[str],
    asset_by_ref: dict[str, Asset],
    signal_count_by_asset_id: dict[int, int],
    threat_count_by_asset_name: dict[str, int],
) -> list[ServiceDependencyItemResponse]:
    items: list[ServiceDependencyItemResponse] = []
    for ref in dependency_refs:
        asset = asset_by_ref.get(ref)
        if asset is None:
            continue
        key = asset.display_name.strip().casefold()
        items.append(
            ServiceDependencyItemResponse(
                id=f"asset-{asset.id}",
                name=asset.display_name,
                type=asset.type,
                owner=_resolve_asset_owner(asset),
                health=_map_asset_health(asset.status),
                is_spof=bool(asset.is_spof),
                signal_count=signal_count_by_asset_id.get(asset.id, 0),
                threat_count=threat_count_by_asset_name.get(key, 0),
            )
        )
    return items


def _resolve_asset_owner(asset: Asset) -> str | None:
    return (
        asset.business_owner_ref
        or asset.technical_owner_ref
        or asset.setup_assignee_ref
        or asset.created_by_ref
    )


def _map_asset_health(status: object) -> str:
    value = getattr(status, "value", status)
    if value == "AT_RISK":
        return "at-risk"
    if value == "PARTIALLY_OBSERVED":
        return "watching"
    return "healthy"
