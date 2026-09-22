from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.api.schemas.risk_intelligence_ingestion import (
    IngestionBatchCreateRequest,
    IngestionBatchDetailResponse,
    IngestionBatchSummaryResponse,
)
from src.api.schemas.risk_intelligence_analysis import AnalysisBatchResponse
from src.api.schemas.risk_intelligence_normalization import NormalizedBatchResponse
from src.core.database import get_db
from src.core.logging_config import get_logger
from src.core.services.risk_intelligence_ingestion_service import (
    create_ingestion_batch,
    get_ingestion_batch,
    list_ingestion_batches,
    serialize_ingestion_batch_detail,
    serialize_ingestion_batch_summary,
)
from src.core.services.risk_intelligence_normalization_service import (
    normalize_ingestion_batch,
    serialize_normalization_result,
)
from src.core.services.risk_intelligence_analysis_service import (
    analyze_normalized_ingestion_batch,
    serialize_analysis_result,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/risk-intelligence/ingestion", tags=["Risk Intelligence Ingestion"])


@router.post("/batches", response_model=IngestionBatchSummaryResponse, status_code=201)
def create_batch(
    body: IngestionBatchCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> IngestionBatchSummaryResponse:
    batch = create_ingestion_batch(
        db,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        source_name=body.sourceName,
        collector_profile=body.collectorProfile,
        raw_payload=body.rawPayload,
        file_name=body.fileName,
        content_type=body.contentType,
    )
    db.commit()
    db.refresh(batch)
    logger.info(
        "risk_intelligence_ingestion_batch_response_created",
        organization_id=ctx.organization_id,
        ingestion_batch_id=batch.id,
    )
    return IngestionBatchSummaryResponse(**serialize_ingestion_batch_summary(batch))


@router.get("/batches/{batch_id}", response_model=IngestionBatchDetailResponse)
def get_batch(
    batch_id: int,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> IngestionBatchDetailResponse:
    batch = get_ingestion_batch(db, organization_id=ctx.organization_id, batch_id=batch_id)
    return IngestionBatchDetailResponse(**serialize_ingestion_batch_detail(batch))


@router.get("/batches", response_model=list[IngestionBatchSummaryResponse])
def list_batches(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[IngestionBatchSummaryResponse]:
    batches = list_ingestion_batches(db, organization_id=ctx.organization_id)
    return [IngestionBatchSummaryResponse(**serialize_ingestion_batch_summary(batch)) for batch in batches]


@router.post("/batches/{batch_id}/normalize", response_model=NormalizedBatchResponse)
def normalize_batch(
    batch_id: int,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> NormalizedBatchResponse:
    result = normalize_ingestion_batch(
        db,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        batch_id=batch_id,
    )
    logger.info(
        "risk_intelligence_ingestion_batch_normalization_response_created",
        organization_id=ctx.organization_id,
        ingestion_batch_id=batch_id,
    )
    return NormalizedBatchResponse(**serialize_normalization_result(result))


@router.post("/batches/{batch_id}/analyze", response_model=AnalysisBatchResponse)
def analyze_batch(
    batch_id: int,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> AnalysisBatchResponse:
    result = analyze_normalized_ingestion_batch(
        db,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        batch_id=batch_id,
    )
    logger.info(
        "risk_intelligence_ingestion_batch_analysis_response_created",
        organization_id=ctx.organization_id,
        ingestion_batch_id=batch_id,
    )
    return AnalysisBatchResponse(**serialize_analysis_result(result))
