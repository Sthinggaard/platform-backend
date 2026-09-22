from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from src.core.constants.risk_intelligence_ingestion import (
    INGESTION_BATCH_CREATED_EVENT,
    INGESTION_BATCH_REVIEWED_EVENT,
)
from src.core.exceptions import ResourceNotFoundError, ValidationError
from src.core.logging_config import get_logger
from src.core.model_defs.common import utcnow
from src.core.models import (
    AuditEvent,
    DecisionRecord,
    Recommendation,
    RiskIngestionBatch,
    RiskIngestionBatchStatus,
    Threat,
)

logger = get_logger(__name__)


def _canonical_json(payload: dict[str, Any] | list[Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _checksum(payload: dict[str, Any] | list[Any]) -> tuple[str, int]:
    canonical = _canonical_json(payload)
    encoded = canonical.encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


def create_ingestion_batch(
    db: Session,
    *,
    organization_id: int,
    actor_user_id: int | None,
    source_name: str,
    collector_profile: str,
    raw_payload: dict[str, Any] | list[Any],
    file_name: str | None = None,
    content_type: str | None = "application/json",
) -> RiskIngestionBatch:
    if not source_name.strip():
        raise ValidationError("sourceName is required")
    if not collector_profile.strip():
        raise ValidationError("collectorProfile is required")
    if raw_payload is None:
        raise ValidationError("rawPayload is required")

    payload_checksum, payload_size = _checksum(raw_payload)
    now = utcnow()
    batch = RiskIngestionBatch(
        organization_id=organization_id,
        source_name=source_name.strip(),
        collector_profile=collector_profile.strip(),
        file_name=file_name.strip() if file_name and file_name.strip() else None,
        content_type=content_type.strip() if content_type and content_type.strip() else "application/json",
        payload_checksum=payload_checksum,
        raw_payload=raw_payload,
        raw_payload_size_bytes=payload_size,
        status=RiskIngestionBatchStatus.RECEIVED,
        received_at=now,
        updated_at=now,
    )
    db.add(batch)
    db.flush()
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            event_type=INGESTION_BATCH_CREATED_EVENT,
            metadata_json={
                "ingestionBatchId": batch.id,
                "sourceName": batch.source_name,
                "collectorProfile": batch.collector_profile,
                "payloadChecksum": batch.payload_checksum,
                "payloadSizeBytes": batch.raw_payload_size_bytes,
                "status": batch.status.value,
            },
        )
    )
    logger.info(
        "risk_intelligence_ingestion_batch_created",
        organization_id=organization_id,
        ingestion_batch_id=batch.id,
        source_name=batch.source_name,
        collector_profile=batch.collector_profile,
    )
    return batch


def get_ingestion_batch(db: Session, *, organization_id: int, batch_id: int) -> RiskIngestionBatch:
    batch = db.get(RiskIngestionBatch, batch_id)
    if not batch or batch.organization_id != organization_id:
        raise ResourceNotFoundError("Ingestion batch not found")
    return batch


def list_ingestion_batches(db: Session, *, organization_id: int) -> list[RiskIngestionBatch]:
    batches = [
        batch
        for batch in db.query(RiskIngestionBatch).all()
        if batch.organization_id == organization_id
    ]
    return sorted(
        batches,
        key=lambda batch: (batch.received_at, batch.updated_at, batch.id),
        reverse=True,
    )


def close_ingestion_batch_after_decision(
    db: Session,
    *,
    organization_id: int,
    actor_user_id: int | None,
    recommendation: Recommendation,
    threat: Threat | None,
    decision_record: DecisionRecord,
) -> RiskIngestionBatch | None:
    batch_id = _extract_ingestion_batch_id(threat)
    if batch_id is None:
        return None

    batch = db.get(RiskIngestionBatch, batch_id)
    if not batch or batch.organization_id != organization_id:
        logger.warning(
            "risk_intelligence_ingestion_batch_closeout_missing",
            organization_id=organization_id,
            ingestion_batch_id=batch_id,
            recommendation_id=recommendation.id,
            decision_id=decision_record.id,
        )
        return None

    closed_at = utcnow()
    batch.status = RiskIngestionBatchStatus.REVIEWED
    batch.decision_evidence = _build_decision_evidence(
        batch=batch,
        recommendation=recommendation,
        threat=threat,
        decision_record=decision_record,
        closed_at=closed_at,
    )
    batch.updated_at = closed_at
    db.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            event_type=INGESTION_BATCH_REVIEWED_EVENT,
            metadata_json={
                "ingestionBatchId": batch.id,
                "recommendationId": recommendation.id,
                "decisionId": decision_record.id,
                "threatId": decision_record.threat_id,
                "status": batch.status.value,
                "selectedAction": decision_record.selected_action,
                "decisionType": decision_record.decision_type,
                "reviewDate": decision_record.review_date,
                "integrationRef": decision_record.integration_ref,
                "integrationProvider": decision_record.integration_provider,
                "externalUrl": decision_record.external_url,
                "closedAt": closed_at.isoformat(),
            },
        )
    )
    logger.info(
        "risk_intelligence_ingestion_batch_reviewed",
        organization_id=organization_id,
        ingestion_batch_id=batch.id,
        recommendation_id=recommendation.id,
        decision_id=decision_record.id,
        batch_status=batch.status.value,
    )
    return batch


def serialize_ingestion_batch_summary(batch: RiskIngestionBatch) -> dict[str, Any]:
    return {
        "ingestionBatchId": batch.id,
        "organizationId": batch.organization_id,
        "sourceName": batch.source_name,
        "collectorProfile": batch.collector_profile,
        "fileName": batch.file_name,
        "contentType": batch.content_type,
        "payloadChecksum": batch.payload_checksum,
        "rawPayloadSizeBytes": batch.raw_payload_size_bytes,
        "status": batch.status.value,
        "receivedAt": batch.received_at.isoformat(),
        "updatedAt": batch.updated_at.isoformat(),
        "errorMessage": batch.error_message,
        "decisionEvidence": batch.decision_evidence,
    }


def serialize_ingestion_batch_detail(batch: RiskIngestionBatch) -> dict[str, Any]:
    payload = serialize_ingestion_batch_summary(batch)
    payload["rawPayload"] = batch.raw_payload
    return payload


def _extract_ingestion_batch_id(threat: Threat | None) -> int | None:
    if not threat:
        return None
    intelligence = threat.intelligence if isinstance(threat.intelligence, dict) else {}
    batch_id = intelligence.get("ingestionBatchId")
    return batch_id if isinstance(batch_id, int) else None


def _build_decision_evidence(
    *,
    batch: RiskIngestionBatch,
    recommendation: Recommendation,
    threat: Threat | None,
    decision_record: DecisionRecord,
    closed_at: datetime,
) -> dict[str, Any]:
    selected_action = decision_record.selected_action
    decision_type = decision_record.decision_type
    rationale = decision_record.rationale
    decided_by = decision_record.decided_by
    decided_role = decision_record.decided_role
    decision_summary = (
        f"{selected_action} decision recorded by {decided_by}"
        if decided_role is None
        else f"{selected_action} decision recorded by {decided_by} ({decided_role})"
    )
    return {
        "ingestionBatchId": batch.id,
        "batchStatus": RiskIngestionBatchStatus.REVIEWED.value,
        "sourceName": batch.source_name,
        "collectorProfile": batch.collector_profile,
        "threatId": threat.id if threat else decision_record.threat_id,
        "recommendationId": recommendation.id,
        "decisionId": decision_record.id,
        "selectedAction": selected_action,
        "decisionType": decision_type,
        "decidedBy": decided_by,
        "decidedRole": decided_role,
        "reviewDate": decision_record.review_date,
        "integrationRef": decision_record.integration_ref,
        "integrationProvider": decision_record.integration_provider,
        "externalUrl": decision_record.external_url,
        "recoveryActionId": decision_record.recovery_action_id,
        "rationale": rationale,
        "decisionSummary": decision_summary,
        "closedAt": closed_at.isoformat(),
    }
