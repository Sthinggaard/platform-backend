from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import risk_intelligence_ingestion as ingestion_routes
from src.api.schemas.risk_intelligence_ingestion import IngestionBatchCreateRequest
from src.core.constants.risk_intelligence_ingestion import (
    DEFAULT_COLLECTOR_PROFILE,
    INGESTION_BATCH_CREATED_EVENT,
    INGESTION_BATCH_REVIEWED_EVENT,
)
from src.core.exceptions import ResourceNotFoundError
from src.core.models import AuditEvent, RiskIngestionBatch, RiskIngestionBatchStatus
from src.core.services import risk_intelligence_ingestion_service as service
from src.core.services.risk_intelligence_analysis_service import (
    AnalysisFindingSummary,
    AnalysisResult,
)


class DummyDB:
    def __init__(
        self,
        batch: RiskIngestionBatch | None = None,
        *,
        batches: list[RiskIngestionBatch] | None = None,
    ) -> None:
        self.added: list[object] = []
        self.commit_calls = 0
        self.refresh_calls = 0
        self.flush_calls = 0
        self._batch = batch
        self._batches = list(batches) if batches is not None else ([batch] if batch else [])

    def add(self, obj: object) -> None:
        self.added.append(obj)

    def flush(self) -> None:
        self.flush_calls += 1
        for index, obj in enumerate(self.added, start=1):
            if getattr(obj, "id", None) is None:
                setattr(obj, "id", index)

    def commit(self) -> None:
        self.commit_calls += 1

    def refresh(self, _obj: object) -> None:
        self.refresh_calls += 1

    def get(self, _model: object, _ident: object) -> RiskIngestionBatch | None:
        if self._batch is None:
            return None
        return self._batch if getattr(self._batch, "id", None) == _ident else None

    def query(self, _model: object) -> SimpleNamespace:
        return SimpleNamespace(all=lambda: list(self._batches))


def _ctx(organization_id: int = 42) -> TenantContext:
    return TenantContext(
        user_id=7,
        organization_id=organization_id,
        email="ciso@risklence.test",
        roles=["ciso"],
        permissions=[],
    )


def _payload() -> dict[str, object]:
    return {
        "hosts": [
            {
                "hostname": "app.example.com",
                "ip": "203.0.113.10",
                "services": [{"port": 443, "protocol": "tcp", "name": "https"}],
            }
        ],
        "findings": [
            {
                "id": "nuclei-cve-2026-0001",
                "severity": "high",
                "title": "Outdated TLS configuration",
            }
        ],
    }


def test_create_ingestion_batch_persists_checksum_and_audit():
    db = DummyDB()
    payload = _payload()
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    batch = service.create_ingestion_batch(
        db,
        organization_id=42,
        actor_user_id=7,
        source_name="telia_full_report.json",
        collector_profile=DEFAULT_COLLECTOR_PROFILE,
        raw_payload=payload,
    )

    assert batch.id == 1
    assert batch.organization_id == 42
    assert batch.source_name == "telia_full_report.json"
    assert batch.collector_profile == DEFAULT_COLLECTOR_PROFILE
    assert batch.payload_checksum == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert batch.raw_payload_size_bytes == len(canonical.encode("utf-8"))
    assert batch.status == RiskIngestionBatchStatus.RECEIVED
    assert batch.received_at.tzinfo is not None
    assert db.flush_calls == 1
    assert db.commit_calls == 0
    audit_event = next(obj for obj in db.added if isinstance(obj, AuditEvent))
    assert audit_event.event_type == INGESTION_BATCH_CREATED_EVENT
    assert audit_event.metadata_json["ingestionBatchId"] == 1
    assert audit_event.metadata_json["payloadChecksum"] == batch.payload_checksum


def test_get_ingestion_batch_rejects_cross_tenant_scope():
    batch = RiskIngestionBatch(
        id=10,
        organization_id=99,
        source_name="telia_full_report.json",
        collector_profile=DEFAULT_COLLECTOR_PROFILE,
        file_name="telia_full_report.json",
        content_type="application/json",
        payload_checksum="a" * 64,
        raw_payload=_payload(),
        raw_payload_size_bytes=128,
        status=RiskIngestionBatchStatus.RECEIVED,
        received_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    with pytest.raises(ResourceNotFoundError):
        service.get_ingestion_batch(DummyDB(batch), organization_id=42, batch_id=10)


def test_list_ingestion_batches_filters_and_sorts_by_recency():
    older = RiskIngestionBatch(
        id=3,
        organization_id=42,
        source_name="older.json",
        collector_profile=DEFAULT_COLLECTOR_PROFILE,
        file_name="older.json",
        content_type="application/json",
        payload_checksum="1" * 64,
        raw_payload=_payload(),
        raw_payload_size_bytes=256,
        status=RiskIngestionBatchStatus.RECEIVED,
        received_at=datetime(2026, 5, 13, 8, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 5, 13, 8, 5, tzinfo=timezone.utc),
    )
    newer = RiskIngestionBatch(
        id=7,
        organization_id=42,
        source_name="newer.json",
        collector_profile=DEFAULT_COLLECTOR_PROFILE,
        file_name="newer.json",
        content_type="application/json",
        payload_checksum="2" * 64,
        raw_payload=_payload(),
        raw_payload_size_bytes=256,
        status=RiskIngestionBatchStatus.REVIEWED,
        received_at=datetime(2026, 5, 13, 9, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 5, 13, 9, 5, tzinfo=timezone.utc),
    )
    foreign = RiskIngestionBatch(
        id=9,
        organization_id=99,
        source_name="foreign.json",
        collector_profile=DEFAULT_COLLECTOR_PROFILE,
        file_name="foreign.json",
        content_type="application/json",
        payload_checksum="3" * 64,
        raw_payload=_payload(),
        raw_payload_size_bytes=256,
        status=RiskIngestionBatchStatus.RECEIVED,
        received_at=datetime(2026, 5, 13, 10, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 5, 13, 10, 5, tzinfo=timezone.utc),
    )

    batches = service.list_ingestion_batches(DummyDB(batches=[older, foreign, newer]), organization_id=42)

    assert [batch.id for batch in batches] == [7, 3]


def test_create_batch_returns_summary_and_commits(monkeypatch):
    batch = RiskIngestionBatch(
        id=17,
        organization_id=42,
        source_name="telia_full_report.json",
        collector_profile=DEFAULT_COLLECTOR_PROFILE,
        file_name="telia_full_report.json",
        content_type="application/json",
        payload_checksum="b" * 64,
        raw_payload=_payload(),
        raw_payload_size_bytes=256,
        status=RiskIngestionBatchStatus.RECEIVED,
        received_at=datetime(2026, 5, 13, 8, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 5, 13, 8, 1, tzinfo=timezone.utc),
    )

    monkeypatch.setattr(ingestion_routes, "create_ingestion_batch", lambda *args, **kwargs: batch)
    db = DummyDB(batch)

    response = ingestion_routes.create_batch(
        body=IngestionBatchCreateRequest(
            sourceName="telia_full_report.json",
            collectorProfile=DEFAULT_COLLECTOR_PROFILE,
            fileName="telia_full_report.json",
            contentType="application/json",
            rawPayload=_payload(),
        ),
        ctx=_ctx(),
        db=db,
    )

    assert response.ingestionBatchId == 17
    assert response.organizationId == 42
    assert response.sourceName == "telia_full_report.json"
    assert response.collectorProfile == DEFAULT_COLLECTOR_PROFILE
    assert response.status == RiskIngestionBatchStatus.RECEIVED.value
    assert db.commit_calls == 1
    assert db.refresh_calls == 1


def test_list_batches_returns_ordered_summaries(monkeypatch):
    older = RiskIngestionBatch(
        id=18,
        organization_id=42,
        source_name="older.json",
        collector_profile=DEFAULT_COLLECTOR_PROFILE,
        file_name="older.json",
        content_type="application/json",
        payload_checksum="4" * 64,
        raw_payload=_payload(),
        raw_payload_size_bytes=256,
        status=RiskIngestionBatchStatus.RECEIVED,
        received_at=datetime(2026, 5, 13, 8, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 5, 13, 8, 5, tzinfo=timezone.utc),
    )
    newer = RiskIngestionBatch(
        id=19,
        organization_id=42,
        source_name="newer.json",
        collector_profile=DEFAULT_COLLECTOR_PROFILE,
        file_name="newer.json",
        content_type="application/json",
        payload_checksum="5" * 64,
        raw_payload=_payload(),
        raw_payload_size_bytes=256,
        status=RiskIngestionBatchStatus.REVIEWED,
        received_at=datetime(2026, 5, 13, 9, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 5, 13, 9, 5, tzinfo=timezone.utc),
    )

    monkeypatch.setattr(ingestion_routes, "list_ingestion_batches", lambda *args, **kwargs: [older, newer])

    response = ingestion_routes.list_batches(
        ctx=_ctx(),
        db=DummyDB(batches=[older, newer]),
    )

    assert [batch.ingestionBatchId for batch in response] == [18, 19]
    assert response[0].decisionEvidence is None


def test_get_batch_returns_raw_payload(monkeypatch):
    batch = RiskIngestionBatch(
        id=21,
        organization_id=42,
        source_name="telia_full_report.json",
        collector_profile=DEFAULT_COLLECTOR_PROFILE,
        file_name="telia_full_report.json",
        content_type="application/json",
        payload_checksum="c" * 64,
        raw_payload=_payload(),
        raw_payload_size_bytes=256,
        status=RiskIngestionBatchStatus.NEEDS_REVIEW,
        received_at=datetime(2026, 5, 13, 8, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 5, 13, 8, 15, tzinfo=timezone.utc),
    )

    monkeypatch.setattr(ingestion_routes, "get_ingestion_batch", lambda *args, **kwargs: batch)

    response = ingestion_routes.get_batch(
        batch_id=21,
        ctx=_ctx(),
        db=DummyDB(batch),
    )

    assert response.ingestionBatchId == 21
    assert response.status == RiskIngestionBatchStatus.NEEDS_REVIEW.value
    assert response.rawPayload == _payload()


def test_close_ingestion_batch_after_decision_records_evidence_and_audit():
    batch = RiskIngestionBatch(
        id=31,
        organization_id=42,
        source_name="telia_full_report.json",
        collector_profile=DEFAULT_COLLECTOR_PROFILE,
        file_name="telia_full_report.json",
        content_type="application/json",
        payload_checksum="d" * 64,
        raw_payload=_payload(),
        raw_payload_size_bytes=256,
        status=RiskIngestionBatchStatus.NEEDS_REVIEW,
        received_at=datetime(2026, 5, 13, 8, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 5, 13, 8, 15, tzinfo=timezone.utc),
    )
    db = DummyDB(batch)
    recommendation = SimpleNamespace(id="rec-1")
    threat = SimpleNamespace(id="threat-1", intelligence={"ingestionBatchId": 31})
    decision_record = SimpleNamespace(
        id="decision-1",
        recommendation_id="rec-1",
        threat_id="threat-1",
        selected_action="servicenow",
        decision_type="alternative",
        rationale="The issue should be routed to operations.",
        decided_by="ciso@risklence.test",
        decided_role="ciso",
        review_date="2026-05-20",
        integration_ref="CHG-123",
        integration_provider="servicenow",
        external_url="https://servicenow.example/change/CHG-123",
        recovery_action_id=77,
    )

    closed_batch = service.close_ingestion_batch_after_decision(
        db,
        organization_id=42,
        actor_user_id=7,
        recommendation=recommendation,
        threat=threat,
        decision_record=decision_record,
    )

    assert closed_batch is batch
    assert batch.status == RiskIngestionBatchStatus.REVIEWED
    assert batch.decision_evidence is not None
    assert batch.decision_evidence["ingestionBatchId"] == 31
    assert batch.decision_evidence["decisionId"] == "decision-1"
    assert batch.decision_evidence["batchStatus"] == RiskIngestionBatchStatus.REVIEWED.value
    audit_event = next(obj for obj in db.added if isinstance(obj, AuditEvent))
    assert audit_event.event_type == INGESTION_BATCH_REVIEWED_EVENT
    assert audit_event.actor_user_id == 7
    assert audit_event.metadata_json["decisionId"] == "decision-1"


def test_serialize_ingestion_batch_includes_decision_evidence():
    batch = RiskIngestionBatch(
        id=41,
        organization_id=42,
        source_name="telia_full_report.json",
        collector_profile=DEFAULT_COLLECTOR_PROFILE,
        file_name="telia_full_report.json",
        content_type="application/json",
        payload_checksum="e" * 64,
        raw_payload=_payload(),
        raw_payload_size_bytes=256,
        status=RiskIngestionBatchStatus.REVIEWED,
        received_at=datetime(2026, 5, 13, 8, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 5, 13, 8, 30, tzinfo=timezone.utc),
        decision_evidence={
            "ingestionBatchId": 41,
            "batchStatus": RiskIngestionBatchStatus.REVIEWED.value,
            "decisionId": "decision-41",
        },
    )

    summary = service.serialize_ingestion_batch_summary(batch)
    detail = service.serialize_ingestion_batch_detail(batch)

    assert summary["decisionEvidence"] == batch.decision_evidence
    assert detail["decisionEvidence"] == batch.decision_evidence


def test_analyze_batch_returns_summary(monkeypatch):
    result = AnalysisResult(
        ingestion_batch_id=21,
        organization_id=42,
        batch_status=RiskIngestionBatchStatus.ANALYZED,
        analyzed_at=datetime(2026, 5, 13, 8, 20, tzinfo=timezone.utc),
        technical_summary="Analyzed 1 normalized finding and generated 1 recommendation.",
        human_decision_required=True,
        finding_count=1,
        high_severity_finding_count=1,
        threat_count=1,
        recommendation_count=1,
        findings=[
            AnalysisFindingSummary(
                finding_id=5,
                asset_id=9,
                asset_name="app.example.com",
                severity="high",
                threat_id="threat-1",
                recommendation_id="rec-1",
                business_consequence="Business operations are significantly disrupted.",
                suggested_action="Patch the exposed asset, rescan to confirm, and route the issue to the business owner for review.",
                evidence_refs=["ingestion-batch:21"],
            )
        ],
    )

    monkeypatch.setattr(ingestion_routes, "analyze_normalized_ingestion_batch", lambda *args, **kwargs: result)

    response = ingestion_routes.analyze_batch(
        batch_id=21,
        ctx=_ctx(),
        db=DummyDB(),
    )

    assert response.ingestionBatchId == 21
    assert response.batchStatus == RiskIngestionBatchStatus.ANALYZED.value
    assert response.humanDecisionRequired is True
    assert response.threatCount == 1
    assert response.recommendationCount == 1
    assert response.findings[0].threatId == "threat-1"
    assert response.findings[0].recommendationId == "rec-1"


def test_analyze_batch_propagates_missing_batch(monkeypatch):
    monkeypatch.setattr(
        ingestion_routes,
        "analyze_normalized_ingestion_batch",
        lambda *args, **kwargs: (_ for _ in ()).throw(ResourceNotFoundError("Ingestion batch not found")),
    )

    with pytest.raises(ResourceNotFoundError):
        ingestion_routes.analyze_batch(
            batch_id=999,
            ctx=_ctx(),
            db=DummyDB(),
        )
