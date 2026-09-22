"""Evidence Source: creation/ownership, scope, file-upload import, manual
entry + degraded exception path, readiness, tenant isolation."""

from __future__ import annotations

import io
from datetime import datetime, timedelta

import pytest
from fastapi import UploadFile
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import ARRAY as PgArray
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.sqltypes import ARRAY as SqlArray

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import evidence_source as evidence_source_routes
from src.core.constants.evidence_source_enums import (
    EVIDENCE_SOURCE_AUDIT_COMPLETED,
    EvidenceSourceExceptionReasonCode,
    EvidenceSourceScopeType,
    EvidenceSourceType,
)
from src.core.database import Base
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.evidence_source import (
    EvidenceImportBatch,
    EvidenceManualEntry,
    EvidenceReceipt,
    EvidenceSource,
    EvidenceSourceException,
    EvidenceSourceScope,
)
from src.core.models import AuditEvent, Organization, User
from src.core.services.evidence_source_readiness_service import (
    build_prepared_evidence_sources,
    evaluate_evidence_source_readiness,
    evaluate_source_health_signals,
)
from src.core.services.evidence_source_service import (
    EvidenceSourceValidationError,
    add_manual_evidence_entry,
    confirm_import_mapping,
    confirm_scope,
    create_evidence_source,
    create_exception,
    save_scope,
    upload_import_file,
)


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, (SqlArray, PgArray, JSONB)):
                column.type = SqliteJSON()
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            User.__table__,
            EvidenceSource.__table__,
            EvidenceSourceScope.__table__,
            EvidenceImportBatch.__table__,
            EvidenceReceipt.__table__,
            EvidenceManualEntry.__table__,
            EvidenceSourceException.__table__,
            AuditEvent.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            Organization(id=1, name="Org", slug="org", country="DK", technical_setup_owner_user_id=1),
            Organization(id=2, name="Other Org", slug="other-org", country="DK"),
            User(id=1, organization_id=1, email="admin@example.com", role="org_admin"),
            User(id=2, organization_id=1, email="member@example.com", role="member"),
            User(id=3, organization_id=2, email="admin2@example.com", role="org_admin"),
        ]
    )
    session.commit()
    yield session
    session.close()


def _ctx(user_id: int, organization_id: int = 1, role: str = "org_admin") -> TenantContext:
    return TenantContext(
        user_id=user_id, organization_id=organization_id, email="x@example.com", roles=[role], permissions=[]
    )


def _confirmed_scope(db: Session, source: EvidenceSource) -> EvidenceSourceScope:
    scope = save_scope(db, source, scope_type=EvidenceSourceScopeType.ENTIRE_ORGANISATION)
    confirm_scope(db, scope, confirmed_by_user_id=1)
    db.commit()
    return scope


# --- Creation / ownership --------------------------------------------------------


def test_create_requires_a_name(db: Session):
    with pytest.raises(EvidenceSourceValidationError):
        create_evidence_source(db, organization_id=1, name="   ", source_type=EvidenceSourceType.MANUAL)


def test_create_defaults_owner_to_technical_setup_owner(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Manual log", source_type=EvidenceSourceType.MANUAL)
    assert source.owner_user_id == 1
    assert source.mode == "manual"


def test_create_requires_owner_or_technical_setup_owner(db: Session):
    org = db.query(Organization).filter(Organization.id == 2).first()
    assert org.technical_setup_owner_user_id is None
    with pytest.raises(EvidenceSourceValidationError):
        create_evidence_source(db, organization_id=2, name="Manual log", source_type=EvidenceSourceType.MANUAL)


def test_file_import_source_has_snapshot_mode(db: Session):
    source = create_evidence_source(
        db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT
    )
    assert source.mode == "snapshot"


# --- Scope -------------------------------------------------------------------------


def test_scope_save_and_confirm(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    scope = save_scope(db, source, scope_type=EvidenceSourceScopeType.COUNTRIES, country_codes=["DK"])
    assert scope.status == "draft"
    confirm_scope(db, scope, confirmed_by_user_id=1)
    assert scope.status == "confirmed"
    assert scope.confirmed_by_user_id == 1


def test_editing_scope_resets_confirmation(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    scope = _confirmed_scope(db, source)
    assert scope.status == "confirmed"
    scope = save_scope(db, source, scope_type=EvidenceSourceScopeType.COUNTRIES, country_codes=["DK"])
    assert scope.status == "draft"
    assert scope.confirmed_by_user_id is None


# --- File / CMDB upload -------------------------------------------------------------


def _csv_bytes(header: str, rows: list[str]) -> bytes:
    return ("\n".join([header, *rows]) + "\n").encode()


def test_upload_detects_columns_and_suggests_mapping(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    content = _csv_bytes("Display Name,Environment", ["POS-DB01,production"])
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    assert batch.status == "mapping_required"
    assert batch.detected_columns == ["Display Name", "Environment"]
    # Case/space-insensitive header matching against the standard vocabulary.
    assert batch.column_mapping["Display Name"] == "displayName"
    assert batch.column_mapping["Environment"] == "environment"


def test_upload_suggests_mapping_from_common_synonyms_not_just_exact_names(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    content = _csv_bytes(
        "name,owner,criticality,artefact_type,status",
        ["mes-aalborg-01,Henrik Olsen,High,Manufacturing system,Discovered"],
    )
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    assert batch.column_mapping["name"] == "displayName"
    assert batch.column_mapping["owner"] == "declaredOwner"
    assert batch.column_mapping["criticality"] == "declaredCriticality"
    assert batch.column_mapping["artefact_type"] == "sourceType"
    # "status" has no equivalent standard field — must not be fabricated.
    assert batch.column_mapping["status"] is None


def test_upload_suggests_mapping_for_representative_servicenow_style_cmdb_headers(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    content = _csv_bytes(
        "name,ci_class,environment,business_criticality,owner_email,managed_by_group,support_group,depends_on,last_updated,ip_address",
        ["SAP S/4HANA Production,Enterprise Application,Production,Critical,eva.nielsen@example.com,Business Applications,Business Applications,DB-HANA-01,2026-07-17,"],
    )
    batch = upload_import_file(db, source, filename="cmdb_export.csv", content_bytes=content, uploaded_by_user_id=1)
    assert batch.column_mapping["name"] == "displayName"
    assert batch.column_mapping["ci_class"] == "sourceType"
    assert batch.column_mapping["environment"] == "environment"
    assert batch.column_mapping["business_criticality"] == "declaredCriticality"
    assert batch.column_mapping["owner_email"] == "declaredOwner"
    assert batch.column_mapping["managed_by_group"] == "supportGroup"
    assert batch.column_mapping["support_group"] == "supportGroup"
    assert batch.column_mapping["depends_on"] == "relationshipTarget"
    assert batch.column_mapping["last_updated"] == "sourceReviewedAt"
    # A field this vocabulary genuinely has no equivalent for must stay unmapped.
    assert batch.column_mapping["ip_address"] is None


def test_upload_rejects_oversized_file(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    oversized = b"a" * (5 * 1024 * 1024 + 1)
    with pytest.raises(EvidenceSourceValidationError, match="5 MB"):
        upload_import_file(db, source, filename="export.csv", content_bytes=oversized, uploaded_by_user_id=1)


def test_upload_rejects_too_many_rows(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    rows = [f"item-{i},production" for i in range(5_001)]
    content = _csv_bytes("displayName,environment", rows)
    with pytest.raises(EvidenceSourceValidationError, match="5,000 row"):
        upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)


def test_upload_rejects_unsupported_extension(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    with pytest.raises(EvidenceSourceValidationError, match="CSV or XLSX"):
        upload_import_file(db, source, filename="notes.txt", content_bytes=b"hello", uploaded_by_user_id=1)


def test_upload_rejects_unreadable_xlsx(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    with pytest.raises(EvidenceSourceValidationError, match="CSV or XLSX"):
        upload_import_file(
            db, source, filename="export.xlsx", content_bytes=b"not a real workbook", uploaded_by_user_id=1
        )


def test_upload_sanitises_formula_injection_cells(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    content = _csv_bytes("displayName,environment", ['=cmd|"/c calc"!A1,production'])
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    assert batch.parsed_rows_json[0]["displayName"].startswith("'=")


def test_confirm_mapping_requires_display_name_mapped(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    content = _csv_bytes("name,environment", ["POS-DB01,production"])
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    with pytest.raises(EvidenceSourceValidationError, match="displayName"):
        confirm_import_mapping(db, batch, column_mapping={"environment": "environment"}, confirmed_by_user_id=1)


def test_confirm_mapping_clean_completes_and_marks_source_healthy(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    content = _csv_bytes("displayName,environment", ["POS-DB01,production", "POS-DB02,production"])
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    confirm_import_mapping(
        db, batch, column_mapping={"displayName": "displayName", "environment": "environment"}, confirmed_by_user_id=1
    )
    assert batch.status == "completed"
    assert batch.accepted_rows == 2
    db.refresh(source)
    assert source.status == "healthy"
    assert source.first_evidence_received_at is not None
    receipts = db.query(EvidenceReceipt).filter(EvidenceReceipt.evidence_source_id == source.id).all()
    assert len(receipts) == 1
    assert receipts[0].record_count == 2


def test_confirm_mapping_with_duplicates_completes_with_warnings_and_degrades_source(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    content = _csv_bytes("displayName", ["POS-DB01", "pos-db01"])
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    confirm_import_mapping(db, batch, column_mapping={"displayName": "displayName"}, confirmed_by_user_id=1)
    assert batch.status == "completed_with_warnings"
    assert batch.warning_rows == 1
    db.refresh(source)
    assert source.status == "degraded"


def test_confirm_mapping_all_rows_missing_display_name_fails(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    content = _csv_bytes("displayName,environment", [",production", ",production"])
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    confirm_import_mapping(
        db, batch, column_mapping={"displayName": "displayName", "environment": "environment"}, confirmed_by_user_id=1
    )
    assert batch.status == "failed"
    db.refresh(source)
    assert source.status == "failed"
    assert db.query(EvidenceReceipt).filter(EvidenceReceipt.evidence_source_id == source.id).first() is None


# --- Manual entry + degraded exception path -----------------------------------------


def test_manual_entry_creates_receipt_and_degrades_source(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Manual log", source_type=EvidenceSourceType.MANUAL)
    entry = add_manual_evidence_entry(db, source, description="Known dependency: payment gateway", entered_by_user_id=1)
    assert entry.description.startswith("Known dependency")
    db.refresh(source)
    assert source.status == "degraded"
    assert source.first_evidence_received_at is not None
    receipts = db.query(EvidenceReceipt).filter(EvidenceReceipt.evidence_source_id == source.id).all()
    assert len(receipts) == 1
    assert receipts[0].record_count == 1


def test_manual_entry_requires_description(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Manual log", source_type=EvidenceSourceType.MANUAL)
    with pytest.raises(EvidenceSourceValidationError):
        add_manual_evidence_entry(db, source, description="   ", entered_by_user_id=1)


# --- Readiness -----------------------------------------------------------------------


def test_readiness_missing_when_no_sources(db: Session):
    result = evaluate_evidence_source_readiness(db, 1)
    assert result.ready is False
    assert result.readiness.value == "missing"
    assert "no_evidence_source_created" in result.missing_reasons


def test_readiness_manual_entry_alone_is_not_functioning(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Manual log", source_type=EvidenceSourceType.MANUAL)
    _confirmed_scope(db, source)
    add_manual_evidence_entry(db, source, description="Known dependency", entered_by_user_id=1)
    db.commit()

    result = evaluate_evidence_source_readiness(db, 1)
    assert result.ready is False
    assert source.id in result.blocked_source_ids
    assert "no_functioning_evidence_source" in result.missing_reasons


def test_readiness_manual_entry_with_approved_exception_is_functioning_but_degraded(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Manual log", source_type=EvidenceSourceType.MANUAL)
    _confirmed_scope(db, source)
    add_manual_evidence_entry(db, source, description="Known dependency", entered_by_user_id=1)
    create_exception(
        db,
        source,
        reason_code=EvidenceSourceExceptionReasonCode.PILOT_SCOPE,
        description="Piloting with a small, manually-declared scope while the collector is procured.",
        approved_by_user_id=1,
        review_at=datetime.utcnow() + timedelta(days=30),
    )
    db.commit()

    result = evaluate_evidence_source_readiness(db, 1)
    assert result.ready is True
    assert result.readiness.value == "degraded"
    assert source.id in result.functioning_source_ids
    assert source.id in result.degraded_source_ids
    assert source.id not in result.healthy_source_ids


def test_readiness_expired_exception_does_not_count(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Manual log", source_type=EvidenceSourceType.MANUAL)
    _confirmed_scope(db, source)
    add_manual_evidence_entry(db, source, description="Known dependency", entered_by_user_id=1)
    create_exception(
        db,
        source,
        reason_code=EvidenceSourceExceptionReasonCode.PILOT_SCOPE,
        description="Already past its review date.",
        approved_by_user_id=1,
        review_at=datetime.utcnow() - timedelta(days=1),
    )
    db.commit()

    result = evaluate_evidence_source_readiness(db, 1)
    assert result.ready is False


def test_readiness_healthy_file_import_source_is_ready(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    _confirmed_scope(db, source)
    content = _csv_bytes("displayName", ["POS-DB01"])
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    confirm_import_mapping(db, batch, column_mapping={"displayName": "displayName"}, confirmed_by_user_id=1)
    db.commit()

    result = evaluate_evidence_source_readiness(db, 1)
    assert result.ready is True
    assert result.readiness.value == "ready"
    assert source.id in result.healthy_source_ids


def test_prepared_evidence_sources_shape(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    _confirmed_scope(db, source)
    content = _csv_bytes("displayName", ["POS-DB01"])
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    confirm_import_mapping(db, batch, column_mapping={"displayName": "displayName"}, confirmed_by_user_id=1)
    db.commit()

    prepared = build_prepared_evidence_sources(db, 1)
    assert prepared.readiness.value == "ready"
    assert len(prepared.sources) == 1
    assert prepared.sources[0].healthy is True
    assert prepared.sources[0].owner_user_id == 1
    assert prepared.sources[0].scope_id is not None
    assert prepared.sources[0].health_status.value == "healthy"
    assert prepared.sources[0].first_evidence_received_at is not None
    assert prepared.active_exceptions == []


# --- Health signals ---------------------------------------------------------------


def test_health_signals_pending_before_anything_happens(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    db.commit()

    signals = evaluate_source_health_signals(db, source, now=datetime.utcnow())
    assert signals.status.value == "pending"
    assert signals.evidence_received is False
    assert "No responsible owner has been assigned." not in signals.reasons  # owner defaults to TSO
    assert "The source scope has not been confirmed." in signals.reasons
    assert "No evidence has been received from this source yet." in signals.reasons


def test_health_signals_healthy_for_a_clean_completed_import(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    _confirmed_scope(db, source)
    content = _csv_bytes("displayName", ["POS-DB01"])
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    confirm_import_mapping(db, batch, column_mapping={"displayName": "displayName"}, confirmed_by_user_id=1)
    db.commit()

    signals = evaluate_source_health_signals(db, source, now=datetime.utcnow())
    assert signals.status.value == "healthy"
    assert signals.evidence_fresh is True
    assert signals.schema_compatible is True
    assert signals.reasons == []


def test_health_signals_degraded_when_stale(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    _confirmed_scope(db, source)
    content = _csv_bytes("displayName", ["POS-DB01"])
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    confirm_import_mapping(db, batch, column_mapping={"displayName": "displayName"}, confirmed_by_user_id=1)
    db.commit()

    # Force the source well past the 90-day default staleness threshold.
    source.last_successful_sync_at = datetime.utcnow() - timedelta(days=120)
    db.add(source)
    db.commit()

    signals = evaluate_source_health_signals(db, source, now=datetime.utcnow())
    assert signals.status.value == "degraded"
    assert signals.evidence_fresh is False
    assert any("exceeding the 90-day freshness policy" in r for r in signals.reasons)


def test_health_signals_respects_explicit_freshness_override(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    _confirmed_scope(db, source)
    content = _csv_bytes("displayName", ["POS-DB01"])
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    confirm_import_mapping(db, batch, column_mapping={"displayName": "displayName"}, confirmed_by_user_id=1)
    source.stale_after_hours = 24 * 5  # override: stale after only 5 days
    source.last_successful_sync_at = datetime.utcnow() - timedelta(days=10)
    db.add(source)
    db.commit()

    signals = evaluate_source_health_signals(db, source, now=datetime.utcnow())
    assert signals.evidence_fresh is False
    assert any("exceeding the 5-day freshness policy" in r for r in signals.reasons)


def test_health_signals_disabled_source(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Manual log", source_type=EvidenceSourceType.MANUAL)
    source.status = "disabled"
    db.add(source)
    db.commit()

    signals = evaluate_source_health_signals(db, source, now=datetime.utcnow())
    assert signals.status.value == "disabled"


def test_health_signals_degraded_for_failed_import(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    _confirmed_scope(db, source)
    content = _csv_bytes("displayName", [""])
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    confirm_import_mapping(db, batch, column_mapping={"displayName": "displayName"}, confirmed_by_user_id=1)
    db.commit()

    signals = evaluate_source_health_signals(db, source, now=datetime.utcnow())
    assert signals.schema_compatible is False
    assert any("failed" in r for r in signals.reasons)


def test_health_route_returns_signals(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    db.commit()
    result = evidence_source_routes.get_source_health_route(source.id, ctx=_ctx(1), db=db)
    assert result.status == "pending"


def test_freshness_policy_route_requires_org_admin(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    db.commit()
    with pytest.raises(AuthorizationError):
        evidence_source_routes.set_freshness_policy_route(
            source.id,
            evidence_source_routes.FreshnessPolicyRequest(warning_after_hours=1, stale_after_hours=2),
            ctx=_ctx(2, role="member"),
            db=db,
        )


def test_freshness_policy_route_updates_source_and_writes_audit(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    db.commit()
    result = evidence_source_routes.set_freshness_policy_route(
        source.id,
        evidence_source_routes.FreshnessPolicyRequest(warning_after_hours=48, stale_after_hours=96),
        ctx=_ctx(1),
        db=db,
    )
    assert result.id == source.id
    db.refresh(source)
    assert source.warning_after_hours == 48
    assert source.stale_after_hours == 96
    events = db.query(AuditEvent).filter(AuditEvent.organization_id == 1).all()
    assert any(e.event_type == "evidence_source.freshness_policy_set" for e in events)


def test_prepared_evidence_sources_surfaces_active_exceptions(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Manual log", source_type=EvidenceSourceType.MANUAL)
    _confirmed_scope(db, source)
    add_manual_evidence_entry(db, source, description="Known dependency", entered_by_user_id=1)
    create_exception(
        db,
        source,
        reason_code=EvidenceSourceExceptionReasonCode.PILOT_SCOPE,
        description="Piloting with a small, manually-declared scope.",
        approved_by_user_id=1,
        review_at=datetime.utcnow() + timedelta(days=30),
    )
    db.commit()

    prepared = build_prepared_evidence_sources(db, 1)
    assert len(prepared.active_exceptions) == 1
    assert prepared.active_exceptions[0].evidence_source_id == source.id


def test_scope_not_confirmed_keeps_source_blocked_even_with_receipt(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    save_scope(db, source, scope_type=EvidenceSourceScopeType.ENTIRE_ORGANISATION)
    content = _csv_bytes("displayName", ["POS-DB01"])
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    confirm_import_mapping(db, batch, column_mapping={"displayName": "displayName"}, confirmed_by_user_id=1)
    db.commit()

    result = evaluate_evidence_source_readiness(db, 1)
    assert result.ready is False
    assert source.id in result.blocked_source_ids


# --- Route-level authorisation, tenant isolation, upload endpoint -------------------


def test_only_org_admin_can_create_a_source(db: Session):
    with pytest.raises(AuthorizationError):
        evidence_source_routes.create_source_route(
            evidence_source_routes.EvidenceSourceRequest(name="Manual log", source_type=EvidenceSourceType.MANUAL),
            ctx=_ctx(2, role="member"),
            db=db,
        )


def test_source_lookup_is_tenant_isolated(db: Session):
    source = create_evidence_source(db, organization_id=1, name="Manual log", source_type=EvidenceSourceType.MANUAL)
    db.commit()
    with pytest.raises(ResourceNotFoundError):
        evidence_source_routes.get_source_route(source.id, ctx=_ctx(3, organization_id=2), db=db)


def test_complete_rejects_when_not_ready(db: Session):
    with pytest.raises(ValidationError):
        evidence_source_routes.complete_evidence_source_setup_route(ctx=_ctx(1), db=db)


def test_complete_succeeds_once_ready_and_writes_audit_event(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    _confirmed_scope(db, source)
    content = _csv_bytes("displayName", ["POS-DB01"])
    batch = upload_import_file(db, source, filename="export.csv", content_bytes=content, uploaded_by_user_id=1)
    confirm_import_mapping(db, batch, column_mapping={"displayName": "displayName"}, confirmed_by_user_id=1)
    db.commit()

    result = evidence_source_routes.complete_evidence_source_setup_route(ctx=_ctx(1), db=db)
    assert result.ready is True
    events = db.query(AuditEvent).filter(AuditEvent.organization_id == 1).all()
    assert any(e.event_type == EVIDENCE_SOURCE_AUDIT_COMPLETED for e in events)


async def test_upload_route_end_to_end(db: Session):
    source = create_evidence_source(db, organization_id=1, name="CMDB export", source_type=EvidenceSourceType.FILE_IMPORT)
    db.commit()
    content = _csv_bytes("displayName,environment", ["POS-DB01,production"])
    upload = UploadFile(file=io.BytesIO(content), filename="export.csv")

    response = await evidence_source_routes.upload_import_route(source.id, upload, ctx=_ctx(1), db=db)
    assert response.status == "mapping_required"
    assert response.detected_columns == ["displayName", "environment"]
