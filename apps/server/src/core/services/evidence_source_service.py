"""Evidence Source — at least one functioning evidence source (post-ORG-STRUCT
onboarding stage).

v1 covers exactly two source types: file/CMDB upload and manual evidence
entry (a degraded, exception-gated path — see ``create_exception``). This
module establishes a functioning evidence *channel*; it must never
determine whether imported records represent unique or relevant assets,
which owners/relationships are authoritative, or any business-impact
conclusion — that is Step 4's job (first import/discovery → shared
artefact inventory), not this one.
"""

from __future__ import annotations

import hashlib
import io
from datetime import datetime, timezone

import pandas as pd
from sqlalchemy.orm import Session

from src.core.constants.evidence_source_enums import (
    EVIDENCE_FIELD_SYNONYMS,
    MAX_IMPORT_FILE_SIZE_BYTES,
    MAX_IMPORT_ROW_COUNT,
    REQUIRED_EVIDENCE_FIELDS,
    STANDARD_EVIDENCE_FIELDS,
    EvidenceImportStatus,
    EvidenceReceiptStatus,
    EvidenceSourceExceptionStatus,
    EvidenceSourceMode,
    EvidenceSourceScopeStatus,
    EvidenceSourceStatus,
    EvidenceSourceType,
    SOURCE_TYPE_MODE,
)
from src.core.model_defs.common import utcnow
from src.core.model_defs.evidence_source import (
    EvidenceImportBatch,
    EvidenceManualEntry,
    EvidenceReceipt,
    EvidenceSource,
    EvidenceSourceException,
    EvidenceSourceScope,
)
from src.core.model_defs.tenant_identity import User
from src.core.model_defs.tenant_org import Organization

# Formula-injection sanitisation (spec §21): a string cell starting with one
# of these characters is a live CSV-injection vector once it round-trips
# into a browser-rendered preview or a spreadsheet export.
_FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@")


class EvidenceSourceValidationError(ValueError):
    """Raised when an evidence-source operation is invalid."""


def _naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _sanitize_cell(value: object) -> object:
    if isinstance(value, str) and value.startswith(_FORMULA_TRIGGER_CHARS):
        return "'" + value
    return value


def _normalize_header(name: str) -> str:
    return "".join(ch for ch in name.lower() if ch.isalnum())


# Exact standard-field-name matches take priority; synonyms fill the rest.
# Both keyed by normalized header so "Display Name", "display_name", and
# "displayname" all resolve identically.
_STANDARD_FIELD_BY_NORMALIZED_NAME = {
    **{_normalize_header(synonym): field for synonym, field in EVIDENCE_FIELD_SYNONYMS.items()},
    **{_normalize_header(field): field for field in STANDARD_EVIDENCE_FIELDS},
}


def _suggest_column_mapping(columns: list[str]) -> dict[str, str | None]:
    return {column: _STANDARD_FIELD_BY_NORMALIZED_NAME.get(_normalize_header(column)) for column in columns}


# --- Evidence sources ----------------------------------------------------------


def create_evidence_source(
    db: Session,
    *,
    organization_id: int,
    name: str,
    source_type: EvidenceSourceType,
    owner_user_id: int | None = None,
    business_service_id: str | None = None,
) -> EvidenceSource:
    if not name.strip():
        raise EvidenceSourceValidationError("A name is required for this evidence source.")

    resolved_owner_user_id = owner_user_id
    if resolved_owner_user_id is None:
        organization = db.query(Organization).filter(Organization.id == organization_id).first()
        resolved_owner_user_id = organization.technical_setup_owner_user_id if organization else None
    if resolved_owner_user_id is None:
        raise EvidenceSourceValidationError(
            "An owner is required — assign a Technical Setup Owner in organisation structure first."
        )

    source = EvidenceSource(
        organization_id=organization_id,
        name=name.strip(),
        type=source_type.value,
        mode=SOURCE_TYPE_MODE[source_type.value],
        status=EvidenceSourceStatus.DRAFT.value,
        owner_user_id=resolved_owner_user_id,
        business_service_id=business_service_id,
    )
    db.add(source)
    db.flush()
    return source


def assign_owner(db: Session, source: EvidenceSource, *, owner_user_id: int) -> EvidenceSource:
    user = db.query(User).filter(User.id == owner_user_id, User.organization_id == source.organization_id).first()
    if user is None or not user.is_active:
        raise EvidenceSourceValidationError("The owner must be an active user of this organisation.")
    source.owner_user_id = owner_user_id
    db.add(source)
    return source


def set_business_service_scope(
    db: Session, source: EvidenceSource, *, business_service_id: str | None
) -> EvidenceSource:
    source.business_service_id = business_service_id
    db.add(source)
    return source


def list_evidence_sources(db: Session, organization_id: int) -> list[EvidenceSource]:
    return (
        db.query(EvidenceSource)
        .filter(EvidenceSource.organization_id == organization_id)
        .order_by(EvidenceSource.created_at.asc())
        .all()
    )


def disable_source(db: Session, source: EvidenceSource) -> EvidenceSource:
    source.status = EvidenceSourceStatus.DISABLED.value
    db.add(source)
    return source


def archive_source(db: Session, source: EvidenceSource) -> EvidenceSource:
    source.status = EvidenceSourceStatus.ARCHIVED.value
    db.add(source)
    return source


# --- Scope -----------------------------------------------------------------------


def save_scope(
    db: Session,
    source: EvidenceSource,
    *,
    scope_type,
    organisation_unit_ids: list[str] | None = None,
    legal_entity_ids: list[str] | None = None,
    country_codes: list[str] | None = None,
) -> EvidenceSourceScope:
    scope = db.query(EvidenceSourceScope).filter(EvidenceSourceScope.evidence_source_id == source.id).first()
    if scope is None:
        scope = EvidenceSourceScope(evidence_source_id=source.id, organization_id=source.organization_id)
    scope.scope_type = scope_type.value if hasattr(scope_type, "value") else scope_type
    scope.organisation_unit_ids = organisation_unit_ids or []
    scope.legal_entity_ids = legal_entity_ids or []
    scope.country_codes = country_codes or []
    # Editing a scope invalidates any prior confirmation — it must be
    # reviewed and confirmed again, never silently treated as still valid.
    scope.status = EvidenceSourceScopeStatus.DRAFT.value
    scope.confirmed_by_user_id = None
    scope.confirmed_at = None
    db.add(scope)
    db.flush()
    return scope


def confirm_scope(db: Session, scope: EvidenceSourceScope, *, confirmed_by_user_id: int) -> EvidenceSourceScope:
    scope.status = EvidenceSourceScopeStatus.CONFIRMED.value
    scope.confirmed_by_user_id = confirmed_by_user_id
    scope.confirmed_at = utcnow()
    db.add(scope)
    return scope


# --- File / CMDB upload path -----------------------------------------------------


def _parse_file(filename: str, content_bytes: bytes) -> tuple[str, pd.DataFrame]:
    lower_name = filename.lower()
    if lower_name.endswith(".csv"):
        file_type = "csv"
    elif lower_name.endswith((".xlsx", ".xls")):
        file_type = "xlsx"
    else:
        raise EvidenceSourceValidationError("The uploaded file could not be read as CSV or XLSX.")

    try:
        if file_type == "csv":
            df = pd.read_csv(io.BytesIO(content_bytes))
        else:
            df = pd.read_excel(io.BytesIO(content_bytes))
    except Exception as exc:  # noqa: BLE001 - any parser failure means "unreadable", not a crash
        raise EvidenceSourceValidationError("The uploaded file could not be read as CSV or XLSX.") from exc

    return file_type, df


def upload_import_file(
    db: Session,
    source: EvidenceSource,
    *,
    filename: str,
    content_bytes: bytes,
    uploaded_by_user_id: int,
) -> EvidenceImportBatch:
    if len(content_bytes) > MAX_IMPORT_FILE_SIZE_BYTES:
        raise EvidenceSourceValidationError("The uploaded file exceeds the 5 MB size limit.")

    file_type, df = _parse_file(filename, content_bytes)

    if len(df) > MAX_IMPORT_ROW_COUNT:
        raise EvidenceSourceValidationError("The uploaded file exceeds the 5,000 row limit.")

    detected_columns = [str(c) for c in df.columns]
    sanitized_df = df.map(_sanitize_cell)
    parsed_rows = sanitized_df.astype(object).where(pd.notnull(sanitized_df), None).to_dict(orient="records")
    suggested_mapping = _suggest_column_mapping(detected_columns)
    checksum = hashlib.sha256(content_bytes).hexdigest()

    batch = EvidenceImportBatch(
        organization_id=source.organization_id,
        evidence_source_id=source.id,
        filename=filename,
        file_type=file_type,
        checksum=checksum,
        status=EvidenceImportStatus.MAPPING_REQUIRED.value,
        uploaded_by_user_id=uploaded_by_user_id,
        detected_columns=detected_columns,
        column_mapping=suggested_mapping,
        parsed_rows_json=parsed_rows,
        total_rows=len(parsed_rows),
    )
    db.add(batch)
    db.flush()
    return batch


def confirm_import_mapping(
    db: Session,
    batch: EvidenceImportBatch,
    *,
    column_mapping: dict[str, str | None],
    confirmed_by_user_id: int,
) -> EvidenceImportBatch:
    mapped_required_fields = {field for field in column_mapping.values() if field in REQUIRED_EVIDENCE_FIELDS}
    if not REQUIRED_EVIDENCE_FIELDS.issubset(mapped_required_fields):
        raise EvidenceSourceValidationError("The column mapping must map a source column to displayName.")

    display_name_column = next(col for col, field in column_mapping.items() if field == "displayName")
    rows = batch.parsed_rows_json or []

    accepted = 0
    rejected = 0
    warnings = 0
    seen_display_names: set[str] = set()

    for row in rows:
        display_name = row.get(display_name_column)
        if display_name is None or not str(display_name).strip():
            rejected += 1
            continue
        normalized_name = str(display_name).strip().lower()
        if normalized_name in seen_display_names:
            warnings += 1
        else:
            seen_display_names.add(normalized_name)
        accepted += 1

    batch.column_mapping = column_mapping
    batch.accepted_rows = accepted
    batch.rejected_rows = rejected
    batch.warning_rows = warnings
    batch.validation_summary = {
        "required_field_missing": rejected,
        "duplicate_display_name": warnings,
    }
    batch.completed_at = utcnow()

    now = utcnow()
    source = db.query(EvidenceSource).filter(EvidenceSource.id == batch.evidence_source_id).first()
    source.last_attempted_sync_at = now

    if accepted == 0:
        batch.status = EvidenceImportStatus.FAILED.value
        existing_receipt = (
            db.query(EvidenceReceipt).filter(EvidenceReceipt.evidence_source_id == source.id).first()
        )
        if existing_receipt is None:
            source.status = EvidenceSourceStatus.FAILED.value
        db.add(source)
        db.add(batch)
        db.flush()
        return batch

    batch.status = (
        EvidenceImportStatus.COMPLETED.value
        if rejected == 0 and warnings == 0
        else EvidenceImportStatus.COMPLETED_WITH_WARNINGS.value
    )
    db.add(batch)
    db.flush()

    receipt = EvidenceReceipt(
        organization_id=source.organization_id,
        evidence_source_id=source.id,
        evidence_import_batch_id=batch.id,
        record_count=accepted,
        status=EvidenceReceiptStatus.PROCESSED.value,
        validation_summary=batch.validation_summary,
    )
    db.add(receipt)

    if source.first_evidence_received_at is None:
        source.first_evidence_received_at = now
    source.last_successful_sync_at = now
    source.status = (
        EvidenceSourceStatus.HEALTHY.value
        if batch.status == EvidenceImportStatus.COMPLETED.value
        else EvidenceSourceStatus.DEGRADED.value
    )
    db.add(source)
    db.flush()
    return batch


def list_import_batches(db: Session, evidence_source_id: str) -> list[EvidenceImportBatch]:
    return (
        db.query(EvidenceImportBatch)
        .filter(EvidenceImportBatch.evidence_source_id == evidence_source_id)
        .order_by(EvidenceImportBatch.uploaded_at.desc())
        .all()
    )


# --- Manual evidence entry --------------------------------------------------------


def add_manual_evidence_entry(
    db: Session,
    source: EvidenceSource,
    *,
    description: str,
    entered_by_user_id: int,
) -> EvidenceManualEntry:
    if not description.strip():
        raise EvidenceSourceValidationError("A description is required for a manual evidence entry.")

    entry = EvidenceManualEntry(
        organization_id=source.organization_id,
        evidence_source_id=source.id,
        description=description.strip(),
        entered_by_user_id=entered_by_user_id,
    )
    db.add(entry)
    db.flush()

    now = utcnow()
    receipt = EvidenceReceipt(
        organization_id=source.organization_id,
        evidence_source_id=source.id,
        record_count=1,
        status=EvidenceReceiptStatus.RECEIVED.value,
    )
    db.add(receipt)

    if source.first_evidence_received_at is None:
        source.first_evidence_received_at = now
    source.last_successful_sync_at = now
    source.last_attempted_sync_at = now
    # Manual evidence is inherently weaker than an observed or imported
    # source (spec §3.3/§15) — it never resolves to "healthy" on its own,
    # and does not satisfy the org-level gate without an approved exception
    # (see evidence_source_readiness_service).
    source.status = EvidenceSourceStatus.DEGRADED.value
    db.add(source)
    db.flush()
    return entry


def list_manual_entries(db: Session, evidence_source_id: str) -> list[EvidenceManualEntry]:
    return (
        db.query(EvidenceManualEntry)
        .filter(EvidenceManualEntry.evidence_source_id == evidence_source_id)
        .order_by(EvidenceManualEntry.entered_at.desc())
        .all()
    )


# --- Degraded-path exception (spec §19) --------------------------------------------


def create_exception(
    db: Session,
    source: EvidenceSource,
    *,
    reason_code,
    description: str,
    approved_by_user_id: int,
    review_at: datetime,
) -> EvidenceSourceException:
    if not description.strip():
        raise EvidenceSourceValidationError("A description is required to approve a degraded-path exception.")
    exception = EvidenceSourceException(
        organization_id=source.organization_id,
        evidence_source_id=source.id,
        reason_code=reason_code.value if hasattr(reason_code, "value") else reason_code,
        description=description.strip(),
        approved_by_user_id=approved_by_user_id,
        review_at=_naive_utc(review_at),
        status=EvidenceSourceExceptionStatus.ACTIVE.value,
    )
    db.add(exception)
    db.flush()
    return exception


def resolve_exception(db: Session, exception: EvidenceSourceException) -> EvidenceSourceException:
    exception.status = EvidenceSourceExceptionStatus.RESOLVED.value
    db.add(exception)
    return exception


def list_exceptions(db: Session, evidence_source_id: str) -> list[EvidenceSourceException]:
    return (
        db.query(EvidenceSourceException)
        .filter(EvidenceSourceException.evidence_source_id == evidence_source_id)
        .order_by(EvidenceSourceException.approved_at.desc())
        .all()
    )


# --- Collector-delivered evidence (BUG-DISC-13) ------------------------------


def record_collector_evidence(
    db: Session,
    source: EvidenceSource,
    *,
    record_count: int,
    succeeded: bool,
    validation_summary: dict | None = None,
) -> EvidenceReceipt:
    """Record that a Collector delivered evidence against a scanner source.

    Before this existed, ``first_evidence_received_at`` and a non-``draft``
    status were set in exactly two places — ``confirm_import_mapping`` (the CSV
    path) and ``record_manual_evidence`` — and no discovery service referenced
    ``EvidenceSource`` at all. A scanner source was therefore structurally
    incapable of leaving ``draft`` no matter how much evidence it collected,
    which is what stalled onboarding readiness after a successful discovery
    (BUG-DISC-13, and the real cause of UX-ONB-01's refresh bounce).

    Deliberately reuses ``EvidenceReceipt`` rather than inventing a parallel
    record: its ``evidence_import_batch_id`` is already nullable, precisely
    because a receipt means "evidence arrived", not "a CSV was uploaded". No
    ``EvidenceImportBatch`` is written — a discovery run is not an import, and
    forcing one would put row counts and validation summaries on something that
    has neither.

    Status follows the import path's own rule rather than a new one: a usable
    delivery is ``HEALTHY``, an unusable one is ``DEGRADED`` — degraded and not
    ``FAILED`` because the Collector channel demonstrably works; it is the
    content of one package that could not be processed.
    """
    now = utcnow()

    receipt = EvidenceReceipt(
        organization_id=source.organization_id,
        evidence_source_id=source.id,
        evidence_import_batch_id=None,
        record_count=record_count,
        status=(
            EvidenceReceiptStatus.PROCESSED.value
            if succeeded
            else EvidenceReceiptStatus.REJECTED.value
        ),
        validation_summary=validation_summary,
    )
    db.add(receipt)

    if source.first_evidence_received_at is None:
        source.first_evidence_received_at = now
    source.last_attempted_sync_at = now
    if succeeded:
        source.last_successful_sync_at = now
    source.status = (
        EvidenceSourceStatus.HEALTHY.value
        if succeeded
        else EvidenceSourceStatus.DEGRADED.value
    )
    db.add(source)
    db.flush()
    return receipt
