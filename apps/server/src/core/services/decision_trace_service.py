"""Epic A3 — decision-to-recommendation trace.

``DecisionRecord`` (``core/model_defs/value_streams.py``) already carries
everything a trace needs: it's created once, append-only (no update path
exists anywhere in this codebase, confirmed by repository search), with
``recommendation_snapshot``/``reasoning_snapshot``/``forecast_snapshot``
frozen exactly as shown to the human at decision time by
``recommendations.py``'s ``create_decision`` route. This module only
assembles that already-authoritative record with its minimal linked
context — it does not recompute or re-derive anything.

Deliberately reads ``Threat``/``RecoveryAction`` context fields only, never
the live, mutable ``Threat.decision`` JSONB — that field is a separate,
weaker, unversioned view populated by ``_apply_decision_to_threat``
(documented as a known gap in the implementation risk register), and
conflating it with this trace's authoritative snapshot would undermine the
exact provenance guarantee this module exists to provide.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from src.api.schemas.decision_trace import (
    DecisionTraceListResponse,
    DecisionTraceResponse,
    DecisionTraceSummary,
    RecoveryActionTraceSummary,
    ThreatTraceContext,
)
from src.core.model_defs.value_streams import DecisionRecord, RecoveryAction, Threat
from src.core.services.audit_cursor import Cursor, encode_cursor, keyset_filter

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100


def _threat_context(db: Session, organization_id: int, threat_id: Optional[str]) -> Optional[ThreatTraceContext]:
    if threat_id is None:
        return None
    threat = (
        db.query(Threat).filter(Threat.id == threat_id, Threat.organization_id == organization_id).first()
    )
    if threat is None:
        return None
    return ThreatTraceContext(
        id=threat.id, asset=threat.asset, severity=threat.severity, status=threat.status, tier=threat.tier
    )


def _recovery_action_summary(
    db: Session, organization_id: int, recovery_action_id: Optional[int]
) -> Optional[RecoveryActionTraceSummary]:
    if recovery_action_id is None:
        return None
    action = (
        db.query(RecoveryAction)
        .filter(RecoveryAction.id == recovery_action_id, RecoveryAction.organization_id == organization_id)
        .first()
    )
    if action is None:
        return None
    return RecoveryActionTraceSummary(id=action.id, title=action.title, status=action.status, progress=action.progress, ref=action.ref)


def resolve_decision_trace(db: Session, organization_id: int, decision_record_id: str) -> Optional[DecisionTraceResponse]:
    record = (
        db.query(DecisionRecord)
        .filter(DecisionRecord.id == decision_record_id, DecisionRecord.organization_id == organization_id)
        .first()
    )
    if record is None:
        return None

    return DecisionTraceResponse(
        decisionRecordId=record.id,
        recommendationId=record.recommendation_id,
        selectedAction=record.selected_action,
        decisionType=record.decision_type,
        rationale=record.rationale,
        decidedBy=record.decided_by,
        decidedRole=record.decided_role,
        reviewDate=record.review_date,
        stale=record.stale,
        decidedAt=record.created_at.isoformat(),
        recommendationSnapshot=record.recommendation_snapshot or {},
        reasoningSnapshot=record.reasoning_snapshot or {},
        forecastSnapshot=record.forecast_snapshot,
        integrationProvider=record.integration_provider,
        integrationRef=record.integration_ref,
        externalUrl=record.external_url,
        threat=_threat_context(db, organization_id, record.threat_id),
        recoveryAction=_recovery_action_summary(db, organization_id, record.recovery_action_id),
    )


def resolve_decision_trace_list_for_threat(
    db: Session,
    organization_id: int,
    threat_id: str,
    *,
    cursor: Optional[Cursor] = None,
    limit: int = DEFAULT_PAGE_SIZE,
) -> DecisionTraceListResponse:
    limit = max(1, min(limit, MAX_PAGE_SIZE))

    query = db.query(DecisionRecord).filter(
        DecisionRecord.organization_id == organization_id, DecisionRecord.threat_id == threat_id
    )
    if cursor is not None:
        query = query.filter(keyset_filter(DecisionRecord.created_at, DecisionRecord.id, cursor, id_cast=str))

    # One extra row fetched to compute hasMore without a second query.
    records = query.order_by(desc(DecisionRecord.created_at), desc(DecisionRecord.id)).limit(limit + 1).all()

    has_more = len(records) > limit
    page = records[:limit]
    next_cursor = encode_cursor(page[-1].created_at, page[-1].id) if page and has_more else None

    return DecisionTraceListResponse(
        entries=[
            DecisionTraceSummary(
                decisionRecordId=record.id,
                selectedAction=record.selected_action,
                decisionType=record.decision_type,
                decidedBy=record.decided_by,
                decidedAt=record.created_at.isoformat(),
            )
            for record in page
        ],
        nextCursor=next_cursor,
        hasMore=has_more,
    )
