"""Epic A3 — general, cursor-paginated audit timelines for the Discovery
Execution Pipeline's four object types.

Deliberately independent of ``discovery_execution_audit_timeline_service.py``
(DISC-41) rather than a shared/delegating implementation — see the Epic A3
plan's design decision §3: DISC-41 must stay byte-for-byte unchanged, and its
one-run-shaped matching logic has a different responsibility from this
module's four-object-type, paginated shape. The two modules independently
share the same real, disclosed constraint DISC-41 already documents:
``AuditEvent`` carries no FK to any domain object, so per-object matching is
done in Python against a bounded, keyset-ordered candidate window rather than
a SQL join. A page's ``hasMore`` is conservatively ``True`` whenever the
candidate scan hit its own bound (``_MAX_CANDIDATE_SCAN``) even if this
specific page found no matches within it — the same honest, disclosed
limitation DISC-41 accepts for its own 2000-row scan, not a claim of
guaranteed completeness beyond that window.
"""

from __future__ import annotations

from typing import Callable, Optional

from sqlalchemy import desc, or_
from sqlalchemy.orm import Session

from src.api.schemas.audit_timeline import AuditTimelineEntry, AuditTimelinePage
from src.core.model_defs.tenant_identity import AuditEvent
from src.core.services.audit_cursor import Cursor, encode_cursor, keyset_filter

_MAX_CANDIDATE_SCAN = 2000
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100

_CATEGORY_PREFIXES: dict[str, str] = {
    "discovery_run.": "LIFECYCLE",
    "discovery_execution_plan.": "EXECUTION",
    "execution_stage.": "EXECUTION",
    "provider_execution.": "EXECUTION",
    "evidence_package.": "EVIDENCE",
}


def _category_for(event_type: str) -> str:
    for prefix, category in _CATEGORY_PREFIXES.items():
        if event_type.startswith(prefix):
            return category
    return "SYSTEM"


def _actor_type_for(event: AuditEvent) -> str:
    return "system" if event.actor_user_id is None else "human"


def _label_for(event_type: str) -> str:
    # A general, honest humanization — not DISC-41's own curated business
    # copy, which is that timeline's specific presentation layer. Curated
    # per-event labels for this general surface are future work (see the
    # A3 doc's deferred-work list).
    return event_type.replace(".", " ").replace("_", " ").strip().capitalize()


def _correlation_id_for(metadata: dict) -> Optional[str]:
    lifecycle = metadata.get("lifecycle")
    if isinstance(lifecycle, dict):
        correlation_id = lifecycle.get("correlationId")
        return correlation_id if isinstance(correlation_id, str) else None
    return None


def _actor_location(event: AuditEvent) -> str | None:
    """"Copenhagen, DK", "DK", or nothing at all.

    Composed from whichever parts were recorded. Nothing is inferred: a person
    who gave a country and no city is shown a country, not a guessed city.
    """
    parts = [event.actor_location_city, event.actor_location_country]
    named = [part for part in parts if part]
    return ", ".join(named) if named else None


def _to_entry(event: AuditEvent) -> AuditTimelineEntry:
    metadata = event.metadata_json or {}
    return AuditTimelineEntry(
        id=event.id,
        eventType=event.event_type,
        category=_category_for(event.event_type),
        actorType=_actor_type_for(event),
        label=_label_for(event.event_type),
        # #281 — the model attaches the offset. A bare isoformat() here put a
        # naive instant on the wire, which every browser outside UTC read as
        # local time.
        occurredAt=event.created_at,
        correlationId=_correlation_id_for(metadata),
        # #284 (TZ-6) — read back exactly as recorded, never re-resolved from
        # the actor's current profile.
        actorTimezone=event.actor_timezone,
        actorLocation=_actor_location(event),
    )


def _resolve_timeline_page(
    db: Session,
    organization_id: int,
    *,
    prefixes: tuple[str, ...],
    predicate: Callable[[str, dict], bool],
    cursor: Optional[Cursor],
    limit: int,
) -> AuditTimelinePage:
    limit = max(1, min(limit, MAX_PAGE_SIZE))

    query = db.query(AuditEvent).filter(
        AuditEvent.organization_id == organization_id,
        or_(*(AuditEvent.event_type.startswith(prefix) for prefix in prefixes)),
    )
    if cursor is not None:
        query = query.filter(keyset_filter(AuditEvent.created_at, AuditEvent.id, cursor, id_cast=int))

    candidates = query.order_by(desc(AuditEvent.created_at), desc(AuditEvent.id)).limit(_MAX_CANDIDATE_SCAN).all()

    matched = [event for event in candidates if predicate(event.event_type, event.metadata_json or {})]
    page = matched[:limit]
    has_more = len(matched) > limit or len(candidates) == _MAX_CANDIDATE_SCAN
    next_cursor = encode_cursor(page[-1].created_at, page[-1].id) if page and has_more else None

    return AuditTimelinePage(
        entries=[_to_entry(event) for event in page],
        nextCursor=next_cursor,
        hasMore=has_more,
    )


def resolve_discovery_run_timeline_page(
    db: Session,
    organization_id: int,
    run_id: str,
    *,
    cursor: Optional[Cursor] = None,
    limit: int = DEFAULT_PAGE_SIZE,
) -> AuditTimelinePage:
    def predicate(_event_type: str, metadata: dict) -> bool:
        return metadata.get("discovery_run_id") == run_id

    return _resolve_timeline_page(
        db, organization_id, prefixes=("discovery_run.",), predicate=predicate, cursor=cursor, limit=limit
    )


def resolve_execution_plan_timeline_page(
    db: Session,
    organization_id: int,
    plan_id: str,
    stage_ids: set[str],
    *,
    cursor: Optional[Cursor] = None,
    limit: int = DEFAULT_PAGE_SIZE,
) -> AuditTimelinePage:
    def predicate(event_type: str, metadata: dict) -> bool:
        if event_type.startswith("discovery_execution_plan."):
            # Same disclosed snake_case/camelCase writer inconsistency
            # DISC-41 already documents — checked both, not assumed one shape.
            return metadata.get("executionPlanId") == plan_id or metadata.get("execution_plan_id") == plan_id
        if event_type.startswith("execution_stage."):
            return metadata.get("executionStageId") in stage_ids
        return False

    return _resolve_timeline_page(
        db,
        organization_id,
        prefixes=("discovery_execution_plan.", "execution_stage."),
        predicate=predicate,
        cursor=cursor,
        limit=limit,
    )


def resolve_provider_execution_timeline_page(
    db: Session,
    organization_id: int,
    provider_execution_id: str,
    *,
    cursor: Optional[Cursor] = None,
    limit: int = DEFAULT_PAGE_SIZE,
) -> AuditTimelinePage:
    def predicate(_event_type: str, metadata: dict) -> bool:
        return metadata.get("providerExecutionId") == provider_execution_id

    return _resolve_timeline_page(
        db, organization_id, prefixes=("provider_execution.",), predicate=predicate, cursor=cursor, limit=limit
    )


def resolve_evidence_package_timeline_page(
    db: Session,
    organization_id: int,
    package_id: str,
    provider_execution_id: Optional[str],
    *,
    cursor: Optional[Cursor] = None,
    limit: int = DEFAULT_PAGE_SIZE,
) -> AuditTimelinePage:
    def predicate(_event_type: str, metadata: dict) -> bool:
        if metadata.get("evidencePackageId") == package_id:
            return True
        # DISC-34: one package per attempt, so a storage_failed event
        # written before the package row existed (no evidencePackageId
        # yet) can still be matched via the owning attempt's own id —
        # the same fallback DISC-41's own matcher already relies on.
        return provider_execution_id is not None and metadata.get("providerExecutionId") == provider_execution_id

    return _resolve_timeline_page(
        db, organization_id, prefixes=("evidence_package.",), predicate=predicate, cursor=cursor, limit=limit
    )
