from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field
from src.api.schemas.timestamps import UtcTimestamp

AuditEventCategory = str  # "LIFECYCLE" | "EXECUTION" | "EVIDENCE" | "SYSTEM" — an open, additive vocabulary, not a closed enum
AuditActorType = str  # "human" | "system"


class AuditTimelineEntry(BaseModel):
    id: int = Field(..., description="AuditEvent row id.")
    eventType: str = Field(..., description="Raw event type, e.g. 'provider_execution.completed'.")
    category: AuditEventCategory = Field(..., description="Business-readable event category, derived from event type.")
    actorType: AuditActorType = Field(..., description="'human' if a user triggered this event, 'system' otherwise.")
    label: str = Field(..., description="Business-readable summary of the event.")
    occurredAt: UtcTimestamp = Field(..., description="ISO timestamp the event occurred.")
    correlationId: Optional[str] = Field(
        default=None,
        description="Correlation identifier from A2 lifecycle metadata, when the writer attached one.",
    )
    #: #284 (TZ-6) — where the actor was and what clock they read **at the time
    #: of the event**, frozen when it was written. Null for a system event and
    #: for anything recorded before the platform kept this; a null means "not
    #: recorded" and must never be rendered as a guess.
    actorTimezone: Optional[str] = Field(
        default=None,
        description="The actor's own time zone when the event happened. Null if not recorded.",
    )
    actorLocation: Optional[str] = Field(
        default=None,
        description="Where the actor was when the event happened, e.g. 'Copenhagen, DK'. Null if not recorded.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": 4821,
                "eventType": "provider_execution.completed",
                "category": "EXECUTION",
                "actorType": "system",
                "label": "Provider execution completed",
                "occurredAt": "2026-07-27T09:15:00+00:00",
                "correlationId": "disc-run-8f21",
                "actorTimezone": "Europe/Copenhagen",
                "actorLocation": "Copenhagen, DK",
            }
        }
    )


class AuditTimelinePage(BaseModel):
    entries: list[AuditTimelineEntry] = Field(default_factory=list, description="Newest-first page of timeline entries.")
    nextCursor: Optional[str] = Field(default=None, description="Opaque cursor to fetch the next page, if hasMore.")
    hasMore: bool = Field(default=False, description="Whether more entries exist beyond this page.")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entries": [],
                "nextCursor": None,
                "hasMore": False,
            }
        }
    )
