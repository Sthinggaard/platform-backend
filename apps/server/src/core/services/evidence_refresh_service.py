"""Ingestion-triggered evidence refresh (BSP-14).

When new scanner evidence lands — an asset is created or its connection is
verified — the Intelligence Engine re-reads the organisation's evidence so
suggestions and confidence boosts appear without anyone opening a wizard:

- the slot-mapping suggestion pass re-runs for every service with a
  dependency pattern (human-decided rows are never touched — BSP-05 rule);
- evidence-driven service discovery re-runs into the current Baseline Risk
  Hypothesis, but only while it is still a draft (``generated`` /
  ``under_review``) — a validated hypothesis is a human decision and new
  evidence must not silently mutate it.

Runs as a FastAPI background task after the triggering request commits, on
its own session. It only ever *recommends*; nothing here decides.
"""

from __future__ import annotations

import structlog
from sqlalchemy.orm import Session

from src.core.constants.value_stream_events import ValueStreamEvent
from src.core.database import get_session_factory
from src.core.model_defs.baseline_risk_hypothesis import (
    HYPOTHESIS_STATUS_GENERATED,
    HYPOTHESIS_STATUS_UNDER_REVIEW,
)
from src.core.models import BusinessService, ValueStreamSignal
from src.core.services.baseline_risk_hypothesis_service import get_current_hypothesis
from src.core.services.service_discovery_service import run_service_discovery_pass
from src.core.services.slot_mapping_suggestion_service import (
    run_slot_mapping_suggestion_pass,
)

logger = structlog.get_logger(__name__)

REFRESH_SIGNAL_SOURCE = "ingestion_evidence_refresh"


def refresh_org_evidence_in_session(db: Session, organization_id: int) -> dict:
    """Re-run both engine passes for one organisation; caller owns the commit."""
    services = (
        db.query(BusinessService)
        .filter(BusinessService.organization_id == organization_id)
        .all()
    )

    refreshed_services: list[str] = []
    for service in services:
        if not (service.archetype or service.template_key):
            continue
        result = run_slot_mapping_suggestion_pass(db, service=service)
        if not result.suggestions:
            continue
        refreshed_services.append(service.id)
        db.add(ValueStreamSignal(
            organization_id=organization_id,
            user_id=None,
            event=ValueStreamEvent.SLOT_MAPPING_SUGGESTED,
            stream_id=None,
            library_item_id=None,
            stream_key=None,
            name=None,
            priority=None,
            source=REFRESH_SIGNAL_SOURCE,
            payload={
                "service_id": service.id,
                "template_version": result.template_version,
                "suggested_slot_ids": [s.slot_id for s in result.suggestions],
                "skipped_human_decided": result.skipped_human_decided,
                "unmatched_slot_ids": result.unmatched_slot_ids,
            },
        ))

    discovery_summary: dict | None = None
    hypothesis = get_current_hypothesis(db, organization_id)
    if hypothesis is not None and hypothesis.status in (
        HYPOTHESIS_STATUS_GENERATED,
        HYPOTHESIS_STATUS_UNDER_REVIEW,
    ):
        discovery = run_service_discovery_pass(
            db, organization_id=organization_id, hypothesis=hypothesis
        )
        discovery_summary = {
            "newly_proposed": discovery.newly_proposed,
            "strengthened": discovery.strengthened,
        }

    return {
        "services_with_new_suggestions": refreshed_services,
        "discovery": discovery_summary,
    }


def refresh_org_evidence(organization_id: int) -> None:
    """Background-task entrypoint: own session, never raises into the caller."""
    session_factory = get_session_factory()
    db = session_factory()
    try:
        summary = refresh_org_evidence_in_session(db, organization_id)
        db.commit()
        logger.info(
            "org_evidence_refreshed",
            org_id=organization_id,
            **summary,
        )
    except Exception as exc:  # noqa: BLE001 — background boundary: log, never crash the request
        db.rollback()
        logger.error("org_evidence_refresh_failed", org_id=organization_id, error=str(exc))
    finally:
        db.close()
