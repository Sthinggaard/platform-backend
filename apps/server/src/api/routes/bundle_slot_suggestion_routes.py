"""BSP-05 — intelligence-engine slot-mapping suggestion route.

Runs the first Intelligence Engine pass for one service: ingested artefacts
(Asset registry) are matched against the service's logical dependency slots
and written as ``mapping_status="suggested"`` rows for human review. The
engine only recommends — approval stays in the slot-mapping wizard.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.value_stream_events import ValueStreamEvent
from src.core.database import get_db
from src.core.models import ValueStreamSignal
from src.core.services.slot_mapping_suggestion_service import (
    run_slot_mapping_suggestion_pass,
)
from src.core.services.slot_provisioning_service import ensure_slot_instances

from .bundle_common import get_service, logger, require_service_process_editor
from .bundle_contracts import ParkedSlotOut, ServiceSlotSuggestionsResponse, SlotSuggestionOut

router = APIRouter()

SUGGESTION_SIGNAL_SOURCE = "slot_mapping_suggestion_engine"


@router.post(
    "/{service_id}/slots/suggestions",
    response_model=ServiceSlotSuggestionsResponse,
    status_code=status.HTTP_200_OK,
)
def suggest_service_slot_mappings(
    service_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ServiceSlotSuggestionsResponse:
    """Generate suggested slot mappings from ingested artefacts for review."""
    service = get_service(service_id, ctx.organization_id, db)
    require_service_process_editor(
        service,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        db=db,
    )

    # Every slot the template defines gets a row before the engine runs, so the
    # count of a service's dependencies comes from its template rather than from
    # what the scanner happened to see — and so an unsuggested slot can still be
    # answered. Idempotent; a slot that already has a row is left alone.
    ensure_slot_instances(db, service=service)

    result = run_slot_mapping_suggestion_pass(db, service=service)

    if result.suggestions:
        db.add(ValueStreamSignal(
            organization_id=ctx.organization_id,
            user_id=ctx.user_id,
            event=ValueStreamEvent.SLOT_MAPPING_SUGGESTED,
            stream_id=None,
            library_item_id=None,
            stream_key=None,
            name=None,
            priority=None,
            source=SUGGESTION_SIGNAL_SOURCE,
            payload={
                "service_id": service_id,
                "template_version": result.template_version,
                "suggested_slot_ids": [s.slot_id for s in result.suggestions],
                "skipped_human_decided": result.skipped_human_decided,
                "unmatched_slot_ids": result.unmatched_slot_ids,
                "parked_by_refutation": [p.slot_id for p in result.parked_by_refutation],
            },
        ))

    db.commit()

    logger.info(
        "slot_mapping_suggestions_generated",
        org_id=ctx.organization_id,
        service_id=service_id,
        suggested=len(result.suggestions),
        skipped_human_decided=len(result.skipped_human_decided),
        unmatched=len(result.unmatched_slot_ids),
        parked=len(result.parked_by_refutation),
        template_version=result.template_version,
    )

    return ServiceSlotSuggestionsResponse(
        service_id=service_id,
        template_version=result.template_version,
        suggestions=[
            SlotSuggestionOut(
                slot_id=s.slot_id,
                group_key=s.group_key,
                slot_label=s.slot_label,
                asset_id=s.asset_id,
                asset_label=s.asset_label,
                confidence=s.confidence,
                reason=s.reason,
            )
            for s in result.suggestions
        ],
        skipped_human_decided=result.skipped_human_decided,
        unmatched_slot_ids=result.unmatched_slot_ids,
        parked_by_refutation=[
            ParkedSlotOut(slot_id=p.slot_id, group_key=p.group_key)
            for p in result.parked_by_refutation
        ],
    )
