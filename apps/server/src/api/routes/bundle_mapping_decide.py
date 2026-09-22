"""Deciding one dependency slot.

Split out of `bundle_slot_mapping_routes.py` rather than added to it: that file
is already past 1,000 lines and owns *publishing a service*, which is a
different act (SRP).

## Why this route exists

Until 2026-09-02 the only way to record an accepted mapping was
`POST /{service_id}/slots/publish`, which takes a list. Rejecting one
suggestion had its own route; accepting one did not — **a reader could say no
to a single suggestion but only yes to all of them at once.** That asymmetry is
what forced the mapping wizard to march through every capability group in a
fixed order before anything could be saved, which Søren, 2026-09-02, described
as *"too linear and it does not really help the users."*

Posting a one-element batch to `publish` is not the same thing and would be
wrong twice over: it sets `bundle.lifecycle_state = "bundle_published"` on
every call, and derives `coverage_score` from **the request body**, so one
answer would report the service published and 100% covered.

## What this route does not do

It records a decision. It does not publish the bundle, does not emit
`SERVICE_PUBLISHED`, and does not compute a coverage score — publishing stays
an explicit, separate act.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Path, status
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.value_stream_events import ValueStreamEvent
from src.core.database import get_db
from src.core.services.slot_provisioning_service import ensure_slot_instances
from src.core.services.template_library_service import resolve_active_service_template

from .bundle_common import (
    check_spof,
    ensure_bundle,
    get_service,
    log_decision,
    logger,
    require_service_process_editor,
)
from .bundle_contracts import (
    DecideSlotMappingRequest,
    DecideSlotMappingResponse,
    SlotPublishFinding,
)

router = APIRouter()

#: The signal each decision emits. A lookup rather than an if-chain, so a
#: decision and the event it records cannot drift apart.
_DECISION_EVENT = {
    "mapped": ValueStreamEvent.SLOT_MAPPED,
    "not_applicable": ValueStreamEvent.SLOT_NOT_APPLICABLE,
    "unknown": ValueStreamEvent.SLOT_UNKNOWN,
}


@router.post(
    "/{service_id}/slots/{slot_id}/decide",
    response_model=DecideSlotMappingResponse,
    status_code=status.HTTP_200_OK,
)
def decide_slot_mapping(
    service_id: str = Path(...),
    slot_id: str = Path(...),
    body: DecideSlotMappingRequest = ...,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DecideSlotMappingResponse:
    """Record one owner decision about one slot, without publishing anything."""
    from .bundle_slot_mapping_routes import (
        _require_slot_instance,
        _slot_instance_to_out,
        _upsert_slot_instance,
        _emit_signal,
    )

    service = get_service(service_id, ctx.organization_id, db)
    require_service_process_editor(
        service,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        db=db,
    )

    # A slot exists because the service's template says so, not because the
    # engine had something to suggest for it. Ensuring here as well as on the
    # suggestion pass means a decision always has somewhere to land, including
    # on a service whose rows predate this rule (2026-09-03).
    ensure_slot_instances(db, service=service)

    # 404s when the slot belongs to another service or another organisation —
    # the tenant filter is the route's, not the caller's, like every other query.
    row = _require_slot_instance(slot_id, service.id, ctx.organization_id, db)
    # `ensure_bundle`, not `get_bundle`: the decision lands on the slot row, but
    # the audit trail it writes needs a bundle id, and a service can legitimately
    # have slots and no bundle. Refusing here told the reader — in a banner
    # quoting a service UUID — to "Call POST /template first" (#433).
    bundle = ensure_bundle(service, ctx.organization_id, db)

    # An asset only belongs on a `mapped` decision. Carrying one onto
    # "not applicable" or "unknown" would record an answer the reader did not
    # give, and leave a dependency attached to a slot they had just set aside.
    asset_id = body.asset_id if body.decision == "mapped" else None
    asset_label = body.asset_label if body.decision == "mapped" else None

    before_state = {
        "slot_id": slot_id,
        "mapping_status": row.mapping_status,
        "status": row.status,
        "asset_id": row.asset_id,
        "asset_label": row.asset_label,
    }

    service_template = resolve_active_service_template(
        db, template_key=service.template_key, archetype=service.archetype
    )
    _upsert_slot_instance(
        db,
        org_id=ctx.organization_id,
        service_id=service_id,
        slot_id=slot_id,
        group_key=row.group_key,
        status=body.decision,
        asset_id=asset_id,
        asset_label=asset_label,
        template_version=service_template.version if service_template else None,
        decided_by=str(ctx.user_id) if ctx.user_id is not None else None,
    )

    log_decision(
        db,
        org_id=ctx.organization_id,
        service_id=service_id,
        bundle_id=bundle.id,
        node_id=None,
        action="decide_slot_mapping",
        group_key=row.group_key,
        before_state=before_state,
        after_state={
            "slot_id": slot_id,
            "status": body.decision,
            "asset_id": asset_id,
            "asset_label": asset_label,
        },
        reason=f"Slot decided as {body.decision} while mapping dependencies.",
    )

    _emit_signal(
        db,
        org_id=ctx.organization_id,
        user_id=ctx.user_id,
        event=_DECISION_EVENT[body.decision],
        service_id=service_id,
        payload={"slot_ids": [slot_id], "group_key": row.group_key, "asset_id": asset_id},
    )

    findings: list[SlotPublishFinding] = []
    if body.decision == "mapped" and asset_id and check_spof(asset_id, service_id, ctx.organization_id, db):
        findings.append(
            SlotPublishFinding(
                group_key=row.group_key,
                severity="warning",
                message=(
                    f"'{asset_label or asset_id}' is also depended on by another service — "
                    "this is a shared dependency and a potential single point of failure."
                ),
            )
        )

    db.commit()
    db.refresh(row)
    logger.info(
        "slot_mapping_decided",
        org_id=ctx.organization_id,
        service_id=service_id,
        slot_id=slot_id,
        decision=body.decision,
    )
    return DecideSlotMappingResponse(slot=_slot_instance_to_out(row), findings=findings)
