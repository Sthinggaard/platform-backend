from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.dependency_mapping_enums import SLOT_REJECTION_REASONS
from src.core.constants.dependency_templates import get_template
from src.core.constants.value_stream_events import ValueStreamEvent
from src.core.database import get_db
from src.core.model_defs.business_process_recommendation import (
    BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION,
)
from src.core.models import (
    Asset,
    BusinessProcessDecisionAction,
    BusinessProcessDecisionLog,
    BusinessService,
    DependencyBundle,
    SlotInstance,
    ValueStreamSignal,
)
from src.core.services.asset_context_service import build_asset_business_context
from src.core.services.dependency_decision_service import (
    live_groups,
    load_service_slot_context,
    upsert_slot_decision,
)
from src.core.services.dependency_live_state_service import is_live_dependency
from src.core.services.template_library_service import (
    list_slot_templates_for_service,
    resolve_active_service_template,
)

from .bundle_common import (
    SLOT_MAPPING_NODE_SOURCE,
    check_spof,
    ensure_bundle,
    find_group,
    get_bundle,
    get_service,
    log_decision,
    logger,
    require_service_process_editor,
)
from .bundle_contracts import (
    BundleGroupRuntime,
    BundleSlotRuntime,
    DependencyAssetDetail,
    DependencyGroupDrillResponse,
    PublishSlotMappingsRequest,
    PublishSlotMappingsResponse,
    RejectionReasonOut,
    RejectSlotMappingRequest,
    ServiceBundleRuntimeResponse,
    ServiceSlotsResponse,
    SlotInstanceOut,
    SlotPublishFinding,
    SupersedeSlotMappingRequest,
)

#: Derived from the offered list, so a reason cannot be accepted that the
#: surface never offers — and adding one needs no second edit here.
_REJECTION_REASON_CODES = frozenset(code for code, _, _ in SLOT_REJECTION_REASONS)

router = APIRouter()


def _parse_asset_pk(asset_id_str: str | None) -> int | None:
    """asset_id format is "asset-{int}" — see SlotInstance.asset_id's own
    doc note (bare string, no DB-level FK to Asset)."""
    if not asset_id_str or not asset_id_str.startswith("asset-"):
        return None
    try:
        return int(asset_id_str[6:])
    except ValueError:
        return None


def _slot_instance_to_out(row: SlotInstance, *, template_orphaned: bool = False) -> SlotInstanceOut:
    return SlotInstanceOut(
        template_orphaned=template_orphaned,
        slot_id=row.slot_id,
        group_key=row.group_key,
        dependency_category=getattr(row, "dependency_category", None),
        status=row.status,
        asset_id=row.asset_id,
        asset_label=row.asset_label,
        template_version=row.template_version,
        mapping_status=getattr(row, "mapping_status", None) or "approved",
        mapping_confidence=getattr(row, "mapping_confidence", None),
        evidence_source=getattr(row, "evidence_source", None),
        mapping_reason=getattr(row, "mapping_reason", None),
        mapping_reason_code=getattr(row, "mapping_reason_code", None),
        provenance=getattr(row, "provenance", None),
        decided_by=getattr(row, "decided_by", None),
    )


def _require_slot_instance(slot_id: str, service_id: str, org_id: int, db: Session) -> SlotInstance:
    """Looked up by slot_id (the SlotTemplate identifier, e.g.
    "identity_provider") rather than SlotInstance's own opaque row id —
    matches _upsert_slot_instance's own (org, service, slot) lookup key,
    and is what the frontend already has (SlotSuggestionOut/SlotInstanceOut
    both key by slot_id, never by the internal row id)."""
    row = (
        db.query(SlotInstance)
        .filter(
            SlotInstance.organization_id == org_id,
            SlotInstance.service_id == service_id,
            SlotInstance.slot_id == slot_id,
        )
        .first()
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Slot mapping for '{slot_id}' not found."
        )
    return row


#: #460 — moved to `dependency_decision_service.upsert_slot_decision`, the one write path for a
#: dependency decision. Kept under its old name because `bundle_mapping_decide` and the routes
#: below call it from here.
_upsert_slot_instance = upsert_slot_decision


def _emit_signal(
    db: Session,
    *,
    org_id: int,
    user_id: int | None,
    event: ValueStreamEvent,
    service_id: str,
    payload: dict,
) -> None:
    """Write a ValueStreamSignal row (best-effort learning signal)."""
    db.add(
        ValueStreamSignal(
            organization_id=org_id,
            user_id=user_id,
            event=event,
            stream_id=None,
            library_item_id=None,
            stream_key=None,
            name=None,
            priority=None,
            source="slot_mapping_wizard",
            payload={"service_id": service_id, **payload},
        )
    )


def _canonical_slot_ids_by_group(service: BusinessService, db: Session) -> dict[str, list[str]]:
    """Return canonical SlotTemplate ids keyed by capability group for a service archetype."""
    service_template = _resolve_service_template(service, db)
    if service_template is None:
        return {}

    slot_ids_by_group: dict[str, list[str]] = {}
    for slot_template in list_slot_templates_for_service(db, service_template.id):
        slot_ids_by_group.setdefault(slot_template.capability_group_key, []).append(
            slot_template.slot_id
        )
    return slot_ids_by_group


def _resolve_service_template(service: BusinessService, db: Session):
    return resolve_active_service_template(
        db, template_key=service.template_key, archetype=service.archetype
    )


def _template_groups_by_key(service_template, archetype: str | None) -> dict[str, dict]:
    """Group definitions the wizard can legitimately publish against, keyed by group key.

    The wizard's steps come from the active service template's capability
    groups; the legacy archetype constants are the fallback for older rows.
    """
    by_key: dict[str, dict] = {}
    if archetype:
        for tg in get_template(archetype) or []:
            by_key[tg["key"]] = tg
    if service_template is not None:
        for tg in getattr(service_template, "capability_groups", None) or []:
            by_key[tg["key"]] = tg
    return by_key


def _materialize_bundle_group(template_group: dict) -> dict:
    """Build a bundle group dict from a template group (same shape as the no-bundle branch)."""
    return {
        "key": template_group["key"],
        "label": template_group.get("label", template_group["key"]),
        "question": template_group.get("question", ""),
        "description": template_group.get("description", ""),
        "required": template_group.get("required", True),
        "template_nodes": template_group.get("template_nodes", []),
        "nodes": [],
    }


def _load_runtime_slot_rows(
    service: BusinessService,
    db: Session,
    *,
    group_key: str | None = None,
) -> list[SlotInstance]:
    """Load only canonical SlotInstance rows, ignoring legacy group-key placeholders."""
    query = db.query(SlotInstance).filter(
        SlotInstance.organization_id == service.organization_id,
        SlotInstance.service_id == service.id,
    )
    if group_key is not None:
        query = query.filter(SlotInstance.group_key == group_key)

    # ⚠️ Ordered, because an unordered query is not a stable list. Without this
    # the same request could return a reader's dependencies in a different order
    # each time, so rows moved under the cursor between loads (2026-09-04).
    #
    # By slot id, which is stable but arbitrary. The template's `display_order`
    # is the order a reader should see and needs the slot-template join to reach;
    # filed rather than half-done here.
    slot_rows = query.order_by(SlotInstance.slot_id.asc()).all()
    slot_ids_by_group = _canonical_slot_ids_by_group(service, db)
    # ⚠️ Nothing to narrow by only when the service has no active template at all. A template
    # that has dropped this *group* still narrows it, to nothing: deciding "no slots here" per group
    # listed every decision in a dropped group as current, so the drill showed them unflagged while
    # runtime and `/slots` flagged them for review (#460, found on org 7, 2026-09-15).
    if not slot_ids_by_group:
        return slot_rows
    canonical_slot_ids = {
        slot_id
        for current_group_key, slot_ids in slot_ids_by_group.items()
        if group_key is None or current_group_key == group_key
        for slot_id in slot_ids
    }

    return [row for row in slot_rows if row.slot_id in canonical_slot_ids]


def _live_orphans(
    service: BusinessService,
    db: Session,
    listed: list[SlotInstance],
    *,
    group_key: str | None = None,
) -> list[SlotInstance]:
    """#460 (Søren, 2026-09-15) — live decisions whose slot has left the active template.

    `_load_runtime_slot_rows` keeps only current-template slots, so a person's answer to a question
    the template has since dropped vanished from every reader. It stays live and is shown flagged
    for review instead; folding it into a current slot is #472. Returned apart from `listed` so a
    reader can always tell the two apart.
    """
    listed_ids = {row.id for row in listed}
    return [
        record
        for record in load_service_slot_context(db, service).orphaned_records()
        if record.id not in listed_ids
        and is_live_dependency(record)
        and (group_key is None or record.group_key == group_key)
    ]


@router.post(
    "/{service_id}/slots/publish",
    response_model=PublishSlotMappingsResponse,
    status_code=status.HTTP_200_OK,
)
def publish_slot_mappings(
    service_id: str,
    body: PublishSlotMappingsRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> PublishSlotMappingsResponse:
    service = get_service(service_id, ctx.organization_id, db)
    require_service_process_editor(
        service,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        db=db,
    )

    if not service.archetype:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Service has no archetype. Set an archetype before publishing slot mappings.",
        )

    # Resolve the active template version for this service's template family.
    service_template = _resolve_service_template(service, db)
    active_template_version: int | None = service_template.version if service_template else None
    previous_template_version = service.template_version
    previous_template_key = service.template_key
    slot_ids_by_group = _canonical_slot_ids_by_group(service, db)

    # This route wrote the lazy-creation block; `decide` now needs the same
    # rule, so it lives in `bundle_common` and both call it (#433).
    bundle = ensure_bundle(service, ctx.organization_id, db)

    # Re-publishing via the slot wizard is allowed — SlotInstance rows are upserted,
    # so running the wizard again updates decisions in place.

    groups_mut: list[dict] = [dict(g) for g in (bundle.groups or [])]
    findings: list[SlotPublishFinding] = []
    mapped_count = not_applicable_count = unknown_count = 0
    template_groups_by_key = _template_groups_by_key(service_template, service.archetype)

    for mapping in body.mappings:
        group = find_group(groups_mut, mapping.group_key)
        if group is None:
            # BSP-07 — a stale bundle can predate the current template's capability
            # groups. An owner decision must never be dropped silently: materialise
            # the group from the template the wizard published against, or surface
            # a blocker so the wizard stays open.
            template_group = template_groups_by_key.get(mapping.group_key)
            if template_group is None:
                findings.append(
                    SlotPublishFinding(
                        group_key=mapping.group_key,
                        severity="blocker",
                        message=(
                            f"'{mapping.group_key}' is not a capability group for this "
                            "service pattern — this decision was not saved. Reload the "
                            "wizard and try again."
                        ),
                    )
                )
                continue
            group = _materialize_bundle_group(template_group)
            groups_mut.append(group)

        slot_ids = slot_ids_by_group.get(mapping.group_key) or [mapping.group_key]

        if mapping.decision == "not_applicable":
            group["rejected"] = True
            group["nodes"] = []
            not_applicable_count += 1
            log_decision(
                db,
                org_id=ctx.organization_id,
                service_id=service_id,
                bundle_id=bundle.id,
                node_id=None,
                action="reject_group",
                group_key=mapping.group_key,
                before_state=None,
                after_state={"rejected": True, "source": SLOT_MAPPING_NODE_SOURCE},
                reason="Marked Not Applicable in slot mapping wizard.",
            )
            for slot_id in slot_ids:
                _upsert_slot_instance(
                    db,
                    org_id=ctx.organization_id,
                    service_id=service_id,
                    slot_id=slot_id,
                    group_key=mapping.group_key,
                    status="not_applicable",
                    asset_id=None,
                    asset_label=None,
                    template_version=active_template_version,
                    decided_by=str(ctx.user_id) if ctx.user_id is not None else None,
                )
            _emit_signal(
                db,
                org_id=ctx.organization_id,
                user_id=ctx.user_id,
                event=ValueStreamEvent.SLOT_NOT_APPLICABLE,
                service_id=service_id,
                payload={"slot_ids": slot_ids, "group_key": mapping.group_key},
            )

        elif mapping.decision == "unknown":
            # #460 — no node is built here; the slot records below are the decision, and the
            # snapshot at the end of this route is composed from them.
            group["rejected"] = False
            log_decision(
                db,
                org_id=ctx.organization_id,
                service_id=service_id,
                bundle_id=bundle.id,
                node_id=None,
                action="defer_asset_mapping",
                group_key=mapping.group_key,
                before_state=None,
                after_state={"deferred_asset_mapping": True, "source": SLOT_MAPPING_NODE_SOURCE},
                reason="Marked Unknown in slot mapping wizard.",
            )
            unknown_count += 1
            for slot_id in slot_ids:
                _upsert_slot_instance(
                    db,
                    org_id=ctx.organization_id,
                    service_id=service_id,
                    slot_id=slot_id,
                    group_key=mapping.group_key,
                    status="unknown",
                    asset_id=None,
                    asset_label=None,
                    template_version=active_template_version,
                    decided_by=str(ctx.user_id) if ctx.user_id is not None else None,
                )
            _emit_signal(
                db,
                org_id=ctx.organization_id,
                user_id=ctx.user_id,
                event=ValueStreamEvent.SLOT_UNKNOWN,
                service_id=service_id,
                payload={"slot_ids": slot_ids, "group_key": mapping.group_key},
            )
            if group.get("required"):
                findings.append(
                    SlotPublishFinding(
                        group_key=mapping.group_key,
                        severity="blocker",
                        message=f"'{group['label']}' is required but has no asset mapped. Return to complete it.",
                    )
                )

        elif mapping.decision == "mapped" and mapping.asset_id:
            asset_id = mapping.asset_id
            group["rejected"] = False
            log_decision(
                db,
                org_id=ctx.organization_id,
                service_id=service_id,
                bundle_id=bundle.id,
                node_id=None,
                action="assign_asset",
                group_key=mapping.group_key,
                before_state=None,
                after_state={
                    "asset_id": asset_id,
                    "asset_label": mapping.asset_label,
                    "source": SLOT_MAPPING_NODE_SOURCE,
                },
                reason="Asset mapped in slot mapping wizard.",
            )
            for slot_id in slot_ids:
                _upsert_slot_instance(
                    db,
                    org_id=ctx.organization_id,
                    service_id=service_id,
                    slot_id=slot_id,
                    group_key=mapping.group_key,
                    status="mapped",
                    asset_id=asset_id,
                    asset_label=mapping.asset_label,
                    template_version=active_template_version,
                    decided_by=str(ctx.user_id) if ctx.user_id is not None else None,
                )
            if service.value_stream_ids:
                db.add(
                    BusinessProcessDecisionLog(
                        id=str(uuid.uuid4()),
                        organization_id=ctx.organization_id,
                        user_id=ctx.user_id,
                        action=BusinessProcessDecisionAction.SLOT_CONFIRMED.value,
                        reason={
                            "title": f"Slot confirmed · {group['label']} · {mapping.asset_label or asset_id}",
                            "slot_name": group["label"],
                            "asset_name": mapping.asset_label or asset_id,
                            "asset_id": asset_id,
                            "service_id": service_id,
                            "service_name": service.name,
                        },
                        model_version=BUSINESS_PROCESS_RECOMMENDATION_MODEL_VERSION,
                    )
                )
            _emit_signal(
                db,
                org_id=ctx.organization_id,
                user_id=ctx.user_id,
                event=ValueStreamEvent.SLOT_MAPPED,
                service_id=service_id,
                payload={
                    "slot_ids": slot_ids,
                    "group_key": mapping.group_key,
                    "asset_id": asset_id,
                    "asset_label": mapping.asset_label,
                },
            )
            if check_spof(asset_id, service_id, ctx.organization_id, db):
                findings.append(
                    SlotPublishFinding(
                        group_key=mapping.group_key,
                        severity="warning",
                        message=(
                            f"'{mapping.asset_label or asset_id}' in '{group['label']}' is also depended on "
                            "by another service — this is a shared dependency and a potential single point of failure."
                        ),
                    )
                )
            mapped_count += 1

    # Mark bundle as published regardless of prior state (allows re-publishing via wizard).
    bundle.lifecycle_state = "bundle_published"

    # #460 — the snapshot is composed from the slot records just written; `groups_mut` supplies
    # group metadata only (including any group materialised above for a stale bundle).
    db.flush()
    bundle.groups = live_groups(groups_mut, load_service_slot_context(db, service))
    db.add(bundle)

    effective = len(body.mappings) - not_applicable_count
    coverage_score = round((mapped_count / effective) * 100) if effective > 0 else 100

    # Emit service_published and coverage_score_recorded signals
    _emit_signal(
        db,
        org_id=ctx.organization_id,
        user_id=ctx.user_id,
        event=ValueStreamEvent.SERVICE_PUBLISHED,
        service_id=service_id,
        payload={
            "archetype": service.archetype,
            "template_version": active_template_version,
            "mapped": mapped_count,
            "not_applicable": not_applicable_count,
            "unknown": unknown_count,
        },
    )
    _emit_signal(
        db,
        org_id=ctx.organization_id,
        user_id=ctx.user_id,
        event=ValueStreamEvent.COVERAGE_SCORE_RECORDED,
        service_id=service_id,
        payload={
            "coverage_score": coverage_score,
            "mapped": mapped_count,
            "not_applicable": not_applicable_count,
            "unknown": unknown_count,
            "total": len(body.mappings),
            "archetype": service.archetype,
            "template_version": active_template_version,
        },
    )

    if service_template is not None:
        service.template_key = service_template.service_key
    service.template_version = active_template_version
    db.add(service)

    if (
        service_template is not None
        and previous_template_version is not None
        and active_template_version is not None
        and previous_template_version < active_template_version
    ):
        _emit_signal(
            db,
            org_id=ctx.organization_id,
            user_id=ctx.user_id,
            event=ValueStreamEvent.TEMPLATE_UPGRADE_ACCEPTED,
            service_id=service_id,
            payload={
                "service_key": service_template.service_key,
                "previous_template_key": previous_template_key,
                "current_version": previous_template_version,
                "latest_version": active_template_version,
            },
        )

    db.commit()
    db.refresh(bundle)

    logger.info(
        "slot_mappings_published",
        org_id=ctx.organization_id,
        service_id=service_id,
        bundle_id=bundle.id,
        mapped=mapped_count,
        not_applicable=not_applicable_count,
        unknown=unknown_count,
        coverage_score=coverage_score,
        template_version=active_template_version,
    )

    return PublishSlotMappingsResponse(
        bundle_id=bundle.id,
        lifecycle_state=bundle.lifecycle_state,
        mapped_count=mapped_count,
        not_applicable_count=not_applicable_count,
        unknown_count=unknown_count,
        coverage_score=coverage_score,
        findings=findings,
    )


@router.get(
    "/{service_id}/bundle/runtime",
    response_model=ServiceBundleRuntimeResponse,
    status_code=status.HTTP_200_OK,
)
def get_service_bundle_runtime(
    service_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ServiceBundleRuntimeResponse:
    """EUC-03 — read-only runtime view of a published dependency bundle for a service."""
    service = get_service(service_id, ctx.organization_id, db)

    # Compute a rough resilience score from BIA completeness indicators
    resilience_score: int | None = None
    financial_exposure: str | None = service.trading_impact or None

    bundle = (
        db.query(DependencyBundle)
        .filter(
            DependencyBundle.service_id == service_id,
            DependencyBundle.organization_id == ctx.organization_id,
        )
        .first()
    )

    if not bundle or bundle.lifecycle_state != "bundle_published":
        # No published bundle — return a shell so the UI can show the CTA
        return ServiceBundleRuntimeResponse(
            service_id=service.id,
            service_name=service.name,
            tier=service.tier,
            archetype=service.archetype,
            resilience_score=resilience_score,
            financial_exposure=financial_exposure,
            value_stream_ids=service.value_stream_ids or [],
            bundle_id=bundle.id if bundle else None,
            lifecycle_state=bundle.lifecycle_state if bundle else "no_bundle",
            coverage_score=None,
            groups=[],
        )

    # Load slot instances for this service, with live orphaned decisions flagged (#460).
    slot_rows = _load_runtime_slot_rows(service, db)
    orphans = _live_orphans(service, db, slot_rows)
    orphaned_ids = {record.id for record in orphans}
    slot_by_group: dict[str, list[SlotInstance]] = {}
    for row in [*slot_rows, *orphans]:
        slot_by_group.setdefault(row.group_key or "", []).append(row)

    # Build per-group runtime view from bundle groups + slot instances
    groups_out: list[BundleGroupRuntime] = []
    for group in bundle.groups:
        gkey = group.get("key", "")
        slots_for_group = slot_by_group.get(gkey, [])
        total = len(slots_for_group)
        mapped_count = sum(1 for s in slots_for_group if s.status == "mapped")

        # Status derivation per EUC-03 spec
        if total == 0:
            grp_status = "unverified"
        elif mapped_count == total:
            grp_status = "healthy"
        elif mapped_count == 0:
            grp_status = "at_risk"
        else:
            grp_status = "attention_needed"

        slot_out = [
            BundleSlotRuntime(
                slot_id=s.slot_id,
                dependency_category=getattr(s, "dependency_category", None),
                label=s.asset_label or s.slot_id,
                status=s.status,
                asset_id=s.asset_id,
                asset_label=s.asset_label,
                template_orphaned=s.id in orphaned_ids,
            )
            for s in slots_for_group
        ]

        groups_out.append(
            BundleGroupRuntime(
                key=gkey,
                label=group.get("label", gkey),
                description=group.get("description", ""),
                required=group.get("required", True),
                status=grp_status,
                slots=slot_out,
                mapped_count=mapped_count,
                total_slots=total,
            )
        )

    # Derive overall coverage from slot instances
    total_slots = sum(g.total_slots for g in groups_out)
    mapped_slots = sum(g.mapped_count for g in groups_out)
    coverage_score = round((mapped_slots / total_slots) * 100) if total_slots > 0 else 0

    return ServiceBundleRuntimeResponse(
        service_id=service.id,
        service_name=service.name,
        tier=service.tier,
        archetype=service.archetype,
        resilience_score=resilience_score,
        financial_exposure=financial_exposure,
        value_stream_ids=service.value_stream_ids or [],
        bundle_id=bundle.id,
        lifecycle_state=bundle.lifecycle_state,
        coverage_score=coverage_score,
        groups=groups_out,
    )


@router.get(
    "/{service_id}/bundle/groups/{group_key}",
    response_model=DependencyGroupDrillResponse,
    status_code=status.HTTP_200_OK,
)
def get_dependency_group_drill(
    service_id: str,
    group_key: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DependencyGroupDrillResponse:
    """EUC-04 — asset drill for one dependency group within a published bundle."""
    service = get_service(service_id, ctx.organization_id, db)

    bundle = (
        db.query(DependencyBundle)
        .filter(
            DependencyBundle.service_id == service_id,
            DependencyBundle.organization_id == ctx.organization_id,
            DependencyBundle.lifecycle_state == "bundle_published",
        )
        .first()
    )
    if not bundle:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No published bundle found for this service.",
        )

    # A bundle is a published snapshot. Its group metadata can therefore lag a
    # current service template, while the live SlotInstance rows already carry
    # a valid decision for that newer group. The drill must not turn that
    # recoverable metadata drift into a false "not found" for the owner.
    #
    # Read-only fallback only: publishing remains the explicit act that updates
    # bundle JSONB. This route still rejects a key absent from both sources.
    group_meta = next((g for g in (bundle.groups or []) if g.get("key") == group_key), None)
    if not group_meta:
        service_template = _resolve_service_template(service, db)
        group_meta = _template_groups_by_key(service_template, service.archetype).get(group_key)
        if group_meta is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Group '{group_key}' is not available for this service.",
            )

    # Load canonical slot instances for this group, then its live orphaned decisions (#460).
    canonical_rows = _load_runtime_slot_rows(service, db, group_key=group_key)
    orphans = _live_orphans(service, db, canonical_rows, group_key=group_key)
    orphaned_ids = {record.id for record in orphans}
    slot_rows = [*canonical_rows, *orphans]

    # Build a count of how many services use each asset_id across the org
    all_slots = (
        db.query(SlotInstance)
        .filter(
            SlotInstance.organization_id == ctx.organization_id,
            SlotInstance.status == "mapped",
        )
        .all()
    )
    asset_service_map: dict[str, set[str]] = {}
    for row in all_slots:
        if row.asset_id:
            asset_service_map.setdefault(row.asset_id, set()).add(row.service_id)

    # Resolve Asset DB records — asset_id format is "asset-{int}"
    asset_pks = [pk for row in slot_rows if (pk := _parse_asset_pk(row.asset_id))]
    asset_records: dict[int, Asset] = {}
    if asset_pks:
        for a in db.query(Asset).filter(Asset.id.in_(asset_pks)).all():
            asset_records[a.id] = a
    asset_contexts: dict[int, bool] = {}

    total = len(slot_rows)
    mapped_count = sum(1 for r in slot_rows if r.status == "mapped")
    grp_status: str
    if total == 0:
        grp_status = "unverified"
    elif mapped_count == total:
        grp_status = "healthy"
    elif mapped_count == 0:
        grp_status = "at_risk"
    else:
        grp_status = "attention_needed"

    assets_out: list[DependencyAssetDetail] = []
    for row in slot_rows:
        shared_services = asset_service_map.get(row.asset_id or "", set())
        shared_count = len(shared_services - {service_id})

        pk = _parse_asset_pk(row.asset_id)
        db_asset = asset_records.get(pk) if pk else None
        if pk is not None and pk not in asset_contexts and db_asset is not None:
            asset_contexts[pk] = build_asset_business_context(
                db_asset, ctx.organization_id, db
            ).crown_jewel_candidate
        crown_jewel = asset_contexts.get(pk, False) if pk is not None else False

        assets_out.append(
            DependencyAssetDetail(
                slot_id=row.slot_id,
                dependency_category=getattr(row, "dependency_category", None),
                asset_id=row.asset_id or "",
                asset_label=row.asset_label
                or row.slot_id
                or row.asset_id
                or group_meta.get("label", ""),
                status=row.status,
                display_name=db_asset.display_name if db_asset else None,
                asset_type=db_asset.type if db_asset else None,
                level=db_asset.level if db_asset else None,
                is_spof=db_asset.is_spof if db_asset else False,
                risk_score=db_asset.risk_score if db_asset else 0.0,
                findings_count=db_asset.findings_count if db_asset else 0,
                shared_service_count=shared_count,
                crown_jewel_candidate=crown_jewel,
                template_orphaned=row.id in orphaned_ids,
            )
        )

    return DependencyGroupDrillResponse(
        service_id=service_id,
        group_key=group_key,
        label=group_meta.get("label", group_key),
        description=group_meta.get("description", ""),
        required=group_meta.get("required", True),
        status=grp_status,
        assets=assets_out,
        mapped_count=mapped_count,
        total_slots=total,
    )


@router.get(
    "/{service_id}/slots",
    response_model=ServiceSlotsResponse,
    status_code=status.HTTP_200_OK,
)
def get_service_slots(
    service_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ServiceSlotsResponse:
    """Return existing SlotInstance rows for a service so the wizard can pre-populate."""
    service = get_service(service_id, ctx.organization_id, db)  # 404 if not found / wrong org

    rows = _load_runtime_slot_rows(service, db)

    return ServiceSlotsResponse(
        service_id=service_id,
        slots=[_slot_instance_to_out(row) for row in rows],
        # #460 — live decisions whose slot has left the active template, kept apart from `slots`
        # so the slide-out never sends a group's answer onto them.
        orphaned_slots=[
            _slot_instance_to_out(record, template_orphaned=True)
            for record in _live_orphans(service, db, rows)
        ],
        rejection_reasons=[
            RejectionReasonOut(code=code, label=label, explanation=explanation)
            for code, label, explanation in SLOT_REJECTION_REASONS
        ],
    )


@router.post(
    "/{service_id}/slots/{slot_id}/reject",
    response_model=SlotInstanceOut,
    status_code=status.HTTP_200_OK,
)
def reject_slot_mapping(
    service_id: str,
    slot_id: str,
    body: RejectSlotMappingRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> SlotInstanceOut:
    """Step 4.1C — persists a rejection of a suggested or previously
    decided mapping. Closes a real gap: the wizard's "Dismiss" only hid a
    suggestion card client-side (mapping_status="rejected" was a
    documented valid value, never actually written anywhere), so a
    dismissed suggestion left no record and could resurface identically
    on the next engine pass (`is_human_decided()` in
    slot_mapping_suggestion_service.py only skips rows already
    mapping_status in {approved, rejected} — "rejected" reaching that set
    for the first time is exactly what this route enables)."""
    if body.reason_code not in _REJECTION_REASON_CODES:
        # Named back rather than stored. An unrecognised code would be written
        # to the row and counted by CA-09A.6 as though it meant something, which
        # is worse than refusing: learning from a vocabulary nobody defined is
        # how a matcher teaches itself someone else's typo.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"'{body.reason_code}' is not a reason a mapping can be refused for.",
        )

    service = get_service(service_id, ctx.organization_id, db)
    require_service_process_editor(
        service,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        db=db,
    )
    row = _require_slot_instance(slot_id, service.id, ctx.organization_id, db)
    bundle = get_bundle(service_id, ctx.organization_id, db)

    before_state = {
        # CA-09A.6 — which slot was refused, not only which capability group.
        # The log recorded `node_id=None` and a `group_key`, and a group can
        # list several slots, so a rejection could not be attributed to the
        # thing it was actually about. Without this a refusal is auditable but
        # not *readable*: the engine cannot tell which suggestion a person
        # ruled out, and goes on making it elsewhere.
        "slot_id": slot_id,
        "mapping_status": row.mapping_status,
        "status": row.status,
        "asset_id": row.asset_id,
        "asset_label": row.asset_label,
    }
    row.mapping_status = "rejected"
    row.status = "needs_review"
    row.asset_id = None
    row.asset_label = None
    row.mapping_reason = body.reason
    row.mapping_reason_code = body.reason_code
    row.provenance = "owner_rejected"
    row.mapping_confidence = None
    row.decided_by = str(ctx.user_id) if ctx.user_id is not None else None
    row.decided_at = datetime.now(timezone.utc)
    db.add(row)

    log_decision(
        db,
        org_id=ctx.organization_id,
        service_id=service_id,
        bundle_id=bundle.id,
        node_id=None,
        action="reject_slot_mapping",
        group_key=row.group_key,
        before_state=before_state,
        after_state={"mapping_status": "rejected", "reason_code": body.reason_code},
        reason=body.reason or f"Rejected: {body.reason_code}",
    )
    db.commit()
    db.refresh(row)
    logger.info(
        "slot_mapping_rejected",
        org_id=ctx.organization_id,
        service_id=service_id,
        slot_id=slot_id,
        reason_code=body.reason_code,
    )
    return _slot_instance_to_out(row)


@router.post(
    "/{service_id}/slots/{slot_id}/supersede",
    response_model=SlotInstanceOut,
    status_code=status.HTTP_200_OK,
)
def supersede_slot_mapping(
    service_id: str,
    slot_id: str,
    body: SupersedeSlotMappingRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> SlotInstanceOut:
    """Step 4.1C — explicitly replaces an existing mapping decision with a
    different asset, capturing the exact prior state in `MappingDecision`
    before overwriting. Distinct from the wizard's bulk `/slots/publish`,
    which upserts without recording what the previous decision was —
    this is the single-mapping, audited "change this one decision" action
    the spec's `supersedeMapping` describes. `SlotInstance` is a single
    current-value row per (org, service, slot) — no separate superseded
    row is created; the audit trail in `MappingDecision` is where "the
    old value" is preserved, an intentional adaptation to this table's
    existing unique constraint rather than a multi-row versioning scheme."""
    service = get_service(service_id, ctx.organization_id, db)
    require_service_process_editor(
        service,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        db=db,
    )
    row = _require_slot_instance(slot_id, service.id, ctx.organization_id, db)
    bundle = get_bundle(service_id, ctx.organization_id, db)

    new_asset_pk = _parse_asset_pk(body.asset_id)
    if new_asset_pk is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="asset_id must be in the form 'asset-{id}'.",
        )
    asset = (
        db.query(Asset)
        .filter(Asset.id == new_asset_pk, Asset.organization_id == ctx.organization_id)
        .first()
    )
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{body.asset_id}' not found in this organisation.",
        )

    before_state = {
        "mapping_status": row.mapping_status,
        "status": row.status,
        "asset_id": row.asset_id,
        "asset_label": row.asset_label,
    }
    row.status = "mapped"
    row.mapping_status = "approved"
    row.asset_id = body.asset_id
    row.asset_label = body.asset_label or asset.display_name
    row.mapping_reason = body.reason
    row.mapping_reason_code = body.reason_code
    row.provenance = "overridden"
    row.evidence_source = "manual"
    row.mapping_confidence = 1.0
    row.decided_by = str(ctx.user_id) if ctx.user_id is not None else None
    row.decided_at = datetime.now(timezone.utc)
    db.add(row)

    log_decision(
        db,
        org_id=ctx.organization_id,
        service_id=service_id,
        bundle_id=bundle.id,
        node_id=None,
        action="supersede_slot_mapping",
        group_key=row.group_key,
        before_state=before_state,
        after_state={
            "asset_id": body.asset_id,
            "asset_label": row.asset_label,
            "reason_code": body.reason_code,
        },
        reason=body.reason or f"Superseded: {body.reason_code}",
    )
    db.commit()
    db.refresh(row)
    logger.info(
        "slot_mapping_superseded",
        org_id=ctx.organization_id,
        service_id=service_id,
        slot_id=slot_id,
        reason_code=body.reason_code,
    )
    return _slot_instance_to_out(row)
