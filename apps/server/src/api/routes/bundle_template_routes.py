from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.dependency_templates import (
    VALID_ARCHETYPES,
    get_template,
)
from src.core.database import get_db
from src.core.models import BusinessService, DependencyBundle, SlotInstance
from src.core.services.asset_context_service import normalise_asset_reference
from src.core.services.dependency_decision_service import (
    DependencyDecisionError,
    ServiceSlotContext,
    find_record_for_node,
    live_groups,
    load_service_slot_context,
    record_assessment,
    upsert_slot_decision,
)
from src.core.services.dependency_live_state_service import (
    MAPPED_STATUS,
    NEEDS_REVIEW_MAPPING_STATUS,
    NOT_APPLICABLE_STATUS,
    UNKNOWN_STATUS,
    is_dependency_record,
    is_live_dependency,
)
from src.core.services.slot_provisioning_service import ensure_slot_instances

from .bundle_common import (
    bundle_to_response,
    find_group,
    get_bundle,
    get_service,
    log_decision,
    logger,
    require_service_process_editor,
)
from .bundle_contracts import BundleActionRequest, DependencyBundleResponse, LoadTemplateResponse

router = APIRouter()


@router.post(
    "/{service_id}/template",
    response_model=LoadTemplateResponse,
    status_code=status.HTTP_201_CREATED,
)
def load_template(
    service_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> LoadTemplateResponse:
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
            detail="Service has no archetype. Set an archetype on the service before loading a dependency template.",
        )

    if service.archetype not in VALID_ARCHETYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown archetype '{service.archetype}'. Valid archetypes: {sorted(VALID_ARCHETYPES)}",
        )

    existing = (
        db.query(DependencyBundle)
        .filter(
            DependencyBundle.service_id == service_id,
            DependencyBundle.organization_id == ctx.organization_id,
        )
        .first()
    )
    if existing:
        logger.info("bundle_template_already_loaded", service_id=service_id, bundle_id=existing.id)
        return LoadTemplateResponse(
            bundle=bundle_to_response(
                existing,
                groups=live_groups(existing.groups, load_service_slot_context(db, service)),
            ),
            message="Bundle already exists for this service.",
        )

    template_groups = get_template(service.archetype)
    groups: list[dict] = [
        {
            "key": tg["key"],
            "label": tg["label"],
            "question": tg["question"],
            "description": tg["description"],
            "required": tg["required"],
            "template_nodes": tg.get("template_nodes", []),
            "nodes": [],
        }
        for tg in (template_groups or [])
    ]

    bundle = DependencyBundle(
        id=str(uuid.uuid4()),
        organization_id=ctx.organization_id,
        service_id=service_id,
        status="draft",
        mode="manual_training",
        lifecycle_state="template_loaded",
        groups=groups,
    )
    db.add(bundle)

    log_decision(
        db,
        org_id=ctx.organization_id,
        service_id=service_id,
        bundle_id=bundle.id,
        node_id=None,
        action="load_template",
        group_key=None,
        before_state=None,
        after_state={
            "archetype": service.archetype,
            "lifecycle_state": bundle.lifecycle_state,
            "group_keys": [group["key"] for group in groups],
        },
        reason="Dependency template loaded from confirmed service pattern.",
    )
    db.commit()
    db.refresh(bundle)

    logger.info(
        "bundle_template_loaded",
        org_id=ctx.organization_id,
        service_id=service_id,
        bundle_id=bundle.id,
        archetype=service.archetype,
        groups=len(groups),
    )
    return LoadTemplateResponse(
        bundle=bundle_to_response(
            bundle, groups=live_groups(bundle.groups, load_service_slot_context(db, service))
        ),
        message=f"Dependency template loaded for archetype '{service.archetype}'.",
    )


@router.get("/{service_id}/bundle", response_model=DependencyBundleResponse)
def get_bundle_route(
    service_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DependencyBundleResponse:
    service = get_service(service_id, ctx.organization_id, db)
    bundle = get_bundle(service_id, ctx.organization_id, db)
    # #460 — the live dependency state, composed from the service's slot records.
    return bundle_to_response(
        bundle, groups=live_groups(bundle.groups, load_service_slot_context(db, service))
    )


# ─── PATCH /bundle: the service setup page's adapter onto the one write path ────────────────

#: (the slot record the action decided on, its state before, its state after). `None` for the
#: record means the action touched several records or none; all `None` means nothing changed.
_ActionResult = tuple[SlotInstance | None, dict | None, dict | None]


class _ActionContext:
    """Everything one page action needs, read once per request."""

    def __init__(
        self,
        *,
        db: Session,
        body: BundleActionRequest,
        service: BusinessService,
        bundle: DependencyBundle,
        context: ServiceSlotContext,
        actor: str | None,
    ) -> None:
        self.db = db
        self.body = body
        self.service = service
        self.bundle = bundle
        self.context = context
        self.actor = actor
        self.group = find_group(list(bundle.groups or []), body.group_key)

    def require_group(self) -> dict:
        if self.group is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Group '{self.body.group_key}' not found.",
            )
        return self.group

    def require_record(self) -> SlotInstance:
        record = find_record_for_node(
            self.context,
            group_key=self.body.group_key,
            node_id=self.body.node_id,
            stored_groups=self.bundle.groups,
        )
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Node '{self.body.node_id}' not found.",
            )
        return record

    def decide(
        self,
        record: SlotInstance,
        *,
        decision: str,
        asset_id: str | None = None,
        asset_label: str | None = None,
    ) -> None:
        upsert_slot_decision(
            self.db,
            org_id=self.service.organization_id,
            service_id=self.service.id,
            slot_id=record.slot_id,
            group_key=record.group_key or self.body.group_key,
            status=decision,
            asset_id=asset_id,
            asset_label=asset_label,
            template_version=self.context.template_version,
            decided_by=self.actor,
        )

    def require_asset_reference(self) -> str:
        reference = normalise_asset_reference(self.body.payload.get("asset_id"))
        if reference is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"payload.asset_id is required for {self.body.action}.",
            )
        return reference


def _mapping_state(record: SlotInstance) -> dict[str, Any]:
    return {
        "slot_id": record.slot_id,
        "status": record.status,
        "asset_id": record.asset_id,
        "mapping_status": record.mapping_status,
    }


def _add_pattern_node(action: _ActionContext) -> _ActionResult:
    """Adding a pattern marks its slot as a dependency the owner has not mapped yet."""
    group = action.require_group()
    template_key = action.body.payload.get("template_key")
    if not isinstance(template_key, str) or not template_key:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="payload.template_key is required for add_pattern_node.",
        )
    option = next(
        (
            node
            for node in group.get("template_nodes", [])
            if node.get("template_key") == template_key or node.get("pattern_key") == template_key
        ),
        None,
    )
    if option is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Dependency pattern '{template_key}' is not available for group '{action.body.group_key}'.",
        )
    record = find_record_for_node(
        action.context,
        group_key=action.body.group_key,
        node_id=None,
        template_key=option["template_key"],
    )
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"This service has no dependency slot for the pattern '{option['template_key']}' "
                f"in '{action.body.group_key}', so it cannot be added."
            ),
        )
    if is_live_dependency(record):
        return None, None, None
    before = _mapping_state(record)
    action.decide(record, decision=UNKNOWN_STATUS)
    return record, before, _mapping_state(record)


def _remove_node(action: _ActionContext) -> _ActionResult:
    record = action.require_record()
    before = _mapping_state(record)
    action.decide(record, decision=NOT_APPLICABLE_STATUS)
    return record, before, _mapping_state(record)


def _assign_asset(action: _ActionContext) -> _ActionResult:
    """One artefact per dependency slot (Søren, 2026-09-15): linking replaces the current one."""
    reference = action.require_asset_reference()
    record = action.require_record()
    before = _mapping_state(record)
    same_asset = normalise_asset_reference(record.asset_id) == reference
    action.decide(
        record,
        decision=MAPPED_STATUS,
        asset_id=reference,
        asset_label=record.asset_label if same_asset else None,
    )
    return record, before, _mapping_state(record)


def _unassign_asset(action: _ActionContext) -> _ActionResult:
    reference = action.require_asset_reference()
    record = action.require_record()
    before = _mapping_state(record)
    if normalise_asset_reference(record.asset_id) == reference:
        action.decide(record, decision=UNKNOWN_STATUS)
    return record, before, _mapping_state(record)


def _assessment_action(**field_by_payload_key: str) -> Callable[[_ActionContext], _ActionResult]:
    """A handler recording resilience answers, read from the named payload keys."""

    def handler(action: _ActionContext) -> _ActionResult:
        record = action.require_record()
        answers = {
            field: action.body.payload.get(payload_key)
            for field, payload_key in field_by_payload_key.items()
        }
        try:
            before = record_assessment(record, **answers)
        except DependencyDecisionError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc
        action.db.add(record)
        return record, before, {field: getattr(record, field) for field in before}

    return handler


def _defer_asset_mapping(action: _ActionContext) -> _ActionResult:
    record = action.require_record()
    before = _mapping_state(record)
    if bool(action.body.payload.get("deferred_asset_mapping")):
        action.decide(record, decision=UNKNOWN_STATUS)
    return record, before, _mapping_state(record)


def _set_uncertain(action: _ActionContext) -> _ActionResult:
    record = action.require_record()
    before = _mapping_state(record)
    record.mapping_status = NEEDS_REVIEW_MAPPING_STATUS
    action.db.add(record)
    return record, before, _mapping_state(record)


def _reject_group(action: _ActionContext) -> _ActionResult:
    action.require_group()
    records = [
        record
        for record in action.context.records
        if (record.group_key or "") == action.body.group_key and is_dependency_record(record)
    ]
    before = {"slots": [_mapping_state(record) for record in records]}
    for record in records:
        action.decide(record, decision=NOT_APPLICABLE_STATUS)
    return None, before, {"rejected": True, "slot_ids": [record.slot_id for record in records]}


#: One handler per page action. A lookup, not an if-chain (AGENTS.md §3.1), so an action the
#: contract accepts cannot silently fall through to "did nothing".
_ACTION_HANDLERS: dict[str, Callable[[_ActionContext], _ActionResult]] = {
    "add_pattern_node": _add_pattern_node,
    "remove_node": _remove_node,
    "assign_asset": _assign_asset,
    "unassign_asset": _unassign_asset,
    "classify_impact": _assessment_action(
        business_choice="business_choice", business_impact_level="business_impact_level"
    ),
    "mark_spof": _assessment_action(spof="spof"),
    "mark_fallback": _assessment_action(fallback_status="fallback_status"),
    "mark_recovery_dependency": _assessment_action(recovery_dependent="recovery_dependent"),
    "defer_asset_mapping": _defer_asset_mapping,
    "set_uncertain": _set_uncertain,
    "reject_group": _reject_group,
}


def _record_live_change(bundle: DependencyBundle) -> None:
    """What a changed decision means for the bundle, by where the bundle stands.

    A published bundle keeps its state and its snapshot: publish is the versioned record,
    and an edit after it changes the live state only (450.2 criterion 2; re-publishing is
    #467). Before publish, the change starts manual training and a validation no longer
    describes what is live, so it is dropped and has to be run again.
    """
    if bundle.lifecycle_state == "bundle_published":
        return
    bundle.lifecycle_state = "bundle_manual_training"
    bundle.validation_snapshot = None
    bundle.acknowledged_warning_ids = []


@router.patch("/{service_id}/bundle", response_model=DependencyBundleResponse)
def update_bundle(
    service_id: str,
    body: BundleActionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DependencyBundleResponse:
    """Record one dependency action from the service setup page or the service journey.

    #460: an adapter onto the one write path. Each node action becomes a decision on the slot record
    the node stands for, and nothing here writes bundle nodes, which are the published snapshot.
    Kept for the service setup page and the service journey until #469 retires them (Søren,
    2026-09-15).
    """
    service = get_service(service_id, ctx.organization_id, db)
    require_service_process_editor(
        service,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        db=db,
    )
    # No lifecycle guard (Søren, 2026-09-16): the slide-out's decide route takes a decision on a
    # published service, so this one does too — one write path, the same rules on every surface.
    bundle = get_bundle(service_id, ctx.organization_id, db)

    # A slot exists because the template says so; ensure every one has a record to decide on.
    ensure_slot_instances(db, service=service)
    db.flush()
    action = _ActionContext(
        db=db,
        body=body,
        service=service,
        bundle=bundle,
        context=load_service_slot_context(db, service),
        actor=str(ctx.user_id) if ctx.user_id is not None else None,
    )
    record, before_state, after_state = _ACTION_HANDLERS[body.action](action)

    if (record, before_state, after_state) == (None, None, None):
        return bundle_to_response(bundle, groups=live_groups(bundle.groups, action.context))

    _record_live_change(bundle)
    db.add(bundle)

    log_decision(
        db,
        org_id=ctx.organization_id,
        service_id=service_id,
        bundle_id=bundle.id,
        node_id=record.id if record is not None else None,
        action=body.action,
        group_key=body.group_key,
        before_state=before_state,
        after_state=after_state,
        reason=body.reason,
    )

    db.commit()
    db.refresh(bundle)

    logger.info(
        "bundle_action",
        org_id=ctx.organization_id,
        service_id=service_id,
        bundle_id=bundle.id,
        action=body.action,
        group_key=body.group_key,
    )
    return bundle_to_response(
        bundle, groups=live_groups(bundle.groups, load_service_slot_context(db, service))
    )
