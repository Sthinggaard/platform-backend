from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.dependency_templates import VALID_ARCHETYPES
from src.core.database import get_db
from src.core.models import DependencyBundle

from .bundle_common import get_service, log_decision, logger, require_service_process_editor
from .bundle_contracts import ArchetypeSuggestResponse, SetArchetypeRequest

router = APIRouter()


def suggest_archetype_from_bia(service_name: str, bia_answers: dict | None) -> tuple[str, str]:
    name = service_name.lower()
    impact_path: set[str] = set((bia_answers or {}).get("impactPath", []))
    workaround: str = (bia_answers or {}).get("workaround", "") or ""
    alt_channel: str = (bia_answers or {}).get("alternativeChannel", "") or ""
    data_sensitivity: str = (bia_answers or {}).get("dataSensitivity", "") or ""
    hint_tokens = {workaround.lower(), alt_channel.lower(), data_sensitivity.lower()}

    payment_names = {"payment", "checkout", "billing", "subscription", "settlement"}
    if any(t in name for t in payment_names) or "transactions_stop" in impact_path or (
        "revenue_stop" in impact_path and "regulatory_failure" in impact_path
    ):
        confidence = "high" if any(t in name for t in payment_names) else "medium"
        return "transactional_system", confidence

    channel_names = {"portal", "channel", "website", "site", "app", "mobile", "banking"}
    if any(t in name for t in channel_names) or "customer_access" in impact_path:
        confidence = "high" if any(t in name for t in channel_names) else "medium"
        return "customer_channel", confidence

    identity_names = {"identity", "access", "login", "auth", "sso", "iam", "directory"}
    if any(t in name for t in identity_names) or ("internal_delay" in impact_path and "none" in hint_tokens):
        confidence = "high" if any(t in name for t in identity_names) else "medium"
        return "identity_access", confidence

    record_names = {"ledger", "record", "order", "transaction", "archive", "registry"}
    if any(t in name for t in record_names) or (
        "regulatory_failure" in impact_path and data_sensitivity == "high"
    ):
        confidence = "high" if any(t in name for t in record_names) else "medium"
        return "data_store", confidence

    ops_names = {"operations", "ops", "fulfil", "fulfill", "processing", "execution", "servicing", "lending"}
    if any(t in name for t in ops_names) or "revenue_stop" in impact_path:
        return "processing_engine", "medium"

    return "support_service", "low"


@router.post("/{service_id}/archetype/suggest", response_model=ArchetypeSuggestResponse)
def suggest_archetype(
    service_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ArchetypeSuggestResponse:
    service = get_service(service_id, ctx.organization_id, db)
    archetype, confidence = suggest_archetype_from_bia(service.name, service.bia_answers)
    logger.info(
        "archetype_suggested",
        org_id=ctx.organization_id,
        service_id=service_id,
        archetype=archetype,
        confidence=confidence,
    )
    return ArchetypeSuggestResponse(suggested_archetype=archetype, confidence=confidence)


@router.put("/{service_id}/archetype", response_model=dict)
def set_archetype(
    service_id: str,
    body: SetArchetypeRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> dict:
    if body.archetype not in VALID_ARCHETYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown archetype '{body.archetype}'. Valid values: {sorted(VALID_ARCHETYPES)}.",
        )

    service = get_service(service_id, ctx.organization_id, db)
    require_service_process_editor(
        service,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        db=db,
    )
    previous_archetype = service.archetype

    service.archetype = body.archetype
    db.add(service)

    existing_bundle = (
        db.query(DependencyBundle)
        .filter(
            DependencyBundle.organization_id == ctx.organization_id,
            DependencyBundle.service_id == service_id,
        )
        .first()
    )

    if existing_bundle is not None:
        log_decision(
            db,
            org_id=ctx.organization_id,
            service_id=service_id,
            bundle_id=existing_bundle.id,
            node_id=None,
            action="change_archetype",
            group_key=None,
            before_state={"archetype": previous_archetype},
            after_state={"archetype": body.archetype},
            reason=body.reason,
        )

    db.commit()
    db.refresh(service)

    logger.info(
        "archetype_set",
        org_id=ctx.organization_id,
        service_id=service_id,
        previous=previous_archetype,
        archetype=body.archetype,
    )
    return {"service_id": service_id, "archetype": body.archetype}
