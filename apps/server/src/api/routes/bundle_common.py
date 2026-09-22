"""Shared building blocks for the dependency-bundle routes.

A ``DependencyBundle`` is the set of dependency slots a Business Service is
expected to have. This module holds what the bundle routes have in common: the
tenant-scoped lookups, the response projections, and the publish-time validation
that turns a bundle into a list of findings.

Two boundaries this module holds, and neither is incidental:

**It reports, it never decides.** ``validate_node_for_publish`` produces findings
with a severity and a recommendation. Nothing here resolves one, and a WARNING is
acknowledged by a person rather than cleared by the system.

**It is the canonical reader of stored asset links.** Those links have existed in
two shapes — ``"asset-92"`` and the bare integer ``92`` — so every read goes
through ``normalise_asset_reference``. A raw comparison silently drops the second
shape, which reads as ordinary incomplete setup rather than as a bug (#363).
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from src.core.constants.dependency_templates import VALID_ARCHETYPES, get_template
from src.core.exceptions import AuthorizationError
from src.core.logging_config import get_logger
from src.core.models import (
    BusinessService,
    DependencyBundle,
    DependencyBundleVersion,
    MappingDecision,
    SlotInstance,
    ValueStream,
)
from src.core.services.asset_context_service import normalise_asset_reference
from src.core.services.dependency_live_state_service import is_live_dependency
from src.core.services.process_ownership_service import (
    ProcessOwnershipValidationError,
    require_process_editor,
)

from .bundle_contracts import (
    BundleVersionResponse,
    DependencyBundleResponse,
    DependencyGroupOut,
    DependencyNodeOut,
    TemplatePatternOptionOut,
)

logger = get_logger(__name__)

SLOT_MAPPING_NODE_SOURCE = "slot_mapping_wizard"


def get_service(service_id: str, org_id: int, db: Session) -> BusinessService:
    service = (
        db.query(BusinessService)
        .filter(
            BusinessService.id == service_id,
            BusinessService.organization_id == org_id,
        )
        .first()
    )
    if not service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Service '{service_id}' not found."
        )
    return service


def require_service_process_editor(
    service: BusinessService,
    *,
    organization_id: int,
    actor_user_id: int,
    db: Session,
) -> None:
    """Require edit access to a process that contains this business service.

    A service can be reused by several processes. A process owner may change
    its dependency mapping when they own at least one linked process; a viewer
    of an unrelated process remains read-only. Services not linked to a
    process fail closed until an administrator links them into the process map.
    """
    process_ids = set(service.value_stream_ids or [])
    processes = (
        db.query(ValueStream)
        .filter(
            ValueStream.organization_id == organization_id,
            ValueStream.id.in_(process_ids),
        )
        .all()
        if process_ids
        else []
    )
    for process in processes:
        try:
            require_process_editor(
                db,
                organization_id=organization_id,
                process_id=process.id,
                actor_user_id=actor_user_id,
            )
        except ProcessOwnershipValidationError:
            continue
        return
    raise AuthorizationError(
        "Business Process Owner or organisation administrator access is required."
    )


def get_bundle(service_id: str, org_id: int, db: Session) -> DependencyBundle:
    bundle = (
        db.query(DependencyBundle)
        .filter(
            DependencyBundle.service_id == service_id,
            DependencyBundle.organization_id == org_id,
        )
        .first()
    )
    if not bundle:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No dependency bundle exists for service '{service_id}'. Call POST /template first.",
        )
    return bundle


def ensure_bundle(service: BusinessService, org_id: int, db: Session) -> DependencyBundle:
    """Return this service's dependency bundle, creating an empty one if absent.

    `publish_slot_mappings` has always done this inline: a service reaching the
    mapping surface without a bundle row gets one, loaded from its archetype
    template. `decide_slot_mapping` did not, and called `get_bundle` — so
    answering *all* of a service's dependencies at once created the bundle it
    needed, while answering *one* 404'd. That is the same yes-to-one /
    yes-to-all asymmetry the decide route exists to remove, in another place.

    Reached in the product by any service whose bundle was never created —
    *Contract Management* on org 7's "Billing & Subscription" is one, and the
    slot rows it already carries prove the decision has somewhere to land.

    Nothing commits here; the caller owns the transaction.
    """
    bundle = (
        db.query(DependencyBundle)
        .filter(
            DependencyBundle.service_id == service.id,
            DependencyBundle.organization_id == org_id,
        )
        .first()
    )
    if bundle is not None:
        return bundle

    if not service.archetype or service.archetype not in VALID_ARCHETYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown archetype '{service.archetype}'.",
        )
    bundle = DependencyBundle(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        service_id=service.id,
        status="draft",
        mode="manual_training",
        lifecycle_state="template_loaded",
        groups=[
            {
                "key": tg["key"],
                "label": tg["label"],
                "question": tg["question"],
                "description": tg["description"],
                "required": tg["required"],
                "template_nodes": tg.get("template_nodes", []),
                "nodes": [],
            }
            for tg in (get_template(service.archetype) or [])
        ],
    )
    db.add(bundle)
    db.flush()
    return bundle


def groups_to_out(raw_groups: list) -> list[DependencyGroupOut]:
    """Project stored bundle groups onto the response contract.

    Every asset link is normalised on the way out, because the contract types
    them ``list[str]`` and Pydantic will not coerce an integer into one (#363).
    """
    return [
        DependencyGroupOut(
            key=g.get("key", ""),
            label=g.get("label", ""),
            question=g.get("question", ""),
            description=g.get("description", ""),
            required=g.get("required", False),
            template_nodes=[
                TemplatePatternOptionOut(
                    template_key=node.get("template_key", ""),
                    label=node.get("label", ""),
                    pattern_key=node.get("pattern_key"),
                )
                for node in g.get("template_nodes", [])
            ],
            rejected=g.get("rejected"),
            nodes=[
                DependencyNodeOut(
                    id=n["id"],
                    label=n["label"],
                    # #363 — the one reader the audit missed. Stored links come
                    # in two shapes; DependencyNodeOut types this list[str], so a
                    # bare integer raises a ValidationError rather than being
                    # dropped. Normalise here as every other reader does.
                    linked_asset_ids=[
                        reference
                        for reference in (
                            normalise_asset_reference(value)
                            for value in n.get("linked_asset_ids", []) or []
                        )
                        if reference is not None
                    ],
                    source=n.get("source", "manual"),
                    validation_status=n.get("validation_status", "suggested"),
                    fallback_status=n.get("fallback_status"),
                    spof=n.get("spof"),
                    confidence=n.get("confidence"),
                    template_key=n.get("template_key"),
                    pattern_key=n.get("pattern_key"),
                    critical_for_business=n.get("critical_for_business"),
                    business_consequence=n.get("business_consequence"),
                    impact_type=n.get("impact_type"),
                    business_impact_level=n.get("business_impact_level"),
                    recovery_dependent=n.get("recovery_dependent"),
                    deferred_asset_mapping=n.get("deferred_asset_mapping", False),
                    slot_id=n.get("slot_id"),
                    template_orphaned=bool(n.get("template_orphaned", False)),
                )
                for n in g.get("nodes", [])
            ],
        )
        for g in (raw_groups or [])
    ]


def bundle_to_response(
    bundle: DependencyBundle,
    latest_version: DependencyBundleVersion | None = None,
    *,
    groups: list | None = None,
) -> DependencyBundleResponse:
    """The bundle as a response.

    #460: pass `groups`, the service's live dependency state composed from its slot records. The
    stored `bundle.groups` nodes are the published snapshot and are answered only when no live
    state is given (a version, or a caller that has not moved yet).
    """
    return DependencyBundleResponse(
        id=bundle.id,
        service_id=bundle.service_id,
        status=bundle.status,
        mode=bundle.mode,
        lifecycle_state=bundle.lifecycle_state,
        groups=groups_to_out(groups if groups is not None else bundle.groups),
        validation_snapshot=bundle.validation_snapshot,
        acknowledged_warning_ids=list(bundle.acknowledged_warning_ids or []),
        created_at=bundle.created_at,
        updated_at=bundle.updated_at,
        latest_version_id=latest_version.id if latest_version else None,
        latest_version_number=latest_version.version_number if latest_version else None,
    )


def version_to_response(version: DependencyBundleVersion) -> BundleVersionResponse:
    return BundleVersionResponse(
        id=version.id,
        bundle_id=version.bundle_id,
        service_id=version.service_id,
        version_number=version.version_number,
        status=version.status,
        lifecycle_state=version.lifecycle_state,
        groups_snapshot=groups_to_out(version.groups_snapshot),
        validation_snapshot=version.validation_snapshot,
        acknowledged_warning_ids=list(version.acknowledged_warning_ids or []),
        published_at=version.published_at,
        created_at=version.created_at,
    )


def find_group(groups: list[dict], group_key: str) -> dict | None:
    return next((g for g in groups if g.get("key") == group_key), None)


def find_node(group: dict, node_id: str) -> dict | None:
    return next((n for n in group.get("nodes", []) if n.get("id") == node_id), None)


def derive_impact_classification(choice: str) -> tuple[bool, str]:
    if choice == "service_stops":
        return True, "availability"
    if choice == "service_degraded":
        return True, "availability"
    if choice == "data_exposed":
        return True, "confidentiality"
    if choice == "records_incorrect":
        return True, "integrity"
    if choice == "combined":
        return True, "combined"
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=(
            "payload.business_choice must be one of 'service_stops', "
            "'service_degraded', 'data_exposed', 'records_incorrect', or 'combined'."
        ),
    )


def validate_impact_level(level: Any) -> str:
    if level in {"high", "medium", "low"}:
        return str(level)
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="payload.business_impact_level must be 'high', 'medium', or 'low'.",
    )


def build_validation_finding(
    *,
    finding_id: str,
    severity: Literal["BLOCKER", "WARNING", "INFO"],
    message: str,
    recommendation: str,
    dependency_id: str | None = None,
    dependency_label: str | None = None,
    group_key: str | None = None,
    group_label: str | None = None,
    requires_acknowledgement: bool | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "dependency_id": dependency_id,
        "dependency_label": dependency_label,
        "group_key": group_key,
        "group_label": group_label,
        "message": message,
        "recommendation": recommendation,
        "requires_acknowledgement": (
            severity == "WARNING" if requires_acknowledgement is None else requires_acknowledgement
        ),
    }


def build_group_finding_id(group_key: str, code: str) -> str:
    return f"group:{group_key}:{code}"


def build_node_finding_id(node_id: str, code: str) -> str:
    return f"node:{node_id}:{code}"


def snapshot_from_findings(
    *,
    findings: list[dict[str, Any]],
    acknowledged_warning_ids: list[str],
) -> dict[str, Any]:
    return {
        "findings": findings,
        "warning_ids": [finding["id"] for finding in findings if finding["severity"] == "WARNING"],
        "acknowledged_warning_ids": acknowledged_warning_ids,
    }


def validate_node_for_publish(group_key: str, group_label: str, node: dict) -> list[dict[str, Any]]:
    """Findings that stand between one dependency slot and a publishable bundle.

    Emits BLOCKERs for what is simply absent (no asset link, no business impact,
    no recovery answer, no resilience classification) and WARNINGs for what a
    person has to weigh: a critical dependency with no fallback, a single point of
    failure in a high-impact part of the service, and a SPOF claim that names more
    than one asset and so contradicts itself.

    A WARNING is acknowledged, never resolved here — the judgement stays with the
    person publishing.
    """
    findings: list[dict[str, Any]] = []
    node_id = str(node.get("id") or "")
    node_label = node.get("label", "Dependency")
    if not node.get("deferred_asset_mapping", False) and not node.get("linked_asset_ids"):
        findings.append(
            build_validation_finding(
                finding_id=build_node_finding_id(node_id, "missing_asset_mapping"),
                severity="BLOCKER",
                dependency_id=node_id,
                dependency_label=node_label,
                group_key=group_key,
                group_label=group_label,
                message=(
                    f"'{node_label}' in '{group_label}' has not been linked to a real asset "
                    "and has not been marked as still unclear."
                ),
                recommendation="Link a real asset to this dependency, or explicitly defer the mapping for now.",
                requires_acknowledgement=False,
            )
        )
    if (
        node.get("critical_for_business") is None
        or not node.get("business_consequence")
        or not node.get("impact_type")
        or not node.get("business_impact_level")
    ):
        findings.append(
            build_validation_finding(
                finding_id=build_node_finding_id(node_id, "missing_business_impact"),
                severity="BLOCKER",
                dependency_id=node_id,
                dependency_label=node_label,
                group_key=group_key,
                group_label=group_label,
                message=(
                    f"'{node_label}' in '{group_label}' has not yet been explained in business terms. "
                    "Confirm what happens if it fails or is compromised."
                ),
                recommendation="Choose the business consequence and impact level before continuing.",
                requires_acknowledgement=False,
            )
        )
    if node.get("recovery_dependent") is None:
        findings.append(
            build_validation_finding(
                finding_id=build_node_finding_id(node_id, "missing_recovery_dependency"),
                severity="BLOCKER",
                dependency_id=node_id,
                dependency_label=node_label,
                group_key=group_key,
                group_label=group_label,
                message=(
                    f"Recovery planning is incomplete for '{node_label}' in '{group_label}'. "
                    "Confirm whether recovery depends on it."
                ),
                recommendation="Confirm whether recovery depends on this dependency before publishing.",
                requires_acknowledgement=False,
            )
        )
    if node.get("fallback_status") is None or node.get("spof") is None:
        findings.append(
            build_validation_finding(
                finding_id=build_node_finding_id(node_id, "missing_resilience_classification"),
                severity="BLOCKER",
                dependency_id=node_id,
                dependency_label=node_label,
                group_key=group_key,
                group_label=group_label,
                message=(
                    f"Resilience planning is incomplete for '{node_label}' in '{group_label}'. "
                    "Confirm its fallback position and whether it is a single point of failure."
                ),
                recommendation="Confirm fallback coverage and single-point-of-failure status before continuing.",
                requires_acknowledgement=False,
            )
        )
    if node.get("critical_for_business") and node.get("fallback_status", "none") == "none":
        findings.append(
            build_validation_finding(
                finding_id=build_node_finding_id(
                    node_id, "missing_fallback_on_critical_dependency"
                ),
                severity="WARNING",
                dependency_id=node_id,
                dependency_label=node_label,
                group_key=group_key,
                group_label=group_label,
                message=(
                    f"This service depends on '{node_label}' in '{group_label}' to keep operating, "
                    "but no fallback has been defined."
                ),
                recommendation="Define the fallback position, or explicitly acknowledge that this remains a resilience risk.",
            )
        )
    if node.get("spof") and node.get("business_impact_level") == "high":
        findings.append(
            build_validation_finding(
                finding_id=build_node_finding_id(node_id, "spof_on_high_impact_dependency"),
                severity="WARNING",
                dependency_id=node_id,
                dependency_label=node_label,
                group_key=group_key,
                group_label=group_label,
                message=f"'{node_label}' in '{group_label}' is a single point of failure in a high-impact part of the service.",
                recommendation="Reduce the single point of failure, or acknowledge that the business is accepting that concentration risk.",
            )
        )
    if node.get("spof") and len(node.get("linked_asset_ids", [])) > 1:
        findings.append(
            build_validation_finding(
                finding_id=build_node_finding_id(node_id, "inconsistent_spof_multiple_assets"),
                severity="WARNING",
                dependency_id=node_id,
                dependency_label=node_label,
                group_key=group_key,
                group_label=group_label,
                message=(
                    f"'{node_label}' in '{group_label}' is linked to multiple assets but is still "
                    "marked as a single point of failure."
                ),
                recommendation="Confirm whether this dependency is truly a single point of failure, or update the resilience classification.",
            )
        )
    return findings


def log_decision(
    db: Session,
    *,
    org_id: int,
    service_id: str,
    bundle_id: str,
    node_id: str | None,
    action: str,
    group_key: str | None,
    before_state: dict | None,
    after_state: dict | None,
    reason: str | None,
) -> None:
    decision = MappingDecision(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        service_id=service_id,
        bundle_id=bundle_id,
        node_id=node_id,
        action=action,
        group_key=group_key,
        before_state=before_state,
        after_state=after_state,
        reason=reason,
        actor_type="human",
    )
    db.add(decision)


def check_spof(asset_id: str, service_id: str, org_id: int, db: Session) -> bool:
    """Whether this asset is also depended on by another service in the tenant.

    An observation, not a verdict: it says the concentration exists, and leaves
    what to do about it to the person reading the finding it feeds.
    """
    # #460 — read from other services' slot records, the one live record of a
    # dependency decision, not from their bundle nodes (the published snapshot).
    # Only a person's live decision counts: an engine suggestion is not a
    # dependency yet, and `teams` records are not dependencies (#434).
    target = normalise_asset_reference(asset_id)
    if target is None:
        return False
    other_records = (
        db.query(SlotInstance)
        .filter(
            SlotInstance.organization_id == org_id,
            SlotInstance.service_id != service_id,
            SlotInstance.status == "mapped",
            SlotInstance.asset_id.isnot(None),
        )
        .all()
    )
    # Normalised on both sides: stored links have appeared as "asset-92" and as
    # the bare integer 92, and a raw comparison silently missed the second — so a
    # genuinely shared asset reported as not shared, and its SPOF warning never
    # fired.
    return any(
        is_live_dependency(record) and normalise_asset_reference(record.asset_id) == target
        for record in other_records
    )
