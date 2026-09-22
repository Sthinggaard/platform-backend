from __future__ import annotations

import copy
import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.process_activation_enums import ProcessActivationErrorMessage
from src.core.database import get_db
from src.core.exceptions import ValidationError
from src.core.models import DependencyBundleVersion, ValueStream
from src.core.repository import TenantRepository
from src.core.services.dependency_decision_service import live_groups, load_service_slot_context
from src.core.services.process_activation_service import resolve_process_activation_readiness

from .bundle_common import (
    build_group_finding_id,
    build_validation_finding,
    bundle_to_response,
    get_bundle,
    get_service,
    log_decision,
    logger,
    require_service_process_editor,
    snapshot_from_findings,
    validate_node_for_publish,
    version_to_response,
)
from .bundle_contracts import (
    BundleVersionResponse,
    DependencyBundleResponse,
    ValidateBundleRequest,
    ValidateBundleResponse,
    ValidationFindingOut,
)

router = APIRouter()


def _require_active_process_context(service, *, ctx: TenantContext, db: Session) -> None:
    process_ids = set(service.value_stream_ids or [])
    if not process_ids:
        return
    processes = [
        process
        for process in TenantRepository(db, ValueStream, ctx.organization_id).get_all()
        if process.id in process_ids
    ]
    readiness = resolve_process_activation_readiness(
        db,
        organization_id=ctx.organization_id,
        processes=processes,
    )
    if any(item.impact_model_active for item in readiness.values()):
        return
    raise ValidationError(
        ProcessActivationErrorMessage.DEPENDENCY_PUBLICATION_REQUIRES_ACTIVATION.value
    )


@router.post("/{service_id}/bundle/validate", response_model=ValidateBundleResponse)
def validate_bundle(
    service_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
    body: ValidateBundleRequest | None = Body(default=None),
) -> ValidateBundleResponse:
    service = get_service(service_id, ctx.organization_id, db)
    require_service_process_editor(
        service,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        db=db,
    )
    bundle = get_bundle(service_id, ctx.organization_id, db)

    if bundle.lifecycle_state == "bundle_validated":
        validation_snapshot = bundle.validation_snapshot or {}
        findings = [
            ValidationFindingOut.model_validate(finding)
            for finding in validation_snapshot.get("findings", [])
        ]
        return ValidateBundleResponse(
            valid=True,
            lifecycle_state="bundle_validated",
            errors=[],
            warnings=[finding.message for finding in findings if finding.severity == "WARNING"],
            findings=findings,
            warning_ids=[finding.id for finding in findings if finding.severity == "WARNING"],
            acknowledged_warning_ids=list(bundle.acknowledged_warning_ids or []),
            requires_warning_acceptance=False,
        )

    if bundle.lifecycle_state not in ("template_loaded", "bundle_manual_training"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Cannot validate a bundle in state '{bundle.lifecycle_state}'.",
        )

    findings: list[dict[str, Any]] = []
    # #460 — validate the live dependency state, composed from the service's slot records.
    for group in live_groups(bundle.groups, load_service_slot_context(db, service)):
        group_key = group.get("key", "")
        group_label = group.get("label", group_key)
        if group.get("rejected") and group.get("required"):
            findings.append(
                build_validation_finding(
                    finding_id=build_group_finding_id(group_key, "required_group_rejected"),
                    severity="BLOCKER",
                    group_key=group_key,
                    group_label=group_label,
                    message=f"Required group '{group_label}' was rejected — it must have at least one dependency.",
                    recommendation="Restore this required dependency group and confirm at least one dependency before publishing.",
                    requires_acknowledgement=False,
                )
            )
            continue
        active_nodes = [
            n for n in group.get("nodes", []) if n.get("validation_status") != "rejected"
        ]
        if group.get("required") and not active_nodes:
            findings.append(
                build_validation_finding(
                    finding_id=build_group_finding_id(
                        group_key, "required_group_missing_dependency"
                    ),
                    severity="BLOCKER",
                    group_key=group_key,
                    group_label=group_label,
                    message=f"Required group '{group_label}' has no dependencies. Add at least one.",
                    recommendation="Add at least one dependency from the pattern library for this required group.",
                    requires_acknowledgement=False,
                )
            )
        for node in active_nodes:
            findings.extend(validate_node_for_publish(group_key, group_label, node))

    errors = [finding["message"] for finding in findings if finding["severity"] == "BLOCKER"]
    warnings = [finding["message"] for finding in findings if finding["severity"] == "WARNING"]
    warning_ids = [finding["id"] for finding in findings if finding["severity"] == "WARNING"]
    finding_models = [ValidationFindingOut.model_validate(finding) for finding in findings]

    if errors:
        bundle.validation_snapshot = snapshot_from_findings(
            findings=findings, acknowledged_warning_ids=[]
        )
        bundle.acknowledged_warning_ids = []
        db.add(bundle)
        db.commit()
        db.refresh(bundle)
        return ValidateBundleResponse(
            valid=False,
            lifecycle_state=bundle.lifecycle_state,
            errors=errors,
            warnings=warnings,
            findings=finding_models,
            warning_ids=warning_ids,
            acknowledged_warning_ids=[],
            requires_warning_acceptance=False,
        )

    accept_warnings = body.accept_warnings if isinstance(body, ValidateBundleRequest) else False
    if warnings and not accept_warnings:
        bundle.validation_snapshot = snapshot_from_findings(
            findings=findings, acknowledged_warning_ids=[]
        )
        bundle.acknowledged_warning_ids = []
        db.add(bundle)
        db.commit()
        db.refresh(bundle)
        return ValidateBundleResponse(
            valid=False,
            lifecycle_state=bundle.lifecycle_state,
            errors=[],
            warnings=warnings,
            findings=finding_models,
            warning_ids=warning_ids,
            acknowledged_warning_ids=[],
            requires_warning_acceptance=True,
        )

    bundle.lifecycle_state = "bundle_validated"
    bundle.status = "validated"
    bundle.acknowledged_warning_ids = warning_ids
    bundle.validation_snapshot = snapshot_from_findings(
        findings=findings,
        acknowledged_warning_ids=warning_ids,
    )
    db.add(bundle)

    log_decision(
        db,
        org_id=ctx.organization_id,
        service_id=service_id,
        bundle_id=bundle.id,
        node_id=None,
        action="validate_bundle",
        group_key=None,
        before_state={"lifecycle_state": "bundle_manual_training"},
        after_state={
            "lifecycle_state": "bundle_validated",
            "acknowledged_warning_ids": warning_ids,
            "warning_count": len(warning_ids),
        },
        reason=None,
    )

    db.commit()
    db.refresh(bundle)

    logger.info(
        "bundle_validated", org_id=ctx.organization_id, service_id=service_id, bundle_id=bundle.id
    )
    return ValidateBundleResponse(
        valid=True,
        lifecycle_state="bundle_validated",
        errors=[],
        warnings=warnings,
        findings=finding_models,
        warning_ids=warning_ids,
        acknowledged_warning_ids=warning_ids,
        requires_warning_acceptance=False,
    )


@router.post("/{service_id}/bundle/publish", response_model=DependencyBundleResponse)
def publish_bundle(
    service_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DependencyBundleResponse:
    service = get_service(service_id, ctx.organization_id, db)
    require_service_process_editor(
        service,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        db=db,
    )
    _require_active_process_context(service, ctx=ctx, db=db)
    bundle = get_bundle(service_id, ctx.organization_id, db)

    if bundle.lifecycle_state != "bundle_validated":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Bundle must be in 'bundle_validated' state to publish. Current state: '{bundle.lifecycle_state}'.",
        )

    validation_snapshot = bundle.validation_snapshot or {}
    snapshot_findings = validation_snapshot.get("findings", [])
    required_warning_ids = {
        finding["id"]
        for finding in snapshot_findings
        if finding.get("severity") == "WARNING" and finding.get("requires_acknowledgement", True)
    }
    acknowledged_warning_ids = set(bundle.acknowledged_warning_ids or [])
    missing_warning_ids = sorted(required_warning_ids - acknowledged_warning_ids)
    if missing_warning_ids:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="All validation warnings must be acknowledged before publish.",
        )

    existing_versions = (
        db.query(DependencyBundleVersion)
        .filter(
            DependencyBundleVersion.bundle_id == bundle.id,
            DependencyBundleVersion.organization_id == ctx.organization_id,
        )
        .all()
    )
    next_version_number = len(existing_versions) + 1

    # #460 — publishing writes the snapshot: the live dependency state, composed from the
    # service's slot records, becomes the bundle's stored nodes and the version's copy. This is
    # the only place bundle nodes are written.
    snapshot = live_groups(bundle.groups, load_service_slot_context(db, service))
    bundle.groups = snapshot
    bundle.lifecycle_state = "bundle_published"
    bundle.status = "published"
    db.add(bundle)
    new_version = DependencyBundleVersion(
        id=str(uuid.uuid4()),
        organization_id=ctx.organization_id,
        bundle_id=bundle.id,
        service_id=service_id,
        version_number=next_version_number,
        status="published",
        lifecycle_state="bundle_published",
        groups_snapshot=copy.deepcopy(snapshot),
        validation_snapshot=copy.deepcopy(validation_snapshot) if validation_snapshot else None,
        acknowledged_warning_ids=sorted(acknowledged_warning_ids),
    )
    db.add(new_version)

    log_decision(
        db,
        org_id=ctx.organization_id,
        service_id=service_id,
        bundle_id=bundle.id,
        node_id=None,
        action="publish_bundle",
        group_key=None,
        before_state={
            "lifecycle_state": "bundle_validated",
            "acknowledged_warning_ids": sorted(acknowledged_warning_ids),
        },
        after_state={
            "lifecycle_state": "bundle_published",
            "acknowledged_warning_ids": sorted(acknowledged_warning_ids),
            "validation_snapshot": validation_snapshot,
            "version_id": new_version.id,
            "version_number": next_version_number,
        },
        reason=None,
    )

    db.commit()
    db.refresh(bundle)
    db.refresh(new_version)

    logger.info(
        "bundle_published",
        org_id=ctx.organization_id,
        service_id=service_id,
        bundle_id=bundle.id,
        version_id=new_version.id,
        version_number=new_version.version_number,
    )
    return bundle_to_response(bundle, latest_version=new_version, groups=snapshot)


@router.get("/{service_id}/bundle/versions", response_model=list[BundleVersionResponse])
def list_bundle_versions(
    service_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> list[BundleVersionResponse]:
    get_service(service_id, ctx.organization_id, db)
    versions = (
        db.query(DependencyBundleVersion)
        .filter(
            DependencyBundleVersion.service_id == service_id,
            DependencyBundleVersion.organization_id == ctx.organization_id,
        )
        .order_by(DependencyBundleVersion.version_number.asc())
        .all()
    )
    return [version_to_response(v) for v in versions]


@router.get("/{service_id}/bundle/versions/{version_id}", response_model=BundleVersionResponse)
def get_bundle_version(
    service_id: str,
    version_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> BundleVersionResponse:
    get_service(service_id, ctx.organization_id, db)
    version = (
        db.query(DependencyBundleVersion)
        .filter(
            DependencyBundleVersion.id == version_id,
            DependencyBundleVersion.service_id == service_id,
            DependencyBundleVersion.organization_id == ctx.organization_id,
        )
        .first()
    )
    if not version:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Bundle version '{version_id}' not found for service '{service_id}'.",
        )
    return version_to_response(version)
