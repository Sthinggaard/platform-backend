"""Risklence Scanner setup routes — Step 3.5 (configure and validate the
scanner; see ``evidence_scanner_enums`` for the scope note).

Nested under the same ``/api/v1/evidence-sources`` prefix as
``evidence_source.py`` but kept in its own router/module (SRP) — every
path here has a fixed ``/scanner`` literal segment after ``{source_id}``,
so registration order relative to ``evidence_source.py``'s routes does not
matter. Mutations require the platform ``org_admin``/``admin`` role,
matching ``evidence_source.py``'s ``_require_org_admin`` pattern.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.evidence_scanner_enums import (
    SCANNER_AUDIT_ACTIVATED,
    SCANNER_AUDIT_DOMAIN_TARGET_ADDED,
    SCANNER_AUDIT_DOMAIN_TARGET_APPROVED,
    SCANNER_AUDIT_DOMAIN_TARGET_EXCLUDED,
    SCANNER_AUDIT_NETWORK_TARGET_ADDED,
    SCANNER_AUDIT_NETWORK_TARGET_APPROVED,
    SCANNER_AUDIT_NETWORK_TARGET_EXCLUDED,
    SCANNER_AUDIT_PROFILE_SELECTED,
    SCANNER_AUDIT_REVOKED,
    SCANNER_AUDIT_SCOPE_CONFIRMED,
    SCANNER_AUDIT_SELF_CHECK_REQUESTED,
    SCANNER_AUDIT_TEST_SCAN_RECORDED,
    SCANNER_AUDIT_TOOLS_VALIDATED,
    SCANNER_ERROR_DOMAIN_TARGET_NOT_FOUND,
    SCANNER_ERROR_NETWORK_TARGET_NOT_FOUND,
    SCANNER_ERROR_NOT_FOUND,
    CollectorInstruction,
    ScannerInstallationMethod,
    ScannerNetworkType,
    ScannerProfile,
    ScannerTargetSource,
)
from src.core.constants.evidence_source_enums import EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.evidence_scanner import (
    ScannerDomainTarget,
    ScannerInstance,
    ScannerNetworkTarget,
)
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.models import AuditEvent, User
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES
from src.core.services.evidence_scanner_readiness_service import (
    build_prepared_scanner_configuration,
    evaluate_scanner_readiness,
)
from src.core.services.collector_instruction_service import request_instruction
from src.core.services.evidence_scanner_service import (
    generate_collector_command,
    EvidenceScannerValidationError,
    add_domain_target,
    add_domain_target_from_verified_identity,
    add_network_target,
    approve_domain_target,
    approve_network_target,
    confirm_scanner_scope,
    exclude_domain_target,
    exclude_network_target,
    install_scanner,
    list_domain_targets,
    list_network_targets,
    list_suggested_domains,
    record_test_scan_result,
    record_tool_validation,
    revoke_scanner,
    select_scan_profile,
)
from src.api.schemas.timestamps import UtcTimestamp

router = APIRouter(prefix="/api/v1/evidence-sources", tags=["Evidence scanner"])


class InstallScannerRequest(BaseModel):
    name: str
    installation_method: ScannerInstallationMethod


class ScannerInstanceResponse(BaseModel):
    id: str
    evidence_source_id: str
    name: str
    public_instance_id: str
    installation_method: str
    status: str
    scan_profile: str | None
    tool_status: dict[str, str]
    tool_validation_at: UtcTimestamp | None
    connection_verified_at: UtcTimestamp | None
    test_scan_status: str | None
    scope_confirmed_at: UtcTimestamp | None
    activated_at: UtcTimestamp


class InstallScannerResponse(BaseModel):
    instance: ScannerInstanceResponse
    activation_token: str


class SuggestedDomainResponse(BaseModel):
    id: str
    domain: str


class AddDomainTargetRequest(BaseModel):
    domain: str | None = None
    organization_domain_id: str | None = None
    include_subdomains: bool = True


class DomainTargetResponse(BaseModel):
    id: str
    domain: str
    source: str
    ownership_status: str
    scan_enabled: bool
    include_subdomains: bool
    status: str


class AddNetworkTargetRequest(BaseModel):
    cidr: str
    name: str
    network_type: ScannerNetworkType
    organisation_unit_id: str | None = None
    location_id: str | None = None
    environment: str | None = None


class NetworkTargetResponse(BaseModel):
    id: str
    cidr: str
    name: str
    network_type: str
    organisation_unit_id: str | None
    location_id: str | None
    environment: str | None
    status: str
    warnings: list[str] = []
    estimated_address_count: int | None = None


class SelectProfileRequest(BaseModel):
    profile: ScannerProfile


class TestScanRequest(BaseModel):
    status: str
    connection_verified: bool = True


class ScannerReadinessResponse(BaseModel):
    ready: bool
    readiness: str
    state: str
    instance_id: str | None
    approved_domain_count: int
    approved_network_count: int
    blocking_reasons: list[str]
    #: CA-02.3 — what the Collector itself reported, on the same payload the
    #: gate above is computed from, so a view cannot show one and gate on
    #: the other.
    collector_readiness: str = "unknown"
    collector_components: list[dict] = []
    collector_reported_at: UtcTimestamp | None = None
    collector_required_components: list[str] = []
    # CA-02.3 slice 3 — what RiskCollectorReadiness renders.
    collector_machine: dict = {}
    collector_version: str | None = None
    collector_template_pack_version: str | None = None
    collector_evidence_storage: str = "unknown"
    collector_platform_link: str = "unknown"
    collector_trigger: str | None = None
    collector_requested_by: str | None = None
    #: The exact command that clears each operator-side gate, keyed by the
    #: blocking reason it clears. Søren, 2026-08-24: a reason a person cannot
    #: act on is the same as no reason at all — "run its tool check on the
    #: machine" names an outcome and leaves the command, the image and the
    #: volume to be guessed. Built from the same generator as the activation
    #: command, so how a Collector is driven has one definition.
    remedy_commands: dict[str, str] = {}


class PreparedScannerResponse(BaseModel):
    organization_id: int
    evidence_source_id: str
    scanner_instance_id: str | None
    capabilities: dict[str, bool]
    approved_domains: list[dict]
    approved_networks: list[dict]
    scan_profile: str | None
    tool_status: dict[str, str]
    connection_verified: bool
    test_scan_passed: bool
    readiness: str
    ready: bool


def _require_org_admin(db: Session, ctx: TenantContext) -> None:
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or user.role not in ADMIN_ROLES:
        raise AuthorizationError(EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED)


def _write_audit(db: Session, *, ctx: TenantContext, event_type: str, metadata: dict) -> None:
    db.add(
        AuditEvent(
            organization_id=ctx.organization_id,
            actor_user_id=ctx.user_id,
            event_type=event_type,
            metadata_json=metadata,
        )
    )


def _require_source(db: Session, *, ctx: TenantContext, source_id: str) -> EvidenceSource:
    source = TenantRepository(db, EvidenceSource, ctx.organization_id).get_by_id(source_id)
    if source is None:
        raise ResourceNotFoundError("Evidence source not found")
    return source


def _require_instance(db: Session, *, ctx: TenantContext, source_id: str) -> ScannerInstance:
    matches = TenantRepository(db, ScannerInstance, ctx.organization_id).filter_by(evidence_source_id=source_id)
    if not matches:
        raise ResourceNotFoundError(SCANNER_ERROR_NOT_FOUND)
    return matches[0]


def _require_domain_target(db: Session, *, ctx: TenantContext, target_id: str) -> ScannerDomainTarget:
    target = TenantRepository(db, ScannerDomainTarget, ctx.organization_id).get_by_id(target_id)
    if target is None:
        raise ResourceNotFoundError(SCANNER_ERROR_DOMAIN_TARGET_NOT_FOUND)
    return target


def _require_network_target(db: Session, *, ctx: TenantContext, target_id: str) -> ScannerNetworkTarget:
    target = TenantRepository(db, ScannerNetworkTarget, ctx.organization_id).get_by_id(target_id)
    if target is None:
        raise ResourceNotFoundError(SCANNER_ERROR_NETWORK_TARGET_NOT_FOUND)
    return target


def _instance_response(instance: ScannerInstance) -> ScannerInstanceResponse:
    return ScannerInstanceResponse(
        id=instance.id,
        evidence_source_id=instance.evidence_source_id,
        name=instance.name,
        public_instance_id=instance.public_instance_id,
        installation_method=instance.installation_method,
        status=instance.status,
        scan_profile=instance.scan_profile,
        tool_status=instance.tool_status or {},
        tool_validation_at=instance.tool_validation_at,
        connection_verified_at=instance.connection_verified_at,
        test_scan_status=instance.test_scan_status,
        scope_confirmed_at=instance.scope_confirmed_at,
        activated_at=instance.activated_at,
    )


def _domain_target_response(target: ScannerDomainTarget) -> DomainTargetResponse:
    return DomainTargetResponse(
        id=target.id,
        domain=target.domain,
        source=target.source,
        ownership_status=target.ownership_status,
        scan_enabled=target.scan_enabled,
        include_subdomains=target.include_subdomains,
        status=target.status,
    )


def _network_target_response(
    target: ScannerNetworkTarget, *, warnings: list[str] | None = None, estimated_address_count: int | None = None
) -> NetworkTargetResponse:
    return NetworkTargetResponse(
        id=target.id,
        cidr=target.cidr,
        name=target.name,
        network_type=target.network_type,
        organisation_unit_id=target.organisation_unit_id,
        location_id=target.location_id,
        environment=target.environment,
        status=target.status,
        warnings=warnings or [],
        estimated_address_count=estimated_address_count,
    )


# --- Installation / activation -------------------------------------------------------


@router.post("/{source_id}/scanner/install", response_model=InstallScannerResponse)
def install_scanner_route(
    source_id: str,
    body: InstallScannerRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> InstallScannerResponse:
    _require_org_admin(db, ctx)
    source = _require_source(db, ctx=ctx, source_id=source_id)
    try:
        result = install_scanner(
            db, source, name=body.name, installation_method=body.installation_method.value
        )
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_AUDIT_ACTIVATED,
        metadata={"evidence_source_id": source.id, "scanner_instance_id": result.instance.id},
    )
    db.commit()
    db.refresh(result.instance)
    return InstallScannerResponse(
        instance=_instance_response(result.instance), activation_token=result.activation_token
    )


@router.get("/{source_id}/scanner", response_model=ScannerInstanceResponse)
def get_scanner_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ScannerInstanceResponse:
    instance = _require_instance(db, ctx=ctx, source_id=source_id)
    return _instance_response(instance)


@router.post("/{source_id}/scanner/revoke", response_model=ScannerInstanceResponse)
def revoke_scanner_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ScannerInstanceResponse:
    _require_org_admin(db, ctx)
    instance = _require_instance(db, ctx=ctx, source_id=source_id)
    revoke_scanner(db, instance)
    _write_audit(db, ctx=ctx, event_type=SCANNER_AUDIT_REVOKED, metadata={"scanner_instance_id": instance.id})
    db.commit()
    db.refresh(instance)
    return _instance_response(instance)


@router.post("/{source_id}/scanner/self-check", response_model=ScannerInstanceResponse)
def request_self_check_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ScannerInstanceResponse:
    """Ask this Collector to re-run its self-check on its next heartbeat.

    CA-02.3 slice 3. This is the *only* user-facing write anywhere near
    readiness, and it deliberately cannot set one: it asks a question, it does
    not supply an answer. The manual "Available / Not available" toggles this
    story removed were the opposite, and that is the whole distinction.

    Org-admin, matching every sibling step of this wizard (approving networks,
    adding a target, confirming scope). That is not a new restriction: anyone
    who has reached the tool-validation step is already an admin, because they
    could not have approved the boundary otherwise. Inventing a laxer rule for
    this one button would be the inconsistency, not the guard.

    Idempotent by construction: requesting again refreshes the pending
    instruction rather than queueing a second, so an impatient user gets one
    fresh answer instead of five checks.
    """
    _require_org_admin(db, ctx)
    instance = _require_instance(db, ctx=ctx, source_id=source_id)
    request_instruction(
        db,
        instance,
        instruction=CollectorInstruction.SELF_CHECK,
        requested_by_user_id=ctx.user_id,
    )
    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_AUDIT_SELF_CHECK_REQUESTED,
        metadata={"scanner_instance_id": instance.id},
    )
    db.commit()
    db.refresh(instance)
    return _instance_response(instance)


# --- Domain targets --------------------------------------------------------------------


@router.get("/{source_id}/scanner/domains/suggested", response_model=list[SuggestedDomainResponse])
def list_suggested_domains_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[SuggestedDomainResponse]:
    source = _require_source(db, ctx=ctx, source_id=source_id)
    try:
        suggestions = list_suggested_domains(db, source)
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    return [SuggestedDomainResponse(id=d.id, domain=d.domain) for d in suggestions]


@router.post("/{source_id}/scanner/domains", response_model=DomainTargetResponse)
def add_domain_target_route(
    source_id: str,
    body: AddDomainTargetRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DomainTargetResponse:
    _require_org_admin(db, ctx)
    source = _require_source(db, ctx=ctx, source_id=source_id)
    try:
        if body.organization_domain_id:
            target = add_domain_target_from_verified_identity(
                db, source, organization_domain_id=body.organization_domain_id
            )
        else:
            if not body.domain:
                raise EvidenceScannerValidationError("A domain is required.")
            target = add_domain_target(
                db,
                source,
                domain=body.domain,
                include_subdomains=body.include_subdomains,
                target_source=ScannerTargetSource.USER_ADDED,
            )
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_AUDIT_DOMAIN_TARGET_ADDED,
        metadata={"evidence_source_id": source.id, "domain_target_id": target.id},
    )
    db.commit()
    db.refresh(target)
    return _domain_target_response(target)


@router.get("/{source_id}/scanner/domains", response_model=list[DomainTargetResponse])
def list_domain_targets_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[DomainTargetResponse]:
    _require_source(db, ctx=ctx, source_id=source_id)
    targets = list_domain_targets(db, source_id)
    return [_domain_target_response(t) for t in targets]


@router.post("/{source_id}/scanner/domains/{target_id}/approve", response_model=DomainTargetResponse)
def approve_domain_target_route(
    source_id: str,
    target_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DomainTargetResponse:
    _require_org_admin(db, ctx)
    target = _require_domain_target(db, ctx=ctx, target_id=target_id)
    approve_domain_target(db, target, approved_by_user_id=ctx.user_id)
    _write_audit(
        db, ctx=ctx, event_type=SCANNER_AUDIT_DOMAIN_TARGET_APPROVED, metadata={"domain_target_id": target.id}
    )
    db.commit()
    db.refresh(target)
    return _domain_target_response(target)


@router.post("/{source_id}/scanner/domains/{target_id}/exclude", response_model=DomainTargetResponse)
def exclude_domain_target_route(
    source_id: str,
    target_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> DomainTargetResponse:
    _require_org_admin(db, ctx)
    target = _require_domain_target(db, ctx=ctx, target_id=target_id)
    exclude_domain_target(db, target)
    _write_audit(
        db, ctx=ctx, event_type=SCANNER_AUDIT_DOMAIN_TARGET_EXCLUDED, metadata={"domain_target_id": target.id}
    )
    db.commit()
    db.refresh(target)
    return _domain_target_response(target)


# --- Network targets -------------------------------------------------------------------


@router.post("/{source_id}/scanner/networks", response_model=NetworkTargetResponse)
def add_network_target_route(
    source_id: str,
    body: AddNetworkTargetRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> NetworkTargetResponse:
    _require_org_admin(db, ctx)
    source = _require_source(db, ctx=ctx, source_id=source_id)
    try:
        result = add_network_target(
            db,
            source,
            cidr=body.cidr,
            name=body.name,
            network_type=body.network_type.value,
            organisation_unit_id=body.organisation_unit_id,
            location_id=body.location_id,
            environment=body.environment,
        )
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_AUDIT_NETWORK_TARGET_ADDED,
        metadata={"evidence_source_id": source.id, "network_target_id": result.target.id, "warnings": result.warnings},
    )
    db.commit()
    db.refresh(result.target)
    return _network_target_response(
        result.target, warnings=result.warnings, estimated_address_count=result.estimated_address_count
    )


@router.get("/{source_id}/scanner/networks", response_model=list[NetworkTargetResponse])
def list_network_targets_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[NetworkTargetResponse]:
    _require_source(db, ctx=ctx, source_id=source_id)
    targets = list_network_targets(db, source_id)
    return [_network_target_response(t) for t in targets]


@router.post("/{source_id}/scanner/networks/{target_id}/approve", response_model=NetworkTargetResponse)
def approve_network_target_route(
    source_id: str,
    target_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> NetworkTargetResponse:
    _require_org_admin(db, ctx)
    target = _require_network_target(db, ctx=ctx, target_id=target_id)
    approve_network_target(db, target, approved_by_user_id=ctx.user_id)
    _write_audit(
        db, ctx=ctx, event_type=SCANNER_AUDIT_NETWORK_TARGET_APPROVED, metadata={"network_target_id": target.id}
    )
    db.commit()
    db.refresh(target)
    return _network_target_response(target)


@router.post("/{source_id}/scanner/networks/{target_id}/exclude", response_model=NetworkTargetResponse)
def exclude_network_target_route(
    source_id: str,
    target_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> NetworkTargetResponse:
    _require_org_admin(db, ctx)
    target = _require_network_target(db, ctx=ctx, target_id=target_id)
    exclude_network_target(db, target)
    _write_audit(
        db, ctx=ctx, event_type=SCANNER_AUDIT_NETWORK_TARGET_EXCLUDED, metadata={"network_target_id": target.id}
    )
    db.commit()
    db.refresh(target)
    return _network_target_response(target)


# --- Profile / scope confirmation -------------------------------------------------------


@router.put("/{source_id}/scanner/profile", response_model=ScannerInstanceResponse)
def select_profile_route(
    source_id: str,
    body: SelectProfileRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ScannerInstanceResponse:
    _require_org_admin(db, ctx)
    instance = _require_instance(db, ctx=ctx, source_id=source_id)
    select_scan_profile(db, instance, profile=body.profile.value)
    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_AUDIT_PROFILE_SELECTED,
        metadata={"scanner_instance_id": instance.id, "profile": body.profile.value},
    )
    db.commit()
    db.refresh(instance)
    return _instance_response(instance)


@router.post("/{source_id}/scanner/scope/confirm", response_model=ScannerInstanceResponse)
def confirm_scope_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ScannerInstanceResponse:
    _require_org_admin(db, ctx)
    source = _require_source(db, ctx=ctx, source_id=source_id)
    instance = _require_instance(db, ctx=ctx, source_id=source_id)
    try:
        confirm_scanner_scope(db, source, instance, confirmed_by_user_id=ctx.user_id)
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db, ctx=ctx, event_type=SCANNER_AUDIT_SCOPE_CONFIRMED, metadata={"scanner_instance_id": instance.id}
    )
    db.commit()
    db.refresh(instance)
    return _instance_response(instance)


# --- Tool validation / test scan --------------------------------------------------------


# CA-02.3 — the manual tool-validation route is deliberately gone.
#
# It let an authorised user mark Nmap/Subfinder/Nuclei "Available" and saved
# that as validation, writing the same `tool_status` the Collector's own
# self-check writes, with nothing to tell the two apart. So the platform could
# not distinguish a measurement from an assertion, and a user could declare a
# failed component healthy.
#
# Readiness now comes only from the Collector's own authenticated self-check
# (`scanner_agent.py`'s /readiness and /tools/validate routes). A user may
# review it, and may request a rerun — they may not write it. Removing the route
# rather than permission-gating it is the point: there is no role for which
# asserting an unverified technical fact is the right answer.
#
# `SCANNER_AUDIT_TOOLS_VALIDATED` stays defined for historical audit rows and is
# written by no live path.

@router.post("/{source_id}/scanner/test-scan", response_model=ScannerInstanceResponse)
def record_test_scan_route(
    source_id: str,
    body: TestScanRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ScannerInstanceResponse:
    _require_org_admin(db, ctx)
    instance = _require_instance(db, ctx=ctx, source_id=source_id)
    record_test_scan_result(db, instance, status=body.status, connection_verified=body.connection_verified)
    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_AUDIT_TEST_SCAN_RECORDED,
        metadata={"scanner_instance_id": instance.id, "status": body.status},
    )
    db.commit()
    db.refresh(instance)
    return _instance_response(instance)


# --- Readiness / prepared read model -----------------------------------------------------


@router.get("/{source_id}/scanner/readiness", response_model=ScannerReadinessResponse)
def get_scanner_readiness_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ScannerReadinessResponse:
    source = _require_source(db, ctx=ctx, source_id=source_id)
    result = evaluate_scanner_readiness(db, source)
    # Scoped to the organisation as well as the source. The source was already
    # tenant-checked, so this is defence in depth — but the isolation check is
    # right that a query without it is one that can be made to cross a tenant
    # later, and it caught this.
    instance = (
        db.query(ScannerInstance)
        .filter(
            ScannerInstance.evidence_source_id == source.id,
            ScannerInstance.organization_id == ctx.organization_id,
        )
        .first()
    )
    method = instance.installation_method if instance else None
    # Only the gates an operator clears by running something. Approving a
    # boundary or a network range happens in the product, not on a machine, and
    # offering a command for those would point somebody at the wrong place.
    remedies = {
        "required_tools_not_validated": generate_collector_command(
            "validate-tools", installation_method=method
        ),
        "controlled_test_scan_not_passed": generate_collector_command(
            "test-scan", installation_method=method
        ),
    }
    return ScannerReadinessResponse(
        ready=result.ready,
        readiness=result.readiness.value,
        state=result.state.value,
        instance_id=result.instance_id,
        approved_domain_count=result.approved_domain_count,
        approved_network_count=result.approved_network_count,
        blocking_reasons=result.blocking_reasons,
        collector_readiness=result.collector_readiness,
        collector_components=result.collector_components,
        collector_reported_at=result.collector_reported_at,
        collector_required_components=result.collector_required_components,
        collector_machine=result.collector_machine,
        collector_version=result.collector_version,
        collector_template_pack_version=result.collector_template_pack_version,
        collector_evidence_storage=result.collector_evidence_storage,
        collector_platform_link=result.collector_platform_link,
        collector_trigger=result.collector_trigger,
        collector_requested_by=result.collector_requested_by,
        remedy_commands={
            reason: command
            for reason, command in remedies.items()
            if reason in result.blocking_reasons
        },
    )


@router.get("/{source_id}/scanner/prepared", response_model=PreparedScannerResponse)
def get_prepared_scanner_route(
    source_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> PreparedScannerResponse:
    source = _require_source(db, ctx=ctx, source_id=source_id)
    prepared = build_prepared_scanner_configuration(db, source)
    return PreparedScannerResponse(
        organization_id=prepared.organization_id,
        evidence_source_id=prepared.evidence_source_id,
        scanner_instance_id=prepared.scanner_instance_id,
        capabilities=prepared.capabilities,
        approved_domains=prepared.approved_domains,
        approved_networks=prepared.approved_networks,
        scan_profile=prepared.scan_profile,
        tool_status=prepared.tool_status,
        connection_verified=prepared.connection_verified,
        test_scan_passed=prepared.test_scan_passed,
        readiness=prepared.readiness.value,
        ready=prepared.ready,
    )
