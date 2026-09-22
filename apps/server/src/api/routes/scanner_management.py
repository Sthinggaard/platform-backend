"""Scanner lifecycle management — organisation-wide, independent of the
Step 3 evidence-source wizard.

Added after real operator testing showed the Step 3.5 wizard's single
"install once, forever" slot was a genuine dead end: no way to recover a
lost activation token, no way to stop/restart a scanner, no way to see or
run more than one at a time. Every action here operates on a
``ScannerInstance`` the same install-time wizard already creates — this
module never introduces a parallel scanner concept, only the lifecycle
actions and an organisation-wide list that were missing. Kept separate
from ``evidence_scanner.py`` (SRP: that file is Step 3.5's single-source
setup wizard; this one is cross-source scanner management) and from
``discovery_run.py`` (Step 4.1 governs *running* a scanner that already
exists; this governs the scanner's own existence).
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from src.api.middleware.tenant_context import TenantContext, get_tenant_context
from src.core.constants.evidence_scanner_enums import (
    SCANNER_AUDIT_CREATED,
    SCANNER_AUDIT_LINKED_TO_BUSINESS_SERVICE,
    SCANNER_AUDIT_PAUSED,
    SCANNER_AUDIT_RESUMED,
    SCANNER_AUDIT_RETIRED,
    SCANNER_AUDIT_UPDATED,
    SCANNER_AUDIT_REVOKED,
    SCANNER_AUDIT_TOKEN_REGENERATED,
    SCANNER_CREDENTIAL_AUDIT_CREATED,
    SCANNER_CREDENTIAL_AUDIT_DELETED,
    SCANNER_CREDENTIAL_AUDIT_PAUSED,
    SCANNER_CREDENTIAL_AUDIT_RESUMED,
    SCANNER_CREDENTIAL_AUDIT_REVOKED,
    SCANNER_CREDENTIAL_AUDIT_ROTATED,
    ScannerCredentialStatus,
    ScannerCredentialValidityPolicy,
    ScannerInstallationMethod,
    ScannerTargetStatus,
)
from src.core.constants.evidence_source_enums import EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED
from src.core.constants.process_scanner_link_enums import (
    PROCESS_SCANNER_LINK_AUDIT_CREATED,
    PROCESS_SCANNER_LINK_AUDIT_PAUSED,
    PROCESS_SCANNER_LINK_AUDIT_REVOKED,
)
from src.core.database import get_db
from src.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationError
from src.core.model_defs.evidence_scanner import (
    ScannerCredential,
    ScannerDomainTarget,
    ScannerInstance,
    ScannerNetworkTarget,
)
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.model_defs.process_scanner_link import ProcessScannerLink
from src.core.model_defs.value_streams import BusinessService
from src.core.models import AuditEvent, User
from src.core.repository import TenantRepository
from src.core.roles import ADMIN_ROLES, MANAGER_ROLES
from src.core.services.evidence_scanner_readiness_service import evaluate_scanner_readiness
from src.core.services.evidence_scanner_service import (
    resolve_scanner_liveness,
    EvidenceScannerValidationError,
    create_credential,
    change_installation_method,
    create_scanner,
    credential_can_authenticate,
    delete_credential,
    generate_activation_command,
    generate_pull_command,
    list_credentials_for_instance,
    list_scanner_instances_for_org,
    pause_credential,
    pause_scanner,
    regenerate_activation_token,
    resume_credential,
    resume_scanner,
    retire_scanner,
    revoke_credential,
    revoke_scanner,
    rotate_credential,
)
from src.core.services.evidence_source_service import set_business_service_scope
from src.core.services.process_ownership_service import (
    ProcessOwnershipValidationError,
    require_accepted_process_owner,
)
from src.core.services.process_scanner_link_service import (
    ProcessScannerLinkNotFoundError,
    ProcessScannerLinkValidationError,
    link_scanner_to_process,
    pause_link,
    revoke_link,
)
from src.api.schemas.timestamps import UtcTimestamp

router = APIRouter(prefix="/api/v1/scanners", tags=["Scanner management"])


class UpdateScannerRequest(BaseModel):
    """What may be corrected about a Collector without consequence.

    One field, and that is the point. Everything else on a Collector either
    governs what it may *do* — scan targets, credentials, process links, each
    with its own approval and audit event — or describes an installation that
    exists on somebody's machine.

    ``installation_method`` was briefly here and was **removed** (Søren,
    2026-08-24): *"if i change the how it is installed it is a much bigger
    change ... this should reset the entire scanner"*. It is not a label, and
    treating it as one let the record claim an install that was never performed.
    It has its own route below, which rotates the credential and clears what the
    old install reported.
    """

    name: str | None = None


class CreateScannerRequest(BaseModel):
    name: str
    installation_method: ScannerInstallationMethod
    # TENANT-79 — set to scope this scanner's evidence source to a business
    # process at create time. Omit/None for the pre-existing org-wide
    # Configuration/onboarding "+Add scanner" path (unchanged behavior).
    business_service_id: str | None = None


class LinkBusinessServiceRequest(BaseModel):
    # Nullable — passing None unlinks the scanner from whatever business
    # service it was previously scoped to.
    business_service_id: str | None = None


class ScannerListItemResponse(BaseModel):
    id: str
    evidence_source_id: str
    name: str
    public_instance_id: str
    installation_method: str
    scanner_version: str | None
    configuration_version: str | None
    status: str
    scan_profile: str | None
    tool_status: dict[str, str]
    test_scan_status: str | None
    connection_verified_at: UtcTimestamp | None
    scope_confirmed_at: UtcTimestamp | None
    last_heartbeat_at: UtcTimestamp | None
    registered_at: UtcTimestamp
    approved_domain_count: int
    approved_network_count: int
    # Same definition as Step 3.5's own readiness check (spec §17) — lets
    # onboarding gate on "at least one scanner is ready" now that many can
    # exist, without re-deriving that logic client-side.
    ready: bool
    # TENANT-79 — null means "org-wide / not yet scoped to a business process".
    business_service_id: str | None
    # CA-02 — null until the agent's first heartbeat that reports it.
    os_name: str | None
    os_version: str | None
    architecture: str | None


class ScannerNetworkTargetResponse(BaseModel):
    cidr: str
    name: str
    network_type: str


class ScannerDetailResponse(ScannerListItemResponse):
    owner_name: str | None
    approved_domains: list[str]
    approved_networks: list[ScannerNetworkTargetResponse]


class CreateScannerResponse(BaseModel):
    instance: ScannerListItemResponse
    activation_token: str


class RegenerateTokenResponse(BaseModel):
    instance: ScannerListItemResponse
    activation_token: str
    # Søren, 2026-08-25: *"it seems like the scanner code in python for
    # onboarding and the scanner page is not the same."* It was not, and this
    # response is why. The Scanners page reads `CredentialSecretResponse`, which
    # has carried a server-composed `activation_command` all along; onboarding
    # reads *this* one, which carried only the raw token — so the guide had no
    # command to show and composed its own, hardcoding the image, the volume and
    # the docker flags.
    #
    # Two definitions of one instruction, and they had already drifted: the
    # server learned to grant `--cap-add=NET_RAW` for scans and the component's
    # copy did not, so onboarding handed out a command that could not see the
    # network it was meant to scan. Both responses now answer from
    # `generate_activation_command`.
    activation_command: str
    #: How to fetch the Collector, for a first install. None where the platform
    #: cannot know — a CLI or server install is provisioned by the operator.
    pull_command: str | None = None
    #: True when this Collector has never reported in, so what follows is an
    #: installation rather than a reconnection.
    first_install: bool = False


class CreateCredentialRequest(BaseModel):
    name: str
    validity_policy: ScannerCredentialValidityPolicy
    custom_days: int | None = None


class RotateCredentialRequest(BaseModel):
    # Both optional — the "keep the same duration" path (rotate_credential's
    # default) vs. "pick a new duration" path (spec: rotate presents both
    # choices to the setup owner).
    validity_policy: ScannerCredentialValidityPolicy | None = None
    custom_days: int | None = None


class ScannerCredentialResponse(BaseModel):
    id: str
    scanner_instance_id: str
    name: str
    validity_policy: str
    status: str
    created_at: UtcTimestamp
    expires_at: UtcTimestamp | None
    last_rotated_at: UtcTimestamp | None
    revoked_at: UtcTimestamp | None
    can_authenticate: bool
    permitted_actions: list[str]


class CredentialSecretResponse(BaseModel):
    """A credential shown once, and what to do with it.

    ``first_install`` distinguishes the two cases the caller must not conflate:
    a Collector that has never checked in is being **installed**, and one that
    has is being **reconnected**. The wording and the number of steps differ, and
    telling somebody to reconnect an install that does not exist gives them an
    instruction that cannot work.
    """
    credential: ScannerCredentialResponse
    activation_token: str  # returned once — only the hash is persisted
    activation_command: str
    #: How to fetch the Collector, for a first install. None where the platform
    #: cannot know — a CLI or server install is provisioned by the operator.
    pull_command: str | None = None
    #: True when this Collector has never reported in, so what follows is an
    #: installation rather than a reconnection.
    first_install: bool = False


class CreateProcessScannerLinkRequest(BaseModel):
    business_process_id: str
    business_service_id: str | None = None


class ProcessScannerLinkResponse(BaseModel):
    id: str
    scanner_instance_id: str
    business_process_id: str
    business_service_id: str | None
    status: str
    linked_by_user_id: int | None
    created_at: UtcTimestamp
    paused_at: UtcTimestamp | None
    revoked_at: UtcTimestamp | None
    revoked_by_user_id: int | None


def _require_org_admin(db: Session, ctx: TenantContext) -> None:
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active or user.role not in ADMIN_ROLES:
        raise AuthorizationError(EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED)


def _require_process_scanner_access(db: Session, ctx: TenantContext, *, business_service_id: str) -> None:
    """AC4 — accountable process owner, manager/oversight role, or org admin.

    A business service can belong to more than one process
    (``value_stream_ids`` is an array); ownership is accepted if the caller
    is the accepted owner of *any* of them, not just the first — trusting an
    arbitrary index could authorise against the wrong process."""
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active:
        raise AuthorizationError(EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED)
    if user.role in MANAGER_ROLES:
        return
    service = TenantRepository(db, BusinessService, ctx.organization_id).get_by_id(business_service_id)
    if service is None:
        raise ResourceNotFoundError("Business service not found")
    for process_id in service.value_stream_ids or []:
        try:
            require_accepted_process_owner(
                db, organization_id=ctx.organization_id, process_id=process_id, user_id=ctx.user_id
            )
            return
        except ProcessOwnershipValidationError:
            continue
    raise AuthorizationError(EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED)


def _require_process_link_access(db: Session, ctx: TenantContext, *, business_process_id: str) -> None:
    """CA-04.6 — same reasoning as _require_process_scanner_access (accepted
    process owner, manager/oversight role, or org admin), simplified: this
    link is keyed directly by one business_process_id, not an array-holding
    BusinessService, so there is nothing to loop."""
    user = TenantRepository(db, User, ctx.organization_id).get_by_id(ctx.user_id)
    if user is None or not user.is_active:
        raise AuthorizationError(EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED)
    if user.role in MANAGER_ROLES:
        return
    try:
        require_accepted_process_owner(
            db, organization_id=ctx.organization_id, process_id=business_process_id, user_id=ctx.user_id
        )
    except ProcessOwnershipValidationError as exc:
        raise AuthorizationError(EVIDENCE_SOURCE_ERROR_ADMIN_REQUIRED) from exc


def _write_audit(db: Session, *, ctx: TenantContext, event_type: str, metadata: dict) -> None:
    db.add(
        AuditEvent(organization_id=ctx.organization_id, actor_user_id=ctx.user_id, event_type=event_type, metadata_json=metadata)
    )


def _require_instance(db: Session, *, ctx: TenantContext, instance_id: str) -> ScannerInstance:
    instance = TenantRepository(db, ScannerInstance, ctx.organization_id).get_by_id(instance_id)
    if instance is None:
        raise ResourceNotFoundError("Scanner not found")
    return instance


def _instance_response(
    db: Session, instance: ScannerInstance, *, domain_count: int = 0, network_count: int = 0
) -> ScannerListItemResponse:
    source = db.query(EvidenceSource).filter(EvidenceSource.id == instance.evidence_source_id).first()
    ready = source is not None and evaluate_scanner_readiness(db, source).ready
    return ScannerListItemResponse(
        id=instance.id,
        evidence_source_id=instance.evidence_source_id,
        name=instance.name,
        public_instance_id=instance.public_instance_id,
        installation_method=instance.installation_method,
        scanner_version=instance.scanner_version,
        configuration_version=instance.configuration_version,
        # Derived, so the Collector inventory and the run panel cannot
        # disagree about whether a Collector is alive (BUG-DISC-05).
        status=resolve_scanner_liveness(instance),
        scan_profile=instance.scan_profile,
        tool_status=instance.tool_status or {},
        test_scan_status=instance.test_scan_status,
        connection_verified_at=instance.connection_verified_at,
        scope_confirmed_at=instance.scope_confirmed_at,
        last_heartbeat_at=instance.last_heartbeat_at,
        registered_at=instance.registered_at,
        approved_domain_count=domain_count,
        approved_network_count=network_count,
        ready=ready,
        business_service_id=source.business_service_id if source else None,
        os_name=instance.os_name,
        os_version=instance.os_version,
        architecture=instance.architecture,
    )


def _require_credential(
    db: Session, *, ctx: TenantContext, instance_id: str, credential_id: str
) -> ScannerCredential:
    credential = TenantRepository(db, ScannerCredential, ctx.organization_id).get_by_id(credential_id)
    if credential is None or credential.scanner_instance_id != instance_id or credential.deleted_at is not None:
        raise ResourceNotFoundError("Scanner credential not found")
    return credential


def _require_process_scanner_link(
    db: Session, *, ctx: TenantContext, instance_id: str, link_id: str
) -> ProcessScannerLink:
    link = TenantRepository(db, ProcessScannerLink, ctx.organization_id).get_by_id(link_id)
    if link is None or link.scanner_instance_id != instance_id:
        raise ResourceNotFoundError("Process scanner link not found")
    return link


def _process_link_response(link: ProcessScannerLink) -> ProcessScannerLinkResponse:
    return ProcessScannerLinkResponse(
        id=link.id,
        scanner_instance_id=link.scanner_instance_id,
        business_process_id=link.business_process_id,
        business_service_id=link.business_service_id,
        status=link.status,
        linked_by_user_id=link.linked_by_user_id,
        created_at=link.created_at,
        paused_at=link.paused_at,
        revoked_at=link.revoked_at,
        revoked_by_user_id=link.revoked_by_user_id,
    )


def _permitted_credential_actions(credential: ScannerCredential) -> list[str]:
    if credential.status == ScannerCredentialStatus.ACTIVE.value:
        return ["rotate", "pause", "revoke"]
    if credential.status == ScannerCredentialStatus.PAUSED.value:
        return ["resume", "revoke", "delete"]
    if credential.status == ScannerCredentialStatus.REVOKED.value:
        return ["delete"]
    return []


def _credential_response(credential: ScannerCredential) -> ScannerCredentialResponse:
    return ScannerCredentialResponse(
        id=credential.id,
        scanner_instance_id=credential.scanner_instance_id,
        name=credential.name,
        validity_policy=credential.validity_policy,
        status=credential.status,
        created_at=credential.created_at,
        expires_at=credential.expires_at,
        last_rotated_at=credential.last_rotated_at,
        revoked_at=credential.revoked_at,
        can_authenticate=credential_can_authenticate(credential),
        permitted_actions=_permitted_credential_actions(credential),
    )


def _approved_counts(db: Session, organization_id: int) -> tuple[dict[str, int], dict[str, int]]:
    domain_rows = (
        db.query(ScannerDomainTarget.evidence_source_id, func.count(ScannerDomainTarget.id))
        .filter(
            ScannerDomainTarget.organization_id == organization_id,
            ScannerDomainTarget.status == ScannerTargetStatus.APPROVED.value,
        )
        .group_by(ScannerDomainTarget.evidence_source_id)
        .all()
    )
    network_rows = (
        db.query(ScannerNetworkTarget.evidence_source_id, func.count(ScannerNetworkTarget.id))
        .filter(
            ScannerNetworkTarget.organization_id == organization_id,
            ScannerNetworkTarget.status == ScannerTargetStatus.APPROVED.value,
        )
        .group_by(ScannerNetworkTarget.evidence_source_id)
        .all()
    )
    return dict(domain_rows), dict(network_rows)


def _owner_name(db: Session, organization_id: int, source: EvidenceSource | None) -> str | None:
    if source is None or source.owner_user_id is None:
        return None
    owner = TenantRepository(db, User, organization_id).get_by_id(source.owner_user_id)
    if owner is None:
        return None
    name = f"{owner.first_name or ''} {owner.last_name or ''}".strip()
    return name or owner.email


def _approved_domains(db: Session, organization_id: int, evidence_source_id: str) -> list[str]:
    rows = (
        db.query(ScannerDomainTarget.domain)
        .filter(
            ScannerDomainTarget.organization_id == organization_id,
            ScannerDomainTarget.evidence_source_id == evidence_source_id,
            ScannerDomainTarget.status == ScannerTargetStatus.APPROVED.value,
        )
        .order_by(ScannerDomainTarget.domain)
        .all()
    )
    return [row[0] for row in rows]


def _approved_networks(db: Session, organization_id: int, evidence_source_id: str) -> list[ScannerNetworkTargetResponse]:
    rows = (
        db.query(ScannerNetworkTarget)
        .filter(
            ScannerNetworkTarget.organization_id == organization_id,
            ScannerNetworkTarget.evidence_source_id == evidence_source_id,
            ScannerNetworkTarget.status == ScannerTargetStatus.APPROVED.value,
        )
        .order_by(ScannerNetworkTarget.cidr)
        .all()
    )
    return [
        ScannerNetworkTargetResponse(cidr=row.cidr, name=row.name, network_type=row.network_type) for row in rows
    ]


@router.get("", response_model=list[ScannerListItemResponse])
def list_scanners_route(
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
    business_service_id: str | None = None,
) -> list[ScannerListItemResponse]:
    instances = list_scanner_instances_for_org(db, ctx.organization_id)
    if business_service_id is not None:
        # TENANT-79 — restrict to scanners already scoped to this business
        # service plus not-yet-scoped ones ("candidates" a process owner
        # could claim). A scanner already linked to a *different* service is
        # excluded — reassigning it would silently steal another BPO's
        # evidence attribution. Both source_ids/organization_id filtered
        # explicitly here, not via a helper, to stay tenant-isolation-checker
        # legible without a new ALLOWLIST entry.
        scoped_source_ids = {
            row[0]
            for row in db.query(EvidenceSource.id)
            .filter(
                EvidenceSource.organization_id == ctx.organization_id,
                or_(
                    EvidenceSource.business_service_id == business_service_id,
                    EvidenceSource.business_service_id.is_(None),
                ),
            )
            .all()
        }
        instances = [instance for instance in instances if instance.evidence_source_id in scoped_source_ids]
    domain_counts, network_counts = _approved_counts(db, ctx.organization_id)
    return [
        _instance_response(
            db,
            instance,
            domain_count=domain_counts.get(instance.evidence_source_id, 0),
            network_count=network_counts.get(instance.evidence_source_id, 0),
        )
        for instance in instances
    ]


@router.get("/{instance_id}", response_model=ScannerDetailResponse)
def get_scanner_route(
    instance_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ScannerDetailResponse:
    instance = _require_instance(db, ctx=ctx, instance_id=instance_id)
    source = db.query(EvidenceSource).filter(EvidenceSource.id == instance.evidence_source_id).first()
    domain_counts, network_counts = _approved_counts(db, ctx.organization_id)
    base = _instance_response(
        db,
        instance,
        domain_count=domain_counts.get(instance.evidence_source_id, 0),
        network_count=network_counts.get(instance.evidence_source_id, 0),
    )
    return ScannerDetailResponse(
        **base.model_dump(),
        owner_name=_owner_name(db, ctx.organization_id, source),
        approved_domains=_approved_domains(db, ctx.organization_id, instance.evidence_source_id),
        approved_networks=_approved_networks(db, ctx.organization_id, instance.evidence_source_id),
    )


@router.post("", response_model=CreateScannerResponse)
def create_scanner_route(
    body: CreateScannerRequest, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> CreateScannerResponse:
    if body.business_service_id is not None:
        _require_process_scanner_access(db, ctx, business_service_id=body.business_service_id)
    else:
        _require_org_admin(db, ctx)
    try:
        result = create_scanner(
            db,
            organization_id=ctx.organization_id,
            name=body.name,
            installation_method=body.installation_method.value,
            business_service_id=body.business_service_id,
        )
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db, ctx=ctx, event_type=SCANNER_AUDIT_CREATED, metadata={"scanner_instance_id": result.instance.id, "name": body.name}
    )
    db.commit()
    db.refresh(result.instance)
    return CreateScannerResponse(instance=_instance_response(db, result.instance), activation_token=result.activation_token)


@router.patch("/{instance_id}", response_model=ScannerListItemResponse)
def update_scanner_route(
    instance_id: str,
    body: UpdateScannerRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ScannerListItemResponse:
    """Rename a Collector, or correct how its installation is recorded.

    PATCH rather than PUT: a caller sends the field it is changing, and one that
    omits a field must not be read as clearing it. With two nullable fields a
    PUT would make "leave the name alone" and "blank the name" the same request.
    """
    _require_org_admin(db, ctx)
    instance = _require_instance(db, ctx=ctx, instance_id=instance_id)

    changed: dict[str, str] = {}
    if body.name is not None:
        name = body.name.strip()
        if not name:
            # Refused rather than silently kept: a caller that sent a name meant
            # to change it, and accepting whitespace would leave them looking at
            # the old one with no idea why.
            raise ValidationError("A Collector's name cannot be empty")
        if name != instance.name:
            changed["name"] = name
            instance.name = name

    if not changed:
        # Nothing to record. An audit event for a request that changed nothing
        # would make the trail harder to read, not more complete.
        return _instance_response(db, instance)

    db.add(instance)
    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_AUDIT_UPDATED,
        metadata={"scanner_instance_id": instance.id, **changed},
    )
    db.commit()
    db.refresh(instance)
    return _instance_response(db, instance)


class ChangeInstallationMethodRequest(BaseModel):
    installation_method: ScannerInstallationMethod


@router.post("/{instance_id}/installation-method", response_model=CreateScannerResponse)
def change_installation_method_route(
    instance_id: str,
    body: ChangeInstallationMethodRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> CreateScannerResponse:
    """Change how a Collector is installed, which means installing it again.

    A POST returning a **new activation token**, not a PATCH, because that is
    what actually happens: the credential rotates, the old install stops being
    able to authenticate, and somebody has to run the new command on a machine.
    Modelling it as a field update would let the record assert an installation
    nobody performed.
    """
    _require_org_admin(db, ctx)
    instance = _require_instance(db, ctx=ctx, instance_id=instance_id)
    previous = instance.installation_method

    if body.installation_method.value == previous:
        # Nothing to do, and rotating a credential for a no-op would strand a
        # working Collector for the sake of a request that changed nothing.
        raise ValidationError("This Collector is already installed that way")

    try:
        result = change_installation_method(
            db, instance, installation_method=body.installation_method.value
        )
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc

    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_AUDIT_UPDATED,
        metadata={
            "scanner_instance_id": instance.id,
            "installation_method": body.installation_method.value,
            "previous_installation_method": previous,
            # Recorded because it is the consequence, not a side effect: the
            # old credential stopped working the moment this was called.
            "credential_rotated": True,
        },
    )
    db.commit()
    db.refresh(instance)
    return CreateScannerResponse(
        instance=_instance_response(db, instance),
        activation_token=result.activation_token,
    )


@router.post("/{instance_id}/link-business-service", response_model=ScannerListItemResponse)
def link_business_service_route(
    instance_id: str,
    body: LinkBusinessServiceRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ScannerListItemResponse:
    """AC2 — select an existing scanner for this business process (or unlink
    it, when ``business_service_id`` is None)."""
    instance = _require_instance(db, ctx=ctx, instance_id=instance_id)
    source = db.query(EvidenceSource).filter(
        EvidenceSource.id == instance.evidence_source_id, EvidenceSource.organization_id == ctx.organization_id
    ).first()
    if source is None:
        raise ResourceNotFoundError("Scanner not found")
    # Access is required for whichever business service ends up on the
    # audit trail: the target when linking, the current one when unlinking.
    access_business_service_id = body.business_service_id or source.business_service_id
    if access_business_service_id is not None:
        _require_process_scanner_access(db, ctx, business_service_id=access_business_service_id)
    else:
        _require_org_admin(db, ctx)
    if (
        body.business_service_id is not None
        and source.business_service_id is not None
        and source.business_service_id != body.business_service_id
    ):
        raise ValidationError(
            "This scanner is already connected to a different business process — unlink it there first."
        )
    set_business_service_scope(db, source, business_service_id=body.business_service_id)
    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_AUDIT_LINKED_TO_BUSINESS_SERVICE,
        metadata={"scanner_instance_id": instance.id, "business_service_id": body.business_service_id},
    )
    db.commit()
    db.refresh(instance)
    return _instance_response(db, instance)


@router.post("/{instance_id}/pause", response_model=ScannerListItemResponse)
def pause_scanner_route(
    instance_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ScannerListItemResponse:
    _require_org_admin(db, ctx)
    instance = _require_instance(db, ctx=ctx, instance_id=instance_id)
    try:
        pause_scanner(db, instance)
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=SCANNER_AUDIT_PAUSED, metadata={"scanner_instance_id": instance.id})
    db.commit()
    db.refresh(instance)
    return _instance_response(db, instance)


@router.post("/{instance_id}/resume", response_model=ScannerListItemResponse)
def resume_scanner_route(
    instance_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ScannerListItemResponse:
    _require_org_admin(db, ctx)
    instance = _require_instance(db, ctx=ctx, instance_id=instance_id)
    try:
        resume_scanner(db, instance)
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=SCANNER_AUDIT_RESUMED, metadata={"scanner_instance_id": instance.id})
    db.commit()
    db.refresh(instance)
    return _instance_response(db, instance)


@router.post("/{instance_id}/regenerate-token", response_model=RegenerateTokenResponse)
def regenerate_token_route(
    instance_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> RegenerateTokenResponse:
    _require_org_admin(db, ctx)
    instance = _require_instance(db, ctx=ctx, instance_id=instance_id)
    try:
        result = regenerate_activation_token(db, instance)
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=SCANNER_AUDIT_TOKEN_REGENERATED, metadata={"scanner_instance_id": instance.id})
    db.commit()
    db.refresh(result.instance)
    return RegenerateTokenResponse(
        instance=_instance_response(db, result.instance),
        activation_token=result.activation_token,
        activation_command=generate_activation_command(
            activation_token=result.activation_token,
            installation_method=instance.installation_method,
        ),
        pull_command=generate_pull_command(installation_method=instance.installation_method),
        first_install=instance.last_heartbeat_at is None,
    )


@router.post("/{instance_id}/revoke", response_model=ScannerListItemResponse)
def revoke_scanner_route(
    instance_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ScannerListItemResponse:
    """Revoke the scanner credential without retiring the scanner record."""
    _require_org_admin(db, ctx)
    instance = _require_instance(db, ctx=ctx, instance_id=instance_id)
    revoke_scanner(db, instance)
    _write_audit(db, ctx=ctx, event_type=SCANNER_AUDIT_REVOKED, metadata={"scanner_instance_id": instance.id})
    db.commit()
    db.refresh(instance)
    return _instance_response(db, instance)


@router.post("/{instance_id}/retire", response_model=ScannerListItemResponse)
def retire_scanner_route(
    instance_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> ScannerListItemResponse:
    _require_org_admin(db, ctx)
    instance = _require_instance(db, ctx=ctx, instance_id=instance_id)
    try:
        retire_scanner(db, instance)
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(db, ctx=ctx, event_type=SCANNER_AUDIT_RETIRED, metadata={"scanner_instance_id": instance.id})
    db.commit()
    db.refresh(instance)
    return _instance_response(db, instance)


# --- Named credentials (TENANT-84) — independent of the instance-level ------------------
# activation_token_hash and its routes above, which stay unchanged until the
# frontend migrates onto this model (TENANT-85).


@router.get("/{instance_id}/credentials", response_model=list[ScannerCredentialResponse])
def list_credentials_route(
    instance_id: str, ctx: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)
) -> list[ScannerCredentialResponse]:
    _require_instance(db, ctx=ctx, instance_id=instance_id)
    credentials = list_credentials_for_instance(db, instance_id)
    return [_credential_response(c) for c in credentials]


@router.post("/{instance_id}/credentials", response_model=CredentialSecretResponse)
def create_credential_route(
    instance_id: str,
    body: CreateCredentialRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> CredentialSecretResponse:
    _require_org_admin(db, ctx)
    instance = _require_instance(db, ctx=ctx, instance_id=instance_id)
    try:
        result = create_credential(
            db,
            instance,
            name=body.name,
            validity_policy=body.validity_policy.value,
            custom_days=body.custom_days,
            created_by_user_id=ctx.user_id,
        )
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_CREDENTIAL_AUDIT_CREATED,
        metadata={"scanner_instance_id": instance.id, "credential_id": result.credential.id, "name": body.name},
    )
    db.commit()
    db.refresh(result.credential)
    return CredentialSecretResponse(
        credential=_credential_response(result.credential),
        activation_token=result.activation_token,
        # The install method decides the command: a Docker Collector has no
        # risklence-scanner on the operator's PATH.
        activation_command=generate_activation_command(
            activation_token=result.activation_token,
            installation_method=instance.installation_method,
        ),
        pull_command=generate_pull_command(installation_method=instance.installation_method),
        # Never heard from is the whole test. A Collector that has checked in
        # once has an install to reconnect; one that has not, does not.
        first_install=instance.last_heartbeat_at is None,
    )


@router.post("/{instance_id}/credentials/{credential_id}/rotate", response_model=CredentialSecretResponse)
def rotate_credential_route(
    instance_id: str,
    credential_id: str,
    body: RotateCredentialRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> CredentialSecretResponse:
    _require_org_admin(db, ctx)
    credential = _require_credential(db, ctx=ctx, instance_id=instance_id, credential_id=credential_id)
    # Needed for the activation command below: a rotated credential is applied
    # by re-running activate, and how that is run depends on how this Collector
    # was installed.
    instance = _require_instance(db, ctx=ctx, instance_id=instance_id)
    try:
        result = rotate_credential(
            db,
            credential,
            validity_policy=body.validity_policy.value if body.validity_policy else None,
            custom_days=body.custom_days,
        )
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_CREDENTIAL_AUDIT_ROTATED,
        metadata={"scanner_instance_id": instance_id, "credential_id": credential.id},
    )
    db.commit()
    db.refresh(result.credential)
    return CredentialSecretResponse(
        credential=_credential_response(result.credential),
        activation_token=result.activation_token,
        # The install method decides the command: a Docker Collector has no
        # risklence-scanner on the operator's PATH.
        activation_command=generate_activation_command(
            activation_token=result.activation_token,
            installation_method=instance.installation_method,
        ),
        pull_command=generate_pull_command(installation_method=instance.installation_method),
        # Never heard from is the whole test. A Collector that has checked in
        # once has an install to reconnect; one that has not, does not.
        first_install=instance.last_heartbeat_at is None,
    )


@router.post("/{instance_id}/credentials/{credential_id}/pause", response_model=ScannerCredentialResponse)
def pause_credential_route(
    instance_id: str,
    credential_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ScannerCredentialResponse:
    _require_org_admin(db, ctx)
    credential = _require_credential(db, ctx=ctx, instance_id=instance_id, credential_id=credential_id)
    try:
        pause_credential(db, credential)
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_CREDENTIAL_AUDIT_PAUSED,
        metadata={"scanner_instance_id": instance_id, "credential_id": credential.id},
    )
    db.commit()
    db.refresh(credential)
    return _credential_response(credential)


@router.post("/{instance_id}/credentials/{credential_id}/resume", response_model=ScannerCredentialResponse)
def resume_credential_route(
    instance_id: str,
    credential_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ScannerCredentialResponse:
    _require_org_admin(db, ctx)
    credential = _require_credential(db, ctx=ctx, instance_id=instance_id, credential_id=credential_id)
    try:
        resume_credential(db, credential)
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_CREDENTIAL_AUDIT_RESUMED,
        metadata={"scanner_instance_id": instance_id, "credential_id": credential.id},
    )
    db.commit()
    db.refresh(credential)
    return _credential_response(credential)


@router.post("/{instance_id}/credentials/{credential_id}/revoke", response_model=ScannerCredentialResponse)
def revoke_credential_route(
    instance_id: str,
    credential_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ScannerCredentialResponse:
    _require_org_admin(db, ctx)
    credential = _require_credential(db, ctx=ctx, instance_id=instance_id, credential_id=credential_id)
    try:
        revoke_credential(db, credential, revoked_by_user_id=ctx.user_id)
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_CREDENTIAL_AUDIT_REVOKED,
        metadata={"scanner_instance_id": instance_id, "credential_id": credential.id},
    )
    db.commit()
    db.refresh(credential)
    return _credential_response(credential)


@router.delete("/{instance_id}/credentials/{credential_id}", status_code=204, response_model=None)
def delete_credential_route(
    instance_id: str,
    credential_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> Response:
    _require_org_admin(db, ctx)
    credential = _require_credential(db, ctx=ctx, instance_id=instance_id, credential_id=credential_id)
    try:
        delete_credential(db, credential)
    except EvidenceScannerValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=SCANNER_CREDENTIAL_AUDIT_DELETED,
        metadata={"scanner_instance_id": instance_id, "credential_id": credential.id},
    )
    db.commit()
    return Response(status_code=204)


# --- CA-04.6: ProcessScannerLink (one scanner, many business processes) -----------------


@router.post("/{instance_id}/process-links", response_model=ProcessScannerLinkResponse)
def create_process_link_route(
    instance_id: str,
    body: CreateProcessScannerLinkRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessScannerLinkResponse:
    instance = _require_instance(db, ctx=ctx, instance_id=instance_id)
    _require_process_link_access(db, ctx, business_process_id=body.business_process_id)
    try:
        link = link_scanner_to_process(
            db,
            organization_id=ctx.organization_id,
            scanner_instance_id=instance.id,
            business_process_id=body.business_process_id,
            business_service_id=body.business_service_id,
            linked_by_user_id=ctx.user_id,
        )
    except ProcessScannerLinkNotFoundError as exc:
        raise ResourceNotFoundError(str(exc)) from exc
    except ProcessScannerLinkValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=PROCESS_SCANNER_LINK_AUDIT_CREATED,
        metadata={
            "scanner_instance_id": instance.id,
            "process_scanner_link_id": link.id,
            "business_process_id": link.business_process_id,
            "business_service_id": link.business_service_id,
        },
    )
    db.commit()
    db.refresh(link)
    return _process_link_response(link)


@router.post("/{instance_id}/process-links/{link_id}/pause", response_model=ProcessScannerLinkResponse)
def pause_process_link_route(
    instance_id: str,
    link_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessScannerLinkResponse:
    link = _require_process_scanner_link(db, ctx=ctx, instance_id=instance_id, link_id=link_id)
    _require_process_link_access(db, ctx, business_process_id=link.business_process_id)
    try:
        pause_link(db, link)
    except ProcessScannerLinkValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=PROCESS_SCANNER_LINK_AUDIT_PAUSED,
        metadata={
            "scanner_instance_id": instance_id,
            "process_scanner_link_id": link.id,
            "business_process_id": link.business_process_id,
            "business_service_id": link.business_service_id,
        },
    )
    db.commit()
    db.refresh(link)
    return _process_link_response(link)


@router.post("/{instance_id}/process-links/{link_id}/revoke", response_model=ProcessScannerLinkResponse)
def revoke_process_link_route(
    instance_id: str,
    link_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db),
) -> ProcessScannerLinkResponse:
    link = _require_process_scanner_link(db, ctx=ctx, instance_id=instance_id, link_id=link_id)
    _require_process_link_access(db, ctx, business_process_id=link.business_process_id)
    try:
        revoke_link(db, link, revoked_by_user_id=ctx.user_id)
    except ProcessScannerLinkValidationError as exc:
        raise ValidationError(str(exc)) from exc
    _write_audit(
        db,
        ctx=ctx,
        event_type=PROCESS_SCANNER_LINK_AUDIT_REVOKED,
        metadata={
            "scanner_instance_id": instance_id,
            "process_scanner_link_id": link.id,
            "business_process_id": link.business_process_id,
            "business_service_id": link.business_service_id,
        },
    )
    db.commit()
    db.refresh(link)
    return _process_link_response(link)
