"""Risklence Scanner setup — Step 3.5 (configure and validate the scanner so
it *can* perform controlled discovery; the discovery run itself is Step 4).

This module never executes Nmap/Subfinder/Nuclei and never talks to a real
scanner agent — see ``evidence_scanner_enums`` for the scope note. Tool
availability and test-scan outcomes are *recorded* from a caller-reported
result (the install script / scanner agent's own self-check in a real
deployment), exactly as ``evidence_source_service.upload_import_file``
records a caller-supplied file rather than crawling a live CMDB itself.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from src.core.constants.evidence_scanner_enums import (
    LARGE_NETWORK_WARNING_PREFIX_THRESHOLD,
    SCANNER_CREDENTIAL_ERROR_ALREADY_DELETED,
    SCANNER_CREDENTIAL_ERROR_ALREADY_REVOKED,
    SCANNER_CREDENTIAL_ERROR_CUSTOM_DAYS_INVALID,
    SCANNER_CREDENTIAL_ERROR_CUSTOM_DAYS_REQUIRED,
    SCANNER_CREDENTIAL_ERROR_DELETE_WHILE_ACTIVE,
    SCANNER_CREDENTIAL_ERROR_NAME_REQUIRED,
    SCANNER_CREDENTIAL_ERROR_NOT_ACTIVE,
    SCANNER_CREDENTIAL_MAX_CUSTOM_DAYS,
    ScannerInstallationMethod,
    SCANNER_CREDENTIAL_VALIDITY_DAYS,
    SCANNER_ERROR_ALREADY_RETIRED,
    SCANNER_HEARTBEAT_STALE_AFTER_SECONDS,
    SCANNER_ERROR_DUPLICATE_CIDR,
    SCANNER_ERROR_DUPLICATE_DOMAIN,
    SCANNER_ERROR_INVALID_CIDR,
    SCANNER_ERROR_INVALID_DOMAIN,
    SCANNER_ERROR_NOT_PAUSED,
    SCANNER_ERROR_PAUSED_OR_RETIRED,
    SCANNER_ERROR_PROFILE_REQUIRED,
    SCANNER_ERROR_SCOPE_EMPTY,
    ScannerCredentialStatus,
    ScannerCredentialValidityPolicy,
    ScannerInstanceStatus,
    ScannerOwnershipStatus,
    ScannerTargetSource,
    ScannerTargetStatus,
    ScannerToolName,
    ScannerToolStatus,
)
from src.core.config import settings
from src.core.constants.evidence_source_enums import EvidenceSourceType
from src.core.crypto import derive_command_signing_key, encrypt_command_signing_key
from src.core.model_defs.common import utcnow
from src.core.services.collector_readiness_service import (
    readiness_from_tool_statuses,
    record_readiness_report,
)
from src.core.model_defs.evidence_scanner import (
    ScannerCredential,
    ScannerDomainTarget,
    ScannerInstance,
    ScannerNetworkTarget,
)
from src.core.model_defs.evidence_source import EvidenceSource
from src.core.model_defs.organization_identity import OrganizationDomain
from src.core.services.evidence_source_service import create_evidence_source

_DOMAIN_PATTERN = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


class EvidenceScannerValidationError(ValueError):
    """Raised when a Step 3.5 scanner-setup operation is invalid."""


def _naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def require_scanner_source(source: EvidenceSource) -> None:
    if source.type != EvidenceSourceType.SCANNER.value:
        raise EvidenceScannerValidationError("This evidence source is not a scanner source.")


# --- Installation / activation ----------------------------------------------------


@dataclass(frozen=True)
class ScannerInstallationResult:
    instance: ScannerInstance
    activation_token: str  # returned once — only the hash is persisted


def install_scanner(
    db: Session,
    source: EvidenceSource,
    *,
    name: str,
    installation_method: str,
) -> ScannerInstallationResult:
    require_scanner_source(source)
    existing = db.query(ScannerInstance).filter(ScannerInstance.evidence_source_id == source.id).first()
    if existing is not None:
        raise EvidenceScannerValidationError("A scanner is already installed for this evidence source.")
    if not name.strip():
        raise EvidenceScannerValidationError("A name is required for the scanner installation.")

    activation_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(activation_token.encode("utf-8")).hexdigest()

    now = utcnow()
    instance = ScannerInstance(
        organization_id=source.organization_id,
        evidence_source_id=source.id,
        name=name.strip(),
        installation_method=installation_method,
        status=ScannerInstanceStatus.REGISTERED.value,
        activation_token_hash=token_hash,
        activated_at=now,
        registered_at=now,
    )
    db.add(instance)
    db.flush()  # populate instance.id (client-side UUID default) before deriving a key salted by it
    # CA-04.1 — derive the per-instance command-signing key while the raw
    # token still exists (only its hash is persisted above); see
    # crypto.py's docstring for the full rationale.
    signing_key = derive_command_signing_key(activation_token, instance.id)
    instance.command_signing_key_encrypted = encrypt_command_signing_key(instance.id, signing_key)
    db.add(instance)
    return ScannerInstallationResult(instance=instance, activation_token=activation_token)


def revoke_scanner(db: Session, instance: ScannerInstance) -> ScannerInstance:
    instance.status = ScannerInstanceStatus.REVOKED.value
    instance.activation_revoked_at = utcnow()
    db.add(instance)
    return instance


# Statuses that record a deliberate operator decision rather than liveness.
# A paused or revoked Collector is not "offline" — someone chose that, and
# overwriting it with an inferred state would erase the decision.
_OPERATOR_DECIDED_STATUSES: frozenset[str] = frozenset(
    {
        ScannerInstanceStatus.PAUSED.value,
        ScannerInstanceStatus.REVOKED.value,
        ScannerInstanceStatus.RETIRED.value,
    }
)


def resolve_scanner_liveness(
    instance: ScannerInstance, *, now: datetime | None = None
) -> str:
    """The Collector's *effective* status, derived rather than read.

    BUG-DISC-05: ``record_heartbeat`` raises status to ONLINE and nothing ever
    lowers it, so a Collector that has stopped keeps reporting "Connected" — with
    a green tick — while a run waits on it forever. That is worse than showing
    nothing: it points the user at the platform when the problem is their own
    agent.

    Derived at read time rather than swept by a background job, matching how
    every other readiness signal in this codebase works: there is no window in
    which the stored value is stale, and no scheduler to depend on.

    A stale heartbeat lowers ONLINE/DEGRADED to OFFLINE. It never overrides a
    status a person chose (paused/revoked/retired), and an instance that has
    never reported stays REGISTERED — "never started" and "stopped" are
    different things to tell someone.
    """
    if instance.status in _OPERATOR_DECIDED_STATUSES:
        return instance.status
    if instance.last_heartbeat_at is None:
        return ScannerInstanceStatus.REGISTERED.value

    current = now or utcnow()
    last_seen = instance.last_heartbeat_at
    if last_seen.tzinfo is None:
        current = current.replace(tzinfo=None)
    age_seconds = (current - last_seen).total_seconds()
    if age_seconds > SCANNER_HEARTBEAT_STALE_AFTER_SECONDS:
        return ScannerInstanceStatus.OFFLINE.value
    return instance.status


def record_heartbeat(
    db: Session,
    instance: ScannerInstance,
    *,
    os_name: str | None = None,
    os_version: str | None = None,
    architecture: str | None = None,
    kernel_release: str | None = None,
    container_runtime: str | None = None,
    runtime_os_name: str | None = None,
    runtime_os_version: str | None = None,
    network_segments: list[dict] | None = None,
) -> ScannerInstance:
    now = utcnow()
    if network_segments is not None:
        # Written on its own, not inside the `kernel_release` gate below:
        # that gate exists for the host/container OS split and has nothing
        # to do with where the Collector sits. `None` leaves the last known
        # position alone — an older build saying nothing must not erase what
        # a newer one reported.
        instance.network_segments = list(network_segments)

    instance.last_heartbeat_at = now
    instance.connection_verified_at = now
    instance.last_successful_connection_at = now
    if instance.status == ScannerInstanceStatus.REGISTERED.value:
        instance.status = ScannerInstanceStatus.ONLINE.value

    # CA-02.3 slice 3 — `kernel_release` marks an agent that understands the
    # host/container distinction, and it is the one field such an agent always
    # sends. That matters because the truthy guards below cannot distinguish
    # "an older agent did not send this" from "a newer agent is telling us it
    # cannot be determined from inside a container".
    #
    # Without this branch an instance that once reported the *image's*
    # os_name would keep it forever: the corrected agent sends None, the guard
    # skips it, and the wrong value outlives the fix (#171).
    if kernel_release:
        instance.kernel_release = kernel_release
        instance.os_name = os_name
        instance.os_version = os_version
        instance.container_runtime = container_runtime
        instance.runtime_os_name = runtime_os_name
        instance.runtime_os_version = runtime_os_version
        if architecture:
            instance.architecture = architecture
    else:
        # CA-02 — only ever set from a real heartbeat payload, never overwritten
        # back to null by an older agent build that doesn't send these fields.
        if os_name:
            instance.os_name = os_name
        if os_version:
            instance.os_version = os_version
        if architecture:
            instance.architecture = architecture
    db.add(instance)
    return instance


# --- Domain targets ------------------------------------------------------------------


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower()


def add_domain_target(
    db: Session,
    source: EvidenceSource,
    *,
    domain: str,
    include_subdomains: bool = True,
    target_source: ScannerTargetSource = ScannerTargetSource.USER_ADDED,
) -> ScannerDomainTarget:
    require_scanner_source(source)
    normalized = _normalize_domain(domain)
    if not normalized or not _DOMAIN_PATTERN.match(normalized):
        raise EvidenceScannerValidationError(SCANNER_ERROR_INVALID_DOMAIN)

    duplicate = (
        db.query(ScannerDomainTarget)
        .filter(
            ScannerDomainTarget.evidence_source_id == source.id,
            ScannerDomainTarget.domain == normalized,
            ScannerDomainTarget.status != ScannerTargetStatus.DISABLED.value,
        )
        .first()
    )
    if duplicate is not None:
        raise EvidenceScannerValidationError(SCANNER_ERROR_DUPLICATE_DOMAIN)

    ownership_status = (
        ScannerOwnershipStatus.VERIFIED.value
        if target_source == ScannerTargetSource.VERIFIED_ORGANISATION_DOMAIN
        else ScannerOwnershipStatus.DECLARED.value
    )

    target = ScannerDomainTarget(
        organization_id=source.organization_id,
        evidence_source_id=source.id,
        domain=normalized,
        source=target_source.value,
        ownership_status=ownership_status,
        include_subdomains=include_subdomains,
        status=ScannerTargetStatus.DRAFT.value,
    )
    db.add(target)
    db.flush()
    return target


def add_domain_target_from_verified_identity(
    db: Session, source: EvidenceSource, *, organization_domain_id: str
) -> ScannerDomainTarget:
    """Prefill a target from the verified organisation identity domains
    established in Step 1 (spec §5.1) rather than requiring re-entry."""
    require_scanner_source(source)
    org_domain = (
        db.query(OrganizationDomain)
        .filter(
            OrganizationDomain.id == organization_domain_id,
            OrganizationDomain.organization_id == source.organization_id,
        )
        .first()
    )
    if org_domain is None:
        raise EvidenceScannerValidationError("Organisation domain not found.")
    return add_domain_target(
        db,
        source,
        domain=org_domain.domain,
        target_source=ScannerTargetSource.VERIFIED_ORGANISATION_DOMAIN,
    )


def list_suggested_domains(db: Session, source: EvidenceSource) -> list[OrganizationDomain]:
    require_scanner_source(source)
    already_added = {
        t.domain
        for t in db.query(ScannerDomainTarget).filter(ScannerDomainTarget.evidence_source_id == source.id).all()
    }
    return [
        d
        for d in db.query(OrganizationDomain)
        .filter(
            OrganizationDomain.organization_id == source.organization_id,
            OrganizationDomain.verification_status == "verified",
        )
        .all()
        if _normalize_domain(d.domain) not in already_added
    ]


def approve_domain_target(db: Session, target: ScannerDomainTarget, *, approved_by_user_id: int) -> ScannerDomainTarget:
    target.status = ScannerTargetStatus.APPROVED.value
    target.approved_by_user_id = approved_by_user_id
    target.approved_at = utcnow()
    db.add(target)
    return target


def exclude_domain_target(db: Session, target: ScannerDomainTarget) -> ScannerDomainTarget:
    target.status = ScannerTargetStatus.EXCLUDED.value
    db.add(target)
    return target


def list_domain_targets(db: Session, evidence_source_id: str) -> list[ScannerDomainTarget]:
    return (
        db.query(ScannerDomainTarget)
        .filter(ScannerDomainTarget.evidence_source_id == evidence_source_id)
        .order_by(ScannerDomainTarget.created_at.asc())
        .all()
    )


# --- Network targets -----------------------------------------------------------------


@dataclass(frozen=True)
class AddNetworkTargetResult:
    target: ScannerNetworkTarget
    warnings: list[str]
    estimated_address_count: int


def _parse_cidr(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(cidr.strip(), strict=True)
    except ValueError as exc:
        raise EvidenceScannerValidationError(SCANNER_ERROR_INVALID_CIDR) from exc


def add_network_target(
    db: Session,
    source: EvidenceSource,
    *,
    cidr: str,
    name: str,
    network_type: str,
    organisation_unit_id: str | None = None,
    location_id: str | None = None,
    environment: str | None = None,
) -> AddNetworkTargetResult:
    require_scanner_source(source)
    if not name.strip():
        raise EvidenceScannerValidationError("A name is required for this network range.")

    network = _parse_cidr(cidr)
    normalized_cidr = str(network)

    active_targets = (
        db.query(ScannerNetworkTarget)
        .filter(
            ScannerNetworkTarget.evidence_source_id == source.id,
            ScannerNetworkTarget.status != ScannerTargetStatus.DISABLED.value,
        )
        .all()
    )
    if any(t.cidr == normalized_cidr for t in active_targets):
        raise EvidenceScannerValidationError(SCANNER_ERROR_DUPLICATE_CIDR)

    warnings: list[str] = []
    if not network.is_private:
        warnings.append("public_range")
    if network.prefixlen < LARGE_NETWORK_WARNING_PREFIX_THRESHOLD:
        warnings.append("large_range")
    if any(network.overlaps(_parse_cidr(t.cidr)) for t in active_targets):
        warnings.append("overlapping_range")

    target = ScannerNetworkTarget(
        organization_id=source.organization_id,
        evidence_source_id=source.id,
        cidr=normalized_cidr,
        name=name.strip(),
        organisation_unit_id=organisation_unit_id,
        location_id=location_id,
        environment=environment,
        network_type=network_type,
        status=ScannerTargetStatus.DRAFT.value,
    )
    db.add(target)
    db.flush()
    return AddNetworkTargetResult(target=target, warnings=warnings, estimated_address_count=network.num_addresses)


def approve_network_target(
    db: Session, target: ScannerNetworkTarget, *, approved_by_user_id: int
) -> ScannerNetworkTarget:
    target.status = ScannerTargetStatus.APPROVED.value
    target.approved_by_user_id = approved_by_user_id
    target.approved_at = utcnow()
    db.add(target)
    return target


def exclude_network_target(db: Session, target: ScannerNetworkTarget) -> ScannerNetworkTarget:
    target.status = ScannerTargetStatus.EXCLUDED.value
    db.add(target)
    return target


def list_network_targets(db: Session, evidence_source_id: str) -> list[ScannerNetworkTarget]:
    return (
        db.query(ScannerNetworkTarget)
        .filter(ScannerNetworkTarget.evidence_source_id == evidence_source_id)
        .order_by(ScannerNetworkTarget.created_at.asc())
        .all()
    )


# --- Scan profile / scope confirmation ------------------------------------------------


def select_scan_profile(db: Session, instance: ScannerInstance, *, profile: str) -> ScannerInstance:
    instance.scan_profile = profile
    # Changing the profile invalidates any prior scope confirmation — the
    # confirmed scope summary (spec Screen 8) named the old profile.
    instance.scope_confirmed_at = None
    instance.scope_confirmed_by_user_id = None
    db.add(instance)
    return instance


def confirm_scanner_scope(
    db: Session, source: EvidenceSource, instance: ScannerInstance, *, confirmed_by_user_id: int
) -> ScannerInstance:
    if instance.scan_profile is None:
        raise EvidenceScannerValidationError(SCANNER_ERROR_PROFILE_REQUIRED)

    approved_domains = (
        db.query(ScannerDomainTarget)
        .filter(
            ScannerDomainTarget.evidence_source_id == source.id,
            ScannerDomainTarget.status == ScannerTargetStatus.APPROVED.value,
        )
        .count()
    )
    approved_networks = (
        db.query(ScannerNetworkTarget)
        .filter(
            ScannerNetworkTarget.evidence_source_id == source.id,
            ScannerNetworkTarget.status == ScannerTargetStatus.APPROVED.value,
        )
        .count()
    )
    if approved_domains + approved_networks == 0:
        raise EvidenceScannerValidationError(SCANNER_ERROR_SCOPE_EMPTY)

    instance.scope_confirmed_by_user_id = confirmed_by_user_id
    instance.scope_confirmed_at = utcnow()
    db.add(instance)
    return instance


# --- Tool validation / test scan (caller-reported, spec §10/§12) ----------------------


def record_tool_validation(db: Session, instance: ScannerInstance, *, tool_status: dict[str, str]) -> ScannerInstance:
    valid_tools = {t.value for t in ScannerToolName}
    valid_statuses = {s.value for s in ScannerToolStatus}
    for tool, status in tool_status.items():
        if tool not in valid_tools:
            raise EvidenceScannerValidationError(f"Unknown scanner tool: {tool}")
        if status not in valid_statuses:
            raise EvidenceScannerValidationError(f"Unknown tool status: {status}")

    instance.tool_status = tool_status
    instance.tool_validation_at = utcnow()
    db.add(instance)

    # CA-02.3 — this is now reachable only through the Collector's own
    # authenticated agent route (the user-facing path that let a person type the
    # same answer has been removed), so it *is* the agent's self-check and
    # records readiness as such. Keeping the two together means there is one
    # place where "the Collector reported its tools" happens, rather than a
    # service that writes half the truth and a route that remembers the rest.
    #
    # `tool_status`/`tool_validation_at` above are still written, for audit
    # continuity with historical rows — they are simply never read as a
    # readiness source again.
    record_readiness_report(
        db,
        instance,
        report=readiness_from_tool_statuses(
            tool_status, collector_version=instance.scanner_version
        ),
    )
    return instance


def record_test_scan_result(
    db: Session, instance: ScannerInstance, *, status: str, connection_verified: bool
) -> ScannerInstance:
    now = utcnow()
    instance.test_scan_status = status
    instance.test_scan_completed_at = now
    if connection_verified:
        instance.connection_verified_at = now
        instance.last_successful_connection_at = now
    db.add(instance)
    return instance


def get_instance(db: Session, evidence_source_id: str) -> ScannerInstance | None:
    return db.query(ScannerInstance).filter(ScannerInstance.evidence_source_id == evidence_source_id).first()


# --- Scanner lifecycle: create-as-one-step, pause/resume, regenerate token, retire ------
#
# Added after real operator testing surfaced that install-once-forever was a
# genuine dead end: no way to recover from a lost activation token, no way
# to stop/restart a scanner, no way to run more than one at a time without
# fighting the single-evidence-source wizard. None of this needed a schema
# change — an organisation could already have many scanner-type evidence
# sources (the DB only ever enforced one *instance* per *source*, never one
# scanner per organisation) — what was missing was the lifecycle actions and
# a way to create one without walking the full Step 3 wizard.


def create_scanner(
    db: Session,
    *,
    organization_id: int,
    name: str,
    installation_method: str,
    owner_user_id: int | None = None,
    business_service_id: str | None = None,
) -> ScannerInstallationResult:
    """Create a dedicated evidence source and install its scanner in one
    call — the "+ Add scanner" convenience path. Equivalent to walking
    Step 3's type/owner steps then calling install_scanner, collapsed
    into one step since a scanner's evidence source is purely a technical
    wrapper (scope/owner), never something a user manages separately.

    ``business_service_id`` (TENANT-79) scopes the new evidence source to a
    business process at create time — service-level granularity only, see
    evidence_source.py's own field comment for why per-dependency-node
    linkage isn't attempted here. Left None for the pre-existing org-wide
    Configuration/onboarding creation path."""
    source = create_evidence_source(
        db,
        organization_id=organization_id,
        name=name,
        source_type=EvidenceSourceType.SCANNER,
        owner_user_id=owner_user_id,
        business_service_id=business_service_id,
    )
    db.flush()
    return install_scanner(db, source, name=name, installation_method=installation_method)


def list_scanner_instances_for_org(db: Session, organization_id: int) -> list[ScannerInstance]:
    return (
        db.query(ScannerInstance)
        .filter(ScannerInstance.organization_id == organization_id)
        .order_by(ScannerInstance.registered_at.desc())
        .all()
    )


def _require_not_retired(instance: ScannerInstance) -> None:
    if instance.status == ScannerInstanceStatus.RETIRED.value:
        raise EvidenceScannerValidationError(SCANNER_ERROR_ALREADY_RETIRED)


def pause_scanner(db: Session, instance: ScannerInstance) -> ScannerInstance:
    """Deliberately stopped by the operator — distinct from OFFLINE (an
    unexpected drop) or REVOKED (a security/trust action). Resumable."""
    _require_not_retired(instance)
    instance.status = ScannerInstanceStatus.PAUSED.value
    db.add(instance)
    return instance


def resume_scanner(db: Session, instance: ScannerInstance) -> ScannerInstance:
    if instance.status != ScannerInstanceStatus.PAUSED.value:
        raise EvidenceScannerValidationError(SCANNER_ERROR_NOT_PAUSED)
    # Back to REGISTERED, not ONLINE — resuming is an operator's intent, not
    # proof of a live connection. Only a real heartbeat earns ONLINE
    # (matches this module's "never fabricate operational certainty" rule).
    instance.status = ScannerInstanceStatus.REGISTERED.value
    db.add(instance)
    return instance


def change_installation_method(
    db: Session, instance: ScannerInstance, *, installation_method: str
) -> ScannerInstallationResult:
    """Change how a Collector is installed — which means installing it again.

    Søren, 2026-08-24, correcting an earlier version of this that treated the
    method as a label and merely rewrote the field: *"if i change the how it is
    installed it is a much bigger change ... this should reset the entire
    scanner"*. He is right, and the reasons are structural rather than
    cosmetic:

    - **The activation command depends on it.** A Docker install is activated by
      ``docker run …``; a CLI install by ``risklence-scanner activate``. The old
      command no longer applies.
    - **The credential lives on the machine**, in the old install's own
      ``~/.risklence-scanner``. A container's volume is not a laptop's home
      directory, so the new install cannot inherit it.
    - **The signing key is per instance and derived from the token.** Leaving the
      old one valid would let a decommissioned install keep accepting signed
      commands.

    So this rotates the credential exactly as ``regenerate_activation_token``
    does, **and additionally clears what the old install reported about itself**
    — version, OS, architecture. Those described a machine that is no longer the
    one running this Collector, and leaving them would state something untrue
    with the platform's own authority.

    What survives, deliberately: the approved scope, the scan profile and the
    permission profile. Those are decisions a *person* made about what this
    Collector may reach, and they are not invalidated by it being reinstalled
    somewhere else.
    """
    if instance.status in (ScannerInstanceStatus.PAUSED.value, ScannerInstanceStatus.RETIRED.value):
        raise EvidenceScannerValidationError(SCANNER_ERROR_PAUSED_OR_RETIRED)
    if installation_method not in {member.value for member in ScannerInstallationMethod}:
        raise EvidenceScannerValidationError(f"Unknown installation method: {installation_method}")

    result = regenerate_activation_token(db, instance)
    instance.installation_method = installation_method
    # What the previous install told us about itself. It described a different
    # machine; keeping it would be the platform asserting something false.
    instance.scanner_version = None
    instance.os_name = None
    instance.architecture = None
    db.add(instance)
    return result


def regenerate_activation_token(db: Session, instance: ScannerInstance) -> ScannerInstallationResult:
    """Solves "I lost the activation token" (previously an unrecoverable
    dead end — see spec: only its hash is ever persisted) without
    discarding the scanner's configuration. Rotates the credential and
    clears connection-proof fields (they proved the *old* credential
    connected, not this one) but leaves scope/profile/tool-validation
    state untouched, since none of that is tied to the credential itself."""
    if instance.status in (ScannerInstanceStatus.PAUSED.value, ScannerInstanceStatus.RETIRED.value):
        raise EvidenceScannerValidationError(SCANNER_ERROR_PAUSED_OR_RETIRED)

    activation_token = secrets.token_urlsafe(32)
    instance.activation_token_hash = hashlib.sha256(activation_token.encode("utf-8")).hexdigest()
    instance.status = ScannerInstanceStatus.REGISTERED.value
    instance.activated_at = utcnow()
    instance.last_heartbeat_at = None
    instance.connection_verified_at = None
    instance.last_successful_connection_at = None
    # CA-04.1 — the old signing key was derived from the token just replaced
    # above, so it must rotate together with it, exactly like tool/command
    # signatures made under a rotated JWT secret would.
    signing_key = derive_command_signing_key(activation_token, instance.id)
    instance.command_signing_key_encrypted = encrypt_command_signing_key(instance.id, signing_key)
    db.add(instance)
    return ScannerInstallationResult(instance=instance, activation_token=activation_token)


def retire_scanner(db: Session, instance: ScannerInstance) -> ScannerInstance:
    """Soft-delete — "remove," matching this codebase's audit-trail-first
    convention everywhere else (evidence sources are archived, never hard-
    deleted). Allowed from any status, including already-revoked/offline."""
    _require_not_retired(instance)
    instance.status = ScannerInstanceStatus.RETIRED.value
    db.add(instance)
    return instance


# --- Named scanner credentials (TENANT-83/84) --------------------------------------
#
# Independent of the instance-level activation_token_hash above, which stays
# untouched and keeps working until the frontend migrates onto this table
# (TENANT-85). A scanner instance can hold many named ScannerCredential rows;
# each is created/rotated/paused/revoked/deleted on its own, and only its
# hash is ever persisted — the raw key is returned once, at create/rotate
# time, and never logged or written to audit metadata.


@dataclass(frozen=True)
class ScannerCredentialCreationResult:
    credential: ScannerCredential
    activation_token: str  # returned once — only the hash is persisted


def _generate_credential_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode("utf-8")).hexdigest()


def compute_credential_expiry(
    *, validity_policy: str, custom_days: int | None, now: datetime | None = None
) -> datetime | None:
    """Returns the calendar expiry for a policy, or ``None`` for policies
    that don't expire on a fixed date (``one_time`` expires on first use,
    tracked via ``consumed_at`` instead)."""
    reference = now or utcnow()
    if validity_policy == ScannerCredentialValidityPolicy.CUSTOM.value:
        if custom_days is None:
            raise EvidenceScannerValidationError(SCANNER_CREDENTIAL_ERROR_CUSTOM_DAYS_REQUIRED)
        if custom_days < 1 or custom_days > SCANNER_CREDENTIAL_MAX_CUSTOM_DAYS:
            raise EvidenceScannerValidationError(SCANNER_CREDENTIAL_ERROR_CUSTOM_DAYS_INVALID)
        return reference + timedelta(days=custom_days)

    days = SCANNER_CREDENTIAL_VALIDITY_DAYS.get(validity_policy)
    if days is None:
        return None
    return reference + timedelta(days=days)


def create_credential(
    db: Session,
    instance: ScannerInstance,
    *,
    name: str,
    validity_policy: str,
    custom_days: int | None = None,
    created_by_user_id: int | None = None,
) -> ScannerCredentialCreationResult:
    if not name.strip():
        raise EvidenceScannerValidationError(SCANNER_CREDENTIAL_ERROR_NAME_REQUIRED)
    expires_at = compute_credential_expiry(validity_policy=validity_policy, custom_days=custom_days)
    token, token_hash = _generate_credential_token()
    credential = ScannerCredential(
        organization_id=instance.organization_id,
        scanner_instance_id=instance.id,
        name=name.strip(),
        token_hash=token_hash,
        validity_policy=validity_policy,
        validity_custom_days=custom_days if validity_policy == ScannerCredentialValidityPolicy.CUSTOM.value else None,
        status=ScannerCredentialStatus.ACTIVE.value,
        created_at=utcnow(),
        created_by_user_id=created_by_user_id,
        expires_at=expires_at,
    )
    db.add(credential)
    db.flush()
    return ScannerCredentialCreationResult(credential=credential, activation_token=token)


def list_credentials_for_instance(db: Session, scanner_instance_id: str) -> list[ScannerCredential]:
    return (
        db.query(ScannerCredential)
        .filter(
            ScannerCredential.scanner_instance_id == scanner_instance_id,
            ScannerCredential.deleted_at.is_(None),
        )
        .order_by(ScannerCredential.created_at.desc())
        .all()
    )


def _require_credential_active(credential: ScannerCredential) -> None:
    if credential.status != ScannerCredentialStatus.ACTIVE.value:
        raise EvidenceScannerValidationError(SCANNER_CREDENTIAL_ERROR_NOT_ACTIVE)


def rotate_credential(
    db: Session,
    credential: ScannerCredential,
    *,
    validity_policy: str | None = None,
    custom_days: int | None = None,
) -> ScannerCredentialCreationResult:
    """Replaces the secret in place — same row, same name — and grants a
    fresh validity window starting now. Two paths, matching the "keep the
    same duration or pick a new one" choice presented at rotate time:
    pass ``validity_policy`` (and ``custom_days`` for CUSTOM) to switch to
    a new duration, or omit both to keep the credential's existing policy
    but renewed for its full length from the rotation moment (not the
    original creation moment — that's the whole point of rotating)."""
    _require_credential_active(credential)

    effective_policy = validity_policy or credential.validity_policy
    if effective_policy == ScannerCredentialValidityPolicy.CUSTOM.value:
        effective_custom_days = custom_days if custom_days is not None else credential.validity_custom_days
    else:
        effective_custom_days = None
    new_expiry = compute_credential_expiry(validity_policy=effective_policy, custom_days=effective_custom_days)

    token, token_hash = _generate_credential_token()
    credential.token_hash = token_hash
    credential.validity_policy = effective_policy
    credential.validity_custom_days = effective_custom_days
    credential.expires_at = new_expiry
    credential.last_rotated_at = utcnow()
    credential.consumed_at = None
    db.add(credential)
    db.flush()
    return ScannerCredentialCreationResult(credential=credential, activation_token=token)


def pause_credential(db: Session, credential: ScannerCredential) -> ScannerCredential:
    _require_credential_active(credential)
    credential.status = ScannerCredentialStatus.PAUSED.value
    credential.paused_at = utcnow()
    db.add(credential)
    return credential


def resume_credential(db: Session, credential: ScannerCredential) -> ScannerCredential:
    if credential.status != ScannerCredentialStatus.PAUSED.value:
        raise EvidenceScannerValidationError(SCANNER_ERROR_NOT_PAUSED)
    credential.status = ScannerCredentialStatus.ACTIVE.value
    credential.paused_at = None
    db.add(credential)
    return credential


def revoke_credential(db: Session, credential: ScannerCredential, *, revoked_by_user_id: int | None = None) -> ScannerCredential:
    """Permanent — unlike pause, revoke is not resumable, and the row (and
    its audit trail) is preserved, never deleted by this action alone."""
    if credential.status == ScannerCredentialStatus.REVOKED.value:
        raise EvidenceScannerValidationError(SCANNER_CREDENTIAL_ERROR_ALREADY_REVOKED)
    credential.status = ScannerCredentialStatus.REVOKED.value
    credential.revoked_at = utcnow()
    credential.revoked_by_user_id = revoked_by_user_id
    db.add(credential)
    return credential


def delete_credential(db: Session, credential: ScannerCredential) -> ScannerCredential:
    """Soft-delete only, and only once the credential can no longer
    authenticate anyone — an active key must be paused or revoked first,
    so a single misclick can't remove a live credential without an
    intermediate deactivation step."""
    if credential.deleted_at is not None:
        raise EvidenceScannerValidationError(SCANNER_CREDENTIAL_ERROR_ALREADY_DELETED)
    if credential.status == ScannerCredentialStatus.ACTIVE.value:
        raise EvidenceScannerValidationError(SCANNER_CREDENTIAL_ERROR_DELETE_WHILE_ACTIVE)
    credential.deleted_at = utcnow()
    credential.status = ScannerCredentialStatus.DELETED.value
    db.add(credential)
    return credential


def credential_can_authenticate(credential: ScannerCredential, *, now: datetime | None = None) -> bool:
    """The single source of truth for "is this key currently usable" —
    used both by the lifecycle API (to compute permitted actions) and by
    the scanner-agent authentication chokepoint (to actually gate a
    request), so the two can never drift apart."""
    if credential.status != ScannerCredentialStatus.ACTIVE.value:
        return False
    if credential.validity_policy == ScannerCredentialValidityPolicy.ONE_TIME.value:
        return credential.consumed_at is None
    if credential.expires_at is None:
        return True
    reference = now or utcnow()
    return _naive_utc(credential.expires_at) > _naive_utc(reference)


#: The published image, and the volume the agent keeps its credential in. Named
#: here so the docker command below and ``RiskScannerActivationGuide.tsx`` can be
#: compared side by side — they build the same command for the same install and
#: must not drift.
SCANNER_IMAGE = "ghcr.io/risklence/risklence-scanner:latest"
SCANNER_DATA_VOLUME = "risklence-scanner-data"


#: Commands an operator runs on the machine, other than activating. Each maps
#: to a real subcommand of ``scanner_agent.cli``.
COLLECTOR_ACTIONS = ("validate-tools", "test-scan")

#: What a Collector needs in order to see the network it is standing on.
#:
#: ``NET_RAW`` lets nmap ARP the local segment, which is the only way a MAC
#: address and hardware vendor are ever observed — and ``HARDWARE_VENDOR`` is
#: the one identity basis that can name a device with nothing listening. Søren
#: approved asking customers for this on 2026-08-25, against the alternative of
#: requesting SSH credentials to learn what an ARP reply gives free.
#:
#: ``--network host`` is on the same line because the capability alone is not
#: enough: a bridged container ARPs the Docker network, not the estate. On
#: Docker Desktop there is no true host networking, which is why the Collector's
#: README tells operators not to trust discovery from it.
SCANNER_NETWORK_FLAGS = "--cap-add=NET_RAW --network host"

#: The actions that actually put packets on the network, and therefore the only
#: ones granted the capability above. ``activate`` and ``validate-tools`` touch
#: nothing outside the container, and handing them a privilege they do not use
#: would teach operators that Risklence asks for more than it needs.
_ACTIONS_NEEDING_THE_NETWORK = frozenset({"test-scan"})


def generate_pull_command(*, installation_method: str | None = None) -> str | None:
    """How to get the Collector onto the machine in the first place.

    ``None`` for anything but Docker: a CLI or server install is fetched
    however that operator provisions software, and inventing a command for it
    would be guessing at their estate.

    Søren, 2026-08-25: rotating a credential shows only the *reconnect*
    command, which assumes an install that in his case did not exist — so the
    one instruction he was given could not work. A Collector that has never
    checked in is being installed, not reconnected, and needs this first.
    """
    if installation_method != ScannerInstallationMethod.DOCKER.value:
        return None
    return f"docker pull {SCANNER_IMAGE}"


def generate_collector_command(action: str, *, installation_method: str | None = None) -> str:
    """The exact command that clears an operator-side readiness gate.

    Søren, 2026-08-24, on being told *"run its tool check on the machine it is
    installed on"*: **"the message is useless i need to be able to do
    something"**. He is right. A blocking reason a person cannot act on is the
    same as no reason at all, and "run its tool check" is not an instruction —
    it names an outcome and leaves the reader to guess the command, the image
    and the volume.

    Shares the shape of ``generate_activation_command`` deliberately: same
    image, same named volume, same rule that a Docker install has no
    ``risklence-scanner`` on the operator's PATH. One definition of how this
    Collector is driven, not two.

    No base URL and no token: these act on the local install, using the
    credential it already stored at activation.
    """
    if installation_method == ScannerInstallationMethod.DOCKER.value:
        network = f"{SCANNER_NETWORK_FLAGS} " if action in _ACTIONS_NEEDING_THE_NETWORK else ""
        return (
            f"docker run --rm {network}-v {SCANNER_DATA_VOLUME}:/root/.risklence-scanner "
            f"{SCANNER_IMAGE} {action}"
        )
    return f"risklence-scanner {action}"


def generate_activation_command(
    *, activation_token: str, installation_method: str | None = None
) -> str:
    """Matches the real scanner CLI's actual signature (``apps/scanner/scanner_agent/cli.py``'s
    ``activate`` command — ``--base-url``/``--token``, no ``--tenant``: the credential itself
    carries the tenant, established at token-verification time via the scanner-agent auth
    chokepoint, not a CLI flag). Re-running ``activate`` with a new token also is how a
    rotated credential gets applied — it overwrites the locally stored credential file
    (``scanner_agent.config.save_credentials``), so no separate "reconfigure" command exists
    or is needed for the rotate case.

    **The method decides the command** (Søren, 2026-08-24, blocked by this).
    A Collector installed as a Docker container has no ``risklence-scanner`` on
    the operator's PATH, and handing them the CLI form gave
    ``zsh: command not found`` at the one step where a new user has nothing else
    to go on. The installation method has always been on the record; it simply
    was not consulted here.

    ``installation_method`` is optional so existing callers that have not been
    updated keep the previous behaviour rather than breaking — but every caller
    that knows the method should pass it, and the CLI form is the fallback for a
    genuinely unknown install, not a default.
    """
    if installation_method == ScannerInstallationMethod.DOCKER.value:
        # The container's view of the platform, which is not the host's. In
        # production both are the public origin and this falls back to it.
        base_url = settings.scanner_docker_api_base_url or settings.scanner_api_base_url
        return (
            f"docker run --rm -v {SCANNER_DATA_VOLUME}:/root/.risklence-scanner "
            f"{SCANNER_IMAGE} activate --base-url {base_url} --token {activation_token}"
        )
    base_url = settings.scanner_api_base_url
    return f"risklence-scanner activate --base-url {base_url} --token {activation_token}"


@dataclass(frozen=True)
class CollectorRestartGuidance:
    """How to get a stopped Collector running again (UX-DISC-06).

    The Collector runs on the customer's own infrastructure and polls outbound;
    the platform queues work and waits. That architecture is correct and does
    not change here — Risklence must never start a process inside a customer
    network. What was missing is the one thing a user cannot work out for
    themselves: that their agent has stopped, and the exact command that starts
    it again on the machine it was installed on.
    """

    #: The command to run, or ``None`` where there is none the user could
    #: usefully run themselves.
    command: str | None
    #: Which machine to run it on. A command with no machine named leaves the
    #: user guessing while already stuck.
    host_label: str | None
    #: False when starting this Collector is not the user's to do. There is no
    #: stored "who installed this" on ScannerInstance, so this deliberately
    #: carries no name: the view says "contact whoever set this up", which is
    #: true, rather than the platform inventing a party it cannot know.
    self_service: bool


#: Per installation method, because a generic instruction is not actionable:
#: someone who installed via Docker cannot use a CLI command and vice versa, and
#: showing the wrong one costs them the time it takes to find out it is wrong.
_RESTART_COMMANDS: dict[str, str] = {
    ScannerInstallationMethod.DOCKER.value: "docker start risklence-scanner",
    ScannerInstallationMethod.LOCAL_CLI.value: "risklence-scanner run",
    ScannerInstallationMethod.SERVER.value: "sudo systemctl start risklence-scanner",
}


def _collector_host_label(instance: ScannerInstance) -> str | None:
    """The machine, as specifically as the agent has actually told us.

    ``os_name``/``architecture`` are null until a heartbeat from an agent build
    that reports them, and are never fabricated for older instances — so this
    degrades to the instance name rather than claiming a platform we were not
    told about.
    """
    platform = " · ".join(part for part in (instance.os_name, instance.architecture) if part)
    if instance.name and platform:
        return f"{instance.name} ({platform})"
    return instance.name or (platform or None)


def resolve_collector_restart_guidance(instance: ScannerInstance) -> CollectorRestartGuidance:
    """What to tell someone whose Collector has stopped.

    ``consultant_assisted`` deliberately returns no command. That install was
    performed by someone else, on infrastructure the user may not have access
    to; printing a command they cannot run is worse than printing none, because
    it reads as "you have not done this" rather than "this is not yours to do".

    An unrecognised installation method also returns no command rather than a
    guessed one — a wrong command sends someone to a terminal to be told the
    binary does not exist, which is a worse outcome than being told plainly that
    we do not know how this one was installed.
    """
    method = (instance.installation_method or "").strip().lower()
    consultant_assisted = method == ScannerInstallationMethod.CONSULTANT_ASSISTED.value
    return CollectorRestartGuidance(
        command=None if consultant_assisted else _RESTART_COMMANDS.get(method),
        host_label=_collector_host_label(instance),
        self_service=not consultant_assisted,
    )
